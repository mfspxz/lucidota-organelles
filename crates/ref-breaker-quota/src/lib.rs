//! org-032 — Reference organelle: breaker-quota (codon `bq`).
//!
//! A circuit breaker and a quota meter as one reusable organelle
//! (GAP-06 in the 2026-11-22 decomposition map: five scoped
//! softwares — FAC, EXC, EVD, RTR, TRN — hand-roll the same
//! machinery today: RTR's per-lane breakers with escalating
//! backoff and RPM windows in `ai-router.js`, EXC's `quotas`
//! table + THROTTLED/suspended states in the governor, FAC's
//! per-provider sliding-window `RateLimiter` in
//! `factory/workers/adapters/_limits.py`, TRN's per-feed poll
//! floor, EVD's resource-governor watch).
//!
//! The doctrine this crate is built under (Zack, 2026-11-21):
//! **telemetry and granular reporting are good; hardcoded policy
//! rules are bad.**  Every threshold — the failure count that
//! trips the breaker, the window those failures count in, the
//! cooldown schedule, the probe budget, the quota limit, the
//! window shape, the reset boundary — is caller-supplied data,
//! stated in full in [`BreakerConfig`] / [`QuotaConfig`].  The
//! structs have no serde defaults and no `Default` impls: a
//! config that does not state its own numbers does not
//! deserialize, and construction validates what was stated.
//! This crate ships **no presets, no named groupings, and no
//! defaults that decide behaviour** — it contributes only the
//! state-machine semantics (closed / open / half-open; windowed
//! accounting) and the accounting.  The organelle meters and
//! trips; it does not legislate.
//!
//! Time is an injected input.  The core state machines take
//! `now_ms` on every call and never read a clock; embedders who
//! want a clock object pass `clock.now_ms()` from the [`Clock`]
//! trait ([`ManualClock`] for tests and replays, [`SystemClock`]
//! native-only).  Jitter is likewise an input: a caller who
//! wants RTR-style ±25% cooldown jitter samples it themselves
//! and passes the signed offset to
//! [`Breaker::record_failure`], so a replayed script reproduces
//! the exact cooldowns the live run took.
//!
//! Every state transition appends a [`TraceRecord`] — what
//! tripped or reset, the counts at that moment, and the sha256
//! of the config in force — so the record drops straight into a
//! receipt or an evidence log.  Same script of calls + same
//! configs → byte-identical state and trace.
//!
//! Semantics (the crate's contract, not policy):
//!
//! * **Breaker.** Failures count *consecutively within the
//!   window*: a success in the closed state clears the recorded
//!   failures, and failures older than `window_ms` stop
//!   counting.  The breaker trips on the call that makes the
//!   count reach `failure_threshold` — not one earlier, not one
//!   later.  While open, calls are denied with the exact
//!   `retry_at_ms`.  Once the cooldown has elapsed the next
//!   `admit` moves the breaker to half-open (traced) and admits
//!   up to `half_open_max_probes` concurrent probes;
//!   `half_open_successes_to_close` consecutive probe successes
//!   close it (open count and failure record reset), and any
//!   probe failure re-opens it with the next cooldown from the
//!   caller's schedule.  Outcomes recorded while open are
//!   ignored: a late failure from a pre-trip call must not
//!   extend an outage, and a late success must not close a
//!   breaker nobody probed.
//! * **Quota.** `try_consume` is all-or-nothing: a request
//!   larger than the remaining quota is denied whole and
//!   consumes nothing — backpressure honesty, no silent partial
//!   grants.  A denial reports `retry_at_ms` whenever the
//!   window shape makes that knowable (fixed/calendar: the
//!   window end; sliding: the moment enough old consumption
//!   expires), and `None` when the request can never fit the
//!   limit.  Windows are caller shapes: [`WindowSpec::Fixed`]
//!   (anchored repeating windows), [`WindowSpec::Sliding`]
//!   (trailing window over individual consumptions), and
//!   [`WindowSpec::CalendarDay`] (a day boundary at the
//!   caller's UTC offset — offset 0 is the Exchange's
//!   daily-row-read shape: a limit resetting at UTC midnight,
//!   expressed as data, not as a special case).
//! * **Concurrency.** The pure cores are `&mut self` state
//!   machines for deterministic embedding; [`SyncBreaker`] and
//!   [`SyncQuota`] wrap them in a mutex so check-and-consume /
//!   check-and-admit are atomic — concurrent callers cannot
//!   overshoot a quota or a probe budget between the check and
//!   the claim.

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(feature = "organelle")]
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;

// ---------------------------------------------------------------------
// Clock.  Time is an injected input: the core logic reads time
// only through the `now_ms` argument of each call.  The trait is
// for embedders who prefer to hold a clock object (the
// ref-lease-queue pattern); the state machines themselves never
// touch it.
// ---------------------------------------------------------------------

pub trait Clock {
    fn now_ms(&self) -> i64;
}

/// A clock the caller sets explicitly.  Deterministic: replays
/// and tests drive time by hand.
pub struct ManualClock {
    now: std::sync::atomic::AtomicI64,
}

impl ManualClock {
    pub fn new(now_ms: i64) -> Self {
        ManualClock {
            now: std::sync::atomic::AtomicI64::new(now_ms),
        }
    }
    pub fn set(&self, now_ms: i64) {
        self.now.store(now_ms, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn advance(&self, delta_ms: i64) {
        self.now
            .fetch_add(delta_ms, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Wall-clock time, native only.  Tests and replays use
/// [`ManualClock`].
#[cfg(not(target_arch = "wasm32"))]
pub struct SystemClock;

#[cfg(not(target_arch = "wasm32"))]
impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------
// Errors.  Construction rejects a config that states nonsense;
// runtime ops on a validated state machine do not fail — they
// return admissions and outcomes.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakerQuotaError {
    InvalidConfig(String),
}

impl fmt::Display for BreakerQuotaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BreakerQuotaError::InvalidConfig(m) => write!(f, "invalid config: {m}"),
        }
    }
}

impl std::error::Error for BreakerQuotaError {}

type CfgResult<T> = std::result::Result<T, BreakerQuotaError>;

fn invalid(msg: impl Into<String>) -> BreakerQuotaError {
    BreakerQuotaError::InvalidConfig(msg.into())
}

// ---------------------------------------------------------------------
// Config as data.  Every field is required: there are no serde
// defaults in this crate, because a default would be a rule the
// caller never stated.
// ---------------------------------------------------------------------

/// How the open-state cooldown grows with the number of
/// consecutive trips (`open_count`, starting at 1 for the first
/// trip).  Data, in the ref-lease-queue backoff shape — RTR's
/// 30s → 60s → 120s → 300s escalation is a `Schedule` an adopter
/// states, not a table this crate ships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooldownPolicy {
    /// Every trip waits `cooldown_ms`.
    Fixed { cooldown_ms: i64 },
    /// Trip `n` waits `base_ms + step_ms * (n - 1)`.
    Linear { base_ms: i64, step_ms: i64 },
    /// Trip `n` waits `base_ms * factor^(n-1)`, capped at
    /// `max_ms`.
    Exponential {
        base_ms: i64,
        factor: u32,
        max_ms: i64,
    },
    /// Trip `n` waits `cooldowns_ms[n - 1]`, holding at the last
    /// entry once the schedule runs out.
    Schedule { cooldowns_ms: Vec<i64> },
}

impl CooldownPolicy {
    /// The cooldown for the `open_count`-th consecutive trip
    /// (1-based).  Pure arithmetic over caller data.
    pub fn cooldown_ms(&self, open_count: u32) -> i64 {
        let n = open_count.max(1);
        match self {
            CooldownPolicy::Fixed { cooldown_ms } => *cooldown_ms,
            CooldownPolicy::Linear { base_ms, step_ms } => base_ms
                .saturating_add(step_ms.saturating_mul(i64::from(n - 1))),
            CooldownPolicy::Exponential {
                base_ms,
                factor,
                max_ms,
            } => {
                let mut v = *base_ms;
                for _ in 1..n {
                    v = v.saturating_mul(i64::from(*factor));
                    if v >= *max_ms {
                        return *max_ms;
                    }
                }
                v.min(*max_ms)
            }
            CooldownPolicy::Schedule { cooldowns_ms } => {
                let idx = (n as usize - 1).min(cooldowns_ms.len() - 1);
                cooldowns_ms[idx]
            }
        }
    }

    fn validate(&self) -> CfgResult<()> {
        match self {
            CooldownPolicy::Fixed { cooldown_ms } if *cooldown_ms < 0 => {
                Err(invalid("cooldown_ms must be >= 0"))
            }
            CooldownPolicy::Linear { base_ms, step_ms }
                if *base_ms < 0 || *step_ms < 0 =>
            {
                Err(invalid("linear cooldown base_ms/step_ms must be >= 0"))
            }
            CooldownPolicy::Exponential {
                base_ms,
                factor,
                max_ms,
            } => {
                if *base_ms < 0 || *max_ms < *base_ms {
                    Err(invalid("exponential cooldown needs 0 <= base_ms <= max_ms"))
                } else if *factor < 1 {
                    Err(invalid("exponential cooldown factor must be >= 1"))
                } else {
                    Ok(())
                }
            }
            CooldownPolicy::Schedule { cooldowns_ms } => {
                if cooldowns_ms.is_empty() {
                    Err(invalid("cooldown schedule must not be empty"))
                } else if cooldowns_ms.iter().any(|c| *c < 0) {
                    Err(invalid("cooldown schedule entries must be >= 0"))
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}

/// The complete breaker configuration.  All fields required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakerConfig {
    /// Consecutive failures inside `window_ms` that trip the
    /// breaker.  The trip happens on the failure that reaches
    /// this count.
    pub failure_threshold: u32,
    /// Trailing window (ms) over which failures count.  A
    /// failure at time `t` counts failures in `(t - window_ms,
    /// t]`; a success clears the record entirely (consecutive
    /// semantics).
    pub window_ms: i64,
    /// Cooldown per consecutive trip, as data.
    pub cooldown: CooldownPolicy,
    /// Maximum probes in flight at once while half-open.
    pub half_open_max_probes: u32,
    /// Consecutive probe successes that close the breaker.
    pub half_open_successes_to_close: u32,
}

impl BreakerConfig {
    pub fn validate(&self) -> CfgResult<()> {
        if self.failure_threshold == 0 {
            return Err(invalid("failure_threshold must be >= 1"));
        }
        if self.window_ms <= 0 {
            return Err(invalid("window_ms must be > 0"));
        }
        if self.half_open_max_probes == 0 {
            return Err(invalid("half_open_max_probes must be >= 1"));
        }
        if self.half_open_successes_to_close == 0 {
            return Err(invalid("half_open_successes_to_close must be >= 1"));
        }
        self.cooldown.validate()
    }
}

/// The shape of a quota window.  All fields required; the reset
/// boundary is whatever the caller's shape computes, never a
/// crate rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowSpec {
    /// Repeating windows of `window_ms` aligned to `anchor_ms`:
    /// window `k` is `[anchor + k*window, anchor + (k+1)*window)`.
    Fixed { window_ms: i64, anchor_ms: i64 },
    /// A trailing window: each consumption counts until it is
    /// `window_ms` old, then expires individually.
    Sliding { window_ms: i64 },
    /// A calendar day in the caller's offset frame: the window
    /// is the day containing `now` where day boundaries fall at
    /// `utc_offset_ms` from UTC midnight.  Offset 0 = reset at
    /// UTC midnight (the Exchange daily-row-read shape).
    CalendarDay { utc_offset_ms: i64 },
}

const DAY_MS: i64 = 86_400_000;

impl WindowSpec {
    fn validate(&self) -> CfgResult<()> {
        match self {
            WindowSpec::Fixed { window_ms, .. } if *window_ms <= 0 => {
                Err(invalid("fixed window_ms must be > 0"))
            }
            WindowSpec::Sliding { window_ms } if *window_ms <= 0 => {
                Err(invalid("sliding window_ms must be > 0"))
            }
            WindowSpec::CalendarDay { utc_offset_ms }
                if *utc_offset_ms <= -DAY_MS || *utc_offset_ms >= DAY_MS =>
            {
                Err(invalid("calendar-day utc_offset_ms must be within one day"))
            }
            _ => Ok(()),
        }
    }

    /// `(window_start_ms, window_end_ms)` of the window
    /// containing `now_ms`, for the bounded shapes.  `None` for
    /// sliding windows, which have no single boundary.
    fn bounds(&self, now_ms: i64) -> Option<(i64, i64)> {
        match self {
            WindowSpec::Fixed {
                window_ms,
                anchor_ms,
            } => {
                let k = (now_ms - anchor_ms).div_euclid(*window_ms);
                let start = anchor_ms + k * window_ms;
                Some((start, start + window_ms))
            }
            WindowSpec::CalendarDay { utc_offset_ms } => {
                let start = (now_ms - utc_offset_ms).div_euclid(DAY_MS) * DAY_MS + utc_offset_ms;
                Some((start, start + DAY_MS))
            }
            WindowSpec::Sliding { .. } => None,
        }
    }
}

/// The complete quota configuration.  All fields required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaConfig {
    /// Maximum units consumable per window.  A single consume
    /// may take any number of units (a count call takes 1; a
    /// D1 query takes its rows-read) — cost is per-call data.
    pub limit: u64,
    /// The window shape and reset semantics.
    pub window: WindowSpec,
}

impl QuotaConfig {
    pub fn validate(&self) -> CfgResult<()> {
        if self.limit == 0 {
            return Err(invalid("limit must be >= 1"));
        }
        self.window.validate()
    }
}

/// sha256 over the canonical serialization of a config — the
/// "config in force" fingerprint every trace record carries.
fn config_sha256<T: Serialize>(config: &T) -> String {
    let bytes = serde_json::to_vec(config).expect("config values are always serializable");
    hex::encode(Sha256::digest(&bytes))
}

// ---------------------------------------------------------------------
// Trace.  Every state transition appends one record: the event,
// the moment it happened (caller time), the counts at that
// moment, and the fingerprint of the config in force.  Records
// are the telemetry product — a caller drains or peeks the log
// and persists it via composition (ref-ledger-append,
// ref-cf-storage, a host receipt log).
// ---------------------------------------------------------------------

/// Trace event names.  Plain strings so the serialized record
/// is stable across crate versions.
pub mod trace_event {
    pub const CONFIGURED: &str = "configured";
    pub const BREAKER_TRIPPED: &str = "breaker_tripped";
    pub const BREAKER_HALF_OPENED: &str = "breaker_half_opened";
    pub const BREAKER_CLOSED: &str = "breaker_closed";
    pub const BREAKER_REOPENED: &str = "breaker_reopened";
    pub const FAILURE_RECORD_CLEARED: &str = "failure_record_cleared";
    pub const QUOTA_WINDOW_RESET: &str = "quota_window_reset";
    pub const QUOTA_EXHAUSTED: &str = "quota_exhausted";
    pub const RESET: &str = "reset";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRecord {
    /// Per-subject sequence number, starting at 0 (the
    /// `configured` record).
    pub seq: u64,
    /// Caller-supplied time of the transition.
    pub at_ms: i64,
    /// The breaker/quota name this record belongs to.
    pub subject: String,
    /// One of [`trace_event`].
    pub event: String,
    /// sha256 of the config in force for this subject.
    pub config_sha256: String,
    /// Event-specific counts and facts (trip counts, cooldown
    /// applied, window bounds, usage at exhaustion…).
    pub detail: Value,
}

// ---------------------------------------------------------------------
// Circuit breaker.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The breaker is open; `retry_at_ms` is the moment the
    /// cooldown elapses.
    BreakerOpen,
    /// The breaker is half-open and every probe slot is taken;
    /// a probe completion, not a clock, changes this.
    ProbesSaturated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    /// Closed-state admission (not a probe).
    Allowed,
    /// Half-open probe admission; the caller must report the
    /// outcome via `record_success` / `record_failure`.
    AllowedProbe,
    Denied {
        retry_at_ms: Option<i64>,
        reason: DenyReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakerSnapshot {
    pub state: BreakerState,
    /// Failures currently counting toward the threshold
    /// (in-window, since the last success).
    pub failures_in_window: u32,
    /// Consecutive trips since the breaker last closed.
    pub open_count: u32,
    /// When the current cooldown elapses (open state only).
    pub cooldown_until_ms: Option<i64>,
    pub probes_in_flight: u32,
    /// Consecutive probe successes toward closing.
    pub probe_successes: u32,
    pub config_sha256: String,
}

/// The breaker state machine.  Pure: every method takes the
/// caller's `now_ms`; nothing here reads a clock, an RNG, the
/// environment, or I/O.
#[derive(Debug, Clone)]
pub struct Breaker {
    name: String,
    config: BreakerConfig,
    config_sha256: String,
    state: BreakerState,
    failures: VecDeque<i64>,
    open_count: u32,
    cooldown_until_ms: Option<i64>,
    probes_in_flight: u32,
    probe_successes: u32,
    trace: Vec<TraceRecord>,
}

impl Breaker {
    pub fn new(name: impl Into<String>, config: BreakerConfig, now_ms: i64) -> CfgResult<Self> {
        config.validate()?;
        let name = name.into();
        let config_sha256 = config_sha256(&config);
        let mut b = Breaker {
            name,
            config,
            config_sha256,
            state: BreakerState::Closed,
            failures: VecDeque::new(),
            open_count: 0,
            cooldown_until_ms: None,
            probes_in_flight: 0,
            probe_successes: 0,
            trace: Vec::new(),
        };
        b.push_trace(
            now_ms,
            trace_event::CONFIGURED,
            serde_json::json!({"kind": "breaker"}),
        );
        Ok(b)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn config(&self) -> &BreakerConfig {
        &self.config
    }

    fn push_trace(&mut self, at_ms: i64, event: &str, detail: Value) {
        let seq = self.trace.len() as u64;
        self.trace.push(TraceRecord {
            seq,
            at_ms,
            subject: self.name.clone(),
            event: event.to_string(),
            config_sha256: self.config_sha256.clone(),
            detail,
        });
    }

    /// The full trace so far, oldest first.
    pub fn trace(&self) -> &[TraceRecord] {
        &self.trace
    }

    fn prune_failures(&mut self, now_ms: i64) {
        let floor = now_ms - self.config.window_ms;
        while let Some(&t) = self.failures.front() {
            if t <= floor {
                self.failures.pop_front();
            } else {
                break;
            }
        }
    }

    /// Ask permission for one call.  Performs the open →
    /// half-open transition when the cooldown has elapsed
    /// (traced), and claims a probe slot when half-open.
    pub fn admit(&mut self, now_ms: i64) -> Admission {
        match self.state {
            BreakerState::Closed => Admission::Allowed,
            BreakerState::Open => {
                let until = self.cooldown_until_ms.unwrap_or(now_ms);
                if now_ms >= until {
                    self.state = BreakerState::HalfOpen;
                    self.probes_in_flight = 0;
                    self.probe_successes = 0;
                    self.push_trace(
                        now_ms,
                        trace_event::BREAKER_HALF_OPENED,
                        serde_json::json!({
                            "open_count": self.open_count,
                            "cooldown_until_ms": until,
                        }),
                    );
                    self.admit_probe()
                } else {
                    Admission::Denied {
                        retry_at_ms: Some(until),
                        reason: DenyReason::BreakerOpen,
                    }
                }
            }
            BreakerState::HalfOpen => self.admit_probe(),
        }
    }

    fn admit_probe(&mut self) -> Admission {
        if self.probes_in_flight < self.config.half_open_max_probes {
            self.probes_in_flight += 1;
            Admission::AllowedProbe
        } else {
            Admission::Denied {
                retry_at_ms: None,
                reason: DenyReason::ProbesSaturated,
            }
        }
    }

    /// Report a successful call.
    pub fn record_success(&mut self, now_ms: i64) {
        match self.state {
            BreakerState::Closed => {
                if !self.failures.is_empty() {
                    let cleared = self.failures.len() as u32;
                    self.failures.clear();
                    self.push_trace(
                        now_ms,
                        trace_event::FAILURE_RECORD_CLEARED,
                        serde_json::json!({"cleared_failures": cleared}),
                    );
                }
            }
            BreakerState::HalfOpen => {
                self.probes_in_flight = self.probes_in_flight.saturating_sub(1);
                self.probe_successes += 1;
                if self.probe_successes >= self.config.half_open_successes_to_close {
                    let trips = self.open_count;
                    self.state = BreakerState::Closed;
                    self.open_count = 0;
                    self.cooldown_until_ms = None;
                    self.probes_in_flight = 0;
                    self.probe_successes = 0;
                    self.failures.clear();
                    self.push_trace(
                        now_ms,
                        trace_event::BREAKER_CLOSED,
                        serde_json::json!({"after_trips": trips}),
                    );
                }
            }
            BreakerState::Open => {
                // A late success from a pre-trip call: not a
                // probe, proves nothing about recovery.  Ignored.
            }
        }
    }

    /// Report a failed call.  `jitter_ms` is the caller's own
    /// sampled cooldown jitter (signed; RTR samples ±25% of the
    /// cooldown) — an input, so replays reproduce live timing.
    /// The total cooldown is clamped at 0.
    pub fn record_failure(&mut self, now_ms: i64, jitter_ms: i64) {
        match self.state {
            BreakerState::Closed => {
                self.prune_failures(now_ms);
                self.failures.push_back(now_ms);
                if (self.failures.len() as u32) >= self.config.failure_threshold {
                    self.trip(now_ms, jitter_ms, trace_event::BREAKER_TRIPPED);
                }
            }
            BreakerState::HalfOpen => {
                self.probes_in_flight = self.probes_in_flight.saturating_sub(1);
                self.probe_successes = 0;
                self.trip(now_ms, jitter_ms, trace_event::BREAKER_REOPENED);
            }
            BreakerState::Open => {
                // A late failure from a pre-trip call.  Ignored:
                // it must not extend the running cooldown.
            }
        }
    }

    fn trip(&mut self, now_ms: i64, jitter_ms: i64, event: &str) {
        self.open_count += 1;
        let base = self.config.cooldown.cooldown_ms(self.open_count);
        let applied = (base + jitter_ms).max(0);
        self.state = BreakerState::Open;
        self.cooldown_until_ms = Some(now_ms + applied);
        self.probes_in_flight = 0;
        self.probe_successes = 0;
        self.push_trace(
            now_ms,
            event,
            serde_json::json!({
                "failures_in_window": self.failures.len(),
                "failure_threshold": self.config.failure_threshold,
                "open_count": self.open_count,
                "cooldown_base_ms": base,
                "jitter_ms": jitter_ms,
                "cooldown_applied_ms": applied,
                "cooldown_until_ms": now_ms + applied,
            }),
        );
    }

    /// Forget all state and return to closed, keeping the same
    /// config.  Traced — a reset is an operator act and belongs
    /// on the record.
    pub fn reset(&mut self, now_ms: i64) {
        self.state = BreakerState::Closed;
        self.failures.clear();
        self.open_count = 0;
        self.cooldown_until_ms = None;
        self.probes_in_flight = 0;
        self.probe_successes = 0;
        self.push_trace(now_ms, trace_event::RESET, serde_json::json!({"kind": "breaker"}));
    }

    pub fn snapshot(&self, now_ms: i64) -> BreakerSnapshot {
        let mut failures = self.failures.clone();
        let floor = now_ms - self.config.window_ms;
        while let Some(&t) = failures.front() {
            if t <= floor {
                failures.pop_front();
            } else {
                break;
            }
        }
        BreakerSnapshot {
            state: self.state,
            failures_in_window: failures.len() as u32,
            open_count: self.open_count,
            cooldown_until_ms: self.cooldown_until_ms,
            probes_in_flight: self.probes_in_flight,
            probe_successes: self.probe_successes,
            config_sha256: self.config_sha256.clone(),
        }
    }
}

// ---------------------------------------------------------------------
// Quota meter.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumeOutcome {
    /// True iff the full `units` were consumed.  Denials
    /// consume nothing — there are no partial grants.
    pub granted: bool,
    /// Units consumed in the current window, after this call.
    pub used: u64,
    /// Units still available in the current window.
    pub remaining: u64,
    /// When a retry could succeed, if the window shape makes
    /// that knowable.  `None` when the request exceeds the
    /// limit itself (it can never fit) or when a sliding window
    /// cannot free enough — never a guessed number.
    pub retry_at_ms: Option<i64>,
    /// Bounds of the window this outcome was computed in
    /// (`window_end_ms` is `None` for sliding windows).
    pub window_start_ms: Option<i64>,
    pub window_end_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaSnapshot {
    pub used: u64,
    pub remaining: u64,
    pub limit: u64,
    pub window_start_ms: Option<i64>,
    pub window_end_ms: Option<i64>,
    pub config_sha256: String,
}

/// The quota state machine.  Pure: every method takes the
/// caller's `now_ms`.
#[derive(Debug, Clone)]
pub struct QuotaMeter {
    name: String,
    config: QuotaConfig,
    config_sha256: String,
    /// Bounded shapes: the start of the window `used` belongs
    /// to.  `None` until the first call.
    window_start: Option<i64>,
    used: u64,
    /// Sliding shape: individual consumptions, oldest first.
    events: VecDeque<(i64, u64)>,
    trace: Vec<TraceRecord>,
}

impl QuotaMeter {
    pub fn new(name: impl Into<String>, config: QuotaConfig, now_ms: i64) -> CfgResult<Self> {
        config.validate()?;
        let name = name.into();
        let config_sha256 = config_sha256(&config);
        let mut q = QuotaMeter {
            name,
            config,
            config_sha256,
            window_start: None,
            used: 0,
            events: VecDeque::new(),
            trace: Vec::new(),
        };
        q.push_trace(
            now_ms,
            trace_event::CONFIGURED,
            serde_json::json!({"kind": "quota"}),
        );
        Ok(q)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn config(&self) -> &QuotaConfig {
        &self.config
    }

    fn push_trace(&mut self, at_ms: i64, event: &str, detail: Value) {
        let seq = self.trace.len() as u64;
        self.trace.push(TraceRecord {
            seq,
            at_ms,
            subject: self.name.clone(),
            event: event.to_string(),
            config_sha256: self.config_sha256.clone(),
            detail,
        });
    }

    pub fn trace(&self) -> &[TraceRecord] {
        &self.trace
    }

    /// Roll bounded-window state into `now`'s window, tracing
    /// the reset when a mutating call first lands in a new
    /// window.  Returns the window bounds.
    fn roll_window(&mut self, now_ms: i64) -> Option<(i64, i64)> {
        let bounds = self.config.window.bounds(now_ms)?;
        let (start, end) = bounds;
        match self.window_start {
            None => {
                self.window_start = Some(start);
            }
            Some(cur) if cur != start => {
                let previous_used = self.used;
                self.window_start = Some(start);
                self.used = 0;
                self.push_trace(
                    now_ms,
                    trace_event::QUOTA_WINDOW_RESET,
                    serde_json::json!({
                        "previous_window_start_ms": cur,
                        "previous_used": previous_used,
                        "window_start_ms": start,
                        "window_end_ms": end,
                        "limit": self.config.limit,
                    }),
                );
            }
            _ => {}
        }
        Some(bounds)
    }

    fn prune_events(&mut self, now_ms: i64) {
        if let WindowSpec::Sliding { window_ms } = self.config.window {
            let floor = now_ms - window_ms;
            while let Some(&(t, _)) = self.events.front() {
                if t <= floor {
                    self.events.pop_front();
                } else {
                    break;
                }
            }
        }
    }

    fn used_at(&self, now_ms: i64) -> u64 {
        match self.config.window {
            WindowSpec::Sliding { window_ms } => {
                let floor = now_ms - window_ms;
                self.events
                    .iter()
                    .filter(|(t, _)| *t > floor)
                    .map(|(_, u)| *u)
                    .sum()
            }
            _ => match self.config.window.bounds(now_ms) {
                Some((start, _)) if self.window_start == Some(start) => self.used,
                _ => 0,
            },
        }
    }

    /// Atomically check and consume `units` (atomicity across
    /// threads is the [`SyncQuota`] wrapper's mutex; this core
    /// is atomic within a call by construction — the check and
    /// the consumption are one indivisible step).
    pub fn try_consume(&mut self, now_ms: i64, units: u64) -> ConsumeOutcome {
        let bounds = self.roll_window(now_ms);
        self.prune_events(now_ms);
        let used = self.used_at(now_ms);
        let limit = self.config.limit;
        let remaining = limit.saturating_sub(used);
        let (win_start, win_end) = match bounds {
            Some((s, e)) => (Some(s), Some(e)),
            None => (None, None),
        };
        if units > remaining {
            return ConsumeOutcome {
                granted: false,
                used,
                remaining,
                retry_at_ms: self.retry_at(now_ms, units, used),
                window_start_ms: win_start,
                window_end_ms: win_end,
            };
        }
        match self.config.window {
            WindowSpec::Sliding { .. } => self.events.push_back((now_ms, units)),
            _ => self.used = used + units,
        }
        let used_after = used + units;
        let remaining_after = limit - used_after;
        if remaining_after == 0 && units > 0 {
            self.push_trace(
                now_ms,
                trace_event::QUOTA_EXHAUSTED,
                serde_json::json!({
                    "used": used_after,
                    "limit": limit,
                    "window_start_ms": win_start,
                    "window_end_ms": win_end,
                }),
            );
        }
        ConsumeOutcome {
            granted: true,
            used: used_after,
            remaining: remaining_after,
            retry_at_ms: None,
            window_start_ms: win_start,
            window_end_ms: win_end,
        }
    }

    /// The earliest moment a denied request of `units` could
    /// fit, or `None` if it can never fit the limit.
    fn retry_at(&self, now_ms: i64, units: u64, used: u64) -> Option<i64> {
        if units > self.config.limit {
            return None;
        }
        match self.config.window {
            WindowSpec::Sliding { window_ms } => {
                // Walk consumptions oldest-first, accumulating
                // what their expiry frees, until enough is free.
                let need_free = (used + units) - self.config.limit;
                let mut freed = 0u64;
                let floor = now_ms - window_ms;
                for (t, u) in self.events.iter().filter(|(t, _)| *t > floor) {
                    freed += u;
                    if freed >= need_free {
                        return Some(t + window_ms);
                    }
                }
                None
            }
            _ => self.config.window.bounds(now_ms).map(|(_, end)| end),
        }
    }

    /// Units available right now.  A peek: records nothing,
    /// mutates nothing.
    pub fn available(&self, now_ms: i64) -> u64 {
        self.config.limit.saturating_sub(self.used_at(now_ms))
    }

    /// Forget all consumption, keeping the same config.
    /// Traced — an operator act, on the record.
    pub fn reset(&mut self, now_ms: i64) {
        self.window_start = None;
        self.used = 0;
        self.events.clear();
        self.push_trace(now_ms, trace_event::RESET, serde_json::json!({"kind": "quota"}));
    }

    pub fn snapshot(&self, now_ms: i64) -> QuotaSnapshot {
        let used = self.used_at(now_ms);
        let (win_start, win_end) = match self.config.window.bounds(now_ms) {
            Some((s, e)) => (Some(s), Some(e)),
            None => (None, None),
        };
        QuotaSnapshot {
            used,
            remaining: self.config.limit.saturating_sub(used),
            limit: self.config.limit,
            window_start_ms: win_start,
            window_end_ms: win_end,
            config_sha256: self.config_sha256.clone(),
        }
    }
}

// ---------------------------------------------------------------------
// Sync wrappers.  A mutex makes check-and-consume /
// check-and-admit atomic across threads: no caller can slip
// between another caller's check and its claim, so a quota
// cannot be overshot and a probe budget cannot be overdrawn.
// ---------------------------------------------------------------------

#[derive(Debug)]
pub struct SyncBreaker {
    inner: Mutex<Breaker>,
}

impl SyncBreaker {
    pub fn new(breaker: Breaker) -> Self {
        SyncBreaker {
            inner: Mutex::new(breaker),
        }
    }

    pub fn admit(&self, now_ms: i64) -> Admission {
        self.inner.lock().expect("breaker lock poisoned").admit(now_ms)
    }

    pub fn record_success(&self, now_ms: i64) {
        self.inner
            .lock()
            .expect("breaker lock poisoned")
            .record_success(now_ms);
    }

    pub fn record_failure(&self, now_ms: i64, jitter_ms: i64) {
        self.inner
            .lock()
            .expect("breaker lock poisoned")
            .record_failure(now_ms, jitter_ms);
    }

    pub fn snapshot(&self, now_ms: i64) -> BreakerSnapshot {
        self.inner
            .lock()
            .expect("breaker lock poisoned")
            .snapshot(now_ms)
    }

    pub fn trace(&self) -> Vec<TraceRecord> {
        self.inner
            .lock()
            .expect("breaker lock poisoned")
            .trace()
            .to_vec()
    }
}

#[derive(Debug)]
pub struct SyncQuota {
    inner: Mutex<QuotaMeter>,
}

impl SyncQuota {
    pub fn new(quota: QuotaMeter) -> Self {
        SyncQuota {
            inner: Mutex::new(quota),
        }
    }

    pub fn try_consume(&self, now_ms: i64, units: u64) -> ConsumeOutcome {
        self.inner
            .lock()
            .expect("quota lock poisoned")
            .try_consume(now_ms, units)
    }

    pub fn available(&self, now_ms: i64) -> u64 {
        self.inner
            .lock()
            .expect("quota lock poisoned")
            .available(now_ms)
    }

    pub fn snapshot(&self, now_ms: i64) -> QuotaSnapshot {
        self.inner
            .lock()
            .expect("quota lock poisoned")
            .snapshot(now_ms)
    }

    pub fn trace(&self) -> Vec<TraceRecord> {
        self.inner
            .lock()
            .expect("quota lock poisoned")
            .trace()
            .to_vec()
    }
}

// ---------------------------------------------------------------------
// Organelle surface.  A registry of named breakers and quotas.
// Configuration arrives as data through `configure_breaker` /
// `configure_quota` — the surface ships no pre-configured
// subjects and no default thresholds, exactly like the pure
// API.  `now_ms` is an input on every timed op.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    let now_prop = ("now_ms".to_string(), serde_json::json!({"type": "integer"}));
    let obj = |required: &[&str], mut props: Vec<(String, Value)>| {
        props.push(now_prop.clone());
        serde_json::json!({
            "type": "object",
            "required": required,
            "properties": Value::Object(props.into_iter().collect()),
        })
    };
    let prop = |name: &str, ty: &str| (name.to_string(), serde_json::json!({"type": ty}));
    let write = Some(MutationClass::Write);
    let read = Some(MutationClass::ReadOnly);
    let cap = Some("breaker.quota".to_string());
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "breaker-quota".to_string(),
        codon: "bq".to_string(),
        version: "1.0.0".to_string(),
        description:
            "circuit breaker + quota meter over caller-supplied configuration: failure \
             thresholds, counting windows, cooldown schedules, probe budgets, quota \
             limits and window shapes are all data stated in full by the caller; \
             every state transition emits a trace record carrying the counts and the \
             config fingerprint; ships no presets, groupings or defaults"
                .to_string(),
        contracts: vec![
            Contract {
                op: "configure_breaker".to_string(),
                description: "configure_breaker {name, config} — supply the complete BreakerConfig {failure_threshold, window_ms, cooldown, half_open_max_probes, half_open_successes_to_close}; replaces any breaker of the same name; there are no defaults".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["name", "config"],
                    "properties": {
                        "name": {"type": "string"},
                        "config": {
                            "type": "object",
                            "required": ["failure_threshold", "window_ms", "cooldown", "half_open_max_probes", "half_open_successes_to_close"]
                        }
                    }
                }),
                mutation_class: write.clone(),
                required_capability: cap.clone(),
            },
            Contract {
                op: "configure_quota".to_string(),
                description: "configure_quota {name, config} — supply the complete QuotaConfig {limit, window: fixed|sliding|calendar_day}; replaces any quota of the same name; there are no defaults".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["name", "config"],
                    "properties": {
                        "name": {"type": "string"},
                        "config": {
                            "type": "object",
                            "required": ["limit", "window"]
                        }
                    }
                }),
                mutation_class: write.clone(),
                required_capability: cap.clone(),
            },
            Contract {
                op: "admit".to_string(),
                description: "admit {name, now_ms} -> {admission: allowed|allowed_probe|denied, retry_at_ms?, reason?}; performs the open -> half-open transition when the cooldown has elapsed".to_string(),
                input_schema: obj(&["name", "now_ms"], vec![prop("name", "string")]),
                mutation_class: write.clone(),
                required_capability: cap.clone(),
            },
            Contract {
                op: "record_success".to_string(),
                description: "record_success {name, now_ms} — report a successful call to the named breaker".to_string(),
                input_schema: obj(&["name", "now_ms"], vec![prop("name", "string")]),
                mutation_class: write.clone(),
                required_capability: cap.clone(),
            },
            Contract {
                op: "record_failure".to_string(),
                description: "record_failure {name, now_ms, jitter_ms?} — report a failed call; jitter_ms is the caller's sampled cooldown jitter (signed), an input so replays reproduce live timing".to_string(),
                input_schema: obj(&["name", "now_ms"], vec![prop("name", "string"), prop("jitter_ms", "integer")]),
                mutation_class: write.clone(),
                required_capability: cap.clone(),
            },
            Contract {
                op: "try_consume".to_string(),
                description: "try_consume {name, now_ms, units} -> {granted, used, remaining, retry_at_ms?, window_start_ms?, window_end_ms?}; all-or-nothing, atomic check-and-consume".to_string(),
                input_schema: obj(&["name", "now_ms", "units"], vec![prop("name", "string"), prop("units", "integer")]),
                mutation_class: write.clone(),
                required_capability: cap.clone(),
            },
            Contract {
                op: "available".to_string(),
                description: "available {name, now_ms} -> {available}; a peek — records nothing".to_string(),
                input_schema: obj(&["name", "now_ms"], vec![prop("name", "string")]),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "state".to_string(),
                description: "state {name?, now_ms} -> breaker/quota snapshots for the named subject, or for every configured subject when name is omitted".to_string(),
                input_schema: obj(&["now_ms"], vec![prop("name", "string")]),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "trace".to_string(),
                description: "trace {name?} -> the transition trace records (breaker and quota) for the named subject, or all subjects; each record carries its counts and the config fingerprint in force".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"name": {"type": "string"}}
                }),
                mutation_class: read,
                required_capability: None,
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::Write,
            declared_valence: Valence::Candidate,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports: Transport::all().to_vec(),
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

#[cfg(feature = "organelle")]
pub struct BreakerQuotaOrganelle {
    manifest: OrganelleManifest,
    breakers: Mutex<BTreeMap<String, SyncBreaker>>,
    quotas: Mutex<BTreeMap<String, SyncQuota>>,
}

#[cfg(feature = "organelle")]
impl BreakerQuotaOrganelle {
    pub fn new() -> Self {
        BreakerQuotaOrganelle {
            manifest: manifest(),
            breakers: Mutex::new(BTreeMap::new()),
            quotas: Mutex::new(BTreeMap::new()),
        }
    }

    /// Register a breaker directly (embedders who build configs
    /// in Rust rather than through the op surface).
    pub fn register_breaker(&self, breaker: Breaker) {
        let name = breaker.name().to_string();
        self.breakers
            .lock()
            .expect("registry lock poisoned")
            .insert(name, SyncBreaker::new(breaker));
    }

    /// Register a quota directly.
    pub fn register_quota(&self, quota: QuotaMeter) {
        let name = quota.name().to_string();
        self.quotas
            .lock()
            .expect("registry lock poisoned")
            .insert(name, SyncQuota::new(quota));
    }
}

#[cfg(feature = "organelle")]
impl Default for BreakerQuotaOrganelle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "organelle")]
pub fn organelle() -> std::sync::Arc<dyn Organelle> {
    std::sync::Arc::new(BreakerQuotaOrganelle::new())
}

#[cfg(feature = "organelle")]
fn req_name(input: &Value) -> Result<String, OrganelleError> {
    input["name"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| OrganelleError::new("rejected", "name (string) is required"))
}

#[cfg(feature = "organelle")]
fn req_now(input: &Value) -> Result<i64, OrganelleError> {
    input["now_ms"]
        .as_i64()
        .ok_or_else(|| OrganelleError::new("rejected", "now_ms (integer) is required"))
}

#[cfg(feature = "organelle")]
impl Organelle for BreakerQuotaOrganelle {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
            "configure_breaker" => {
                let name = req_name(&input)?;
                let config: BreakerConfig =
                    serde_json::from_value(input["config"].clone()).map_err(|e| {
                        OrganelleError::new("rejected", format!("breaker config: {e}"))
                    })?;
                let now = input["now_ms"].as_i64().unwrap_or(0);
                let breaker = Breaker::new(name, config, now)
                    .map_err(|e| OrganelleError::new("rejected", e.to_string()))?;
                let snapshot = breaker.snapshot(now);
                self.register_breaker(breaker);
                serde_json::to_value(snapshot)
                    .map_err(|e| OrganelleError::failed(format!("serialize snapshot: {e}")))
            }
            "configure_quota" => {
                let name = req_name(&input)?;
                let config: QuotaConfig = serde_json::from_value(input["config"].clone())
                    .map_err(|e| {
                        OrganelleError::new("rejected", format!("quota config: {e}"))
                    })?;
                let now = input["now_ms"].as_i64().unwrap_or(0);
                let quota = QuotaMeter::new(name, config, now)
                    .map_err(|e| OrganelleError::new("rejected", e.to_string()))?;
                let snapshot = quota.snapshot(now);
                self.register_quota(quota);
                serde_json::to_value(snapshot)
                    .map_err(|e| OrganelleError::failed(format!("serialize snapshot: {e}")))
            }
            "admit" => {
                let name = req_name(&input)?;
                let now = req_now(&input)?;
                let reg = self.breakers.lock().expect("registry lock poisoned");
                let b = reg
                    .get(&name)
                    .ok_or_else(|| OrganelleError::not_found(format!("no breaker named {name}")))?;
                serde_json::to_value(b.admit(now))
                    .map_err(|e| OrganelleError::failed(format!("serialize admission: {e}")))
            }
            "record_success" => {
                let name = req_name(&input)?;
                let now = req_now(&input)?;
                let reg = self.breakers.lock().expect("registry lock poisoned");
                let b = reg
                    .get(&name)
                    .ok_or_else(|| OrganelleError::not_found(format!("no breaker named {name}")))?;
                b.record_success(now);
                serde_json::to_value(b.snapshot(now))
                    .map_err(|e| OrganelleError::failed(format!("serialize snapshot: {e}")))
            }
            "record_failure" => {
                let name = req_name(&input)?;
                let now = req_now(&input)?;
                let jitter = input["jitter_ms"].as_i64().unwrap_or(0);
                let reg = self.breakers.lock().expect("registry lock poisoned");
                let b = reg
                    .get(&name)
                    .ok_or_else(|| OrganelleError::not_found(format!("no breaker named {name}")))?;
                b.record_failure(now, jitter);
                serde_json::to_value(b.snapshot(now))
                    .map_err(|e| OrganelleError::failed(format!("serialize snapshot: {e}")))
            }
            "try_consume" => {
                let name = req_name(&input)?;
                let now = req_now(&input)?;
                let units = input["units"].as_u64().ok_or_else(|| {
                    OrganelleError::new("rejected", "units (non-negative integer) is required")
                })?;
                let reg = self.quotas.lock().expect("registry lock poisoned");
                let q = reg
                    .get(&name)
                    .ok_or_else(|| OrganelleError::not_found(format!("no quota named {name}")))?;
                serde_json::to_value(q.try_consume(now, units))
                    .map_err(|e| OrganelleError::failed(format!("serialize outcome: {e}")))
            }
            "available" => {
                let name = req_name(&input)?;
                let now = req_now(&input)?;
                let reg = self.quotas.lock().expect("registry lock poisoned");
                let q = reg
                    .get(&name)
                    .ok_or_else(|| OrganelleError::not_found(format!("no quota named {name}")))?;
                Ok(serde_json::json!({"available": q.available(now)}))
            }
            "state" => {
                let now = req_now(&input)?;
                let mut out = serde_json::json!({"breakers": {}, "quotas": {}});
                let want = input["name"].as_str();
                let breg = self.breakers.lock().expect("registry lock poisoned");
                for (name, b) in breg.iter() {
                    if want.map(|w| w == name).unwrap_or(true) {
                        out["breakers"][name] = serde_json::to_value(b.snapshot(now))
                            .map_err(|e| OrganelleError::failed(format!("serialize: {e}")))?;
                    }
                }
                let qreg = self.quotas.lock().expect("registry lock poisoned");
                for (name, q) in qreg.iter() {
                    if want.map(|w| w == name).unwrap_or(true) {
                        out["quotas"][name] = serde_json::to_value(q.snapshot(now))
                            .map_err(|e| OrganelleError::failed(format!("serialize: {e}")))?;
                    }
                }
                Ok(out)
            }
            "trace" => {
                let want = input["name"].as_str();
                let mut records = Vec::new();
                let breg = self.breakers.lock().expect("registry lock poisoned");
                for (name, b) in breg.iter() {
                    if want.map(|w| w == name).unwrap_or(true) {
                        records.extend(b.trace());
                    }
                }
                let qreg = self.quotas.lock().expect("registry lock poisoned");
                for (name, q) in qreg.iter() {
                    if want.map(|w| w == name).unwrap_or(true) {
                        records.extend(q.trace());
                    }
                }
                serde_json::to_value(records)
                    .map_err(|e| OrganelleError::failed(format!("serialize trace: {e}")))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  The five required proofs: (a) trips exactly at the
// threshold, (b) half-open probe behaviour, (c) quota denies
// exactly at the limit and resets at the boundary, (d)
// determinism of replayed scripts, (e) concurrent quota
// check-and-consume cannot overshoot.  The rest pin the
// doctrine (no defaults, config validation) and the semantics.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Test-chosen numbers — the crate ships none.  Threshold 3
    /// and a 30s fixed cooldown are this test's data.
    fn breaker_config() -> BreakerConfig {
        BreakerConfig {
            failure_threshold: 3,
            window_ms: 60_000,
            cooldown: CooldownPolicy::Fixed { cooldown_ms: 30_000 },
            half_open_max_probes: 1,
            half_open_successes_to_close: 1,
        }
    }

    fn fixed_quota(limit: u64, window_ms: i64) -> QuotaConfig {
        QuotaConfig {
            limit,
            window: WindowSpec::Fixed {
                window_ms,
                anchor_ms: 0,
            },
        }
    }

    // (a) Trips exactly at the configured threshold.
    #[test]
    fn trips_exactly_at_threshold_not_one_earlier() {
        let mut b = Breaker::new("lane", breaker_config(), 0).unwrap();
        assert_eq!(b.admit(0), Admission::Allowed);
        b.record_failure(1_000, 0);
        assert_eq!(b.snapshot(1_000).state, BreakerState::Closed);
        assert_eq!(b.snapshot(1_000).failures_in_window, 1);
        assert_eq!(b.admit(1_000), Admission::Allowed);
        b.record_failure(2_000, 0);
        assert_eq!(
            b.snapshot(2_000).state,
            BreakerState::Closed,
            "two failures must not trip a threshold of three"
        );
        assert_eq!(b.admit(2_000), Admission::Allowed);
        b.record_failure(3_000, 0);
        let snap = b.snapshot(3_000);
        assert_eq!(snap.state, BreakerState::Open);
        assert_eq!(snap.open_count, 1);
        assert_eq!(snap.cooldown_until_ms, Some(33_000));
        // Denied while open, with the exact retry moment.
        assert_eq!(
            b.admit(3_001),
            Admission::Denied {
                retry_at_ms: Some(33_000),
                reason: DenyReason::BreakerOpen,
            }
        );
        // The trip is on the trace with its counts and config.
        let trip = b
            .trace()
            .iter()
            .find(|r| r.event == trace_event::BREAKER_TRIPPED)
            .expect("trip must be traced");
        assert_eq!(trip.detail["failures_in_window"], json!(3));
        assert_eq!(trip.detail["cooldown_applied_ms"], json!(30_000));
        assert_eq!(trip.config_sha256.len(), 64);
    }

    // (a') Failures outside the window stop counting; a success
    // clears the record (consecutive-within-window semantics).
    #[test]
    fn failures_age_out_of_window_and_success_clears() {
        let mut cfg = breaker_config();
        cfg.window_ms = 10_000;
        let mut b = Breaker::new("lane", cfg, 0).unwrap();
        b.record_failure(0, 0);
        b.record_failure(1_000, 0);
        // Both failures are older than the window by t=12_000.
        b.record_failure(12_000, 0);
        assert_eq!(b.snapshot(12_000).failures_in_window, 1);
        assert_eq!(b.snapshot(12_000).state, BreakerState::Closed);
        // A success clears what remains.
        b.record_success(12_500);
        assert_eq!(b.snapshot(12_500).failures_in_window, 0);
        assert!(b
            .trace()
            .iter()
            .any(|r| r.event == trace_event::FAILURE_RECORD_CLEARED));
    }

    // (b) Half-open: probe success closes.
    #[test]
    fn half_open_probe_success_closes() {
        let mut b = Breaker::new("lane", breaker_config(), 0).unwrap();
        for t in [0, 1, 2] {
            b.record_failure(t, 0);
        }
        assert_eq!(b.snapshot(2).state, BreakerState::Open);
        // One ms before the cooldown ends: still denied.
        assert!(matches!(
            b.admit(30_001),
            Admission::Denied { .. }
        ));
        // At the boundary: half-open, one probe admitted.
        assert_eq!(b.admit(30_002), Admission::AllowedProbe);
        assert_eq!(b.snapshot(30_002).state, BreakerState::HalfOpen);
        // The single probe slot is taken.
        assert_eq!(
            b.admit(30_002),
            Admission::Denied {
                retry_at_ms: None,
                reason: DenyReason::ProbesSaturated,
            }
        );
        b.record_success(30_100);
        let snap = b.snapshot(30_100);
        assert_eq!(snap.state, BreakerState::Closed);
        assert_eq!(snap.open_count, 0);
        assert_eq!(snap.failures_in_window, 0);
        assert!(b
            .trace()
            .iter()
            .any(|r| r.event == trace_event::BREAKER_HALF_OPENED));
        assert!(b
            .trace()
            .iter()
            .any(|r| r.event == trace_event::BREAKER_CLOSED));
    }

    // (b') Half-open: probe failure re-opens, with the next
    // cooldown from the caller's escalating schedule (the
    // ai-router's 30/60/120/300 shape, stated as test data).
    #[test]
    fn half_open_probe_failure_reopens_with_escalated_cooldown() {
        let cfg = BreakerConfig {
            failure_threshold: 1,
            window_ms: 60_000,
            cooldown: CooldownPolicy::Schedule {
                cooldowns_ms: vec![30_000, 60_000, 120_000, 300_000],
            },
            half_open_max_probes: 1,
            half_open_successes_to_close: 1,
        };
        let mut b = Breaker::new("lane", cfg, 0).unwrap();
        b.record_failure(0, 0); // trip 1 -> 30s
        assert_eq!(b.snapshot(0).cooldown_until_ms, Some(30_000));
        assert_eq!(b.admit(30_000), Admission::AllowedProbe);
        b.record_failure(30_500, 0); // probe fails -> trip 2 -> 60s
        let snap = b.snapshot(30_500);
        assert_eq!(snap.state, BreakerState::Open);
        assert_eq!(snap.open_count, 2);
        assert_eq!(snap.cooldown_until_ms, Some(30_500 + 60_000));
        assert!(b
            .trace()
            .iter()
            .any(|r| r.event == trace_event::BREAKER_REOPENED));
        // Closing resets the escalation.
        assert_eq!(b.admit(90_500), Admission::AllowedProbe);
        b.record_success(90_600);
        assert_eq!(b.snapshot(90_600).open_count, 0);
        b.record_failure(90_700, 0); // fresh trip -> back to 30s
        assert_eq!(b.snapshot(90_700).cooldown_until_ms, Some(90_700 + 30_000));
    }

    // (b'') Multiple successes required to close, when the
    // caller configures them.
    #[test]
    fn half_open_needs_configured_successes_to_close() {
        let mut cfg = breaker_config();
        cfg.half_open_successes_to_close = 2;
        cfg.half_open_max_probes = 2;
        let mut b = Breaker::new("lane", cfg, 0).unwrap();
        for t in [0, 1, 2] {
            b.record_failure(t, 0);
        }
        assert_eq!(b.admit(30_002), Admission::AllowedProbe);
        assert_eq!(b.admit(30_002), Admission::AllowedProbe);
        b.record_success(30_010);
        assert_eq!(b.snapshot(30_010).state, BreakerState::HalfOpen);
        b.record_success(30_020);
        assert_eq!(b.snapshot(30_020).state, BreakerState::Closed);
    }

    // Jitter is an input: it shifts the cooldown, clamps at 0,
    // and lands on the trace.
    #[test]
    fn jitter_is_an_input_and_is_traced() {
        let mut cfg = breaker_config();
        cfg.failure_threshold = 1;
        let mut b = Breaker::new("lane", cfg, 0).unwrap();
        b.record_failure(0, 7_500);
        assert_eq!(b.snapshot(0).cooldown_until_ms, Some(37_500));
        let trip = b
            .trace()
            .iter()
            .find(|r| r.event == trace_event::BREAKER_TRIPPED)
            .unwrap();
        assert_eq!(trip.detail["jitter_ms"], json!(7_500));
        let mut cfg1 = breaker_config();
        cfg1.failure_threshold = 1;
        let mut b3 = Breaker::new("lane", cfg1, 0).unwrap();
        b3.record_failure(0, -999_999);
        assert_eq!(
            b3.snapshot(0).cooldown_until_ms,
            Some(0),
            "negative jitter clamps the cooldown at 0, never below"
        );
    }

    // (c) Fixed window: denies exactly at the limit, resets at
    // the boundary, all-or-nothing.
    #[test]
    fn quota_denies_exactly_at_limit_and_resets_at_boundary() {
        let mut q = QuotaMeter::new("calls", fixed_quota(5, 60_000), 0).unwrap();
        assert!(q.try_consume(1_000, 2).granted);
        assert!(q.try_consume(2_000, 2).granted);
        let fifth = q.try_consume(3_000, 1);
        assert!(fifth.granted);
        assert_eq!(fifth.remaining, 0);
        // Exactly at the limit: the next unit is denied, with
        // the window end as the retry moment.
        let denied = q.try_consume(4_000, 1);
        assert!(!denied.granted);
        assert_eq!(denied.used, 5);
        assert_eq!(denied.remaining, 0);
        assert_eq!(denied.retry_at_ms, Some(60_000));
        // All-or-nothing: a request bigger than the limit is
        // denied whole even in a fresh window, and can never
        // fit, so no retry moment is claimed.
        let too_big = q.try_consume(4_000, 6);
        assert!(!too_big.granted);
        assert_eq!(too_big.retry_at_ms, None);
        // One ms before the boundary: still denied.
        assert!(!q.try_consume(59_999, 1).granted);
        // At the boundary: a new window, consumption reset.
        let fresh = q.try_consume(60_000, 1);
        assert!(fresh.granted);
        assert_eq!(fresh.used, 1);
        assert!(q
            .trace()
            .iter()
            .any(|r| r.event == trace_event::QUOTA_EXHAUSTED));
        let reset = q
            .trace()
            .iter()
            .find(|r| r.event == trace_event::QUOTA_WINDOW_RESET)
            .expect("window reset must be traced");
        assert_eq!(reset.detail["previous_used"], json!(5));
    }

    // (c') Cost units: one consume may take many units (the
    // D1 rows-read shape), and a partial fit is denied whole.
    #[test]
    fn quota_cost_units_are_all_or_nothing() {
        let mut q = QuotaMeter::new("rows", fixed_quota(100, 60_000), 0).unwrap();
        assert!(q.try_consume(0, 60).granted);
        let denied = q.try_consume(1, 41);
        assert!(!denied.granted, "41 does not fit in 40 remaining");
        assert_eq!(denied.used, 60, "a denial consumes nothing");
        assert!(q.try_consume(2, 40).granted);
        assert_eq!(q.available(3), 0);
    }

    // (c'') Calendar day at offset 0: the Exchange shape — a
    // limit that resets at UTC midnight, as caller data.
    #[test]
    fn quota_calendar_day_resets_at_utc_midnight() {
        let cfg = QuotaConfig {
            limit: 3,
            window: WindowSpec::CalendarDay { utc_offset_ms: 0 },
        };
        // 2026-11-22T23:59:00Z, midnight, and 2026-11-23T00:00:01Z
        // (epoch ms verified against the system clock calendar).
        let before_midnight: i64 = 1_795_391_940_000;
        let midnight: i64 = 1_795_392_000_000;
        let after_midnight: i64 = 1_795_392_001_000;
        let mut q = QuotaMeter::new("d1-rows", cfg, before_midnight).unwrap();
        assert!(q.try_consume(before_midnight, 3).granted);
        let denied = q.try_consume(before_midnight + 1_000, 1);
        assert!(!denied.granted);
        assert_eq!(denied.retry_at_ms, Some(midnight));
        let fresh = q.try_consume(after_midnight, 1);
        assert!(fresh.granted, "the day rolled: quota reset at UTC midnight");
        assert_eq!(fresh.used, 1);
        assert_eq!(fresh.window_start_ms, Some(midnight));
    }

    // (c''') Sliding window: consumptions expire individually.
    #[test]
    fn quota_sliding_window_expires_individually() {
        let cfg = QuotaConfig {
            limit: 3,
            window: WindowSpec::Sliding { window_ms: 60_000 },
        };
        let mut q = QuotaMeter::new("rpm", cfg, 0).unwrap();
        assert!(q.try_consume(0, 1).granted);
        assert!(q.try_consume(10_000, 1).granted);
        assert!(q.try_consume(20_000, 1).granted);
        let denied = q.try_consume(30_000, 1);
        assert!(!denied.granted);
        // The oldest consumption (t=0) expires at t=60_000.
        assert_eq!(denied.retry_at_ms, Some(60_000));
        assert!(!q.try_consume(59_999, 1).granted);
        assert!(q.try_consume(60_000, 1).granted);
        // Now the t=10_000 consumption is the binding one.
        let denied2 = q.try_consume(60_001, 1);
        assert!(!denied2.granted);
        assert_eq!(denied2.retry_at_ms, Some(70_000));
    }

    // (d) Determinism: the same scripted sequence replays to
    // byte-identical state and trace.
    #[test]
    fn determinism_replay_byte_identical() {
        fn run() -> String {
            let mut b = Breaker::new("lane", breaker_config(), 0).unwrap();
            let mut q = QuotaMeter::new("rows", fixed_quota(10, 60_000), 0).unwrap();
            let mut log = Vec::new();
            for (t, ok) in [(0, false), (100, false), (200, true), (300, false), (400, false), (500, false)] {
                log.push(json!(b.admit(t)));
                if ok {
                    b.record_success(t);
                } else {
                    b.record_failure(t, 25);
                }
            }
            log.push(json!(b.admit(30_500)));
            log.push(json!(b.admit(31_000)));
            b.record_success(31_100);
            for t in [0, 1_000, 2_000, 61_000] {
                log.push(json!(q.try_consume(t, 4)));
            }
            serde_json::to_string(&json!({
                "log": log,
                "breaker_state": b.snapshot(31_100),
                "quota_state": q.snapshot(61_000),
                "breaker_trace": b.trace(),
                "quota_trace": q.trace(),
            }))
            .unwrap()
        }
        assert_eq!(run(), run(), "same script + same configs must replay byte-identically");
    }

    // (e) Concurrent callers cannot overshoot the quota:
    // check-and-consume is atomic under the wrapper's mutex.
    #[test]
    fn concurrent_quota_never_overshoots() {
        let quota = SyncQuota::new(QuotaMeter::new("shared", fixed_quota(1_000, 3_600_000), 0).unwrap());
        let granted = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        std::thread::scope(|s| {
            for _ in 0..16 {
                let quota = &quota;
                let granted = granted.clone();
                s.spawn(move || {
                    for _ in 0..200 {
                        if quota.try_consume(1_000, 1).granted {
                            granted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                });
            }
        });
        assert_eq!(
            granted.load(std::sync::atomic::Ordering::SeqCst),
            1_000,
            "3,200 racing attempts against a limit of 1,000 must grant exactly 1,000"
        );
        assert_eq!(quota.snapshot(1_000).used, 1_000);
        assert_eq!(quota.available(1_000), 0);
    }

    // (e') Concurrent probe admission cannot overdraw the
    // probe budget either.
    #[test]
    fn concurrent_probes_never_overdraw() {
        let mut cfg = breaker_config();
        cfg.half_open_max_probes = 3;
        let mut b = Breaker::new("lane", cfg, 0).unwrap();
        for t in [0, 1, 2] {
            b.record_failure(t, 0);
        }
        let sync = SyncBreaker::new(b);
        let probes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        std::thread::scope(|s| {
            for _ in 0..16 {
                let sync = &sync;
                let probes = probes.clone();
                s.spawn(move || {
                    if sync.admit(30_002) == Admission::AllowedProbe {
                        probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(probes.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    // Doctrine: configs state everything or fail.  No field
    // has a default to fall back on.
    #[test]
    fn config_states_everything_or_fails() {
        // Missing failure_threshold: does not deserialize.
        assert!(serde_json::from_value::<BreakerConfig>(json!({
            "window_ms": 60_000,
            "cooldown": {"fixed": {"cooldown_ms": 30_000}},
            "half_open_max_probes": 1,
            "half_open_successes_to_close": 1
        }))
        .is_err());
        // Missing window: does not deserialize.
        assert!(serde_json::from_value::<QuotaConfig>(json!({"limit": 5})).is_err());
        // Stated but nonsensical: does not construct.
        let mut bad = breaker_config();
        bad.failure_threshold = 0;
        assert!(Breaker::new("x", bad, 0).is_err());
        let badq = QuotaConfig {
            limit: 0,
            window: WindowSpec::Sliding { window_ms: 1_000 },
        };
        assert!(QuotaMeter::new("x", badq, 0).is_err());
        let empty_schedule = BreakerConfig {
            cooldown: CooldownPolicy::Schedule { cooldowns_ms: vec![] },
            ..breaker_config()
        };
        assert!(Breaker::new("x", empty_schedule, 0).is_err());
    }

    // Cooldown arithmetic over caller data: exponential with
    // cap, linear.
    #[test]
    fn cooldown_policies_compute_from_data() {
        let exp = CooldownPolicy::Exponential {
            base_ms: 1_000,
            factor: 2,
            max_ms: 5_000,
        };
        assert_eq!(exp.cooldown_ms(1), 1_000);
        assert_eq!(exp.cooldown_ms(2), 2_000);
        assert_eq!(exp.cooldown_ms(3), 4_000);
        assert_eq!(exp.cooldown_ms(4), 5_000);
        assert_eq!(exp.cooldown_ms(9), 5_000);
        let lin = CooldownPolicy::Linear {
            base_ms: 100,
            step_ms: 50,
        };
        assert_eq!(lin.cooldown_ms(1), 100);
        assert_eq!(lin.cooldown_ms(3), 200);
    }

    #[cfg(feature = "organelle")]
    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }

    // The organelle surface end-to-end: configure from data,
    // trip a breaker, consume a quota dry, read the trace.
    #[cfg(feature = "organelle")]
    #[test]
    fn organelle_surface_roundtrip() {
        use organelle_host::{CallContext, Host};
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["breaker.quota".to_string()]);
        let call = |op: &str, input: Value| h.call(&ctx, "bq", op, input).unwrap().output;

        call(
            "configure_breaker",
            json!({"name": "lane", "now_ms": 0, "config": {
                "failure_threshold": 2,
                "window_ms": 60_000,
                "cooldown": {"fixed": {"cooldown_ms": 5_000}},
                "half_open_max_probes": 1,
                "half_open_successes_to_close": 1
            }}),
        );
        call(
            "configure_quota",
            json!({"name": "rows", "now_ms": 0, "config": {
                "limit": 2,
                "window": {"calendar_day": {"utc_offset_ms": 0}}
            }}),
        );
        assert_eq!(
            call("admit", json!({"name": "lane", "now_ms": 0})),
            json!("allowed")
        );
        call("record_failure", json!({"name": "lane", "now_ms": 1}));
        call("record_failure", json!({"name": "lane", "now_ms": 2}));
        let denied = call("admit", json!({"name": "lane", "now_ms": 3}));
        assert_eq!(denied["denied"]["reason"], json!("breaker_open"));
        assert_eq!(denied["denied"]["retry_at_ms"], json!(5_002));

        let dry = call("try_consume", json!({"name": "rows", "now_ms": 0, "units": 2}));
        assert_eq!(dry["granted"], json!(true));
        let denied_q = call("try_consume", json!({"name": "rows", "now_ms": 1, "units": 1}));
        assert_eq!(denied_q["granted"], json!(false));

        // Unknown subjects fail closed.
        assert!(h
            .call(&ctx, "bq", "admit", json!({"name": "nope", "now_ms": 0}))
            .is_err());

        let trace = call("trace", json!({}));
        let events: Vec<&str> = trace
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["event"].as_str().unwrap())
            .collect();
        assert!(events.contains(&"breaker_tripped"), "trace: {events:?}");
        assert!(events.contains(&"quota_exhausted"), "trace: {events:?}");
        // Every record carries the fingerprint of its config.
        for r in trace.as_array().unwrap() {
            assert_eq!(r["config_sha256"].as_str().unwrap().len(), 64);
        }
    }
}

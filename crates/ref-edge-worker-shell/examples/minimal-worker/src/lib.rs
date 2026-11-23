//! The minimal edge worker — the whole of a new estate worker
//! once the shell exists:
//!
//! * the shell (`ref-edge-worker-shell`, org-031) stated once:
//!   one gate, two routes, one cron;
//! * one organelle (`ref-entropy-source`, org-025) doing the
//!   only domain work (minting a nonce);
//! * the workers-rs entry points, which are pure dispatch into
//!   the shell's glue.
//!
//! Everything else a TEN-era JS worker carried by hand — the
//! timing-safe gate, the routing, the error envelopes, the
//! scheduled-event plumbing — is the shell's, not this file's.

use ref_edge_worker_shell::{GateConfig, Shell, ShellError, ShellResponse};
use serde_json::json;
use std::sync::OnceLock;
use worker::{event, Context, Env, Request, Response, Result, ScheduleContext, ScheduledEvent};

fn shell() -> &'static Shell {
    static SHELL: OnceLock<Shell> = OnceLock::new();
    SHELL.get_or_init(|| {
        Shell::new()
            .gate(GateConfig {
                header: "x-heartbeat-secret".to_string(),
                secret_env: "HEARTBEAT_SECRET".to_string(),
                exempt: vec!["/health".to_string()],
                query_param: None,
            })
            .route("GET", "/health", |_req, _ctx| async {
                Ok(ShellResponse::ok(json!({"up": true})))
            })
            .route("GET", "/v1/nonce", |_req, _ctx| async {
                let mut buf = [0u8; 16];
                ref_entropy_source::fill_bytes(&mut buf)
                    .map_err(|e| ShellError::internal(format!("entropy: {e}")))?;
                let nonce: String = buf.iter().map(|b| format!("{b:02x}")).collect();
                Ok(ShellResponse::ok(json!({"nonce": nonce})))
            })
            .scheduled("*/30 * * * *", |_ctx| async { Ok(()) })
    })
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    ref_edge_worker_shell::workers_glue::fetch_dispatch(shell(), req, env).await
}

#[event(scheduled)]
pub async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    ref_edge_worker_shell::workers_glue::scheduled_dispatch(shell(), event, env).await
}

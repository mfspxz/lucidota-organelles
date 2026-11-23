//! LIVE PROOF — a real pinned call to NVIDIA NIM through the
//! estate credential path, asserting the pin contract against
//! the provider itself.
//!
//! Env-gated: without `MODEL_CALL_LIVE_NIM=1` the test passes
//! trivially (the offline suite must stay offline).  Run it
//! with:
//!
//! ```text
//! MODEL_CALL_LIVE_NIM=1 cargo test -p ref-model-call-live \
//!     --test live_nim -- --nocapture
//! ```
//!
//! The credential is the estate's dynamic surrogate: this test
//! asks authd (the same unix-socket path the NIM connector CLI
//! uses via `dynamic_credentials.py`) for the `custom.nvidia-nim`
//! surrogate, and hands the `hsurr:*` value to the caller as a
//! Bearer credential through `MemoryCredentials`.  Sentinel
//! replaces the surrogate with the real key on egress to
//! integrate.api.nvidia.com.  The surrogate is never printed,
//! and the real key never exists in this process at all.

#![cfg(not(target_arch = "wasm32"))]

use ref_credential_broker::CredentialRef;
use ref_model_call_live::*;
use serde_json::Value;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

const MODEL: &str = "nvidia/nemotron-3-ultra-550b-a55b";

/// Fetch the `custom.nvidia-nim` surrogate entry from authd,
/// exactly the protocol `dynamic_credentials.py` speaks:
/// POST /v1/credentials/surrogate {"name": …} over the unix
/// socket, entry `access_token`, placement `bearer_header`.
/// Returns the surrogate value (never the real key).
fn nim_surrogate() -> String {
    let sock = std::env::var("JARVIS_AUTHD_SOCK")
        .unwrap_or_else(|_| "/run/hatch/auth/authd.sock".to_string());
    let payload = serde_json::json!({"name": "custom.nvidia-nim"}).to_string();
    let request = format!(
        "POST /v1/credentials/surrogate HTTP/1.1\r\nHost: authd.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    let mut stream = UnixStream::connect(&sock).expect("connect authd socket");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .expect("authd response has a body");
    let parsed: Value = serde_json::from_str(body).expect("authd response is JSON");
    for entry in parsed["credentials"].as_array().expect("credentials array") {
        if entry["name"] == "access_token" {
            assert_eq!(
                entry["placement"], "bearer_header",
                "expected bearer_header placement for the NIM credential"
            );
            let surrogate = entry["surrogate"].as_str().expect("surrogate string");
            assert!(
                surrogate.starts_with("hsurr:"),
                "authd must hand out a surrogate, never the key"
            );
            return surrogate.to_string();
        }
    }
    panic!("no access_token entry in authd surrogate response");
}

#[test]
fn live_pinned_nim_call_is_served_by_the_pinned_model() {
    if std::env::var("MODEL_CALL_LIVE_NIM").as_deref() != Ok("1") {
        eprintln!("skipping live NIM proof (set MODEL_CALL_LIVE_NIM=1 to run)");
        return;
    }

    let surrogate = nim_surrogate();
    let cred = CredentialRef::new("nvidia-nim", "nim").unwrap();
    let mut credentials = MemoryCredentials::new();
    credentials.insert(cred.clone(), AuthStyle::Bearer, surrogate);

    // The receipt log for this proof: one JSONL file under the
    // cargo TMPDIR (the workspace .tmp dir, never /tmp).
    let log_path = std::env::var("TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("model-call-live-nim-receipts.jsonl");
    let _ = std::fs::remove_file(&log_path);
    let sink = JsonlFileSink::new(log_path.clone());

    let lane = Lane {
        name: "nvidia".to_string(),
        base_url: "https://integrate.api.nvidia.com/v1".to_string(),
        credential: Some(cred),
        models: vec![MODEL.to_string()],
        strategy: ModelStrategy::PoolOrder,
        timeout_ms: 180_000,
        model_timeouts_ms: vec![(MODEL.to_string(), 180_000)],
        max_response_bytes: 1_048_576,
        allow_http: false,
        abort_lane_on_429: false,
    };
    let config = RouterConfig {
        lanes: vec![lane],
        // The router's alias, stated as caller data.
        aliases: vec![("nim".to_string(), "nvidia".to_string())],
        failover: FailoverPolicy {
            failover_statuses: vec![401, 403, 404, 429],
            failover_on_5xx: true,
            failover_on_transport_error: true,
            max_attempts: None,
        },
    };

    let caller = ModelCaller::host(config, credentials, NoGuard, sink).unwrap();
    let request = ChatRequest::new(vec![ChatMessage::text(
        "user",
        "Reply with exactly this word: OK",
    )])
    .model(format!("nim/{MODEL}"))
    .max_tokens(64)
    .purpose("a4-live-proof");

    let response = caller.chat(&request).expect("live pinned NIM call succeeds");
    assert_eq!(response.lane, "nvidia");
    assert_eq!(response.pin.as_ref().unwrap().model, MODEL);
    assert_eq!(response.model_sent, MODEL);
    assert_eq!(
        response.model_served.as_deref(),
        Some(MODEL),
        "the provider's own model field must be the pinned model"
    );
    assert!(
        !response.substituted,
        "a pin served by the pinned model is not a substitution"
    );
    assert!(
        !response.content.trim().is_empty(),
        "the pinned model answered with content"
    );
    println!(
        "live proof: lane={} served={} substituted={} content={:?}",
        response.lane,
        response.model_served.as_deref().unwrap_or("<none>"),
        response.substituted,
        response.content.chars().take(80).collect::<String>()
    );

    // The receipt for the attempt landed in the test log file,
    // in the estate calls.jsonl shape.
    let log = std::fs::read_to_string(&log_path).expect("receipt log exists");
    let lines: Vec<Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).expect("receipt line is JSON"))
        .collect();
    assert_eq!(lines.len(), 1, "exactly one attempt, exactly one receipt");
    let receipt = &lines[0];
    assert_eq!(receipt["status"], "ok");
    assert_eq!(receipt["model"], MODEL);
    assert_eq!(receipt["model_returned"], MODEL);
    assert_eq!(receipt["model_requested"], format!("nim/{MODEL}"));
    assert_eq!(receipt["pinned"], true);
    assert_eq!(receipt["substituted"], false);
    assert_eq!(receipt["lane"], "nvidia");
    assert_eq!(receipt["tool"], "ref-model-call-live");
    println!("receipt landed: {}", receipt["call_id"]);
}

//! Live proof (read-only): one D1 query against the real account
//! through the native REST client.
//!
//! Credentials are INJECTED by the caller through the environment —
//! this example is the caller, and the crate never sources them:
//!
//!   CF_ACCOUNT_ID=<account id> CF_API_TOKEN=<token> \
//!     cargo run --example live_d1 [database-id]
//!
//! Defaults to the Exchange database.  The token is never printed.
//! The query is `SELECT 1 AS one` — read-only, no writes, one call.

use ref_cf_storage::{CfRestClient, D1Store};

fn main() {
    let account = std::env::var("CF_ACCOUNT_ID").unwrap_or_else(|_| {
        eprintln!("live_d1: CF_ACCOUNT_ID not set (injected credential missing)");
        std::process::exit(2);
    });
    let token = std::env::var("CF_API_TOKEN").unwrap_or_else(|_| {
        eprintln!("live_d1: CF_API_TOKEN not set (injected credential missing)");
        std::process::exit(2);
    });
    let db = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0ea89801-9b0a-4efa-9d2f-170d7d285e69".to_string());

    let client = CfRestClient::new(account, token);
    match client.d1_query(&db, "SELECT 1 AS one", &[]) {
        Ok(r) => {
            println!("live D1 query OK: results={}", serde_json::to_string(&r.results).unwrap());
            println!(
                "meta: rows_read={:?} rows_written={:?} duration_ms={:?}",
                r.meta.rows_read, r.meta.rows_written, r.meta.duration_ms
            );
        }
        Err(e) => {
            eprintln!("live D1 query FAILED: {e}");
            std::process::exit(1);
        }
    }
}

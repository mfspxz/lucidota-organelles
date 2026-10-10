//! wave-7b validation lane: run organelle-manifest::validate_manifest_json
//! over manifest JSON files. Usage: validate <manifest.json> [...]
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: validate <manifest.json> [...]");
        return ExitCode::from(2);
    }
    let mut failed = false;
    for path in &args {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{path}: cannot read: {e}");
                failed = true;
                continue;
            }
        };
        let v: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{path}: not JSON: {e}");
                failed = true;
                continue;
            }
        };
        match organelle_manifest::validate_manifest_json(&v) {
            Ok(m) => println!("{path}: VALID name={} codon={} version={}", m.name, m.codon, m.version),
            Err(errs) => {
                failed = true;
                eprintln!("{path}: INVALID");
                for e in errs {
                    eprintln!("  {}: {}", e.field, e.message);
                }
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

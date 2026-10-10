// QA audit harness: validate every *.manifest.json under given roots with
// organelle-manifest::validate_manifest_json, and report codon usage.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn collect_manifests(root: &Path, out: &mut Vec<PathBuf>) {
    let wd = match walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(_) => return,
    };
    for e in wd {
        let p = e.path().to_path_buf();
        // skip build artifacts / vendored / git
        let s = p.to_string_lossy();
        if s.contains("/target/") || s.contains("/.git/") || s.contains("/node_modules/") {
            continue;
        }
        if p.extension().and_then(|x| x.to_str()) == Some("json")
            && p.file_name().and_then(|x| x.to_str()).map(|n| n.ends_with(".manifest.json")).unwrap_or(false)
        {
            out.push(p);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: qa-manifest-check <root...>");
        std::process::exit(2);
    }
    let mut manifests: Vec<PathBuf> = Vec::new();
    for a in &args {
        collect_manifests(Path::new(a), &mut manifests);
    }
    manifests.sort();
    manifests.dedup();
    println!("manifests found: {}", manifests.len());
    let mut codons: HashMap<String, Vec<String>> = HashMap::new();
    let mut failures = 0usize;
    for p in &manifests {
        let text = match std::fs::read_to_string(p) {
            Ok(t) => t,
            Err(e) => {
                println!("READ-ERROR {} : {e}", p.display());
                failures += 1;
                continue;
            }
        };
        let v: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                println!("JSON-ERROR {} : {e}", p.display());
                failures += 1;
                continue;
            }
        };
        match organelle_manifest::validate_manifest_json(&v) {
            Ok(m) => {
                let codon = m.codon.clone();
                if codon.is_empty() {
                    println!("MISSING-CODON {}", p.display());
                    failures += 1;
                } else {
                    codons.entry(codon.clone()).or_default().push(p.display().to_string());
                }
                println!("OK {} name={} codon={} ops={}", p.display(), m.name, m.codon, m.contracts.len());
            }
            Err(errs) => {
                failures += 1;
                println!("INVALID {} :", p.display());
                for e in errs {
                    println!("    {:?} : {}", e.field, e.message);
                }
            }
        }
    }
    println!("--- codon collisions (2+ manifests sharing a codon) ---");
    let mut keys: Vec<&String> = codons.keys().collect();
    keys.sort();
    for k in keys {
        let v = &codons[k];
        if v.len() > 1 {
            println!("COLLISION codon={k}");
            for m in v {
                println!("    {m}");
            }
        }
    }
    println!("--- summary: {} manifests, {} failures ---", manifests.len(), failures);
    if failures > 0 {
        std::process::exit(1);
    }
}

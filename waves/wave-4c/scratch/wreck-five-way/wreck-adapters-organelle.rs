//! wreck-adapters as an organelle (Tier A native migration).
//!
//! The substrate layer: the governor decides, the substrate executes.
//! Callable ops over local git (the proven path — the demo runs end to
//! end on real git):
//!   git_diff_view      {repo, change_id, scope, base, head} -> ChangeView
//!   git_measure_symbols {repo, head, view} -> ChangeView (tree-sitter symbols)
//!   git_merge          {baseline, fork, change} -> {merge_sha}
//!
//! `git_merge` fetches the fork head into the baseline and merges --no-ff;
//! it is the only op with effects outside the host (ExternalEffect, gated
//! on `wx.merge`). The other two only read.
//!
//! Deliberate exclusions (documented, not oversights):
//! - TokenCustodian mint/adjudicate: credential issuance stays with the
//!   deployer; the organelle never mints or holds tokens.
//! - ArtifactsClient live HTTP: URL/payload construction is pure and
//!   unit-tested, but live calls are UNVERIFIED (pending Workers Paid
//!   access) and need account credentials. Excluded until proven.
//!
//! Execution personality: fs allowlist = repo paths supplied per call;
//! process: spawn git only; network: none. Stateless: suspend = no-op,
//! kill = drop in-flight (a killed merge may leave the baseline repo
//! mid-merge; the caller re-runs — git state is the substrate's, not ours).
//! Envelope: 1 cpu / 256 MB / 120 s wall-time.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::{LocalGit, LocalMergePort};
use wreck_governor::MergePort;
use wreck_graph::ChangeView;
use wreck_protocol::{ChangeClaim, ScopeItem, Sha};

fn str_in(v: &Value, key: &str) -> Result<String, OrganelleError> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| OrganelleError::failed(format!("missing string field {key:?}")))
}

fn obj_schema(props: Value, required: &[&str]) -> Value {
    serde_json::json!({ "type": "object", "properties": props, "required": required })
}

fn contract(op: &str, description: &str, schema: Value) -> Contract {
    Contract {
        op: op.to_string(),
        description: description.to_string(),
        input_schema: schema,
        mutation_class: None,
        required_capability: None,
    }
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "wreck-substrate".to_string(),
        codon: "wx".to_string(),
        version: "0.1.0".to_string(),
        description: "wreck substrate layer: build change views from local git, measure symbols, execute merges".to_string(),
        contracts: vec![
            contract(
                "git_diff_view",
                "build the mechanical ChangeView from (base, head) via git diff",
                obj_schema(
                    serde_json::json!({
                        "repo": {"type": "string"},
                        "change_id": {"type": "string"},
                        "scope": {"type": "array", "items": {"type": "object"}},
                        "base": {"type": "string"},
                        "head": {"type": "string"}
                    }),
                    &["repo", "change_id", "base", "head"],
                ),
            ),
            contract(
                "git_measure_symbols",
                "enrich a ChangeView with measured enclosing function names",
                obj_schema(
                    serde_json::json!({
                        "repo": {"type": "string"},
                        "head": {"type": "string"},
                        "view": {"type": "object"}
                    }),
                    &["repo", "head", "view"],
                ),
            ),
            Contract {
                op: "git_merge".to_string(),
                description: "fetch the fork head into the baseline and merge --no-ff".to_string(),
                input_schema: obj_schema(
                    serde_json::json!({
                        "baseline": {"type": "string"},
                        "fork": {"type": "string"},
                        "change": {"type": "object"}
                    }),
                    &["baseline", "fork", "change"],
                ),
                mutation_class: Some(MutationClass::ExternalEffect),
                required_capability: Some("wx.merge".to_string()),
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: Valence::Proven,
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

pub struct WreckSubstrate {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(WreckSubstrate { manifest: manifest() })
}

fn failed(e: String) -> OrganelleError {
    OrganelleError::failed(e)
}

impl Organelle for WreckSubstrate {
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
            "git_diff_view" => {
                let repo = PathBuf::from(str_in(&input, "repo")?);
                let change_id = str_in(&input, "change_id")?;
                let scope: Vec<ScopeItem> = match input.get("scope") {
                    Some(s) => serde_json::from_value(s.clone()).map_err(|e| failed(e.to_string()))?,
                    None => vec![],
                };
                let base = Sha::new(&str_in(&input, "base")?).map_err(failed)?;
                let head = Sha::new(&str_in(&input, "head")?).map_err(failed)?;
                let g = LocalGit::new(&repo);
                let view = g.diff_view(&change_id, &scope, &repo, &base, &head).map_err(failed)?;
                serde_json::to_value(&view).map_err(|e| failed(e.to_string()))
            }
            "git_measure_symbols" => {
                let repo = PathBuf::from(str_in(&input, "repo")?);
                let head = Sha::new(&str_in(&input, "head")?).map_err(failed)?;
                let view_v = input
                    .get("view")
                    .ok_or_else(|| failed("missing field \"view\"".to_string()))?;
                let mut view: ChangeView =
                    serde_json::from_value(view_v.clone()).map_err(|e| failed(e.to_string()))?;
                let g = LocalGit::new(&repo);
                g.measure_symbols(&repo, &head, &mut view).map_err(failed)?;
                serde_json::to_value(&view).map_err(|e| failed(e.to_string()))
            }
            "git_merge" => {
                let baseline = PathBuf::from(str_in(&input, "baseline")?);
                let fork = PathBuf::from(str_in(&input, "fork")?);
                let change_v = input
                    .get("change")
                    .ok_or_else(|| failed("missing field \"change\"".to_string()))?;
                let change: ChangeClaim =
                    serde_json::from_value(change_v.clone()).map_err(|e| failed(e.to_string()))?;
                let mut forks = HashMap::new();
                forks.insert(change.change_id.clone(), fork);
                let port = LocalMergePort { baseline, forks };
                let sha = port.merge(&change).map_err(failed)?;
                Ok(serde_json::json!({"merge_sha": sha.as_str(), "port": port.name()}))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;
    use organelle_manifest::validate_manifest_json;

    fn manifest_json() -> Value {
        let txt = include_str!("../../organelles/wreck-substrate.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("wreck-substrate-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// Build a baseline + one fork with a real change, on real git.
    fn fixture() -> (PathBuf, PathBuf, Sha, Sha) {
        let root = tmp_root("fixture");
        let g = LocalGit::new(&root);
        let base = g
            .init_baseline(&[("src/auth.rs", "line1\nline2\nline3\nline4\nline5\n")])
            .expect("init baseline");
        let fork = g.fork("a").expect("fork");
        let head = g
            .commit_change(
                &fork,
                &[("src/auth.rs", "line1\nLINE2\nline3\nline4\nline5\nline6\n")],
            )
            .expect("commit change");
        (root, fork, base, head)
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "wreck-substrate");
        assert_eq!(m.codon, "wx");
    }

    #[test]
    fn rust_manifest_matches_static_json() {
        let from_rust = serde_json::to_value(manifest()).unwrap();
        assert_eq!(from_rust, manifest_json(), "Rust manifest() and organelles/*.json must agree");
    }

    #[test]
    fn registers_and_serves_through_host_with_receipts() {
        let (root, fork, base, head) = fixture();
        let baseline = root.join("baseline");

        let host = Host::new();
        host.register(organelle()).expect("registration must succeed");
        let ctx = CallContext::new("wx-test", vec!["wx.merge".to_string()]);
        let ro = CallContext::new("wx-ro", vec![]);

        // diff_view measures the changed lines
        let view = host
            .call(
                &ro,
                "wx",
                "git_diff_view",
                serde_json::json!({
                    "repo": fork.to_str().unwrap(),
                    "change_id": "chg-a",
                    "scope": [{"kind": "file", "path": "src/auth.rs"}],
                    "base": base.as_str(),
                    "head": head.as_str()
                }),
            )
            .expect("git_diff_view");
        assert_eq!(view["change_id"], "chg-a");
        assert!(view["files"].as_array().unwrap().len() >= 1);

        // merge gate: without wx.merge the op is refused
        let mut claim = ChangeClaim::propose(
            "chg-a", "agent-a", "task-9",
            Sha::new(base.as_str()).unwrap(), Sha::new(head.as_str()).unwrap(),
            "improve auth",
        )
        .unwrap();
        let merge_input = serde_json::json!({
            "baseline": baseline.to_str().unwrap(),
            "fork": fork.to_str().unwrap(),
            "change": serde_json::to_value(&claim).unwrap()
        });
        assert!(host.call(&ro, "wx", "git_merge", merge_input.clone()).is_err());

        // with the capability, the merge executes on real git
        let m = host
            .call(&ctx, "wx", "git_merge", merge_input)
            .expect("git_merge");
        assert_eq!(m["merge_sha"].as_str().unwrap().len(), 40);
        assert_eq!(m["port"], "local-git");

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 3, "register + calls = >=3 receipts, got {n}");

        let _ = std::fs::remove_dir_all(&root);
    }
}

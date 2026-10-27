//! Side-effect containment policies (P1 lane 3).
//!
//! Two fail-closed, **default-deny** policies owned by the [`Host`](crate::Host).
//! The host is the membrane: organelles never decide for themselves whether a
//! filesystem write or a network egress is allowed — they ask the host through
//! [`HostRef`](crate::HostRef) (`approve_write_path` / `approve_egress`), and
//! the host answers from the deployment's declared policy.
//!
//! 1. **Write roots** ([`resolve_write_path`]): the operator declares the
//!    filesystem roots organelles may write under. Every write path is
//!    canonicalized (symlinks resolved, `..` rejected lexically first) and
//!    must sit under an approved root. No roots configured = deny everything.
//! 2. **Egress policy** ([`EgressPolicy`]): default-deny outbound network.
//!    An explicit allowlist of host patterns (`example.com`, `*.example.com`)
//!    names the hosts organelles may contact. Blocked egress is denied with a
//!    receipt; the denial names only the host, never the full URL (query
//!    strings may carry secrets).
//!
//! Known limitation (documented, not hidden): the write-path check and the
//! organelle's subsequent write are not atomic — a TOCTOU race exists if an
//! attacker can rename paths between approval and write. The organelle must
//! write to the canonical path *returned* by the approval (never re-derive
//! it from raw input), which closes the check/use gap for everything except
//! a concurrent filesystem mutator, which this reference membrane does not
//! defend against.

use std::path::{Component, Path, PathBuf};

// ---------------------------------------------------------------------------
// Egress policy
// ---------------------------------------------------------------------------

/// One allowlist entry: an exact host or a domain-plus-subdomains pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// Exact host, case-insensitive: `api.example.com`.
    Exact(String),
    /// From `*.example.com`: matches `example.com` and every subdomain.
    Suffix(String),
}

/// Outbound network policy: default-deny with an explicit host allowlist.
///
/// There is deliberately no "allow all" constructor: open egress is an
/// explicit operator decision expressed as allowlist entries, never a
/// default and never a flag an organelle can set for itself.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    allowed: Vec<HostPattern>,
}

impl EgressPolicy {
    /// Deny everything. This is also the `Default`.
    pub fn deny_all() -> Self {
        EgressPolicy { allowed: Vec::new() }
    }

    /// Parse an allowlist. Entries are `example.com` (exact host) or
    /// `*.example.com` (the domain and all subdomains). Anything else is an
    /// error and the policy is refused wholesale — a malformed allowlist is
    /// never installed partially (fail-closed).
    pub fn allowlist(patterns: &[&str]) -> Result<Self, String> {
        let mut allowed = Vec::new();
        for raw in patterns {
            let p = raw.trim().to_ascii_lowercase();
            if p.is_empty() {
                return Err("egress allowlist: empty pattern".to_string());
            }
            // Hostnames never contain whitespace or controls; refuse them
            // outright rather than letting a typo widen or break matching.
            if p.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(format!("egress allowlist: bad pattern {raw:?}"));
            }
            if let Some(suffix) = p.strip_prefix("*.") {
                if suffix.is_empty()
                    || suffix.contains(['/', ':', '*', '@'])
                    || suffix.starts_with('.')
                {
                    return Err(format!("egress allowlist: bad pattern {raw:?}"));
                }
                allowed.push(HostPattern::Suffix(suffix.to_string()));
            } else {
                if p.contains(['/', ':', '*', '@']) || p.starts_with('.') {
                    return Err(format!("egress allowlist: bad pattern {raw:?}"));
                }
                allowed.push(HostPattern::Exact(p));
            }
        }
        Ok(EgressPolicy { allowed })
    }

    /// True when `host` (any case, optional trailing dot, optional port —
    /// call [`egress_host_of`] first for URLs) may be contacted.
    pub fn allows(&self, host: &str) -> bool {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            return false;
        }
        self.allowed.iter().any(|pat| match pat {
            HostPattern::Exact(e) => *e == h,
            HostPattern::Suffix(s) => h == *s || h.ends_with(&format!(".{s}")),
        })
    }

    /// True when the allowlist is empty (deny-all, the default).
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

/// Extract the lowercase host (no port, no userinfo, no trailing dot) from a
/// URL for policy checking. Fails closed on anything malformed. Any scheme
/// parses here — scheme enforcement stays with the transport layer
/// (ref-common honestly refuses non-http); the policy only answers "may this
/// host be contacted".
pub fn egress_host_of(url: &str) -> Result<String, String> {
    let rest = url
        .split("://")
        .nth(1)
        .ok_or_else(|| "egress: malformed URL (no scheme)".to_string())?;
    let authority = rest.split('/').next().unwrap_or("");
    // Strip userinfo if present.
    let authority = authority.rsplit('@').next().unwrap_or("");
    if authority.is_empty() {
        return Err("egress: empty host".to_string());
    }
    let host = if let Some(inner) = authority.strip_prefix('[') {
        // IPv6 literal.
        inner
            .split(']')
            .next()
            .ok_or_else(|| "egress: bad IPv6 literal".to_string())?
    } else {
        authority.split(':').next().unwrap_or("")
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("egress: empty host".to_string());
    }
    Ok(host)
}

// ---------------------------------------------------------------------------
// Write roots
// ---------------------------------------------------------------------------

/// Resolve `raw` against the approved write `roots` (already canonicalized).
/// Returns the canonical absolute path the organelle must write to.
///
/// Fail-closed denials: no roots configured (default deny), empty path,
/// any `..` component (lexical, defense in depth — canonicalization would
/// catch it anyway), unresolvable ancestors, or a resolved path outside
/// every root. Symlinks are resolved via canonicalization, so a symlink
/// inside a root pointing outside is denied.
pub fn resolve_write_path(roots: &[PathBuf], raw: &str) -> Result<PathBuf, String> {
    if roots.is_empty() {
        return Err("write denied: no approved write roots configured (default deny)".to_string());
    }
    if raw.trim().is_empty() {
        return Err("write denied: empty path".to_string());
    }
    let p = Path::new(raw);
    if p
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("write denied: path must not contain `..`".to_string());
    }
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("write denied: cannot resolve cwd: {e}"))?
            .join(p)
    };
    // Walk up to the nearest existing ancestor, remembering the missing tail.
    let mut ancestor: &Path = &abs;
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let existing = loop {
        if ancestor.exists() {
            break ancestor;
        }
        match ancestor.file_name() {
            Some(name) => {
                tail.push(name.to_os_string());
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| "write denied: no existing ancestor".to_string())?;
            }
            None => return Err("write denied: no existing ancestor".to_string()),
        }
        if tail.len() > 4096 {
            return Err("write denied: path too deep".to_string());
        }
    };
    // Canonicalize: resolves symlinks, so escapes through symlinked
    // directories land outside the roots and are denied below.
    let mut resolved = existing
        .canonicalize()
        .map_err(|e| format!("write denied: cannot canonicalize ancestor: {e}"))?;
    for comp in tail.iter().rev() {
        let comp_path = Path::new(comp);
        let mut it = comp_path.components();
        match (it.next(), it.next()) {
            (Some(Component::Normal(_)), None) => {}
            _ => return Err("write denied: invalid path component".to_string()),
        }
        resolved.push(comp);
    }
    if roots.iter().any(|r| resolved.starts_with(r)) {
        Ok(resolved)
    } else {
        Err("write denied: path is outside all approved write roots".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("organelle-policy-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p.canonicalize().unwrap()
    }

    // -- egress ----------------------------------------------------------

    #[test]
    fn default_is_deny_all() {
        let p = EgressPolicy::deny_all();
        assert!(p.is_empty());
        assert!(!p.allows("example.com"));
        assert!(!p.allows("127.0.0.1"));
        let d: EgressPolicy = Default::default();
        assert!(!d.allows("example.com"));
    }

    #[test]
    fn exact_and_suffix_patterns() {
        let p = EgressPolicy::allowlist(&["api.example.com", "*.internal.example"]).unwrap();
        assert!(p.allows("api.example.com"));
        assert!(p.allows("API.EXAMPLE.COM")); // case-insensitive
        assert!(p.allows("api.example.com.")); // trailing dot
        assert!(!p.allows("evil.com"));
        assert!(!p.allows("api.example.com.evil.com"));
        // Suffix pattern covers the bare domain and subdomains.
        assert!(p.allows("internal.example"));
        assert!(p.allows("db.internal.example"));
        assert!(p.allows("a.b.internal.example"));
        assert!(!p.allows("notinternal.example"));
    }

    #[test]
    fn malformed_patterns_refused_wholesale() {
        for bad in ["", "*.  ", "exa mple.com", "*.*.com", "a/b", "h:1", "@x", ".lead"] {
            assert!(EgressPolicy::allowlist(&[bad]).is_err(), "pattern {bad:?}");
        }
        // One bad entry poisons the whole allowlist (fail-closed).
        assert!(EgressPolicy::allowlist(&["ok.example.com", "bad/x"]).is_err());
    }

    #[test]
    fn host_extraction() {
        assert_eq!(egress_host_of("http://example.com/x").unwrap(), "example.com");
        assert_eq!(egress_host_of("http://EXAMPLE.com:8080/x").unwrap(), "example.com");
        assert_eq!(egress_host_of("http://127.0.0.1:1/").unwrap(), "127.0.0.1");
        assert_eq!(egress_host_of("http://user@example.com/").unwrap(), "example.com");
        assert_eq!(egress_host_of("http://[::1]:8080/x").unwrap(), "::1");
        assert_eq!(egress_host_of("https://example.com/").unwrap(), "example.com");
        for bad in ["", "no-scheme", "http://", "http:///x", "http://:8080/"] {
            assert!(egress_host_of(bad).is_err(), "url {bad:?}");
        }
    }

    // -- write roots -----------------------------------------------------

    #[test]
    fn write_inside_root_allowed() {
        let root = tmp_root("wok");
        let target = root.join("sub").join("f.jsonl");
        let got = resolve_write_path(std::slice::from_ref(&root), target.to_str().unwrap()).unwrap();
        assert_eq!(got, target);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_outside_root_denied() {
        let root = tmp_root("wout");
        let outside = std::env::temp_dir().canonicalize().unwrap().join("nope.jsonl");
        // (guard against the test root accidentally being a parent)
        assert!(!outside.starts_with(&root));
        let e = resolve_write_path(std::slice::from_ref(&root), outside.to_str().unwrap()).unwrap_err();
        assert!(e.contains("outside all approved write roots"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_roots_default_deny() {
        let e = resolve_write_path(&[], "/tmp/x.jsonl").unwrap_err();
        assert!(e.contains("default deny"), "{e}");
    }

    #[test]
    fn dotdot_rejected_lexically() {
        let root = tmp_root("wdd");
        // Even a `..` that would resolve back inside the root is refused:
        // lexical rejection, no canonicalization games.
        let sneaky = format!("{}/sub/../f.jsonl", root.display());
        let _ = std::fs::create_dir_all(root.join("sub"));
        let e = resolve_write_path(std::slice::from_ref(&root), &sneaky).unwrap_err();
        assert!(e.contains(".."), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn symlink_escape_denied() {
        let root = tmp_root("wsym");
        let outside = tmp_root("wsym-out");
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let via_link = root.join("link").join("evil.jsonl");
        let e = resolve_write_path(std::slice::from_ref(&root), via_link.to_str().unwrap()).unwrap_err();
        assert!(e.contains("outside all approved write roots"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    // -- WIRE-1 (LUCIDOTA P0, Letta Code v0.34.24 sibling-prefix fix) -----
    // The overlay package shipped these as an integration test using
    // `organelle_host::policy::resolve_write_path`, but `policy` is a
    // private module (lib.rs: `mod policy;`), so that form cannot
    // compile. They are wired here as unit tests instead, which keeps
    // the module boundary unchanged. Source: the 2026-10-25 security
    // package (lucidota-security-p0-2026-10-25.zip, policy_regression.rs).

    #[test]
    fn sibling_prefix_is_not_containment() {
        // Letta's flaw: permitting /x/project inadvertently permitted
        // /x/project-private via a raw string-prefix check. Rust's
        // Path::starts_with is component-aware, so this must stay denied.
        let base = tmp_root("wsib");
        let allowed = base.join("project");
        let sibling = base.join("project-private");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let root = allowed.canonicalize().unwrap();
        let bad = sibling.join("secret.txt");
        let e = resolve_write_path(std::slice::from_ref(&root), bad.to_str().unwrap()).unwrap_err();
        assert!(e.contains("outside all approved write roots"), "{e}");
        // And the real project path itself must still be allowed.
        let good = allowed.join("secret.txt");
        assert!(resolve_write_path(std::slice::from_ref(&root), good.to_str().unwrap()).is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_with_nonexistent_target_denied() {
        // A symlink inside the root pointing outside must stay denied
        // even when the final path components do not exist yet (the
        // resolver walks to the nearest existing ancestor, which is the
        // symlink itself, and canonicalizes through it).
        let base = tmp_root("wsym-non");
        let allowed = base.join("allowed");
        let outside = base.join("outside");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, allowed.join("link")).unwrap();
        let bad = allowed.join("link").join("new").join("sub").join("file.txt");
        let e = resolve_write_path(
            std::slice::from_ref(&allowed.canonicalize().unwrap()),
            bad.to_str().unwrap(),
        )
        .unwrap_err();
        assert!(e.contains("outside all approved write roots"), "{e}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn nonexistent_root_never_matches() {
        // A root that was deleted after being configured still resolves
        // against the canonical path recorded at set time.
        let root = tmp_root("wgone");
        let target = root.join("f.jsonl");
        let got = resolve_write_path(std::slice::from_ref(&root), target.to_str().unwrap()).unwrap();
        assert_eq!(got, target);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_path_denied() {
        let root = tmp_root("wempty");
        for bad in ["", "   "] {
            assert!(resolve_write_path(std::slice::from_ref(&root), bad).is_err());
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}

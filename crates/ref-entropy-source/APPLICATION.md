# Applying `ref-entropy-source` to a getrandom-blocked crate

Add the organelle as a **target-only** dependency of a package that is
part of the WASM build.  It costs nothing on native targets.  Select the
one feature matching the getrandom line that fails:

```toml
[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies]
ref-entropy-source = {
  path = "<relative path>/organelles/crates/ref-entropy-source",
  default-features = false, # activation only: no host/manifest deps
  features = ["getrandom-0_2"] # or getrandom-0_3 / getrandom-0_4
}
```

Version rules (verified against the vendored upstream sources):

| getrandom | Feature on this crate | Upstream switch | Extra build setting |
|---|---|---|---|
| 0.2.x | `getrandom-0_2` | `getrandom/js` (wasm-bindgen + js-sys) | none |
| 0.3.x | `getrandom-0_3` | `getrandom/wasm_js` | **required:** `--cfg getrandom_backend="wasm_js"` |
| 0.4.x | `getrandom-0_4` | `getrandom/wasm_js` | none |

For 0.3.x, add this to the consuming workspace's `.cargo/config.toml`:

```toml
[target.wasm32-unknown-unknown]
rustflags = ["--cfg", 'getrandom_backend="wasm_js"']
```

If that file already has a `[target.wasm32-unknown-unknown]` table,
merge the `rustflags` key into it rather than duplicating the table.
If a project checks only one workspace member in production, put the
dependency on that member: Cargo feature unification is per build
invocation, so a root-wide check can be green while an unrelated
single-package check remains red.

This pattern fixes the getrandom backend only.  It does not make
Tokio/mio networking, `std::os::unix`, SQLite C build scripts, ring's C
build script, or native filesystem/process APIs available on Workers.

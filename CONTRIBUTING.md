# Contributing

This is an experimental Unix-only Rust project. Please keep changes focused and
include regressions for protocol behavior. Avoid implying complete MTA Hooks
draft compliance when adding one capability.

## Local checks

Use Rust 1.90 or newer. From the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps
python3 scripts/check_package.py
cargo package --locked --allow-dirty
```

The socket tests bind loopback TCP and Unix sockets. On a sandboxed machine,
enable that permission rather than silently omitting tests. For state-machine or
wire changes, also run the [Postfix suite](interop/README.md) for both transports.
Its Docker build needs network access; its containers intentionally do not.

Keep the manifest's minimum Rust version and CI matrix aligned. Commit
`Cargo.lock`: this repository includes a deployable daemon, not only a library.
If updating dependencies, rerun the checks and review the lockfile diff.

## Protocol invariants

- Bound input lengths before allocations and preserve untrusted message bytes.
- Process one outstanding policy callback per milter connection.
- Negotiate actions/no-reply flags honestly; always terminate an EOM response.
- Validate a whole decision before writing any mutation frames.
- Reset transaction state without losing legitimate connection metadata.
- Never put credentials, SMTP bodies, or personal mail in logs or fixtures.

Document behavior that Postfix cannot express through milter, and distinguish
core capabilities from HTTP adapter capabilities. The controlled scanner fixture
is not independent conformance evidence.

Use `cargo fmt`, avoid unsafe Rust, and use synthetic mail in regressions. Use
commit subjects such as `[Feature] ...`, `[Fix] ...`, or `[Test] ...`; maintainer
commits must be GPG-signed. Contributions use this repository's Apache-2.0 license.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public
issue with sensitive details.

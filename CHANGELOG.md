# Changelog

## Unreleased — initial 0.1.0 candidate

- Independent milter v6 codec and explicit transaction state machine.
- Tokio TCP/Unix listeners and async policy callbacks with bounded resources,
  deadlines and graceful shutdown.
- Axum health, readiness and Prometheus endpoints.
- Experimental single-scanner MTA Hooks draft-01 JSON/data adapter with
  registration recovery, decision validation and temporary-failure defaults.
- Low-level header/body/envelope modifications; narrower HTTP update allowlist.
- 30 Rust tests and real Postfix 3.7.11 coverage: 24 checks for each transport.
- Reproducible network-isolated Postfix harness, CI and package-file checks.

The HTTP adapter is not a complete draft implementation. Independent draft-01
scanner interoperability and production hardening remain open; see the README.

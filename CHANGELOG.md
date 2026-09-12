# Changelog

## Unreleased — initial 0.1.0 candidate

- Raw-message response translation with bounded header/body replacement,
  explicit empty bodies and preservation of unchanged original fields.
- Folded output headers (including DKIM signatures) with field-injection checks,
  and body-replacement capability negotiation for the HTTP scanner policy.
- Configurable inbound hook stages (`connect`, `ehlo`, `mail`, `rcpt`, `data`),
  property negotiation with `/tls`, `/auth` and `/server` projections, and a
  `disconnect` action mapped to `SMFIR_SHUTDOWN`.
- Hook response translation for header change/delete, envelope sender change
  and recipient add/delete, validated atomically with the existing header adds.
- Bounded hook retries with backoff on transient scanner failures, optional
  startup registration wait, and deregistration on shutdown.
- Macro-list requests in the milter negotiation reply and `SMFIR_PROGRESS`
  keepalives while a policy callback is pending.
- Unix socket permission bits and opt-in stale socket replacement.
- Scanner HTTP options for custom CA bundles, mutual TLS, explicit proxy policy,
  connection pooling, bearer/Basic credential files and bounded gzip responses.
- JSON logs with connection/request correlation; classified failures, operation
  latency histograms, in-flight/waiter gauges, listener state and drain outcomes.
- Separate opt-in milter idle expiry from the absolute partial-frame deadline;
  leave SMTP idle handling to Postfix by default and expose both CLI settings.
- Independent milter v6 codec and explicit transaction state machine.
- Tokio TCP/Unix listeners and async policy callbacks with bounded resources,
  deadlines and graceful shutdown.
- Axum health, readiness and Prometheus endpoints.
- Experimental single-scanner MTA Hooks draft-01 JSON/data adapter with
  registration recovery, decision validation and temporary-failure defaults.
- Low-level header/body/envelope modifications; narrower HTTP update allowlist.
- 60 Rust tests and real Postfix 3.7.11 coverage: 26 data-only and 33
  multi-stage checks for each transport, including a 65-second idle SMTP session
  followed by another scanned message, stage-level rejections and queue edits.
- Reproducible network-isolated Postfix harness, CI and package-file checks.

The HTTP adapter is not a complete draft implementation. Independent draft-01
scanner interoperability and production hardening remain open; see the README.

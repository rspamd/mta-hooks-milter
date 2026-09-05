# mta-hooks-milter

**Experimental: initial 0.1.0 release candidate.** The milter core has automated
Postfix coverage; the HTTP adapter implements only the documented draft-01
subset. API stability and production readiness are not claimed.

Standalone Rust milter library and daemon, with Tokio networking and Axum HTTP.
The initial daemon bridges a Postfix milter connection to one HTTP scanner using
a deliberately limited MTA Hooks draft-01 profile. No Rspamd runtime or libmilter
dependency is required.

Postfix initiates the milter connection. The bridge initiates HTTP registration
and hook requests to the scanner. The bridge's own Axum server provides health,
readiness and metrics; it is not a scanner registration endpoint.

```text
Postfix -- milter/TCP or Unix --> daemon -- HTTPS/JSON --> scanner
                                  |
                                  +-- Axum: health / readiness / metrics
```

## Build and test

Rust 1.90 or newer, on Unix (Linux/macOS). Windows is not supported.
`Cargo.lock` is included. From a checkout of this repository:

```sh
cargo build --locked
cargo test --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

Build an optimized daemon with `cargo build --release --locked`, or install it
from the checkout with `cargo install --path . --locked`. Crates.io installation
is not available until a registry release has actually been published.

Tests cover fragmented/coalesced frames, malformed packets, option negotiation,
no-reply fallback, transaction reuse, abort and connection reuse, rejected RCPT
state, macro scoping, binary content, output validation and size limits. Async
tests use real loopback TCP/Unix sockets and an Axum scanner, plus in-memory I/O
for timeout and shutdown checks. Socket tests need permission to bind locally.
Real Postfix 3.7.11 interoperability has also passed over TCP and Unix milter
sockets, including SMTP STARTTLS. See [the interoperability report](interop/README.md)
for evidence, reproducible commands and the remaining independent-scanner gap.

## Local demonstration

Run the accept-all development scanner in one terminal:

```sh
export MTA_HOOKS_TOKEN=local-development-only
cargo run --example scanner
```

Run the bridge in another terminal with the same token:

```sh
export MTA_HOOKS_TOKEN=local-development-only
cargo run -- \
  --scanner http://127.0.0.1:18080/register \
  --insecure-loopback
```

The example scanner adds `X-MTA-Hooks: scanned`. It is a protocol fixture, not
a full scanner implementation: no discovery, status or deregistration API.
Do not use its accept-all policy or demonstration token in production.

For a real scanner, pass its HTTPS registration URL and set `MTA_HOOKS_TOKEN`
through the service environment. Startup fails if registration fails. HTTP is
only allowed with the explicit development switch and a literal loopback IP;
`localhost` and remote plaintext endpoints are not accepted. Redirects and
cross-origin hook endpoints are refused to avoid forwarding credentials.

The default milter endpoint is `127.0.0.1:11332`; the default administrative HTTP
endpoint is `127.0.0.1:8080`. `--milter-unix /path/to/socket` selects a Unix socket.
Existing socket paths are never deleted; the service manager owns permissions
and cleanup. Keep both listeners private: milter and the administrative HTTP
listener do not provide authentication or TLS.

`--passthrough` explicitly selects a no-scanner development mode. It cannot be
combined with `--scanner`. Use `cargo run -- --help` for available options.

## Scanner HTTP transport

Choose one authentication source: `MTA_HOOKS_TOKEN` / `--scanner-token`,
`--scanner-token-file PATH`, or `--scanner-basic-user USER` together with
`--scanner-basic-password-file PATH`. Prefer files to command-line secrets.
Credential files are UTF-8, at most 8 KiB, with one optional trailing LF/CRLF;
password spaces are preserved. Files are read once at startup, not hot-reloaded.
Keep them readable only by the service account. Unset `MTA_HOOKS_TOKEN` when
selecting file or Basic authentication: conflicting sources are rejected.
Static JWTs can be supplied as bearer tokens; OAuth2/OIDC token acquisition and
refresh are not implemented.

TLS options apply to both registration and hooks:

- `--scanner-ca PATH` adds a PEM CA bundle; repeat for multiple bundles.
  Built-in roots remain trusted unless `--scanner-custom-roots-only` is set,
  which requires a custom CA. Each PEM file is limited to 1 MiB.
- `--scanner-identity PATH` loads a PEM client certificate chain and private key
  for mutual TLS, in addition to the chosen HTTP authentication. Protect the key
  file. Certificate and hostname verification remain mandatory.

Transport controls:

| Option | Default / behavior |
| --- | --- |
| `--scanner-proxy URL` | Explicit HTTP(S) proxy origin, without credentials; overrides all environment proxy settings, including `NO_PROXY` |
| `--scanner-no-proxy` | Disables proxies entirely; mutually exclusive with the explicit proxy option |
| `--scanner-connect-timeout-ms` | 5000, capped by the policy deadline |
| `--scanner-pool-idle-timeout-ms` | 90000; positive idle-socket expiry |
| `--scanner-pool-max-idle` | 16 sockets per host; 0 disables pooling; does not limit active requests |
| `--scanner-gzip` | Opt-in gzip response negotiation/decompression; outgoing JSON is uncompressed |

Without a proxy option, reqwest honors environment proxies and `NO_PROXY`.
Use `--scanner-no-proxy` for direct loopback development if the service environment
sets a proxy. A proxy can observe traffic metadata; plaintext development requests
also expose their credentials and content to it. Authenticated proxies are not
supported by the explicit proxy option in this pass.

The 1 MiB HTTP response limit applies **after decompression**. Registration and
hook requests share the same configured HTTP client and connection pool.
The whole invocation, including registration waits and 404/410 recovery, remains
bounded by `--policy-timeout-ms`; transport settings do not extend that budget.
Standalone startup registration has the same total deadline.

No application-level transport-error retry is added. A failed POST may already
have been processed by the scanner. Reqwest retains its limited default retries
for safe protocol-level rejections; the only bridge recovery is one registration
renewal on hook 404/410, retaining the request ID and body.

## Observability

Use `--log-format json` for structured logs (text remains the default), and
`RUST_LOG=mta_hooks_milter=debug` for per-connection and request lifecycle events.
Connection spans carry a generated `session_id`; scanner spans carry the same
`request_id` sent in `X-MTA-Hooks-Request-Id`, preserved across recovery. Logs
include sanitized error categories, HTTP status codes and request elapsed time,
not scanner URLs, credentials or message content. Enabling third-party HTTP
trace logging separately can expose more detail; handle those logs accordingly.

`/metrics` retains the existing counters and active-connection gauge and adds:

- `milter_operations_active` and `milter_operations_total`, labeled by fixed
  operation (`policy`, `registration`, `hook`, `registration_wait`) and, for the
  counter, outcome. Registration wait measures mutex contention, not a mail queue.
- `milter_operation_duration_seconds`, a histogram for the same operations.
  Policy timing includes decision validation; HTTP operation timing includes
  response parsing. Cancelled/dropped futures also release gauges and contribute
  a duration sample with a `cancelled` outcome. Thus a policy timeout can appear
  as `timeout` at the policy layer and `cancelled` at the inner HTTP layer.
- `milter_connection_failures_total{kind=...}`, with bounded error categories,
  and `milter_listener_up{transport="tcp"|"unix"}` for the active accept loop.
- `milter_ready` and `milter_drain_total{outcome="graceful"|"forced"}`. Drain counts
  shutdown attempts, not messages or connections; forced drain aborts remaining
  tasks after the deadline.

IDs, addresses and URLs are never metric labels. This daemon has one milter
listener; use the scraper's target labels to distinguish deployed instances.
The legacy `milter_protocol_errors_total` counts all connection-driver errors,
including I/O and deadlines; use the classified counter for a breakdown.
Readiness reflects startup/listener state, not continuous scanner health.

The operational HTTP listener still has **no built-in authentication or TLS**.
Keep the default loopback binding and use a protected authenticated TLS reverse
proxy for remote scraping. OpenTelemetry/OTLP, systemd integration, OS packages
and direct Unix-socket ownership/mode configuration remain follow-up work.

## Postfix configuration example

For a dedicated test Postfix instance, merge the following into its configuration
(do not overwrite an existing milter chain):

```ini
smtpd_milters = inet:127.0.0.1:11332
milter_protocol = 6
milter_default_action = tempfail
milter_command_timeout = 60s
milter_content_timeout = 60s
```

The daemon does not install, configure or restart Postfix. Start with SMTP
ingress only; `non_smtpd_milters`, chained filters, chroot socket paths and queue
semantics require their own integration validation. Supply required Postfix
macros through its configuration; this implementation does not request custom
macro lists during negotiation. Missing queue IDs remain null, never fabricated.

### Timeout sizing

Milter socket idle time and incomplete-frame time are separate:

- `--milter-idle-timeout-ms` defaults to `0` (disabled). It limits waiting for
  the first byte of the next frame, including the initial negotiation. The
  library equivalent is `Config::idle_timeout: Option<Duration>` (`None` by
  default). A configured idle deadline starts afresh after each callback/reply.
- `--milter-frame-timeout-ms` defaults to `60000`. `Config::frame_timeout` is
  an absolute deadline from the first length byte until the complete command
  and payload arrive. Partial progress does not restart it. Time already spent
  idle does not consume this budget.

Postfix keeps the milter socket for the SMTP session; a quiet milter socket does
not mean the SMTP session has ended. The normal default
[`smtpd_timeout`](https://www.postfix.org/smtpd.8.html) is 300 seconds (10 seconds
under overload), applied to SMTP network I/O, not the whole session. Delays
between milter events can also include message reception and other SMTP work.
Idle expiry is therefore opt-in: let Postfix own SMTP idle handling unless the
deployment has an explicit upper bound on gaps between callbacks. If enabled,
size it above that bound with margin, not merely above the frame deadline.
An idle or partial-frame timeout closes the socket; Postfix then applies
`milter_default_action`. Keep the milter listener private and use
`--max-connections` to bound resources even when idle expiry is disabled.

Postfix's [milter timeouts](https://www.postfix.org/MILTER_README.html)
go in the other direction: `milter_connect_timeout` (default 30s) bounds connection
and negotiation, `milter_command_timeout` (30s) bounds command exchanges, and
`milter_content_timeout` (300s) bounds content exchanges. The example above
overrides the latter two to 60s. Allow room for the bridge's policy evaluation
(20s by default), reply writes (10s) and transport overhead inside the applicable
Postfix timeout. Increasing those Postfix settings does not extend a separately
configured bridge idle deadline. Shutdown cancels idle and partial-frame reads;
only an in-flight policy callback/reply is drained.

## Library design

| Module | Responsibility |
| --- | --- |
| `protocol` | Bounded length-prefixed wire frames, strict command decoding, capability constants, response encoding |
| `session` | Transport-independent SMTP/milter state and complete-decision validation |
| `server` | Tokio TCP/Unix listeners, concurrency bounds, async `Policy`, deadlines and shutdown |
| `hooks` | Reqwest HTTPS client, registration cache and JSON data-stage translation |
| `transport` | Validated authentication, TLS, proxy and connection-pool settings |
| `stats` | Bounded-cardinality counters, gauges and operation histograms |
| `http` | Axum `/healthz`, `/readyz`, `/metrics` routes |

`Policy::evaluate` returns a Send future borrowing an immutable session snapshot.
The driver processes one callback at a time per milter connection; other
connections proceed concurrently. It never reads the next command while a
callback is pending, and only the driver writes replies. Subscribe through
`Policy::stages()` and declare requested modifications through `Policy::actions()`.

The normal state progression is negotiation → CONNECT → MAIL → RCPT(s) → DATA →
headers → EOH → body → EOM → ready for another MAIL. HELO is connection-scoped.
ABORT clears transaction data; QUIT closes; QUIT_NC retains negotiated options
but clears the old connection. A rejected RCPT removes only that recipient.
Macros are scoped to the next matching command and reset between transactions,
with CONNECT/HELO metadata retained.

The core supports async CONNECT, HELO, MAIL, RCPT and EOM callbacks. It negotiates
version 6, intersects offered capabilities and only suppresses replies where
both parties agreed. It preserves incoming header/body bytes and ESMTP arguments.
Low-level modifications include add/insert/change/delete header, chunked body
replacement, envelope sender/recipient changes and quarantine. Message edits
are emitted only at EOM and only with negotiated capability bits. Header insert
indexes are absolute/zero-based; change/delete occurrences are per-name/one-based.
Output header values must be unfolded and cannot contain CR, LF or NUL.

## Implemented Hooks profile and limits

This is **not a complete draft-01 MTA implementation**. Current adapter behavior:

- One manually configured scanner; JSON and inbound `data` only, invoked at EOM.
- Registration is cached, renewed on demand near expiry, and recovered once on
  hook HTTP 404/410. Recovery retains the invocation ID and shares its deadline.
- Requested properties: `/stage`, `/action`, `/timestamp`, `/protocol`,
  `/rawMessage`, `/envelope`, `/queue`, `/client`. The scanner must confirm this
  exact profile. Optional metadata depends on the milter events/macros available.
- HTTP 204 or an empty operation object continues processing. Supported updates:
  set `/action`, set `/response` or its code/enhancedCode/message fields, and add
  `/message/headers` with an optional insertion index.
- Actions: accept (milter CONTINUE), reject (4xx or 5xx reply), discard, quarantine.
  Quarantine additionally requires the MTA's negotiated quarantine capability.
- Unsupported paths, operations or actions fail the whole decision; no partial
  wire edits are sent. The draft's registration schema does not carry the
  `updateProperties` negotiation mentioned elsewhere, so this adapter uses a
  fixed local allowlist. A scanner must be configured for that allowlist.

No outbound delivery/DSN hooks, disconnect emulation, CBOR, discovery, status
polling, deregistration, scanner chains, structured MIME projection, body or
envelope **HTTP update translation**, TLS/auth metadata projection, retry backoff
or durable registration state yet. The core's lower-level edit API is broader
than the HTTP translator. Those are explicit follow-up integration areas.

`rawMessage` is Base64 of the message visible through milter, reconstructed from
headers and body. Header leading-space negotiation is honoured, but this is not
a promise of the original SMTP octets or the complete/final Postfix queue file.
Incoming binary body/header bytes are preserved; non-UTF8 envelope/metadata
cannot be represented by this JSON adapter and triggers its failure policy.

Defaults: 128 connections, 25,000,000 message bytes in the CLI (25 MiB in the
library defaults), 1 MiB envelope data, 10,000 headers, 1,000 recipients, 64 KiB
macro data, 1,000 modifications, 1 MiB HTTP response and 131,073 bytes per milter
frame including opcode. Idle expiry is disabled by default; started frames have
a 60-second absolute deadline. Policy evaluation has 20 seconds, writes 10
seconds and shutdown draining 30 seconds. See timeout sizing above.
Messages are buffered in memory; raw reconstruction, Base64 and JSON add copies.
These are per-connection limits, **not** a global memory budget. Tune connection
and message limits together; disk spooling and global byte admission remain work.

Scanner timeouts/errors and invalid decisions produce temporary failure by
default; `--fail-open` opts into CONTINUE. Invalid wire input, input limit breaches
and overloaded connections close the socket, leaving the outcome to Postfix's
`milter_default_action`. Startup registration failure is always fatal, including
in fail-open mode. `/readyz` reflects listener/startup readiness, not continuous
scanner health. Metrics do not contain message content or credentials.

## References and provenance

- [Rspamd milter.c](https://github.com/rspamd/rspamd/blob/638e9e5b94cc31330e6eb57c94f090927b82c4c0/src/libserver/milter.c)
  and [milter_internal.h](https://github.com/rspamd/rspamd/blob/638e9e5b94cc31330e6eb57c94f090927b82c4c0/src/libserver/milter_internal.h)
  informed the wire constants, version profile and header-space handling.
- [MTA Hooks draft-01](https://datatracker.ietf.org/doc/html/draft-degennaro-mta-hooks-01)
  is the HTTP protocol reference, a work-in-progress draft rather than a final RFC.
- [Postfix MILTER_README](https://www.postfix.org/MILTER_README.html) is the
  operational reference for deployment and Postfix-specific restrictions.

Apache-2.0; see `LICENSE.md` and `NOTICE`.

For development, see [CONTRIBUTING.md](CONTRIBUTING.md). Report sensitive issues
privately as described in [SECURITY.md](SECURITY.md). Maintainers should follow
[RELEASING.md](RELEASING.md); publication is deliberately not automated.

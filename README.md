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

Tests cover fragmented/coalesced frames, malformed packets, option negotiation
with macro-list requests, no-reply fallback, transaction reuse, abort and
connection reuse, rejected RCPT state, disconnect verdicts, macro scoping,
binary content, output validation and size limits. Async tests use real loopback
TCP/Unix sockets and an Axum scanner (early stages, property negotiation,
retries, deregistration, late scanner startup), plus in-memory I/O for timeout,
progress keepalive and shutdown checks. Socket tests need permission to bind locally.
Real Postfix 3.7.11 interoperability has also passed over TCP and Unix milter
sockets, including SMTP STARTTLS, both with the default data-only subscription
and with all five inbound stages (MAIL/RCPT rejections, EHLO disconnect,
envelope and header edits verified in the queue). See [the interoperability report](interop/README.md)
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

The example scanner adds `X-MTA-Hooks: scanned` at the data stage, accepts any
earlier stage unchanged and answers deregistration. It is a protocol fixture,
not a full scanner implementation: no discovery or status API. Do not use its
accept-all policy or demonstration token in production.

For a real scanner, pass its HTTPS registration URL and set `MTA_HOOKS_TOKEN`
through the service environment. Startup fails if registration fails. HTTP is
only allowed with the explicit development switch and a literal loopback IP;
`localhost` and remote plaintext endpoints are not accepted. Redirects and
cross-origin hook endpoints are refused to avoid forwarding credentials.

The default milter endpoint is `127.0.0.1:11332`; the default administrative HTTP
endpoint is `127.0.0.1:8080`. `--milter-unix /path/to/socket` selects a Unix socket.
`--milter-unix-mode 0660` applies permission bits after binding; ownership stays
with the service manager. An existing path is kept unless
`--milter-unix-replace-stale` is set, which removes it only when it is a socket
that refuses connections (a leftover from an unclean stop); a path that answers
or is not a socket still fails startup. The socket file is not removed on exit.
Keep both listeners private: milter and the administrative HTTP listener do not
provide authentication or TLS.

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

Registration responses are limited to 1 MiB **after decompression**. Hook responses
allow base64 expansion of the configured message limit plus 1 MiB of JSON overhead,
so bounded raw-message replacements can carry a full message. Registration and
hook requests share the same configured HTTP client and connection pool.
The whole invocation, including registration waits and 404/410 recovery, remains
bounded by `--policy-timeout-ms`; transport settings do not extend that budget.
Standalone startup registration has the same total deadline.

Hook requests follow the draft's retry guidance for *transient* failures only:
a connect error, HTTP 5xx or 429 is retried up to `--scanner-retries` times
(default 2) with exponential backoff from 100 ms, capped at 5 s plus jitter, and
`Retry-After` (seconds) is honored up to the same cap. The request ID stays the
same so the scanner can deduplicate. Timeouts are never retried: the scanner may
still be processing the first attempt and the policy budget is shared. Set
`--scanner-retries 0` to disable. Independently, one registration renewal is
attempted on hook 404/410, also retaining the request ID. Everything stays inside
`--policy-timeout-ms`; a retry that could not finish in time is not started.

Startup registration is tried once by default. `--scanner-startup-wait-ms`
keeps retrying transient failures (connection refused, timeouts, 5xx, 429) with
the same backoff for that long, so the bridge can start before its scanner
under a service manager. Authentication and schema failures remain immediately
fatal. On shutdown, after milter connections have drained, the bridge sends a
`DELETE` to the deregistration endpoint the scanner returned, if any
(`--scanner-no-deregister` skips it); no hook is sent after that point.

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
- `milter_progress_total`, the number of `SMFIR_PROGRESS` keepalives written
  while callbacks were pending; `milter_hook_retries_total`, repeated hook
  requests after transient scanner failures; and a `deregistration` operation
  in the operation counters/histogram.

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
macros through its configuration, or let the bridge request them: by default
the scanner policy sends macro-list overrides in the negotiation reply for the
names its projection uses (`i`, `{client_addr}`, `{client_ptr}`, `{daemon_addr}`,
`{tls_version}`, `{auth_authen}`, ...). Postfix and Sendmail replace *all* their
configured lists when any override is present, so every class is sent
explicitly. `--no-request-macros` keeps the MTA's own lists. Missing queue IDs
remain null, never fabricated.

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
overrides the latter two to 60s. While a policy callback is pending, the bridge
writes an `SMFIR_PROGRESS` keepalive every `--milter-progress-interval-ms`
(default 10 s; 0 disables), which restarts Postfix's command/content timer, so
the policy deadline (20 s by default) no longer has to fit inside one Postfix
timeout. Keep the interval well below the Postfix timeouts and still allow room
for reply writes (10 s) and transport overhead. Increasing those Postfix
settings does not extend a separately configured bridge idle deadline. Shutdown
cancels idle and partial-frame reads; only an in-flight policy callback/reply is
drained.

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
version 6, intersects offered capabilities, optionally appends macro-list
requests (`Policy::macros`) and only suppresses replies where both parties
agreed. Verdicts include continue/accept/reject/tempfail/discard, a custom SMTP
reply and `Shutdown` (`SMFIR_SHUTDOWN`), after which the MTA closes the SMTP
session and the state machine accepts only ABORT/QUIT. It preserves incoming header/body bytes and ESMTP arguments.
Low-level modifications include add/insert/change/delete header, chunked body
replacement, envelope sender/recipient changes and quarantine. Message edits
are emitted only at EOM and only with negotiated capability bits. Header insert
indexes are absolute/zero-based; change/delete occurrences are per-name/one-based.
Output header values may contain folded lines (a newline followed by space or
tab). Bare CR, NUL, other control bytes and newlines introducing a new field are
rejected. Raw header insertions preserve colon whitespace when leading-space
support was negotiated; otherwise only the representable single-space form is accepted.

## Implemented Hooks profile and limits

This is **not a complete draft-01 MTA implementation**. Current adapter behavior:

- One manually configured scanner; JSON only. `--scanner-stages` selects the
  inbound stages (`connect`, `ehlo`, `mail`, `rcpt`, `data`; default `data`).
  The scanner must confirm exactly the configured stages. Each stage produces
  one hook request per milter event; `rcpt` is invoked per recipient with that
  recipient last in `/envelope/to`.
- Registration is cached, renewed on demand near expiry, and recovered once on
  hook HTTP 404/410. Recovery retains the invocation ID and shares its deadline.
- Offered properties: `/stage`, `/action`, `/timestamp`, `/protocol`,
  `/rawMessage`, `/envelope`, `/queue`, `/client`, `/tls`, `/auth`, `/server`.
  The scanner confirms a subset (at least `/stage` and `/action`; anything
  outside the offer is refused) and receives only the confirmed properties.
  `/rawMessage` and `/envelope` are `null` before they exist (before `data` and
  before `mail`). `/tls`, `/auth`, `/server`, `/queue` and the client PTR and
  connection count come from milter macros and are `null` when absent.
  `/senderAuth`, `/message` and `activeConnections` beyond the macro value are
  not projected.
- HTTP 204 or an empty operation object continues processing. At the `data`
  stage the translator supports: set `/action`; set `/response` or its
  code/enhancedCode/message fields; add `/message/headers` (optional index);
  set `/message/headers/N` (same name; milter cannot rename) or
  `/message/headers/N/value`; delete `/message/headers/N`; set `/envelope/from`;
  add `/envelope/to`; delete `/envelope/to/N`. Header indexes refer to the
  milter-visible header list (the `rawMessage` headers) as the draft's
  set/add/delete order leaves them; deletes and changes are emitted before
  inserts, ordered so occurrence counts stay valid. Earlier stages accept only
  `/action` and `/response`.
- At `data`, set `/rawMessage` replaces the milter-visible message from canonical
  base64. Identical original fields are retained without reserializing them;
  changed fields are deleted/inserted and changed bodies use chunked milter body
  replacement, including explicit empty bodies. Structured `/message` operations
  are ignored when `/rawMessage` is replaced, as required by draft-01. Envelope
  and action operations still apply. Size, header-count, modification and
  negotiated-capability limits are checked before emitting any edits.
- Actions: accept (milter CONTINUE), reject (4xx or 5xx reply; at `rcpt` only
  that recipient), discard (from `mail` onwards), quarantine (`data` only, needs
  the negotiated capability) and disconnect (`SMFIR_SHUTDOWN`; Postfix answers
  `421 4.7.0 Server closing connection`).
- Unsupported paths, operations, actions or stage combinations fail the whole
  decision; no partial wire edits are sent. The draft's registration schema
  does not carry the `updateProperties` negotiation mentioned elsewhere, so this
  adapter uses a fixed local allowlist. A scanner must be configured for it.

No outbound delivery/DSN hooks, CBOR, discovery, status polling, scanner chains,
structured MIME projection, `/senderAuth` projection or durable registration
state yet. Those are explicit follow-up integration areas.

`rawMessage` is Base64 of the message visible through milter, reconstructed from
headers and body. Header leading-space negotiation is honoured, but this is not
a promise of the original SMTP octets or the complete/final Postfix queue file.
Incoming binary body/header bytes are preserved; non-UTF8 envelope/metadata
cannot be represented by this JSON adapter and triggers its failure policy.

Defaults: 128 connections, 25,000,000 message bytes in the CLI (25 MiB in the
library defaults), 1 MiB envelope data, 10,000 headers, 1,000 recipients, 64 KiB
macro data, 1,000 modifications, bounded HTTP responses as described above, and 131,073 bytes per milter
frame including opcode. Idle expiry is disabled by default; started frames have
a 60-second absolute deadline. Policy evaluation has 20 seconds, writes 10
seconds and shutdown draining 30 seconds. See timeout sizing above.
Header and recipient counts after hook edits are held to the same limits.
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

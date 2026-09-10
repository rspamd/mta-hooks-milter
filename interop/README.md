# Postfix interoperability

Verified on 2026-09-05 using Colima/Docker on an Apple Silicon Mac:

- Postfix **3.7.11** (`3.7.11-0+deb12u1`), Debian bookworm, Linux aarch64.
- Rust **1.90**, locked dependencies, the actual `mta-hooks-milter` executable.
- Two full runs after the idle-timeout fix: **25 checks over TCP and 25 over
  Unix sockets**, both exit 0. The initial baseline had 24 checks per transport.
- Both 25-check runs were repeated after the HTTP transport/observability pass.
  The harness now also checks in-flight gauge cleanup, callback/HTTP histogram
  counts, classified policy failures and the selected listener's state.
- The new regression leaves an existing SMTP session quiet for 65 seconds, then
  requires successful scanning, SMTP acceptance and the scanner-added queue
  header. A paused-clock Rust regression failed before the fix at 61 seconds
  and passes with separate idle and partial-frame deadlines.
- HTTP scanner: a controlled Python standard-library draft-01 fixture written
  for this suite, not an independent third-party scanner. It has no external
  service dependencies and never forwards messages elsewhere.

Re-run on 2026-09-09 after the functionality pass (configurable stages, hook
retries, progress keepalives, macro-list requests, deregistration), same
Postfix 3.7.11 image and Colima profile: **26 checks over TCP and 26 over Unix
sockets**, both exit 0. The harness now runs the bridge with a 1.5 s policy
deadline, a 1 s `SMFIR_PROGRESS` interval and the default two hook retries.
Observed on both transports: `milter_messages_total 23`,
`milter_policy_errors_total 3`, `milter_hook_retries_total 2` (the 503 case
received three requests with one request ID), `milter_progress_total 1` (Postfix
accepted the keepalive during the scanner-timeout case and still applied the
451), 25 hook samples against 23 policy samples, and one authenticated `DELETE`
to the deregistration endpoint after SIGTERM. The bridge requested macro lists
in every negotiation; queue IDs and client metadata continued to match the
Postfix queue records. Raw logs: `results/postfix-robustness-{tcp,unix}.log`.

Multi-stage run on 2026-09-10 (`HOOK_STAGES=all`, the bridge started with
`--scanner-stages connect,ehlo,mail,rcpt,data`): **33 checks over TCP and 33
over Unix sockets**, both exit 0, alongside the 26-check data-only runs repeated
the same day. Per transport the scanner received 8 connect, 8 ehlo, 30 mail,
30 rcpt and 29 data requests (103 policy evaluations, 105 hook requests with
the two retries, 27 end-of-message events). Observed through real Postfix:

- MAIL-stage reject: SMTP 550 with the scanner's text at `MAIL FROM`; the
  session continues and the next message is scanned normally.
- MAIL-stage discard: Postfix accepts the transaction, sends no further events
  for it and retains nothing in the queue.
- RCPT-stage reject (550) and temporary reject (451): only that recipient is
  refused, the next RCPT request no longer lists it, and the data-stage
  envelope contains the accepted recipient alone.
- EHLO-stage `disconnect`: Postfix answers 421 and closes the session.
- Data-stage edits: sender rewritten (`postcat -qe` shows the new `sender:`),
  one recipient deleted and one added (`done_recipient:` versus `recipient:`),
  a header value changed and one of two duplicate headers deleted, all in the
  same response as the usual header addition.
- Metadata: `/server` carries `myhostname`; the EHLO after STARTTLS carries
  `/tls` with version and cipher bits from the requested macros; earlier
  requests have `/tls` null. Postfix does not know the queue ID at MAIL time
  (`/queue` was null in all 30 mail requests and present at data).

The port-readiness probe is a bare TCP connection that Postfix also reports as
a connect event, so the connect count is checked as a lower bound. Raw logs:
`results/postfix-multistage-{tcp,unix}.log`.

## What was verified

Each transport run submits 23 message scenarios through real SMTP. Assertions
inspect both the received hook JSON/raw content and Postfix queue records:

| Case | Required result |
| --- | --- |
| Normal acceptance and header addition | SMTP 250; added header exists in the queue |
| 65-second pause on an existing SMTP session | Next message still scanned, accepted and queued with its added header |
| Null envelope sender | HTTP envelope contains null; message accepted |
| RSET and multiple messages on one SMTP connection | Fresh envelope/queue ID for each message |
| Reject / temporary policy rejection | SMTP 550 / 451; no queued message |
| Message after reject/tempfail | Successfully scanned and accepted |
| Discard | SMTP 250 but no retained queue entry |
| Quarantine | SMTP 250 and Postfix hold-queue entry |
| HTTP 204 | Message accepted without a scanner-added header |
| 180 KB body | Complete body reaches the scanner across milter chunks |
| Duplicate and folded headers | Both duplicates and folded value survive |
| Malformed output header, HTTP 503, scanner timeout | SMTP 451; no partial edits or retained queue entry |
| Message after scanner errors | Successfully scanned and accepted |
| SMTP STARTTLS followed by EHLO | Filtering continues after the TLS transition |
| Empty body, dot-stuffed lines, UTF-8 body bytes | Correct milter-visible body |
| Four simultaneous SMTP sessions | All four scanned and correctly queued |
| Bridge deliberately stopped | Postfix rejects EHLO or MAIL temporarily; no silent bypass |
| Multi-stage only: sender denied at MAIL | SMTP 550 at `MAIL FROM`; next message scanned |
| Multi-stage only: discard at MAIL | SMTP 250; no data hook, nothing queued |
| Multi-stage only: recipient rejected/deferred at RCPT | 550 / 451 for that recipient; message queued for the other |
| Multi-stage only: `disconnect` at EHLO | SMTP 421 and session closed |
| Multi-stage only: envelope and header edits | Queue file shows new sender, swapped recipient, changed and deleted headers |

The three additional top-level checks are quarantine's actual hold-queue state,
deregistration on shutdown and the absent-bridge negative control. The harness also checks the complete set
of retained queue IDs, so discarded/rejected/error messages cannot silently
remain queued. Every queued message's queue ID must match the ID sent to the
scanner. Both runs reported `milter_messages_total 23`,
`milter_protocol_errors_total 0`, and `milter_policy_errors_total 3` (the three
intentional malformed-response/unavailable/timeout cases).
The latter classify as `invalid`, `http_status` and `timeout`, one each. Policy
and hook duration histograms contain 23 samples; all operation gauges return to
zero after the scenarios.

This verifies Postfix's SMTP ingress path, not `non_smtpd_milters`, multiple
milter chains, other Postfix versions, all negotiated flag combinations, or the
core's body replacement API, which the HTTP adapter does not expose.
SMTP STARTTLS uses the container's test certificate; scanner HTTP is deliberately
plaintext loopback via `--insecure-loopback`. Production HTTPS trust validation,
certificate rollover and remote scanner behavior are not covered by this suite.
Separate Rust transport tests use ephemeral certificates for custom-CA and mTLS
success/failure cases, including a hostname-mismatch negative control. They also
cover proxy selection, Basic authentication, pooling, gzip limits and JSON log
correlation; these are local fixtures, not production deployment evidence.

## Reproduce on this Mac

Use the dedicated profile; these commands do not switch the active Docker context:

```sh
colima start mta-hooks-interop --activate=false --cpu 2 --memory 4 --disk 20 \
  --mount none --ssh-config=false --ssh-agent=false

# Run from the root of your mta-hooks-milter checkout.
docker --context colima-mta-hooks-interop build \
  -t mta-hooks-postfix-interop:local -f interop/Dockerfile .

docker --context colima-mta-hooks-interop run --rm --network none \
  mta-hooks-postfix-interop:local
docker --context colima-mta-hooks-interop run --rm --network none \
  -e MILTER_TRANSPORT=unix mta-hooks-postfix-interop:local

# All five inbound stages; add MILTER_TRANSPORT=unix for the Unix socket run.
docker --context colima-mta-hooks-interop run --rm --network none \
  -e HOOK_STAGES=all mta-hooks-postfix-interop:local

colima stop mta-hooks-interop
```

Building downloads official Rust/Debian images and distribution packages. Running
has **no external network, host mounts or published ports**. Postfix, the bridge,
the SMTP client and the scanner all communicate inside one disposable container.
Mail delivery is explicitly deferred; all addresses/messages are synthetic.
The `--rm` commands remove only those test containers and their synthetic queues.
The harness refuses to run directly on the host. Unix socket ownership/permissions
are set to the container's Postfix group (0660); the daemon does not change them.

The base image digests observed during this run were:

- `rust:1.90-bookworm`: `sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f`
- `debian:bookworm-slim`: `sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171`

The Dockerfile retains readable image tags; future rebuilds can pick up package
updates. Test output always records the actual Postfix version. Locally captured
raw baseline logs are in `results/postfix-tcp.log` and `results/postfix-unix.log`;
the idle-fix runs are in `results/postfix-idle-tcp.log` and
`results/postfix-idle-unix.log` (ignored by Git). The executable assertions in
`postfix_test.py` are the portable evidence. Each run includes a 65-second wait.
Captured logs are local evidence only and are excluded from the published crate.

## Independent scanner search

No usable draft-01 scanner was found in the searches performed for this test.
This is a bounded finding, not proof that none exists. The public candidates
inspected use the older Stalwart request/response shape:

- [enaut/stalwart-mta-hook-types, revision b5d6f91](https://github.com/enaut/stalwart-mta-hook-types/blob/b5d6f91e96e9a30e3c190bde09f48e7f555d4554/src/request.rs)
  requires `context.stage` and `message.contents`, unlike draft-01's top-level
  stage and raw-message representation.
- [Har-Kuun/mail-summarizer-stalwart, revision 22cf274](https://github.com/Har-Kuun/mail-summarizer-stalwart/blob/22cf2740eb3fd6db4195542ee5308f8312d3d634/auto-summary-stalwart.php)
  returns `action` and typed `modifications`, not the draft-01 operation object.
  Its external AI integration was not executed.
- [DACHXY/mail-ntfy-server](https://github.com/DACHXY/mail-ntfy-server/blob/main/src/model.py)
  also expects a `context` object and `message.contents`. It was not executed.

GitHub code search for `X-MTA-Hooks-Registration` returned only the specification
repository at the time of inspection. Rspamd's checked-out source had no MTA Hooks
implementation, and the open-PR search found no matching work. The
[Stalwart announcement](https://stalw.art/blog/mta-hooks-ietf/) describes planned
Rspamd scanner-side support, but that is not executable interoperability evidence.

Next independent end-to-end target: native draft-01 scanner endpoints in Rspamd,
then rerun the SMTP/queue assertions against real scanning decisions. That work
was explicitly deferred for this pass; no Rspamd changes or PR were made.

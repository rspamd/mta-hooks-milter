# Postfix interoperability

Verified on 2026-09-05 using Colima/Docker on an Apple Silicon Mac:

- Postfix **3.7.11** (`3.7.11-0+deb12u1`), Debian bookworm, Linux aarch64.
- Rust **1.90**, locked dependencies, the actual `mta-hooks-milter` executable.
- Two full runs: **24 checks over TCP and 24 over Unix sockets**, both exit 0.
- No Rust implementation changes were needed to pass these tests.
- HTTP scanner: a controlled Python standard-library draft-01 fixture written
  for this suite, not an independent third-party scanner. It has no external
  service dependencies and never forwards messages elsewhere.

## What was verified

Each transport run submits 22 message scenarios through real SMTP. Assertions
inspect both the received hook JSON/raw content and Postfix queue records:

| Case | Required result |
| --- | --- |
| Normal acceptance and header addition | SMTP 250; added header exists in the queue |
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
| Bridge deliberately stopped | Postfix rejects MAIL temporarily; no silent bypass |

The two additional top-level checks are quarantine's actual hold-queue state
and the absent-bridge negative control. The harness also checks the complete set
of retained queue IDs, so discarded/rejected/error messages cannot silently
remain queued. Every queued message's queue ID must match the ID sent to the
scanner. Both runs reported `milter_messages_total 22`,
`milter_protocol_errors_total 0`, and `milter_policy_errors_total 3` (the three
intentional malformed-response/unavailable/timeout cases).

This verifies Postfix's SMTP ingress path, not `non_smtpd_milters`, multiple
milter chains, other Postfix versions, all negotiated flag combinations, or the
core's body/envelope edit APIs not currently exposed by the HTTP adapter.
SMTP STARTTLS uses the container's test certificate; scanner HTTP is deliberately
plaintext loopback via `--insecure-loopback`. Production HTTPS trust validation,
certificate rollover and remote scanner behavior are not covered by this suite.

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
raw logs are in `results/postfix-tcp.log` and `results/postfix-unix.log` (ignored by
Git); the executable assertions in `postfix_test.py` are the portable evidence.
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

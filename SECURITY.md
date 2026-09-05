# Security policy

## Status

The initial 0.1.0 candidate is experimental. There is no stable supported release
or security-response SLA yet. Security fixes target the latest development code.
Test deployment behavior before putting the daemon in a mail acceptance path.

## Reporting

Use [GitHub's private vulnerability report form](https://github.com/rspamd/mta-hooks-milter/security/advisories/new)
once the public repository has private reporting enabled. Do not post exploit
details, credentials or real mail in public issues. If private reporting is not
available, contact a repository maintainer privately to arrange a secure channel
before sharing details; the release checklist requires enabling that form.

Include the affected version, negotiated milter options, expected and observed
behavior, and a minimal synthetic reproducer where appropriate. Remove real
addresses, tokens, queue contents and other personal data from logs.

## Deployment boundaries

- Bind milter and administrative HTTP listeners to loopback or protected Unix
  sockets. They are unauthenticated and do not provide TLS themselves.
- The scanner receives message content and controls mail outcomes. Use a trusted
  scanner over verified HTTPS; `--insecure-loopback` is for local testing only.
- Prefer `--scanner-token-file` or a Basic password file to command-line secrets
  that may be visible in process listings. `MTA_HOOKS_TOKEN` remains supported.
  Keep credential files, service environments and mutual-TLS private keys private.
- Custom CAs and client identities do not disable certificate/hostname validation.
  Audit proxy settings: environment proxies apply unless explicitly disabled or
  replaced. A proxy also sees plaintext loopback-development credentials/content.
- Align Postfix's timeouts and failure policy with the daemon. Scanner failure
  temporarily rejects mail by default; `--fail-open` explicitly permits bypass.
- Per-connection byte limits are not a global memory budget. Tune concurrency
  and message size together and enforce service-level resource limits.
- The example scanners accept synthetic mail; they are not production policies.

Dependency advisory checks in CI do not substitute for a protocol/security audit.

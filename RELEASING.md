# Maintainer release checklist

Target repository: `rspamd/mta-hooks-milter`. Preparing this checklist does not
create a remote, publish a crate, create a tag, or upload binaries.

## Before making the repository public

1. Confirm the owner/name, public visibility and Apache-2.0 licensing. Preserve
   `NOTICE` and `LICENSE.md` in source distributions.
2. Review every file in the initial commit, not just `git diff` (all files are
   untracked before the initial commit). Exclude local logs, `.env` files, keys,
   build output and editor/agent state. Keep the example token visibly test-only.
3. Make a GPG-signed initial commit and verify its signature. Create the remote
   and push only after the maintainer explicitly authorizes publication.
4. Enable private vulnerability reporting and verify the link in `SECURITY.md`.
   Configure appropriate branch protections/reviews for `main`.
5. Wait for actual GitHub CI on the public repository. Local success is not proof
   that the hosted matrix has passed. No workflow has publication credentials or
   write permission by default.

## Before tagging a release

1. Run all commands in `CONTRIBUTING.md` and both Postfix transports. Inspect
   SMTP outcomes, queue contents and negative controls; do not count a fixture
   as an independent scanner implementation.
2. Install `cargo-audit` 0.22.2 with `cargo install --version 0.22.2 --locked
   cargo-audit`, then run `cargo audit --deny warnings` with a current advisory
   database. Investigate findings; do not add blanket ignores to obtain green CI.
3. Run `python3 scripts/check_package.py` and `cargo package --locked` from a
   clean checkout. Inspect the resulting `.crate` file under `target/package`.
   The package allowlist must not contain `interop/results` or any credentials.
4. Decide whether 0.1.0 is a GitHub-only experimental source release or also a
   crates.io release. Confirm registry ownership/name availability separately;
   metadata alone does not reserve a crate name.
5. Update the changelog from Unreleased to the actual version/date, ensure the
   manifest agrees, and commit/sign the release changes. Create a signed version
   tag only on the tested commit.
6. If publishing to crates.io is explicitly authorized, run
   `cargo publish --locked --dry-run` first, then publish with a scoped maintainer
   credential. Never store that token in this repository or test logs.
7. For any prebuilt binaries, build/test each claimed OS/architecture, include
   license/notice files and checksums, and document runtime dependencies. No
   binary release automation is provided yet.
8. State the draft-01 subset and known interoperability limits in release notes.
   Verify remote tag/release/package state after publication.

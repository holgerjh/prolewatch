# Experimental first public release TODO

Target: the first public, explicitly experimental release. There has been no
public release yet; the current application version is `0.12.0`.

`docs/ai-review.md` and the local-pilot profile work are intentionally excluded
from this checklist while they are being edited separately.

## Do before tagging

- [ ] Finish the concurrent program-code work, then run `make release-check` on
  the exact release candidate.
- [ ] Put that exact candidate on `main` and require green CI for it. Push CI
  currently runs only for `main` and `dev`; do not tag the present feature
  branch merely because an older local run was green.
- [ ] Run the installed-system acceptance gate on a disposable Arch VM:

  ```bash
  make dev-install
  prolewatch doctor --no-probe
  prolewatch setup
  make acceptance-probes
  ```

  Keep the command output as release evidence, including the commit, package
  version, `PASS:` line, report paths, and build-log path. This is the only gate
  that drives a real `yay` transaction through the installed hook and both
  wrappers, and the documentation currently says it has no recorded pass.
- [x] Correct the release history and version language:
  - Before the tag, say: "There is no public release yet. The current tree
    targets `0.12.0` as the first public experimental release."
  - After the tag, say: "`0.12.0` is the first public experimental release."
  - Remove the three `SECURITY.md` claims that `0.11.0` was the first public
    release.
  - Change the present-tense "`0.12.0` ships" in `docs/architecture.md` to
    prerelease/future wording until the release exists.
  - The security assessment date is current. Its release-candidate commit is
    explicitly pending until the concurrent program work is complete.
- [ ] Record the exact release-candidate commit in `SECURITY.md` after the
  concurrent program work is complete and before tagging.
- [x] Replace the hard-coded subordinate-ID range in `CONTRIBUTING.md` with the
  system allocator already documented elsewhere:

  ```bash
  grep -q "^$(id -un):" /etc/subuid ||
    sudo usermod --add-subids -- "$(id -un)"
  ```

  Do not select `100000-165535` manually; it can overlap an existing account.
  The package already requires `shadow >= 4.20`, which provides
  `usermod --add-subids` and allocates both subordinate UID and GID entries.
- [x] Make the GitHub release visibly experimental. Add `--prerelease` and
  preferably `--latest=false` to `gh release create` in
  `.github/workflows/release.yml`.

## Important documentation and release-artifact fixes

- [x] Correct the README outcome table:
  - `BUILD STOPPED` also covers cancellation, killed processes, output limits,
    workspace limits, and timeouts. Raising a `build.*` value is not always the
    remedy.
  - `BUILD FAILED` means the contained process exited non-zero. Do not assert
    that this proves a packaging defect.
- [x] Change "Nine deterministic scenarios" to ten in
  `docs/reviewing-prolewatch.md`.
- [x] Fix "Prelease" to "Prerelease" in `README.md`.
- [x] Replace "Every commit passes a release gate" with a claim scoped to the
  release candidate, such as "Every release candidate must pass...".
- [x] Name the prerequisites for the source-checkout installation. At minimum,
  users need `base-devel`, Git, and Go before `make dev-install` can be the
  advertised one-step command.
- [x] Decide what the custom GitHub release tarballs support. They contain the
  binaries, documentation, and `share/`, but no `Makefile`, packaging scripts,
  or installer; the bundled README's `make dev-install` instructions therefore
  cannot be followed from those tarballs. Either document a supported binary
  installation procedure or do not present them as installable distributions.
  They are now documented as verification artifacts, not installable
  distributions.
- [x] Resolve the architecture promise. The release workflow publishes arm64
  binaries, while the Arch package and acceptance instructions are x86-64-only.
  Either label arm64 explicitly untested/experimental or publish amd64 only for
  the first release. The first release now publishes amd64 only.
- [x] Write short, curated release notes stating:
  - this is the first public release;
  - it is experimental and independently unaudited;
  - it is not on the AUR and has no maintainer-signed source path;
  - installation is currently from a reviewed checkout on Arch Linux; and
  - which CPU architecture and installation artifact are actually supported.

## Conditional and deferred work

- [x] Bound Ollama generation and use that cap for context budgeting. Routine
  generation uses 6,144 tokens with reasoning and 4,096 with it off; input
  batching reserves the same cap plus template margin. Adapter policy v5 and
  benchmark schema v3 expose the changed request semantics and invalidate old
  attestations.
- [x] Fix Qwen's invented deterministic-finding guidance before treating the
  local Ollama pilot as release-ready. Live diagnosis with `qwen3:14b` confirmed
  the same failure in `remote-execution`, `cross-file-persistence`, and
  `privileged-writable-deserialization`: every request had
  `guidance_target_count: 0`, but the model returned one guidance item with a
  non-64-character finding ID. The actual verdict was `block` in all three
  cases, so the configured 40,960-token context is not the cause. Reproduce with:

  ```bash
  prolewatch doctor --diagnose-llm-quality-case remote-execution
  prolewatch doctor --diagnose-llm-quality-case cross-file-persistence
  prolewatch doctor --diagnose-llm-quality-case privileged-writable-deserialization
  ```

  Decide whether the schema can conditionally forbid guidance without targets
  or whether the prompt/model profile needs tightening; do not weaken guidance
  ID binding or silently accept invented IDs. The Ollama adapter now specializes
  each request schema to the exact guidance count and allowed finding IDs;
  empty target sets have `maxItems: 0` and an exact empty-array enum, and the
  independent binding checks remain in place.
- [x] Re-run the live Qwen quality corpus against the release candidate. The
  attest-free benchmark passed all seven cases under the 6,144-token Thinking
  cap, including the three earlier guidance/source-binding failures, with no
  source-binding warnings; the largest case reported 357 visible-answer tokens.
- [ ] Leave the signed AUR path, maintainer fingerprint ceremony, archive-parser
  differential corpus, representative real-package corpus, and independent
  audit as explicitly disclosed follow-up work. They do not need to block this
  clearly experimental, unsigned, off-AUR release.

## Repository hygiene

- [x] Do not add the historical untracked review and plan documents wholesale.
  Several contain stale `0.11.0` and nine-scenario statements. They do not enter
  current release archives while untracked, but `git add .` would change that.
- [x] Re-run the local Markdown link/anchor check after editing. All 86 checked
  local links and anchors across 13 Markdown files resolved on 2026-09-10.

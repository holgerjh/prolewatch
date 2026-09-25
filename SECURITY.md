# Security Policy

Prolewatch is experimental security software and has not received an
independent security audit. It was written with AI assistance and its
maintainer has not yet read all of it line by line; see
[Development and testing](README.md#development-and-testing). Reports that could affect its inspection,
containment, privilege, artifact-integrity, or fail-closed guarantees are
especially important.

## Supported versions

The current tree targets `0.12.2` as the first public experimental release for
x86-64 Arch Linux. AUR publication is pending its signed-source acceptance run.
Security fixes are made against the current default branch; older checkouts may
no longer match the documented security boundary, though reports remain useful
when the behavior also reproduces on current code.

## Release distribution and verification

**AUR publication is pending.** Until the package page is live, install from a
reviewed checkout using the development path in
[Installation](README.md#installation). Its local package signature
authenticates the artifact to `pacman`; it says nothing about the source's
origin or safety.

### Signed AUR source path

The `0.12.2` release will publish `prolewatch-0.12.2.tar.gz`, its detached
`.sig`, and `prolewatch-release-key.asc` on the `v0.12.2` GitHub prerelease.
The source archive is deterministic and includes vendored Go dependencies. The
AUR recipe fetches those exact assets, checks the archive SHA-256, and pins the
signing key through `validpgpkeys`.

The full 40-character maintainer fingerprint is:

```text
296E983E7120909958BD38E557F1F87148E02B27
```

Once published, download the public key from the release, display its
fingerprint, compare it with this document through a separate path, and import
it into the normal build user's keyring:

```bash
curl --fail --location --remote-name \
  https://github.com/holgerjh/prolewatch/releases/download/v0.12.2/prolewatch-release-key.asc
gpg --show-keys --with-fingerprint prolewatch-release-key.asc
gpg --import prolewatch-release-key.asc
```

`makepkg` verifies the signature before running any of the recipe's build
steps, and the build then compiles only what is inside the verified archive:
`-mod=vendor` with `GOPROXY=off` means no dependency is fetched while building.
Installation never edits the pacman keyring or `LocalFileSigLevel`. Once
`validpgpkeys` names a fingerprint, stock `makepkg` accepts a signature from
that fingerprint independently of local GPG ownertrust — verified against
`/usr/share/makepkg/integrity/verify_signature.sh` on pacman 7.1.0, where the
ownertrust branch applies only when `validpgpkeys` is empty. Importing the key
would therefore not be the trust decision, and `gpg --lsign-key` would not be
required; comparing the fingerprint against an independently obtained copy
would be. Even then it would establish only that the archive is the one that
fingerprint signed, not that the maintainer is trustworthy.

GitHub Actions also publishes Linux amd64 binaries, SBOMs, a binary archive,
checksums, and attestations. Those checksums and attestations cover the
workflow-built artifacts, not the source archive and signature uploaded later
by the maintainer. The AUR source is authenticated through the recipe checksum
and detached GPG signature.

Prolewatch's own installation runs before any Prolewatch control exists. The
release signature authenticates the source for that first build; it does not
contain the build or establish that the source is safe.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/holgerjh/prolewatch/security/advisories/new)
to contact the maintainer privately. If the private reporting form is
unavailable, open a minimal public issue requesting a private contact channel
without including vulnerability details.

Include, when available:

- the affected version or commit;
- the required privileges and trust boundary;
- a minimal reproduction or concrete attack path;
- the expected and observed behavior; and
- any suggested mitigation.

Do not include credentials or data from other people. Do not execute a
destructive proof of concept, attempt persistence, or test systems you do not
own or have explicit permission to assess. A reasoned reproduction is welcome
when demonstrating the impact would require unsafe root-side effects.

The maintainer will validate the report, coordinate remediation, and discuss
disclosure through the private advisory. No response or remediation deadline is
currently guaranteed.

## Open findings

- Assessment date: 2026-09-10
- Release-candidate commit: pending selection after the concurrent release work
- Applies to: the tree targeting `0.12.2` as the first public experimental release

Prolewatch installs no privileged component: no daemon, socket, service
account, `sudoers` entry, or setuid binary.

Configuration compatibility starts with the first public release. The current
`0.12.2` prerelease tree intentionally carries no migration parser or legacy
hook namespace; an obsolete local configuration fails strict validation and
should be replaced with the shipped default.

The current residual areas, without operational attack instructions:

- **Containment shares the host kernel.** Bubblewrap is not a virtual machine.
  A kernel or `bubblewrap` defect defeats every claim in the threat model.
- **The yay hook is user-owned and user-removable.** Anything running as the
  invoking user once can delete it, after which every `yay -S` runs unprotected
  with no signal. This is inherent to hooking a third-party tool's extension
  point, and it is stated rather than mitigated.
- **Hook health is not verified through a real `yay` transaction.** `setup`
  checks the installed bytes, supported version range, and yay's effective
  `makepkg`/GPG wrapper paths. A disposable end-to-end `yay -B` transaction is
  still required as release evidence for the full interception path.
- **Prolewatch bootstraps without containment.** Its own package is built and
  installed before any Prolewatch control exists. The release signature
  authenticates its source, but the first build itself runs outside Prolewatch.
- **Detection is fallible in both directions**, which is why it no longer
  decides. Recognised patterns describe; only structurally decidable properties
  block.
- **Installation remains privileged by design.** A package the user chooses to
  install can do anything an Arch package can do. The privileged-integration
  gate narrows this; it does not close it.
- **Workspace byte and file limits are monitored, not hard quotas.** During
  `makepkg`'s execute-only `pkg/` interval, recursive accounting cannot observe
  growth below that directory; the filesystem reserve remains the backstop.
- **Signed distribution is pending publication.** The signed source tooling and
  fingerprint-pinned AUR recipe are implemented and tested. The private key
  backup, signed archive acceptance run, and AUR push remain release work.
- Real multi-package `yay` transactions, upgrade interruption, disk-full and
  rollback behaviour still need testing on a disposable Arch host.
- Archive-parser fuzzing and independent review remain open.

Maximum impact is compromise of the invoking user's account if containment
fails. Full root compromise can also follow the user's install decision or the
later activation of package integration installed with root privileges, as well
as a failure in `pacman`, `sudo`, the kernel, or signed Arch repositories.
Prolewatch adds no privileged interface of its own that could be the origin.

Reports that show a build escaping containment, a prompt being forged by
package-controlled output, an approval crossing a structural finding, or a
root-execution surface reaching an install unenumerated are the most valuable.

# Security Policy

Prolewatch is experimental security software and has not received an
independent security audit. It was written with AI assistance and its
maintainer has not yet read all of it line by line; what that does and does not
mean is set out in [How this was built](README.md#how-this-was-built). Reports that could affect its inspection,
containment, privilege, artifact-integrity, or fail-closed guarantees are
especially important.

## Supported versions

There is no public release yet. The current tree targets `0.12.0` as the first
public experimental release. Security fixes are made against the current
default branch; older checkouts may no longer match the documented security
boundary, though reports remain useful when the behavior also reproduces on
current code.

## How this release is distributed, and where the trust decision is

**This release is not on the AUR and carries no maintainer signature.** It is
installed by building the package from a checkout, signed with a key the
installing user generates themselves (see
[Installation](README.md#installation)). That local signature authenticates the
built artifact to `pacman`. It says nothing about the source it was built from.

So for this release the trust decision is the one the user makes about the
checkout: review the source, or confine it to a disposable Arch system. There
is no cryptographic step that can substitute for that, and this document will
not pretend otherwise. The signature check against the development key home and
the installed-file allow-list check what was built; they cannot check what it
was built from.

### The signed path exists but is deliberately unpublished

The machinery for a signed release is implemented and tested, and is being held
back rather than shipped half-finished. When a signed release is made, this
section will carry the full 40-character maintainer fingerprint — a short key
id identifies a key ambiguously and is deliberately not used — and
`packaging/arch/PKGBUILD.in` will carry the same value in `validpgpkeys`. The
release artifacts are `prolewatch-<version>.tar.gz` and its detached `.sig`,
attached to the `v<version>` GitHub release; `scripts/source-archive.sh` builds
the archive deterministically and vendored, so the same tree yields the same
SHA-256.

What that will buy, and what it will not. `makepkg` verifies the signature
before running any of the recipe's build steps, and the build then compiles only
what is inside the verified archive: `-mod=vendor` with `GOPROXY=off` means no
dependency is fetched while building. Installation never edits the pacman
keyring or `LocalFileSigLevel`. Once `validpgpkeys` names a fingerprint, stock
`makepkg` accepts a signature from that fingerprint independently of local GPG
ownertrust — verified against
`/usr/share/makepkg/integrity/verify_signature.sh` on pacman 7.1.0, where the
ownertrust branch applies only when `validpgpkeys` is empty. Importing the key
would therefore not be the trust decision, and `gpg --lsign-key` would not be
required; comparing the fingerprint against an independently obtained copy
would be. Even then it would establish only that the archive is the one that
fingerprint signed, not that the maintainer is trustworthy.

Prolewatch's own installation runs before any Prolewatch control exists. In a
signed release the signature covers that first build. In this one, nothing
does.

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
- Applies to: the tree targeting `0.12.0` as the first public experimental release

Prolewatch installs no privileged component: no daemon, socket, service
account, `sudoers` entry, or setuid binary. That removes the class of finding
this section used to track, and changes what a serious report looks like.

Configuration compatibility starts with the first public release. The current
`0.12.0` prerelease tree intentionally carries no migration parser or legacy
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
- **Prolewatch bootstraps unprotected.** Its own package is built and installed
  before any Prolewatch control exists, and in this release no maintainer
  signature covers that first build either.
- **Detection is fallible in both directions**, which is why it no longer
  decides. Recognised patterns describe; only structurally decidable properties
  block.
- **Installation remains privileged by design.** A package the user chooses to
  install can do anything an Arch package can do. The privileged-integration
  gate narrows this; it does not close it.
- **Workspace byte and file limits are monitored, not hard quotas.** During
  `makepkg`'s execute-only `pkg/` interval, recursive accounting cannot observe
  growth below that directory; the filesystem reserve remains the backstop.
- **Signed distribution is not part of this release.** The signed source
  archive, the published maintainer fingerprint, and the AUR recipe that pins it
  are implemented and tested but unpublished; a protected signing process
  remains release work. What ships is a package the user builds and signs
  locally, which authenticates the artifact and not its source.
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

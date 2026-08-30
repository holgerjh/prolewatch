# Reviewing Prolewatch

This document hands you what you need to check Prolewatch yourself. It
deliberately contains no verdict. Prolewatch was written with AI assistance
(see [How this was built](../README.md#how-this-was-built)), and a document in
this repository declaring the result of a scan would be the project marking its
own homework — worth less than the checks below, while reading as though it were
worth more.

Everything here is runnable. Where a check proves less than it appears to, that
is stated.

## Start with the part that carries the weight

The codebase is about 20,000 lines of non-test Go. You do not need to read all
of it to judge whether the boundary holds, because most of it cannot break the
boundary. A defect in the scanner or the briefing produces a wrong *description*
of a package. A defect in the files below removes the containment itself.

| Read | Lines | Why |
| --- | --- | --- |
| `internal/contain/userns.go`, `sandbox.go`, `scope.go`, `subid.go` | ~1,160 | The whole containment boundary: the user namespace, the Bubblewrap argument vector, the transient systemd unit that carries the resource limits, and subordinate-ID delegation. If the sandbox is wrong, it is wrong here. |
| `internal/audit/build.go` | ~2,080 | The `makepkg` wrapper. Decides which phase is running, what the sandbox gets, when the network broker is open, and what is rescanned after sources arrive. |
| `internal/audit/gate.go` | ~290 | The privileged-integration gate: enumerating and stripping surfaces that would run with package-manager privileges. |

That is roughly a fifth of the code and it is where the security properties
actually live. `internal/contain` is the smallest and the most load-bearing; if
you read one file, read `userns.go`.

Two questions are worth holding while reading, because they are the ones a test
suite is worst at answering:

- Does a flag do what its name suggests *on this kernel*, or only in the
  argument vector? The probes below exist for exactly this reason.
- Is a check performed on the same bytes that are later used, or on a copy that
  could have changed in between?

## What you can run

None of these require trusting anything in this repository except the code you
are about to read.

```bash
make release-check
```

`go mod verify`, `govulncheck`, race-enabled tests, `go vet`, `bash -n` over the
shell scripts, an import-direction layering check, the privileged-asset
invariant (release invariant 1: no daemon, socket, service account, `sudoers`
entry, or setuid binary ships), the ten deterministic security scenarios, a 72%
coverage floor across every internal package, a deterministic rebuild compared
against a source fingerprint, and SBOM generation.

This proves the tree is internally consistent and free of known-vulnerable
dependencies. It does not prove the design is right, and a test suite written
alongside an implementation shares that implementation's blind spots.

```bash
make scenarios
```

Nine deterministic scenarios drawn from real AUR incident classes, each
asserting a decision and whether an approval could cross it. Read
[`docs/security-scenarios.md`](security-scenarios.md) for what each one claims:
they verify declared synthetic inputs, not an entire attack family.

```bash
make probes
```

The probes are the interesting ones, because they measure behaviour on a real
kernel rather than asserting it. They answer questions like whether `makepkg`
works with host `/usr` read-only, what the joined namespace actually permits,
and what package code runs during source acquisition. Several assert an
*expected failure* — that `install -o root -g root` fails under Bubblewrap's
namespace, for instance — and pass when that failure reproduces. If one starts
reporting the opposite, a tool underneath changed and the architecture needs
re-reading.

`make probes` tolerates a skip and says so. `make acceptance-probes` treats a
skip as a failure, which is the form release acceptance has to use: two probes
exit 0 after printing `SKIP:` when their prerequisites are missing, so a run
can otherwise report success having tested nothing.

Two probes are outside the default run:

- `probe-yay-interception.sh` needs Prolewatch installed on a disposable Arch
  system. **It has no recorded pass.** It is the end-to-end acceptance gate for
  the interception path and is named as an open item in
  [SECURITY.md](../SECURITY.md) and
  [`docs/architecture.md`](architecture.md).
- `probe-redirect-chains.sh` measures live CDN topology and drifts by design.

```bash
make arch-package
make verify-arch-package PACKAGE=/absolute/path/to/prolewatch-dev-*.pkg.tar.zst
```

Checks the built package against an allow-list of installed files, so you can
confirm the package installs what the recipe claims and nothing else.

## If you want to review it with a model

Reasonable, given how it was written — but be clear about what it is. A model
reviewing code written with model assistance is not an independent check; the
blind spots correlate. Treat a clean result as weak evidence and a specific
finding as worth chasing.

Two things make it more useful than "look for malicious code", which is the
wrong question here. The realistic risk in this codebase is not a planted
backdoor; it is a flag that does not mean what it looks like, a check performed
on the wrong bytes, or an ordering mistake.

**Pin a commit**, so a finding can be reproduced and so a later reader knows
what was actually reviewed:

```bash
git rev-parse HEAD
```

**Ask targeted questions** against the files in the table above, one at a time,
rather than asking for a global verdict:

- In `internal/contain/userns.go` and `sandbox.go`: enumerate everything the
  sandboxed process can still reach — mounts, environment, file descriptors,
  sockets, capabilities. Which of those is unintended for code that is assumed
  hostile?
- In `internal/contain/scope.go`: which resource limits are enforced by systemd,
  and which are only monitored? Under what conditions does the difference matter?
- In `internal/audit/build.go`: for each `makepkg` phase, when is the network
  broker open, and is any package-authored code able to run while it is?
- In `internal/audit/build.go`: is every value used to make a decision derived
  from the same bytes that were inspected, or could anything be re-read after
  the check?
- In `internal/audit/gate.go`: what would a root-executed surface have to look
  like to be missed by the enumeration?

Findings that name a file, a line, and a concrete sequence are the useful
output. If you get one, [SECURITY.md](../SECURITY.md) says how to report it
privately.

## What none of this establishes

- **No independent security audit has been done.** Nothing above is one.
- **The maintainer has not yet read the whole codebase line by line.** The
  commitment made in the README is to read the trust boundary named in the
  table above before a signed release.
- **The archive-parser differential is open.** Prolewatch inventories the
  finished `.pkg.tar.zst` with its own Go reader while `pacman` extracts it with
  libarchive, and the two have not been compared against a differential corpus.
- **Field coverage is not representative.** There is no compatibility corpus of
  real AUR packages yet, so prompt rates and false-positive rates on real
  transactions are unmeasured.
- **Containment shares the host kernel.** Bubblewrap is not a virtual machine.
  A kernel or `bubblewrap` defect defeats every claim in the threat model.

[SECURITY.md](../SECURITY.md) carries the full list of residual areas and the
trust boundary in prose. [`docs/architecture.md`](architecture.md) explains why
each control is shaped the way it is, which is the context that makes a review
finding land rather than bounce.

# Reviewing Prolewatch

This guide lists files and checks for reviewing Prolewatch, along with the
limits of each check. For background on its AI-assisted development, see
[Development and testing](../README.md#development-and-testing).

## Security-critical code

The codebase is about 20,000 lines of non-test Go. Start with the files that
implement containment and the installation gate. Defects here can expose the
host to package-controlled code; scanner and briefing defects can mislead the
user's decision.

| Read | Lines | Why |
| --- | --- | --- |
| `internal/contain/userns.go`, `sandbox.go`, `scope.go`, `subid.go` | ~1,160 | The containment boundary: the user namespace, Bubblewrap arguments, the transient systemd unit enforcing resource limits, and subordinate-ID delegation. |
| `internal/audit/build.go` | ~2,080 | The `makepkg` wrapper. Decides which phase is running, what the sandbox gets, when the network broker is open, and what is rescanned after sources arrive. |
| `internal/audit/gate.go` | ~290 | The privileged-integration gate: enumerating and stripping surfaces that would run with package-manager privileges. |

These files make up roughly a fifth of the code. Start with
`internal/contain/userns.go`.

Check these questions while reading:

- Does a flag do what its name suggests *on this kernel*, or only in the
  argument vector? The probes below exist for exactly this reason.
- Is a check performed on the same bytes that are later used, or on a copy that
  could have changed in between?

## Verification commands

Review the relevant code before running these commands.

```bash
make release-check
```

`go mod verify`, `govulncheck`, race-enabled tests, `go vet`, `bash -n` over the
shell scripts, an import-direction layering check, the privileged-asset
invariant (release invariant 1: no daemon, socket, service account, `sudoers`
entry, or setuid binary ships), the ten deterministic security scenarios, a 72%
coverage floor across every internal package, a deterministic rebuild compared
against a source fingerprint, and SBOM generation.

These checks cover consistency and known dependency vulnerabilities. They do
not establish design correctness, and tests can share the implementation's
blind spots.

```bash
make scenarios
```

Ten deterministic scenarios drawn from real AUR incident classes, each
asserting a decision and whether an approval could cross it. Read
[`docs/security-scenarios.md`](security-scenarios.md) for what each one claims:
they verify declared synthetic inputs, not an entire attack family.

```bash
make probes
```

The probes measure behaviour on a real kernel: whether `makepkg`
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

## AI-assisted code review

AI review can miss the same defects as AI-assisted implementation. Verify
specific findings and treat a clean result as weak evidence. Focus on concrete
failure modes: misunderstood flags, checks on the wrong bytes, and ordering
mistakes.

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

## Review limitations

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
trust boundary. [`docs/architecture.md`](architecture.md) explains the controls
and their rationale.

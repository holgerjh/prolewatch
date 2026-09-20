# Probes

Runtime checks for assumptions in `docs/architecture.md`. Each
script is self-contained, re-runnable, needs no privilege, and touches no host
package database.

## Design assumptions under test

Verify claims about tool behaviour with a probe. Earlier design assumptions
that testing disproved include:

| Claim | Reality |
| --- | --- |
| `bwrap` keeps `--disable-userns` after `--userns <fd>` | Mutually exclusive; bwrap rejects it |
| `pkgver()` runs during `makepkg --verifysource` | It does not; top-level `PKGBUILD` code does |
| A `fakeroot` rewrite flattens every owner to root | It does not; ownership round-trips |
| `max_user_namespaces` cannot be clamped from the mapped namespace | It can, from ns-uid 0 |
| `--hookdir` can disable the system hook directory | It only ever adds |
| Mapping uid 0 and the caller is enough for the build namespace | It leaves 65534 unmapped, and `chown` there still returns `EINVAL` |
| The proxy broker can enforce the declared source set as exact URLs | It cannot; HTTPS reaches a proxy as `CONNECT`, which carries host and port only |
| A dotted scratch filename is hidden from the package glob | Go's `filepath.Glob` matches dotfiles; only shell globbing skips them |
| The gate's path list is the single enumeration of root-execution surfaces | A second, wider list already existed and had diverged; both omitted `/etc/pacman.d/hooks` |
| Reading prompts from `/dev/tty` stops package output forging an answer | It stops package bytes becoming input; it does nothing about a keystroke the user typed in response to a fake prompt |

The `CONNECT` assumption survived design review and implementation without a
test of URL enforcement. The surface-enumeration probe also missed omissions:
it generated fixtures from the same incomplete list it tested.

Measure tool behaviour before documenting it as fact. Derive expected coverage
from the platform or an independent implementation, not a copy of the list
under test.

## Running the probes

```bash
for p in scripts/probes/probe-*.sh; do bash "$p"; done
```

All exit 0 when the assumptions they encode still hold. A failing probe is a
finding about the system, not usually a broken script — read the output before
editing the probe.

Several deliberately assert an *expected failure* (for example, that
`install -o root -g root` fails under Bubblewrap's own namespace). Those pass
when the failure reproduces. If one starts reporting the opposite, the
underlying tool changed and the architecture needs re-reading.

| Probe | Answers | CI |
| --- | --- | --- |
| `probe-contained-makepkg.sh` | Does `makepkg` work with host `/usr` read-only and a tmpfs `$HOME`? | yes |
| `probe-namespace-properties.sh` | What does the joined namespace permit, and does the ucount clamp hold? | yes |
| `probe-verifysource-execution.sh` | What package code runs during source acquisition? | yes |
| `probe-integration-gate.sh` | Does the hook placement and a representative four-surface archive rewrite work? | yes |
| `probe-stream-filter.sh` | Does a stream-filtered package verify clean once installed? | yes |
| `probe-integration-surfaces.sh` | Does one fixture per registered path remain enumerable, classified, and strippable? | yes |
| `probe-release-signature.sh` | Does `validpgpkeys` accept exactly the declared fingerprint, without consulting local ownertrust? | yes |
| `probe-yay-interception.sh` | Does an installed hook drive a local `yay -B` transaction with a checksum-bound public source through both configured wrappers and record sandbox enforcement? | **no** |
| `probe-redirect-chains.sh` | What redirect chains do declared-source fetches traverse? | **no** |

`probe-yay-interception.sh` needs an installed Prolewatch on a disposable Arch
system and outbound HTTPS to GitHub for its checksum-bound source.
`probe-redirect-chains.sh` measures live CDN topology and will drift by design.
Run both manually in their stated acceptance environments; do not gate
source-tree CI on them.

## Handling skipped probes

`probe-yay-interception.sh` and `probe-release-signature.sh` print `SKIP:` and
exit 0 when their prerequisites are absent. Source-tree checks tolerate these
skips; release acceptance must reject them.

```bash
make probes             # source tree: skips are tolerated and reported
make acceptance-probes  # acceptance: a skip is a failure
```

`make acceptance-probes` sets `PROLEWATCH_PROBE_STRICT=1`. Run it on the
disposable Arch system where Prolewatch is installed and `prolewatch setup` has
completed, and keep the output: the command, the package and version, the
commit, and the paths of the reports and build log it produced.
`probe-yay-interception.sh` has no recorded acceptance pass yet.

# Reproducible security scenarios

The security scenario suite lets readers inspect harmless fake AUR packages and
run them through Prolewatch's deterministic scanner and policy. It supplements
the Go tests with a public, human-readable acceptance command:

```bash
make scenarios
```

No `PKGBUILD`, install script, downloaded command, native fixture, or archive
member is executed. The runner does not invoke yay, makepkg, a shell, an AI
provider, or a network client. As with any `go run` command, the Go tool may
populate its module or build cache if dependencies are not already available;
the scenario runner itself makes no network requests.

## What `PASS` means

Each `scenario.json` declares the expected deterministic decision, approval
eligibility, coverage state, and a required subset of findings. The runner
scans the package bytes with `audit.NewScanner` and evaluates them with the same
deterministic policy function used by production `deterministic-only` mode.

`PASS` means those declared properties matched. It does not mean:

- the fixture is byte-for-byte historical malware;
- every variation of the technique will be detected;
- an allowed package is safe;
- the AI reviewer would return a particular verdict; or
- the installed yay, sudoers, hook, clean-root, network, build, and artifact
  pipeline was exercised.

AI is intentionally excluded because provider output, credentials, cost, and
availability would make these acceptance results non-reproducible. The
deterministic scan tested here runs before AI in both review modes.

## Scenario map

| Scenario | Technique | Historical or control mapping | Expected result | Claim boundary |
|---|---|---|---|---|
| `baseline-safe` | Control | Benign control package | Allow with no findings | Detects accidental overblocking in the corpus baseline; it is not a general safety proof. |
| `network-warning` | Control | Deterministic-only warning policy | Allow with a visible `unexpected-network-client` warning | Shows that medium findings remain visible and are not silently promoted to malware claims. |
| `aur-2018-remote-pipeline` | [`T01`](aur-threat-model.md#t01) | 2018 `curl \| bash` AUR modifications | Non-approval-eligible hard block | Covers the represented direct pipeline form, not arbitrary downloader obfuscation. |
| `aur-2025-remote-source` | [`T01`](aur-threat-model.md#t01) | Representative remote second-stage delivery related to the 2025 RAT incident | Non-approval-eligible hard block | Uses a synthetic remote-source form; it is not a reconstruction of the recovered package. |
| `aur-2026-install-ecosystem` | [`T02`](aur-threat-model.md#t02) | May 2026 `python-utils` install-script campaign | Non-approval-eligible `shell-ecosystem-install` block | Demonstrates behavioral coverage without treating every historical package name as permanent threat intelligence. |
| `aur-2026-atomic-arch` | [`T02`](aur-threat-model.md#t02) | June 2026 npm and Bun Atomic Arch variants | Non-approval-eligible known-indicator and installer blocks | Covers the embedded names and represented installer forms; renamed or indirect dependencies remain outside this claim. |
| `aur-2026-native-binary` | [`T04`](aur-threat-model.md#t04) | July 2026 reports of committed ELF payloads | Approval-eligible high-severity block | Format recognition cannot establish behavior, so this remains only partially mitigated. |
| `aur-2026-native-sudo` | [`T04`](aur-threat-model.md#t04), [`T06`](aur-threat-model.md#t06) | Reported `openconnect-sso` native `validator` plus `sudo` execution | Non-approval-eligible privilege hard block, plus the binary finding | Covers the explicit native-file and privilege-command combination. |
| `structural-escapes` | [`T07`](aur-threat-model.md#t07) | Archive and filesystem confinement | Non-approval-eligible hard blocks for an escaping symlink and tar member | Demonstrates the represented path escapes, not every parser or kernel vulnerability. |

The incident sources and the broader status assessment are maintained in the
[AUR threat model and incident map](aur-threat-model.md).

## Safety properties

Stored fixture files must be small, regular, and non-executable. Package content
may reference only reserved `.invalid` hostnames. Synthetic inputs that Git
cannot represent clearly are generated in a fresh temporary directory:

- `minimal-elf` is a short, non-executable ELF-identification header with no
  program body;
- `traversal-tar` contains only the text `harmless traversal fixture` under an
  escaping member name; and
- `escaping-symlink` points only to the inert `../outside` target.

The manifest parser rejects unknown fields, path traversal, duplicate generated
paths, unsupported generator types, omitted policy expectations, executable
stored fixtures, real network destinations, and corpus size-limit violations.
Temporary materializations are removed after each scan.

## Running and inspecting cases

Run the whole corpus:

```bash
make scenarios
```

Run a single case:

```bash
go run ./cmd/prolewatch-scenarios --scenario aur-2026-atomic-arch
```

The source package for that example is under
`testdata/security-scenarios/aur-2026-atomic-arch/package/`; its expected result
is in the adjacent `scenario.json`. Additional findings are allowed for attack
fixtures so improved detection does not make them fail merely by finding more.
The benign baseline requires exactly zero findings, preventing new false
positives from being hidden.

## Checking an installed system

After installing the same Prolewatch version as the current checkout and
finishing the normal-user hook setup, run:

```bash
make installed-scenarios
```

Run this command as the normal yay user, never as root. It first requires the
installed `/usr/bin/prolewatch` version to match the checkout exactly, then
runs `prolewatch doctor --no-probe`, and finally evaluates this complete corpus
through the installed binary's `security-scenarios` command. The doctor check
validates the installed files, permissions, yay hook, clean root, sandbox
smoke test, and—when AI mode is configured—the existing provider attestation.
It does not make a live provider request.

The installed scenario command deliberately uses the deterministic scanner and
policy without loading the configured review mode. It writes no reports or
markers, executes no fixture content, and leaves package-manager and Prolewatch
state unchanged. A single case can be selected explicitly:

```bash
go run ./cmd/prolewatch-scenarios --installed --scenario aur-2026-atomic-arch
```

This is an installed acceptance check, not a system E2E test. Its purpose is to
catch an incomplete installation, source/installation version skew, or an
installed scanner that disagrees with the declared corpus.

## Test classification and remaining E2E work

This suite is an unprivileged acceptance/integration test: it exercises actual
inventory, rule, threat-bundle, structural, and deterministic decision code.
It deliberately does not construct a production report with installed-tool
identity, write markers, consume approvals, or invoke privileged components.

A true system E2E suite would require a disposable Arch VM or similarly isolated
host and would cover:

```text
yay -> Lua hook -> pre/post scan -> makepkg wrapper -> clean-root sandbox
    -> artifact inspection and sealing -> yay handoff
```

That future suite should use a benign allow path and blocked fixtures whose
package-controlled code is never reached. It should not run attack simulations
on a developer host. Maintainer compromise, adoption abuse, typosquatting,
runtime-only behavior, compromised upstreams, and AUR availability attacks
remain threat-model statements rather than misleading green non-detection
tests.

## Adding a scenario

Create a lowercase-slug directory with `scenario.json` and `package/`. Keep the
package minimal, use `.invalid` URLs, and declare only stable finding IDs that
directly support the documented claim. Use `exact_rule_ids` only for control
cases where any additional finding should fail the suite. Then run:

```bash
make scenarios
go test ./internal/scenarios
```

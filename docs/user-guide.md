# Prolewatch User Guide

This guide covers installation, configuration, daily operation, updates, and
troubleshooting. For the process and privilege model behind these procedures,
see the [technical architecture](architecture.md).

> [!WARNING]
> Prolewatch is experimental and has not received an independent security
> audit. Install and test it on an isolated Arch Linux system before relying on
> it for routine AUR builds.

## Requirements

Arch Linux is the supported platform.

| Component | Requirement | Purpose |
| --- | --- | --- |
| Go | 1.26.6 or newer | Build Prolewatch from source |
| `yay` | 13.0.1 or newer | Resolve the AUR transaction and invoke the Lua hook |
| Codex CLI | `>=0.146.1`, `<0.147.0` | AI mode with the Codex adapter only |
| Claude Code | `>=2.1.205`, `<3.0.0` | AI mode with the Anthropic adapter only |
| `base-devel` and Git | Current Arch packages | Build toolchain and source checkout |
| `devtools` | Current Arch package | Administrator-controlled clean-root creation with `mkarchroot` |
| Pacman and `pacman-conf` | Current Arch package | Dependency staging and hardened configuration resolution |
| Bubblewrap and a systemd user manager | Current Arch versions | Privileged staging, normal-user build isolation, and resource enforcement |
| libarchive and GnuPG | Current Arch packages | Archive recognition and source-signature verification |
| sudo | Current Arch package | Fixed, no-argument dispatcher boundaries |

`devtools` supplies `mkarchroot`; Pacman supplies both `pacman` and
`pacman-conf`. Deterministic-only mode does not require a provider CLI,
provider account, provider credentials, provider dispatcher, review prompt,
verdict schema, or provider sudoers rule.

## Installation

### 1. Install common dependencies

```bash
sudo pacman -S --needed base-devel devtools go git bubblewrap libarchive gnupg sudo
```

Install `yay` separately if it is not already present. AI mode also requires
one supported provider CLI:

- `openai-codex` for the Codex adapter; or
- a compatible Claude Code release for the Anthropic adapter.

The system installer verifies every required executable. It reports missing
commands together with the Arch package expected to provide them; it does not
install dependencies itself.

### 2. Build as the normal `yay` user

```bash
git clone https://github.com/holgerjh/prolewatch.git
cd prolewatch
go mod verify
make test vet build
```

Do not build or run `yay` as root.

### 3. Choose a review mode

| Mode | Provider required | Behavior |
| --- | --- | --- |
| `ai` | Codex or Anthropic | Deterministic inspection runs first, followed by isolated review of a bounded snapshot when no hard block has already decided the phase |
| `deterministic-only` | No | Uses deterministic inventory, rules, containment, artifact inspection, and sealing without probing or invoking a provider |

Both modes fail closed by default on incomplete deterministic coverage and
structural hard blocks. AI review cannot override a deterministic hard block.
An explicitly enabled unsafe user bypass is documented separately below; it is
not an AI decision and not a claim of safety.

Install the default Codex-backed mode with:

```bash
sudo ./scripts/install-system.sh --review-mode ai --provider codex
```

Install the Anthropic-backed mode with:

```bash
sudo ./scripts/install-system.sh --review-mode ai --provider anthropic
```

Install without a provider with:

```bash
sudo ./scripts/install-system.sh --review-mode deterministic-only
```

Before changing the system, the installer validates:

- built binaries, dependencies, configuration, and account state;
- the required Bubblewrap boundary;
- provider presence and compatibility in AI mode;
- root-managed paths; and
- the exact sudoers rules required by the selected mode.

By default, it then explains the privileged operations and requires typed
confirmation. The first installation creates a root-owned `base-devel`
generation and may download packages from signed Arch repositories.

For reviewed automation, add `-y` or `--assume-yes`:

```bash
sudo ./scripts/install-system.sh --review-mode ai --provider codex --assume-yes
```

This skips only the typed confirmation and permits the installer to run
without an attached terminal. It does not bypass root and caller validation,
dependency checks, the Bubblewrap boundary test, configuration validation,
sudoers validation, or managed-path safety checks. The installation plan and
an explicit confirmation-skipped warning are still printed. Use `-h` or
`--help` to list all installer options.

The default `brand` terminal style uses color only when stdout is a capable
terminal. Redirected output and `TERM=dumb` are plain automatically. Set
`NO_COLOR` to remove ANSI color while keeping glyphs and structural status
markers, or pass `--terminal-style plain` to disable the branded presentation,
glyphs, activation marker, and live status line entirely.

The installer does not authenticate a provider or edit the user's `yay`
configuration.

### 4. Authenticate the locked provider account

Skip this step in deterministic-only mode. Do not copy a normal interactive
provider home into the locked account.

For Codex:

```bash
sudo -u prolewatch env \
  HOME=/var/lib/prolewatch/providers/codex \
  CODEX_HOME=/var/lib/prolewatch/providers/codex \
  /usr/bin/codex login --device-auth

sudo -u prolewatch env \
  HOME=/var/lib/prolewatch/providers/codex \
  CODEX_HOME=/var/lib/prolewatch/providers/codex \
  /usr/bin/codex login status
```

For Claude:

```bash
sudo -u prolewatch env \
  HOME=/var/lib/prolewatch/providers/anthropic \
  CLAUDE_CONFIG_DIR=/var/lib/prolewatch/providers/anthropic \
  /usr/bin/claude auth login

sudo -u prolewatch env \
  HOME=/var/lib/prolewatch/providers/anthropic \
  CLAUDE_CONFIG_DIR=/var/lib/prolewatch/providers/anthropic \
  /usr/bin/claude auth status
```

Credential files must belong to `prolewatch`, and other users must not have
access. Both provider directories belong to the same locked account. Use
separate host accounts if Codex and Anthropic credentials must be isolated from
each other.

### 5. Install the hook and verify the boundary

Run these commands as the normal `yay` user:

```bash
prolewatch install-hook
prolewatch doctor
```

In AI mode, `doctor` performs a real isolated provider request and may consume
a small amount of subscription quota. `prolewatch doctor --no-probe` validates
an existing provider attestation without renewing it. Deterministic-only mode
omits provider, credential, dispatcher, prompt, schema, canary, and attestation
checks.

## Updating an existing installation

A normal update preserves the configured review mode and provider:

```bash
git pull --ff-only
go mod verify
make test vet build
sudo ./scripts/install-system.sh
prolewatch install-hook
prolewatch doctor
```

The installer never changes the existing review mode unless `--review-mode` is
explicitly present. It also does not replace an existing provider selection
merely because `--provider` was passed.

Normal updates reuse the active clean-root generation. Refresh it only when
that system-level change is intended:

```bash
sudo ./scripts/install-system.sh --update-clean-root
prolewatch doctor
```

A new generation changes the policy fingerprint and invalidates old markers
and unused approvals.

## Changing review mode or provider

### Disable AI review

```bash
sudo ./scripts/install-system.sh --review-mode deterministic-only
prolewatch doctor
```

This removes the installed provider dispatcher, review prompt, verdict schema,
and provider sudoers rule. The locked account and credential directories are
preserved for a possible later return to AI mode.

### Re-enable AI review

Use the provider already selected in `/etc/prolewatch/config.json`:

```bash
sudo ./scripts/install-system.sh --review-mode ai
```

If the existing configuration already selects Codex, this explicit form is
also valid:

```bash
sudo ./scripts/install-system.sh \
  --review-mode ai \
  --provider codex
```

`--review-mode ai` performs the mode change. On an existing installation,
`--provider codex` does **not** change the stored provider; `--provider` only
seeds a newly created configuration. This prevents a routine update from
silently switching provider or leaving deterministic-only mode.

The installer reuses the existing clean root, creates the locked account if
needed, installs the provider dispatcher and review assets, restores the
provider sudoers rule, and creates a root-only configuration backup when it
migrates the configuration. It does not install or authenticate the provider.

After enabling AI mode, complete or verify the dedicated provider login and
run:

```bash
prolewatch doctor
```

### Change the provider on an existing installation

Because `--provider` is seed-only, changing an existing provider is an explicit
configuration operation:

1. Create a private backup.

   ```bash
   sudo install -o root -g root -m 0600 \
     /etc/prolewatch/config.json \
     /etc/prolewatch/config.json.provider-backup
   ```

2. Edit the top-level `provider` value with `sudoedit` and select either
   `codex` or `anthropic`.

   ```bash
   sudoedit /etc/prolewatch/config.json
   prolewatch config-check
   ```

3. Install the assets for the configured provider and AI mode.

   ```bash
   sudo ./scripts/install-system.sh --review-mode ai
   ```

4. Authenticate the selected provider as the locked account, then run
   `prolewatch doctor`.

Do not hand-edit the provider command. Provider executables and argument shapes
are compiled adapters; configuration cannot supply an arbitrary command.

## Configuration

The root-owned policy is `/etc/prolewatch/config.json`. Installed defaults live
in `/usr/share/prolewatch/default-config.json`. Unknown keys, unsupported
values, and unsafe combinations are rejected.

```bash
prolewatch config-check
```

| Group | Controls |
| --- | --- |
| `provider` | Active adapter selection |
| `providers` | Model and effort for each compiled adapter |
| `review` | Review mode, minimum AI confidence, timeout, kill grace, and batch limits |
| `limits` | Scanner, archive, text, binary, finding, and time bounds |
| `build` | Resource, workspace, clean-root, cache, and disk limits |
| `network` | Automatic recognized-tool policy plus broker connection, timeout, and transfer limits |
| `sandbox` | Fixed filesystem policy; arbitrary extra host paths are rejected |
| `vendor` | Optional semantic inspection depth for declared upstream sources; `0` by default |
| `overrides` | Administrator-controlled unsafe escape hatch; disabled by default |
| `terminal` | Presentation only: `brand` (default) or `plain`; excluded from the security policy fingerprint |

Use the system installer, not only a manual config edit, when changing review
mode so installed assets and sudoers policy remain synchronized. Run `doctor`
after any security-sensitive policy change.

### Vendor source trust and scan depth

Prolewatch treats the AUR checkout and its local control files as untrusted, but
does not attempt to establish that all code published by an upstream vendor is
benign. The default policy therefore binds declared vendor sources without
semantically scanning their bodies:

```json
"vendor": {
  "scan_depth": 0
}
```

At depth `0`, the post gate records source URL and transport, declared checksum
or VCS binding, the observed SHA-256, and the source-verification receipt. It
does not decompress a declared vendor archive or send its content to the AI
reviewer. A missing fixed binding or mutable VCS reference is reported as a
warning and accepted by default; this is provenance evidence, not proof of
safety.

Set depth `1` to inspect direct vendor files and the first archive layer. Depth
`2` additionally inspects archives nested inside that layer, and higher values
continue in the same way up to `limits.max_archive_depth`. Greater depth costs
more time and can produce upstream-code findings that are unrelated to the AUR
recipe itself. Changing the value invalidates existing policy-bound decisions.

The setting does not apply to AUR-controlled `PKGBUILD`, `.install`, local
patches or scripts, and it does not apply to produced `.pkg.tar.*` files. Those
remain fully scanned at every vendor depth. Build execution is still contained;
explicitly allowlisted dependency-fetch steps may receive the bounded network
broker under the separate policy below, while arbitrary or unknown egress
remains offline.

### Build-network policy

The shipped policy automatically recognizes a narrow set of static recipe
steps and enables bounded public HTTP(S) access only for the `makepkg`
invocation corresponding to the recipe function that contains the step:

```json
"network": {
  "auto_enable_known_tools": true
}
```

The initial allowlist contains exactly `cargo fetch --locked`. The `--locked`
flag makes Cargo reject dependency resolution that would change `Cargo.lock`;
it does not establish that the locked dependencies are benign. A report and
the live terminal identify the exact step and recipe phase that triggered the
policy. A bare executable name is insufficient: `npm`, `pnpm`, `yarn`, `bun`,
`go get`, generic `curl`/`wget`, shell indirection, and unknown commands never
auto-enable egress. This intentionally keeps ecosystem-installer second stages
behind an explicit content-bound lease.

For Cargo recipes, Prolewatch places `CARGO_HOME` below the monitored vendor
`srcdir`. A locked fetch performed during Prepare therefore remains available
to yay's later, separate Build invocation, allowing `cargo build --frozen` to
stay offline without exposing the user's real Cargo cache.

The full report still hashes and binds every cached path. At vendor depth `0`,
the AI payload omits the individual uninspected `src/` manifest entries and
diffs so large locked dependency caches do not crowd out the AUR control files
that the reviewer is meant to assess. The snapshot declares that omission and
provides separate hashes for the complete report manifest and supplied view.

Network isolation is applied per `makepkg` invocation, not per child process.
Once enabled, other package-controlled code in that same invocation can also
reach the bounded broker. The broker permits only public destinations on ports
80 and 443 and applies connection, idle, and transfer limits; it does not prove
that a destination or response is trustworthy. Set
`network.auto_enable_known_tools` to `false` to require an exact one-time lease
for every post-verification build-network request.

### Terminal presentation and live status

With `terminal.style` set to `brand`, a real interactive terminal uses the
dashboard palette and a small inspection vocabulary: `◆` for a security gate,
`•` for status, `└─` for supporting detail, and stamps such as `[ ALLOW ]`,
`[ BLOCK ]`, `[ SEALED ]`, and `[ READY ]`. The first AUR pre-scan prints
`PROLEWATCH ACTIVE` exactly once per `yay` transaction, so the handoff from
`yay` is visible without consuming a banner-sized block.

During scans and AI review, one in-place line displays only measured state:
the current stage and package, files and bytes seen, archive and entry counts,
the current AI batch, and the active deadline. A small rotating Unicode wheel
(or ASCII fallback) shows that the live guard line is active; it is a heartbeat,
not a progress estimate. A silent provider still leaves the current AI batch
and countdown visible. Prolewatch does not infer that an agent is “stuck” and
does not show synthetic percentages; it reports `deadline reached` only when
the configured deadline has actually elapsed. The line is cleared before
reports, prompts, subprocess output, and exit.

During sandbox execution the live line initially names the outer command, such
as `makepkg --nobuild`. Once the child process emits output, its latest non-empty
line replaces that wrapper command as `live …`. Control characters are rendered
inert and the text is length-bounded, so package-controlled output cannot inject
terminal commands or masquerade as a separate Prolewatch result. The complete
bounded child output is still emitted normally when the process finishes.

If an offline sandbox remains active for 15 seconds, a one-time line explains
the applicable policy. A build whose locked dependencies were fetched earlier
is identified as an offline compile that may legitimately take a while. Other
offline builds recommend granting network only after a concrete fetch failure.
Allowlisted recipe steps show their automatic network decision before launch.

To change or remove the presentation without invalidating package markers or
approvals:

```bash
sudo ./scripts/install-system.sh --terminal-style plain
# or restore it:
sudo ./scripts/install-system.sh --terminal-style brand
```

`NO_COLOR` is narrower: it removes color only. Terminals without Unicode use
ASCII markers automatically. JSON, version strings, configuration selector
output, sealed package paths, redirected output, `TERM=dumb`, and internal
dispatcher protocols never receive decoration or ANSI control sequences.

### Decision confidence and interactive control

The AI adapter returns both `verdict` and `confidence`. The root-owned
`review.minimum_confidence` value sets the lowest confidence that may pass
automatically:

| Configured minimum | AI `high` allow | AI `medium` allow | AI `low` allow |
| --- | --- | --- | --- |
| `high` (default) | `ALLOW` | Block; offer one-time `[y/N]` confirmation | Block; offer one-time `[y/N]` confirmation |
| `medium` | `ALLOW` | `AUTO-ALLOW` | Block; offer one-time `[y/N]` confirmation |
| `low` | `ALLOW` | `AUTO-ALLOW` | `AUTO-ALLOW` |

`AUTO-ALLOW` is deliberately not called an approval. No token or reusable
exception is created: the current policy itself accepted a validated AI
`allow` verdict. The terminal report prints the actual AI confidence, the
configured minimum, and an automatic-policy summary. A high-confidence normal
pass remains `ALLOW`.

Set the threshold during installation or migration, then verify it:

```bash
sudo ./scripts/install-system.sh --minimum-confidence medium
prolewatch config-check
```

When `yay` invokes the installed hook on a real terminal, blocked decisions are
handled without terminating the whole transaction when an applicable choice
exists:

| Gate result | Interactive confirmation | Meaning and binding |
| --- | --- | --- |
| AI `allow` below `minimum_confidence`, with no other blocking condition | `y` or default `N` | Exact one-time approval for package, phase, content hash, policy fingerprint, and current transaction |
| Other ordinary approval-eligible block, provider review failure, or non-empty AI coverage notes | Type `OVERRIDE` exactly | Same exact one-time binding; explicitly overrules the displayed decision |
| Hard/structural block, detected prompt injection, scanner failure, or broken provider/archive trust initialization | No prompt by default; type `BYPASS` exactly only if unsafe overrides are enabled | Explicit unsafe continuation; never represented as safe, never network-eligible |

Anything other than the exact requested input declines. With no real TTY,
Prolewatch never waits for input and fails closed. The existing
`prolewatch approve REPORT_ID` command remains available for ordinary eligible
reports outside an active `yay` prompt; it still requires content confirmation
and a reason.

To make the last-resort escape hatch available, an administrator must edit the
root-owned policy:

```json
"overrides": {
  "allow_unsafe": true
}
```

Then validate and reinstall the policy assets:

```bash
sudoedit /etc/prolewatch/config.json
prolewatch config-check
sudo ./scripts/install-system.sh
prolewatch doctor
```

This switch intentionally weakens fail-closed behavior. The installer prints a
warning when it preserves such a configuration, and `doctor` reports
`UNSAFE OVERRIDES ENABLED`. A report produced through this path has disposition
`UNSAFE-BYPASS`, retains a critical bypass finding, and cannot authorize build
network access. If the scanner failed before a content manifest existed, the
bypass can only bind package, phase, policy, and the live transaction; the
report says that its content hash is unavailable.

### Reading findings

Findings are ordered by `critical`, `high`, `medium`, `low`, then `info`.
Within a severity, deterministic findings precede AI findings. Every terminal,
JSON, and dashboard finding carries a visible `source` (`deterministic` or
`ai`), so similarly worded observations do not look like the same authority.

The static `.SRCINFO` consistency check does not execute or source `PKGBUILD`.
It resolves only simple earlier scalar assignments and literal variable
references such as `_pkgver=6.30` followed by
`pkgver="${_pkgver}.1.${_suffix2}"`. Command substitution, arithmetic,
parameter operators, unset variables, and shell control syntax remain
unevaluated. This removes the Canon-style false positive without turning the
metadata check into package-code execution.

## Everyday use

Use `yay` normally:

```bash
yay -S package-name
```

Inspect reports with:

```bash
prolewatch report --latest
prolewatch report REPORT_ID
```

Run a standalone pre-download gate with:

```bash
prolewatch scan \
  --phase pre \
  --dir /path/to/aur/checkout \
  --package-base package-name
```

| Exit code | Meaning |
| --- | --- |
| `0` | Allowed |
| `10` | Blocked by security or policy |
| `20–29` | Validation, scanner, provider, sandbox, artifact, or operational failure; blocked by default |

### One-time finding approvals

Approve an eligible non-structural finding with:

```bash
prolewatch approve REPORT_ID
```

The command displays the package, phase, content identity, policy, and
findings. It requires a real terminal, typed confirmation, and a reason.
Structural hard blocks cannot receive a normal approval. See
[Decision confidence and interactive control](#decision-confidence-and-interactive-control)
for the separately configured unsafe escape hatch.

### One-time build-network leases

Grant network access to a matching build with:

```bash
prolewatch allow-network POST_REPORT_ID
```

The lease is tied to the allowed post-download report and live transaction. It
is consumed by the matching build. A finding approval never grants network
access, a network lease never approves findings, and neither creates a package
allowlist.

With the shipped `network.auto_enable_known_tools: true` setting, the exact
`cargo fetch --locked` shape does not require this manual command. The lease
path remains available for unknown or indirect network requirements, and it is
the only build-network path when automatic detection is disabled.

## Local dashboard

```bash
prolewatch web
```

The foreground server listens only on `127.0.0.1` and chooses an ephemeral port
by default. It prints a URL containing a fresh token in the URL fragment. The
browser stores the token only for that tab session and sends it as a bearer
credential to the local API. Host and remote-address checks protect the
loopback boundary as well.

The dashboard shows:

- the active clean-root identity;
- live scan and build stages without invented percentages, including total and
  current-stage age;
- deterministic scan operation, file, input-byte, archive, and archive-entry
  counters, plus the last progress checkpoint;
- AI provider checks and review batches with their configured deadline;
- validated AI verdicts per batch, including decision, confidence, summary,
  prompt-injection status, and coverage notes (raw provider output is not
  retained or displayed);
- declared vendor-source provenance, configured inspection depth, observed
  hashes, and checksum/PGP verification receipts;
- separate dependency-staging, normal-user sandbox, supervisor, and network
  states; and
- validated report summaries, findings, and sandbox evidence.

Health labels are deliberately conservative. A scan is marked for attention
only when its counters have not advanced for 30 seconds (or half a shorter
configured scan timeout). An AI request is marked as taking longer after 80
percent of its timeout; this is not presented as proof that the model is stuck.
An overdue label means the configured deadline has been reached and timeout
shutdown is in progress. A vanished worker is shown as interrupted, while a
completed timeout or provider/scanner error is shown with a bounded reason and
a report link when a validated report exists.

It remains read-only. It cannot invoke `sudo`, stage dependencies, run `doctor`,
approve findings, grant network leases, cancel builds, update clean roots, or
browse files.

Use `prolewatch web --port PORT` for a fixed loopback port and `Ctrl-C` to stop
the server.

## Clean-root maintenance

Inspect the active generation as the normal user:

```bash
prolewatch clean-root status
```

Create or deliberately update it as an administrator:

```bash
sudo prolewatch clean-root init
sudo prolewatch clean-root update
prolewatch doctor
```

Normal builds copy from the shared generation but never update it implicitly.
`Ctrl-C` and `SIGTERM` trigger bounded cleanup of the current disposable job.
If an older build, crash, `SIGKILL`, or power loss leaves prepared jobs at the
configured concurrency limit, first confirm that no Prolewatch build remains
active, then run:

```bash
sudo prolewatch clean-root prune
```

Type `PRUNE` when prompted. This removes only disposable prepared-root jobs for
the invoking user; it does not remove the shared generation, reports, source
worktrees, sealed artifacts, or the artifact cache.

## State and retention

User state is rooted at
`${XDG_STATE_HOME:-$HOME/.local/state}/prolewatch/`.

| Path | Purpose |
| --- | --- |
| `reports/` | Durable content and policy decisions, findings, manifests, and sandbox evidence |
| `activities/` | Bounded live and completed dashboard progress records |
| `decision-markers/` | Checkout-path- and transaction-bound pre/post decision pointers that survive yay clean-builds |
| `approvals/{pending,used}/` | Exact one-time finding decisions |
| `network-leases/` | Transaction-bound one-time build-network permission |
| `gnupg-public/` | Public-key material used by the dedicated GPG wrapper |
| `sealed/` | Private, read-only exact artifacts returned to `yay` |
| `quarantine/` | Blocked or incompletely handed-off artifacts |
| `provider-attestation.json` | AI-mode provider canary and compatibility attestation |

Finished activities are retained for seven days, with at most 200 records.
Reports have independent retention. Activity records omit disposable root paths
and dispatcher tokens.

System state lives under `/var/lib/prolewatch/`:

| Path | Owner and meaning |
| --- | --- |
| `providers/{codex,anthropic}/` | Locked `prolewatch` account; credentials preserved across mode changes |
| `build-roots/` | Root-owned active identity and base generations |
| `build-jobs/` | Root-owned caller-bound disposable roots |
| `artifact-pool/` | Root-owned, content-addressed but explicitly untrusted AUR dependency cache |

State files are validated on read and written atomically. Sensitive directories
are private.

## Troubleshooting

### Provider authentication failure

Run the selected provider status command as `prolewatch` using the environment
from the login section. Check ownership without printing credential contents:

```bash
sudo stat -c '%U %G %a %n' \
  /var/lib/prolewatch/providers/codex/auth.json

sudo stat -c '%U %G %a %n' \
  /var/lib/prolewatch/providers/anthropic/.credentials.json
```

Only the active provider credential is required. Never include credential
contents in a report or issue.

### Provider version rejection

Unknown provider versions fail closed. Changed CLI feature output can also
invalidate compatibility. Update Prolewatch's adapter and tests before widening
the accepted range; do not bypass the check based only on familiar CLI flags.

### Offline build failure

Inspect the post-download report and build output. The allowlisted
`cargo fetch --locked` shape is enabled automatically under the shipped policy
and is named in the terminal. For unknown or indirect network requirements,
grant a matching
one-time lease only after reviewing that exact report.

### Quarantined artifact

Quarantine means the artifact was not authorized for installation. Address the
report and rebuild. Moving the old file does not recreate its report, marker,
or sealed handoff.

### Dashboard cannot connect

Reopen the exact URL printed by `prolewatch web`; the bearer token lives in the
URL fragment and is removed from the visible URL after the page loads. The
server intentionally rejects `localhost`, non-loopback clients, wrong Host
headers, and requests without the token.

## Uninstalling

For a clean policy reinstall, remove the user hook first, then the system
installation:

```bash
prolewatch uninstall-hook
sudo ./scripts/uninstall-system.sh
```

The system uninstaller removes `/etc/prolewatch/config.json` as well as the
installed binaries, shared assets, dispatchers, and sudoers policy. A following
`sudo ./scripts/install-system.sh ...` therefore starts from the shipped
configuration defaults; an old `mode` or other obsolete config field cannot be
reused accidentally.

Credentials, per-user reports, clean roots, cached artifacts, quarantine, and
backups are preserved for explicit review and recovery. If a genuinely empty
test installation is desired and none of that state is needed, inspect and
remove these two trees after uninstalling:

```text
/var/lib/prolewatch
$HOME/.local/state/prolewatch
```

Deleting the first tree also deletes the dedicated provider login and all
clean-root generations; deleting the second removes the invoking user's
reports, approvals, sealed packages, and quarantine. This state deletion is
intentionally not performed by the uninstall script.

## Security interpretation

- A report describes a bounded decision, not a package reputation score.
- A changed file, policy, root generation, review mode, or provider identity
  requires a new decision.
- Bubblewrap shares the host kernel and is not a virtual machine.
- The final package remains untrusted input to a privileged host package
  transaction.
- If suspicious code may already have executed, a later clean report is not
  evidence that the host is clean.

See the [AUR threat model](aur-threat-model.md) for incident sources and
technique-level claim boundaries, and the [architecture guide](architecture.md)
for the full trusted computing base.

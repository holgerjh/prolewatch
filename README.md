# Prolewatch

<p align="center">
  <img src="docs/images/prolewatch-logo-community-shield.png" alt="Prolewatch" width="620">
</p>

<p align="center">
  <strong>Contain the build. See what runs as root.</strong>
</p>

<p align="center">
  <a href="https://github.com/holgerjh/prolewatch/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/holgerjh/prolewatch/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="go.mod"><img alt="Go 1.26.6 or newer" src="https://img.shields.io/badge/Go-1.26.6%2B-00ADD8?logo=go&amp;logoColor=white"></a>
  <img alt="Status: experimental" src="https://img.shields.io/badge/status-experimental-1793d1">
  <img alt="Platform: Arch Linux" src="https://img.shields.io/badge/platform-Arch%20Linux-1793d1">
  <a href="LICENSE"><img alt="License: AGPL-3.0-only" src="https://img.shields.io/badge/license-AGPL--3.0--only-663399"></a>
</p>

Installing from the AUR runs a stranger's code on your machine twice. First
`makepkg` builds the package, and that build runs as you, with access to
everything you can reach. Then `pacman` installs the result as root.

Prolewatch breaks that in two places. The build gets no home directory and no
network: just the sources the recipe declared, and a prompt if it reaches for
more. The install gets no blank cheque: before `pacman` sees the package you get
its root integration on screen, and the parts that need nobody's help to run
stop and wait for you. Install scriptlets, pacman hooks, udev rules. Keep them,
or strip them out of the archive.

Prolewatch hooks into `yay` instead of replacing it. `yay` still resolves the
transaction, `makepkg` still builds the package, and the final install stays
your own `sudo pacman -U`. Prolewatch itself installs no daemon, socket, service,
service account, `sudoers` entry, or setuid binary. The optional local Ollama
pilot can use a daemon you separately install and operate as part of your local
trusted computing base.

**Prerelease, not released as an AUR package yet**

There is no public release yet. The current tree targets `0.12.0` as the first
public experimental release.

> [!WARNING]
> Prolewatch is experimental and has not been independently audited. It does not
> certify AUR packages as safe. 
> See [How this was built](#how-this-was-built) and, if in doubt, start on an
> isolated Arch Linux system before relying on it.

## See it in action

### A guarded transaction

Prolewatch reviews the recipe, pauses before network contact, and keeps source
acquisition and `makepkg` inside the contained transaction. It ends where its
job ends: at `pacman` asking for your password, because the install itself
stays yours.

<p align="center">
  <a href="docs/images/prolewatch-basic.gif"><img src="docs/images/prolewatch-basic.gif" alt="Animated terminal demo of Prolewatch reviewing catclock-git, prompting before network access, and running makepkg in containment." width="1105"></a>
</p>

<p align="center"><em>Basic guarded transaction</em></p>

### What the package intends to run as root

`gtk2` is about as ordinary as a package gets, and nothing in it is malicious.
It also ships an install scriptlet and a pacman hook, and that hook runs as root
on every pacman transaction you make from then on. You have almost certainly
never seen either one.

Prolewatch prints them before `pacman` receives the archive, with the code they
would run, and lets you keep everything or strip what you did not ask for.

<p align="center">
  <a href="docs/images/prolewatch-root-gate.png"><img src="docs/images/prolewatch-root-gate.png" alt="Prolewatch's privileged-integration gate listing gtk2's install scriptlet and its pacman hook, each with the code it would run as root, above a keep-or-strip menu." width="1105"></a>
</p>

<p align="center"><em>The privileged-integration gate · gtk2 2.24.33-5</em></p>

### Detection, inspection, and AI guidance

AI review is optional and off by default. This is what it adds when you turn it
on. The `moon-buggy` recipe contains several `eval` statements. Prolewatch finds
them without any provider, requires a decision, opens the verified read-only
inspection, and puts bounded AI guidance beside each exact finding.

<p align="center">
  <a href="docs/images/prolewatch-ai-guidance.gif"><img src="docs/images/prolewatch-ai-guidance.gif" alt="Animated terminal demo of Prolewatch detecting eval statements in moon-buggy, opening read-only finding inspection, and showing contextual AI guidance." width="1105"></a>
</p>

<p align="center"><em>Detection and contextual guidance</em></p>

## How it works

Five controls sit between `yay` resolving a transaction and your own
`sudo pacman -U`.

### 1. Containment first

Package-controlled code runs in a user namespace with a temporary home,
enumerated `/etc`, read-only `/usr`, no capabilities, private process and
network namespaces, and hard limits on memory, CPU, tasks, runtime, file size,
and the whole process tree.

Your SSH keys, GnuPG directory, browser profiles etc stay safe outside of the
build's scope.

That is why containment comes first: it does not have to recognise malicious
code to limit what the build can reach.

A dedicated build account gets you part of this, and it is the honest thing to
measure against. But its home persists between builds, so package code can
settle in and wait for the next one, its network and resources stay
unrestricted, and your whole AUR workflow has to move into that account with the
built package coming back out. `yay` stays where it is here.

### 2. Sources arrive before the package can speak

Prolewatch evaluates the `PKGBUILD` inside containment, freezes the source set
it declared, and fetches those sources on the trusted side, before one line of
package-authored shell runs. A recipe that computes a different URL later fails
closed.

The build has no direct egress. When a phase does reach for the network, the
first public HTTP(S) destination stops the build and asks you, in your terminal,
separated from package output. A grant is bound to that transaction and that
destination; a later phase gets a fresh broker and asks again.
Cargo and Go detection adds context to that question and never grants access on
its own.

### 3. Inspection at three points

Prolewatch inventories the AUR checkout, the sources that arrived, and the
finished package, then reports recognised behavior at full severity. Structurally
decidable failures stop outright: archive traversal, escaping symlinks, special
files, content-binding failures.

Vendor content is not scanned semantically by default (`vendor.scan_depth: 0`).
Depth `1` scans direct vendor content, depth `2` opens one nested archive, and so
on. The checkout and the final artifact are always scanned.

Every gate prints a report id, and a gate that stops you offers `[i]` for the
findings above your decision threshold and `[a]` for all of them. To read a
report that did not stop you, or to read one again afterwards:

```bash
prolewatch inspect --latest
prolewatch inspect <report id>
```

That reopens the findings with their source context and any AI guidance, without
approving anything or contacting a provider. `prolewatch report <report id>`
prints the report itself.

### 4. Optional AI guidance

Off by default. `review.mode` is `deterministic-only`, so a stock installation
contacts no provider, sends nothing anywhere, and decides everything locally.

Set it to `ai` and Prolewatch adds a contextual pass after deterministic
inspection. Codex and Anthropic use a provider CLI, your account and quota; the
Ollama pilot uses one exact local model digest through a fixed loopback API, so
package content stays local and no provider account is required. `review.phases`
selects recipe, Sources and artifact gates. When a disabled gate needs a manual
decision, `[r] Run AI review now` offers a one-shot review without enabling
that gate for future packages.

#### Which local models are usable

No model is trusted by default: each one must pass a fixed seven-case safety
corpus bound to its exact digest. A case passes when the model reaches the
correct verdict. It can pass and still be marked, because a finding has to name
the exact dangerous line: a model that blocks correctly but points one line off
sends the inspector to the wrong place. `providers.ollama.reasoning` controls
Thinking and is the single largest latency factor. These are operator
measurements, not an allowlist.

`model`, `context_tokens` and `reasoning` are the three values that change per
model; the rest of the configuration does not depend on which one you pick.

| | `model` | Size | `context_tokens` | `reasoning` | Seven-case corpus | Corpus wall time |
| --- | --- | --- | --- | --- | --- | --- |
| ✅ | `qwen3:14b` | 9.3 GB | 40960 | `off` | 7/7, every finding on the exact line | 50 s |
| ✅ | `qwen2.5-coder:14b` | 9.0 GB | 32768 (its maximum) | `off` | 7/7, but one finding a line off | 47 s |
| ✅ | `qwen2.5-coder:7b` | 4.7 GB | 32768 (its maximum) | `off` | 7/7, but two findings a line off | 36 s |
| ✅ | `qwen3:14b` | 9.3 GB | 40960 | `auto` (Thinking) | 7/7, every finding on the exact line | 101 s |
| ✅ | `gpt-oss:20b` | 13.8 GB | 40960 | `auto` (Thinking) | 7/7, but two findings off the mark | 143 s |
| ❌ | `gpt-oss:20b` | 13.8 GB | 40960 | `low` | 6/7, missed a `curl \| sh` block | 76 s |
| ❌ | `llama3.1:8b` | 4.9 GB | 32768 | `off` | 6/7, invented findings on a benign recipe | 32 s |
| ❌ | `qwen3:8b` | 5.2 GB | 40960 | `off` | 5/7, comments not tied to the quoted line | 39 s |

Start with the shipped `qwen3:14b` example and `reasoning: off`. Thinking doubles the wall time
without winning a single case here. `qwen2.5-coder:7b` is the smallest model
that passed and the only tested option for an 8 GB card, at the price of naming
the wrong line twice where `qwen3:14b` never does. Both qwen2.5-coder models
cap `context_tokens` at 32,768.

With a local model, start with `phases: [artifact]` rather than the shipped
`[sources, artifact]`. The times above are for seven small cases; the Sources
gate is a different scale, projecting 13 to 18 minutes for these models against
an 8 MiB reference. Add `sources` once you have decided that coverage is worth
the wait, and see the gate order below for what each one buys. This is a local
concern: Codex and Anthropic review Sources without that latency.

Measured on an RTX 5080 (16,303 MiB VRAM) with Ollama 0.32.13, one fresh model
load per case. Full table, residency, throughput and recommended settings:
[AI review](docs/ai-review.md#local-pilot-profiles).

The phase choice changes AI coverage, not the deterministic scanner: local
inspection still runs at every gate.

| Configuration value | AI sees | Main benefit | Cost or limitation |
| --- | --- | --- | --- |
| `recipe` | `PKGBUILD`, `.SRCINFO`, install scripts and other AUR recipe files, before source fetch | Small, early review of build/install intent; can stop before downloading anything | Cannot see the fetched upstream implementation, and recipe-specific deterministic rules already cover many common hazards, so routine AI has the smallest marginal benefit here |
| `sources` | Fetched, readable upstream source together with the recipe, before the build | Finds source-level backdoors, unsafe parsing/deserialization and cross-file behavior that may disappear into a compiled binary | Usually the largest input and therefore the slowest local-model phase; generated and final package output does not exist yet |
| `artifact` | The exact built package before `pacman` installs it, including hooks, services, install scripts and shipped readable code | Best single phase for what will actually reach the host and what will later run as root | The contained build has already run, and native binaries can be less explainable than their source |

No phase completely replaces another. Sources preserve the readable
implementation before the build, while the artifact shows which activation
paths and payloads are actually shipped.

If you are paying local latency for AI, enable the gates in this order:

1. **`artifact`, the one that earns its cost.** Containment already bounds what
   the build itself can reach, so what remains is what gets installed and runs
   as root from then on. Only this gate sees that, and a package usually ships
   little readable code, so it is also cheap.
2. **`sources`, the one you buy deliberately.** It is the only gate that
   catches what disappears into a compiled binary, and by far the most
   expensive: the largest and least structured input in the transaction. For
   the models measured above, the provisional 8 MiB reference projects 13 to 18
   minutes, where recipe and artifact take seconds.
3. **`recipe`, the cheapest and the smallest gain.** Deterministic rules are
   written for `PKGBUILD` shapes and are strongest exactly here, so routine AI
   adds the least.

Deterministic inspection runs at all three gates regardless of this setting,
and AI can only turn an allow into a decision, never clear a deterministic
finding. A gate without AI retains deterministic detection, but loses any
additional semantic findings and context the model could have supplied.

For a latency-oriented everyday Ollama setup, start with artifact review only
and keep the model warm across adjacent batches:

```yaml
provider: ollama
providers:
  ollama:
    keep_alive_seconds: 300
review:
  mode: ai
  phases: [artifact]
```

These are the fields to change in the shipped full configuration, not a
replacement file by themselves.

This normally spends one model load per package, on the payload that could
actually be installed. It deliberately gives up the additional semantic review
of fetched upstream Sources; deterministic inspection still runs at every gate,
and the build remains contained. Enable `sources` when that extra coverage is
worth the latency. If deterministic inspection in a disabled gate needs a
decision, use `[r]` at the prompt when the additional AI context is worth the
wait; no provider call runs there automatically.

For stronger routine coverage when the added Sources latency is acceptable,
use:

```yaml
review:
  mode: ai
  phases: [sources, artifact]
```

This is the practical high-coverage profile: readable upstream code and the
final payload are always reviewed, while recipe AI stays off by default because
that phase has the strongest specialized deterministic coverage. Put all three
names in `phases` only when routine AI review before source fetch is also worth
an additional provider call for every package.

When a disabled phase already needs a manual decision and an attested reviewer
is available, its prompt also offers `[r] Run AI review now`. That action
rescans the current bytes, runs AI once, writes a new content-bound report, and
then asks from the refreshed evidence. It does not enable the phase globally.

The fresh-runner cold load before every semantic case belongs only to the
explicit `doctor --probe-llm-quality` diagnostics. Normal `yay` review keeps the
model warm across adjacent batches, unloads it before `makepkg` so VRAM is
available to the build, and unloads it after artifact review. Avoid running the
full quality probe alongside a package build: the shared lock prevents unsafe
concurrent requests, but the diagnostic can add waiting and another cold load.
The shipped `providers.ollama.reasoning` default is `off` for the measured
`qwen3:14b` example. `auto` retains capability-driven Thinking; `low`,
`medium`, and `high` require an exact
quality recheck. Generation is capped at 4,096 tokens with reasoning off and
6,144 otherwise. Input batching reserves that same cap plus a separate template
margin, while `providers.ollama.timeout_seconds` bounds each batch in wall time.
The stored quality evidence uses a narrower semantic fingerprint, so changing
only `review.phases` or build/network policy does not require repeating the
seven model cases. Model/runtime/context/reasoning, prompt/schema, review batch
size, and guidance-threshold changes still do.

The built-in read-only inspector shows each such finding beside a short, clearly
separated AI comment, anchored to the displayed occurrence by an exact quote. A
comment that fails to match is discarded. The provider receives the manifest,
source-verification status, deterministic findings, selected text, and a bounded
context window. It does not receive a mount of the package tree.

AI can turn an allow into a decision. It can never clear a deterministic
finding, and a provider that fails or times out leaves the install proceeding on
deterministic grounds alone. This is contextual review, not runtime monitoring.
Setup, providers, cost and tuning live in [AI review](docs/ai-review.md).

### 5. The root gate

Before installation Prolewatch enumerates every known root-relevant surface in
the finished `.pkg.tar.zst`, and shows all of them. It *stops* only for the ones
that run as root, or grant privilege, with no further step by anyone: install
scriptlets, `libalpm` hooks, udev rules, `sysusers.d`, `tmpfiles.d`, generators,
`sudoers` drop-ins. A systemd unit nobody has enabled, a user-session unit, a
polkit action declaration, a PAM module nothing references: those are printed
and passed.

That line is drawn on purpose. Asking about every ordinary service unit puts the
same unanswerable question on the most common AUR package there is, and the
reflex it trains gets paid back on the `.INSTALL` scriptlet that really does run
as root today.

When the gate opens, keep everything or strip any listed member before `yay`
hands the archive to `pacman`. A package carrying one of those surfaces needs a
terminal, so an unattended install stops there.

Containment limits what the build could reach. The gate shows what the finished
package intends to run as root, which no build sandbox can do for you.

## Installation

> [!IMPORTANT]
> **Experimental release, not on the AUR.** You install Prolewatch by building it
> from a checkout. Nothing here vouches for that checkout on your behalf: there
> is no published maintainer signature for this release, so reviewing the source,
> or confining it to a disposable Arch system, is the trust decision. The
> signed-release path (maintainer key, signed source archive, AUR recipe pinning
> it in `validpgpkeys`) is implemented and tested but deliberately unpublished
> until a signed release; see [SECURITY.md](SECURITY.md).

The supported installation target for the first release is x86-64 Arch Linux,
from a source checkout you have reviewed. The Linux amd64 binaries and archives
attached to the GitHub release are verification artifacts, not installable
distributions: they do not include the `Makefile`, packaging scripts, or an
installer, and copying the binaries alone would omit required policy and shared
files.

Prolewatch installs four unprivileged binaries and its policy file, and no
privileged component at all.

### 1. Build and install the package

The build produces an ordinary Arch package, which you sign with a key you
generate yourself. That signature authenticates *your own build artifact* to
`pacman`. It says nothing about the source it was built from. Install the source
checkout prerequisites first:

```bash
sudo pacman -Syu --needed base-devel git go
```

Run as the normal `yay` user, from an interactive shell:

```bash
make dev-install
```

That is the whole step. It creates the signing key if there is not one, builds
and signs the package, verifies that signature directly against the private
development key home, checks the installed-file allow-list, and gives only the
final `pacman -U` invocation that key home. Re-running reuses the existing key,
so it is also how you rebuild after a change. The default path modifies neither
the system pacman keyring nor `/etc/pacman.conf`.

Stock Arch uses `LocalFileSigLevel = Optional`. That does not make the direct
verification above optional: `dev-install` performs it before installation and
stops on a bad signature. Administrators may still opt into the system-wide
`Required TrustedOnly` policy with `PROLEWATCH_SET_PACMAN_SIGLEVEL=1`; the old
configuration is kept as `/etc/pacman.conf.prolewatch-bak`. Be aware that this
policy rejects unsigned local packages, including normal `makepkg` output, so
ordinary AUR installs fail until it is relaxed again.

Prolewatch's own build is not protected by Prolewatch. It is installed before any
of its controls exist, and for this release no maintainer signature covers that
first build either. Containment begins with the next AUR transaction.

<details>
<summary><strong>Doing it by hand instead</strong></summary>

Reasonable for a security tool, and worth reading once either way.

Create the signing key once. `tty` must print a device path, not
`not a tty`. Use `pinentry-tty` rather than `pinentry-curses`: the curses dialog
needs a minimum terminal size and fails with "Screen or window too small" on a
small window or a serial console.

```bash
dev_key_dir="${XDG_DATA_HOME:-$HOME/.local/share}/prolewatch/dev-signing-gnupg"
install -d -m 0700 "$dev_key_dir"
printf '%s\n' 'pinentry-program /usr/bin/pinentry-tty' \
  > "$dev_key_dir/gpg-agent.conf"
chmod 0600 "$dev_key_dir/gpg-agent.conf"
export GPG_TTY="$(tty)"
gpgconf --homedir "$dev_key_dir" --kill gpg-agent
gpg --homedir "$dev_key_dir" \
  --quick-generate-key "Prolewatch local development package" ed25519 sign 1y
fingerprint="$(gpg --homedir "$dev_key_dir" --with-colons --list-secret-keys \
  | awk -F: '/^fpr:/{print $10; exit}')"
printf '%s\n' "$fingerprint" > "$dev_key_dir/fingerprint"
gpg --homedir "$dev_key_dir" --armor --export "$fingerprint" \
  > "$dev_key_dir/public-key.asc"
```

Then build, verify, and install. Verification uses the development key home
directly and does not depend on pacman's global local-file policy:

```bash
make release-check
make arch-package
make verify-arch-package PACKAGE=/absolute/path/to/prolewatch-dev-VERSION-x86_64.pkg.tar.zst
sudo pacman --gpgdir "$dev_key_dir" -U -- /absolute/path/to/prolewatch-dev-VERSION-x86_64.pkg.tar.zst
```

Use the exact `prolewatch-dev-*.pkg.tar.zst` path printed by `make arch-package`.
`verify-arch-package` verifies the detached signature and checks the built
package against an allow-list of installed files. Installation modifies neither
the pacman keyring nor `LocalFileSigLevel`.
The package provides `prolewatch` and will conflict cleanly with a future release
package.

</details>

### 2. Check the session prerequisites

Contained evaluation and builds run as transient `systemd --user` units. This
user manager is a security prerequisite: it enforces the memory, CPU, task,
runtime, file-size, and whole-process-tree kill limits around package-authored
code.

Run `prolewatch setup` and later `yay` commands from a normal TTY, desktop, or
SSH login created through PAM, then verify the current session:

```bash
printf 'XDG_RUNTIME_DIR=%s\n' "${XDG_RUNTIME_DIR:-<unset>}"
systemctl --user show --property=Version
prolewatch doctor --no-probe
```

Do not fix an absent manager by merely exporting `XDG_RUNTIME_DIR`. The runtime
directory and its user bus must belong to a running manager.

<details>
<summary><strong>If there is no user manager: lingering and headless accounts</strong></summary>

For a dedicated or headless account that cannot keep a login session, enable
lingering explicitly:

```bash
account=$(id -un)
uid=$(id -u)
sudo loginctl enable-linger "$account"
sudo systemctl start "user@${uid}.service"
```

Leave the current shell and start a fresh direct TTY or SSH login before running
`doctor` again; `su` and `sudo -iu` may not create the required PAM session
environment even when lingering is enabled. If a direct login is unavailable,
first confirm that the lingering manager has created a runtime directory and user
bus, then reconnect the current shell to that existing manager:

```bash
uid=$(id -u)
runtime_dir="/run/user/${uid}"

if ! test -O "$runtime_dir" ||
   ! test -S "$runtime_dir/bus" ||
   ! test -O "$runtime_dir/bus"; then
  echo "No live user manager owned by uid ${uid} at ${runtime_dir}" >&2
  exit 1
fi

export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=${runtime_dir}/bus"

systemctl --user show --property=Version
prolewatch doctor --no-probe
```

Run `yay` from this same shell after `doctor` succeeds. These exports only tell
the client how to reach an already running, same-user manager. They do not start
one or make an unowned runtime directory safe. Do not skip the ownership and
socket checks.

Lingering starts the user manager at boot and keeps it, its runtime directory,
user services, and timers available after logout. It grants no root privilege,
but it lets anything already running as that account maintain user-level
persistence and consume resources without an active session. Prefer a normal
login for an everyday account and reserve lingering for a dedicated or headless
one. Disable it when it is no longer needed:

```bash
sudo loginctl disable-linger "$(id -un)"
```

</details>

The sandbox also needs subordinate UID and GID ranges, which existing accounts do
not always have. Only if `setup` or `doctor` reports them missing, let the system
account tools allocate unused ranges:

```bash
sudo usermod --add-subids -- "$(id -un)"
prolewatch doctor
```

Do not choose a numeric range yourself: overlaps let accounts map the same host
IDs, and computing a free range before invoking `sudo` creates a race. The
delegation permits mappings inside user namespaces and grants no host root or
capabilities. `doctor` exercises the real namespace before setup continues.

### 3. Hook it into yay

```bash
prolewatch setup
```

`prolewatch setup` checks the installed files and sandbox before changing `yay`,
then installs and verifies the hook. It changes only `makepkg_bin` and `gpg_bin`;
existing clean, diff, edit, and redownload preferences stay untouched. Its
required resource-envelope probe starts the same kind of transient systemd user
unit a real build uses, so setup fails before changing `yay` when the current
session cannot enforce those limits. Configuration lives at
`/etc/prolewatch/config.yaml` as a pacman backup file. This is a hard cut:
existing `config.json` files are ignored. Edit the YAML file and run
`prolewatch config-check` before relying on the new package.
`prolewatch install-hook` is available when only the lower-level hook step is
wanted.

### If Prolewatch stops a package you want

Most stops have a way through that keeps containment on. Reach for the narrowest
one that fits. There is no global override and no setting that turns enforcement
off; configurations carrying the retired `overrides.allow_unsafe` key are
rejected.

| What you saw | Way through | Build stays contained |
| --- | --- | --- |
| `NEEDS YOUR DECISION` | `prolewatch approve <report id>`, then run the same `yay` command again. The token is one-time and bound to that exact content and policy. | Yes |
| A privileged-integration prompt | `k` keeps every listed surface. Numbers strip only the ones you name. | Yes |
| `BUILD STOPPED` | The build was cancelled or killed, or hit an output, workspace, resource, or runtime limit. Read the preceding error; raise a matching `build.*` value only when that limit caused the stop, then retry. | Yes |
| `BUILD FAILED` | The contained process exited non-zero. Inspect its output, fix the recipe, source, toolchain, or environment issue as appropriate, and retry; this status is not a Prolewatch verdict. | Yes |
| `SANDBOX ERROR` | Containment could not be established. `prolewatch doctor` checks the prerequisites. | — |
| `STRUCTURAL FAILURE` | Nothing. No approval crosses it. The output names what to inspect, rebuild, or report. | — |
| An unsupported input shape | Supported inputs are narrow on purpose: package artifacts must use Arch's default `.pkg.tar.zst`, and declared sources must be fetchable over HTTP(S). `git://` and `git+ssh://` sources are refused instead of being handed broader network or credentials. | — |

#### Building one package without Prolewatch

If you want a specific package that Prolewatch will not build for you, build that
one package without `yay`:

```bash
git clone https://aur.archlinux.org/<package>.git
cd <package>
# Read the PKGBUILD and any .install file before running this.
makepkg -si
```

Prolewatch only redirects `yay`. It installs no pacman hook and does not replace
`/usr/bin/makepkg`, so a manual build runs with **no containment, inspection,
network prompt, or integration gate**: the package's build code runs as your
user, with your `$HOME`, your SSH and GnuPG keys, and your network.

That costs one package and one deliberate act, and every later `yay` build stays
contained. Removing the hook, below, costs every future build until you put it
back.

#### Deliberately removing the yay hook

If a yay or makepkg update produces a command shape this Prolewatch release does
not support, first run `prolewatch doctor` and update or repair Prolewatch. As an
explicit compatibility escape hatch, you can remove only the yay integration:

```bash
prolewatch uninstall-hook
```

This removes Prolewatch's managed block from yay's `init.lua`. The managed
`prolewatch.lua` module is removed only when it still matches the packaged copy;
a modified module and unrelated yay configuration or backups are preserved. It
does not uninstall the Prolewatch package.

Do not use it to bypass a finding or a structural failure. Once the
compatibility problem is resolved, run `prolewatch setup` to recheck the
prerequisites and reinstall the hook.

## How this was built

Prolewatch was written with AI assistance, spanning implementation, tests and
most of this documentation. I know that may seem discouraging for a security
tool, which is why I am disclosing it here. However, I also know I would never
have gotten this far this fast without it. In addition, the benefit that
prolewatch offers is real, and I believe guarding the AUR will only become more
important.

The design went through many iterations and received much improvement and many
targeted corrections by me. The project was also challenged using AI. Three
frontier models (Fable 5, Opus 5 and gpt-5.6-sol) were used adversarially repeatedly
against the codebase and
the threat model, and their findings substantially drove what the design is now.
Every release candidate must pass a release gate: race-enabled tests,
`govulncheck`, an
import-direction layering check, a privileged-asset invariant, ten deterministic
security scenarios, and a coverage floor. The isolation claims are measured on a
real kernel by the probes in `scripts/probes/`.

If you would rather check it than take that on trust,
[Reviewing Prolewatch](docs/reviewing-prolewatch.md) names the files that carry
the weight (about a fifth of the code) and the checks you can run yourself.

## Limits

Prolewatch reduces the reach of untrusted build code and makes known
root-integration surfaces visible. Five things it is not:

- **It stops at `pacman -U`.** Once you install the package, Prolewatch is not
  watching it. Nothing here is runtime monitoring.
- **It is not a virtual machine.** Bubblewrap shares the host kernel. Prolewatch
  trusts the kernel, systemd, Bubblewrap, the local toolchain, `yay`, `makepkg`,
  `pacman`, sudo policy, and the signed Arch repositories.
- **It is not a malware verdict.** Deterministic and AI inspection both miss
  things and both flag benign code. Prolewatch establishes no maintainer,
  source-host, signing-key, or upstream trust.
- **The root-surface enumeration is maintained, not exhaustive.** Software
  already on the host can define another root-executed directory. Prolewatch also
  reads the `.pkg.tar.zst` with its own Go reader while `pacman` extracts it with
  libarchive, and the two have never been compared against a differential corpus.
  The gate is an accurate account of what Prolewatch's reader saw.
- **The hook belongs to your user.** Code that has already run as you can remove
  it, after which later AUR builds run unprotected.

If package-controlled code may already have executed, a later clean report says
nothing about whether the host is clean. Perform normal incident response. The
complete trust boundary, control design, and measured properties are in the
[architecture document](docs/architecture.md).

## Documentation and evidence

The repository contains harmless synthetic security scenarios. `make scenarios`
passes them through the production deterministic scanner and policy without
executing a `PKGBUILD`, install script, downloaded command, native fixture, or
archive member:

```bash
make scenarios
```

A `PASS` means a fixture's declared decision, approval eligibility, findings, and
coverage state all matched. It does not mean every variation of the technique is
detected. The complete table and claim boundaries are in the
[scenario methodology](docs/security-scenarios.md).

After installing the same version as the checkout and completing setup, the
normal `yay` user can run `make installed-scenarios`, which checks the installed
version and hook health and then evaluates the same corpus through the installed
binary, under the same restrictions.

| I want to… | Read |
| --- | --- |
| Understand the design, trust boundary, and implementation details | [Architecture](docs/architecture.md) |
| Turn on AI review and tune it | [AI review](docs/ai-review.md) |
| Check the code yourself | [Reviewing Prolewatch](docs/reviewing-prolewatch.md) |
| See how isolation claims are measured on a real kernel | [Probes](scripts/probes/README.md) |
| Inspect the acceptance corpus and exact scenario claims | [Reproducible security scenarios](docs/security-scenarios.md) |
| Review incident sources, mitigation labels, and residual risk | [AUR threat model and incident map](docs/aur-threat-model.md) |
| Report a vulnerability | [Security policy](SECURITY.md) |
| Contribute or disclose AI-assisted work | [Contributing](CONTRIBUTING.md) |

Blocked or failed archives are retained at
`~/.local/state/prolewatch/quarantine/<report id>/`, and contained `makepkg`
output as a terminal-safe private log at
`~/.local/state/prolewatch/reports/<report id>.makepkg-build.log`. Prolewatch
prints both paths; the logs are pruned with report history.

## Project information

Prolewatch is licensed under [GNU AGPL version 3 only](LICENSE)
(`AGPL-3.0-only`). Commercial use is allowed under its terms. Third-party notices
are collected in [`THIRD_PARTY_NOTICES`](THIRD_PARTY_NOTICES).

Issues, security reports, and design feedback remain welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md).

The name refers to the proles in George Orwell's *1984*: here, the watch belongs
to the users and maintainers who keep Linux and the AUR working, and it is
pointed at the package. Prolewatch is human-directed and human-maintained;
generative AI assistants have been used for implementation, debugging,
documentation, and review, while maintainers decide what is accepted.

Copyright (C) 2026 Holger Heinz.

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

It hooks into `yay` instead of replacing it. `yay` still resolves the
transaction, `makepkg` still builds the package, and the final install stays
your own `sudo pacman -U`. Prolewatch installs no daemon, socket, service,
service account, `sudoers` entry, or setuid binary.

> [!WARNING]
> Prolewatch is experimental and has not been independently audited. It does not
> certify AUR packages as safe. It was written with AI assistance and its
> maintainer has not yet read all of it line by line, see
> [How this was built](#how-this-was-built). Compatibility across a
> representative range of real AUR packages has not been measured. Start on an
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
inspection, and puts bounded AI guidance beside each exact finding. Guidance can
raise a question. It never clears a deterministic finding.

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

### 2. Sources arrive before the package can speak

Prolewatch evaluates the `PKGBUILD` inside containment, freezes the source set
it declared, and fetches those sources on the trusted side, before one line of
package-authored shell runs. A recipe that computes a different URL later fails
closed.

The build has no direct egress. When a phase does reach for the network, the
first public HTTP(S) destination stops the build and asks you, in your terminal,
separated from package output. A later phase gets a fresh broker and asks again.
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

### 4. Optional AI guidance

Off by default. `review.mode` is `deterministic-only`, so a stock installation
contacts no provider, sends nothing anywhere, and decides everything locally.

Set it to `ai` and Prolewatch adds a contextual pass after deterministic
inspection, through a provider CLI and account you configure yourself, on your
own quota. Sources and built artifacts are reviewed every time. A recipe gets a
guidance pass when it produces an approval-eligible finding at your decision
threshold (`HIGH` by default), even when routine recipe review is off.

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

### What the outcomes mean

| Outcome | Meaning |
| --- | --- |
| `NO BLOCKING FINDINGS` | No finding needs a decision. |
| `NO NEW DECISION NEEDED` | The report contains a severe deterministic finding you already approved at the recipe gate; its full file-manifest entry is unchanged in this live transaction, and no new evidence needs an answer. |
| `NEEDS YOUR DECISION` | A severe finding requires review and may be approved. |
| `STRUCTURAL FAILURE - NOT APPROVABLE` | A structural failure stopped the transaction. No approval can cross it. |
| `APPROVED BY YOU` | You approved this exact snapshot once. |

A build that never reaches a verdict is labelled separately, because a broken
recipe and a hostile package are not the same event and should not look alike:

| Outcome | Meaning |
| --- | --- |
| `BUILD FAILED` | The contained build exited non-zero. Usually a defect in the recipe or its upstream, though Prolewatch can only tell you the contained command failed, not that it was the package's own build that failed. |
| `BUILD STOPPED` | Prolewatch's resource envelope ended the build: runtime timeout, output ceiling (`build.output_bytes`), workspace ceiling (`build.workspace_bytes`), a kill, or cancellation. Containment worked as configured. Raise the matching `build.*` limit if the package legitimately needs more. |
| `SANDBOX ERROR` | Containment could not be established. This one is about Prolewatch or the host, not the package. |

When a build fails, contained `makepkg` output is replayed in the order
Prolewatch observed it, so the failure reads in the order it happened instead of
with every error hoisted above its cause. Successful phases print each stream
separately.

Approvals are one-time and bound to the exact content and policy shown. Network
grants are bound to the transaction and the displayed destination. There is no
global override and no setting that turns enforcement off; configurations
carrying the retired `overrides.allow_unsafe` key are rejected. Neither review
mode judges a package safe.

### Why not just run `yay` as a separate user

A dedicated build account is the usual answer, and a real improvement: package
code no longer runs with your SSH keys, GnuPG directory and browser profiles in
reach. It is the honest baseline, so here is what a build still gets once it is
on the other side of it.

| | `yay` as a separate user | Prolewatch |
| --- | --- | --- |
| **Home the build writes to** | The account's own home, persistent between builds, somewhere package code can settle in and wait for the next one | A temporary home discarded with the build, with no host identity files mounted |
| **Network while package code runs** | Unrestricted | Declared sources fetched on the trusted side before the package's shell runs; a later connection pauses the build for a decision |
| **Resources** | Unrestricted | Memory, CPU, task, runtime, file-size, and whole-process-tree limits |
| **What it costs you** | Your AUR workflow moves into that account, and the built package has to come back out | `yay` stays where it is |

## Installation

> [!IMPORTANT]
> **Experimental release, not on the AUR.** You install Prolewatch by building it
> from a checkout. Nothing here vouches for that checkout on your behalf: there
> is no published maintainer signature for this release, so reviewing the source,
> or confining it to a disposable Arch system, is the trust decision. The
> signed-release path (maintainer key, signed source archive, AUR recipe pinning
> it in `validpgpkeys`) is implemented and tested but deliberately unpublished
> until a signed release; see [SECURITY.md](SECURITY.md).

Prolewatch installs four unprivileged binaries and its policy file, and no
privileged component at all.

### 1. Build and install the package

The build produces an ordinary Arch package, which you sign with a key you
generate yourself. That signature authenticates *your own build artifact* to
`pacman`. It says nothing about the source it was built from.

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
`/etc/prolewatch/config.json` as a pacman backup file. `prolewatch install-hook`
is available when only the lower-level hook step is wanted.

### If Prolewatch stops a package you want

Most stops have a way through that keeps containment on. Reach for the narrowest
one that fits.

| What you saw | Way through | Build stays contained |
| --- | --- | --- |
| `NEEDS YOUR DECISION` | `prolewatch approve <report id>`, then run the same `yay` command again. The token is one-time and bound to that exact content and policy. | Yes |
| A privileged-integration prompt | `k` keeps every listed surface. Numbers strip only the ones you name. | Yes |
| `BUILD STOPPED` | Raise the matching `build.*` value in `/etc/prolewatch/config.json`, then build again. | Yes |
| `BUILD FAILED` | A packaging defect, not a verdict. Report it to the AUR maintainer, or repair the recipe with `yay -S <package> --editmenu`. | Yes |
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
frontier models (Fable 5, Opus 5 and gpt-5.6-sol) were used adversarially again
and again against the codebase and
the threat model, and their findings substantially drove what the design is now.
Every commit passes a release gate: race-enabled tests, `govulncheck`, an
import-direction layering check, a privileged-asset invariant, nine deterministic
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

`0.11.0` is the first public release. There are no earlier public versions: the
number is where development arrived, not the eleventh release. There is no
changelog yet for the same reason.

Run the full local release gate with `make release-check`. It checks modules,
vulnerabilities, race behavior, vet, shell scripts, public security scenarios,
and security-code coverage, then builds deterministic Linux binaries and
CycloneDX SBOMs. CI runs the same gate.

Prolewatch is licensed under [GNU AGPL version 3 only](LICENSE)
(`AGPL-3.0-only`). Commercial use is allowed under its terms. Third-party notices
are collected in [`THIRD_PARTY_NOTICES`](THIRD_PARTY_NOTICES). External code
contributions are paused while the licensing arrangement for outside patches is
settled; issues, security reports, and design feedback remain welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md).

The name refers to the proles in George Orwell's *1984*: here, the watch belongs
to the users and maintainers who keep Linux and the AUR working, and it is
pointed at the package. Prolewatch is human-directed and human-maintained;
generative AI assistants have been used for implementation, debugging,
documentation, and review, while maintainers decide what is accepted.

Copyright (C) 2026 Holger Heinz.

# AUR threat model and incident map

Incident research cutoff: **2026-08-16**.

This document describes what Prolewatch can realistically do about attacks
involving the Arch User Repository. It is not a claim that AUR packages can be
made trustworthy by a scanner. AUR packages are user-produced build
instructions, and Arch explicitly expects users to inspect them.

**Containment is the product; detection describes.** That ordering is
deliberate. A regular expression or a shell parser recognises a *shape*, and
shapes can be rewritten — so a control an attacker can rename around does not
earn the strongest label, however useful it is for telling a user what a package
does. Almost every incident below executes at one of exactly two sites,
and each has a control that does not depend on recognising anything:

- **Build-time code running as the invoking user.** Contained: no real home, an
  enumerated `/etc`, no ambient network, host `/usr` read-only, a private PID
  namespace, and resource limits. Recognition is not involved.
- **Privileged integration executed as root by `pacman`** — `.install`
  scriptlets, `libalpm` hooks, systemd units, `sysusers.d`, `tmpfiles.d`, udev
  rules, PAM modules, polkit rules, D-Bus system services. No sandbox can reach
  this: the user's own `sudo pacman -U` runs it by design. The controls are
  showing the user the code and removing the surface from the archive before
  handoff.

Detection still runs, and it is how a user learns what a package will do. It
does not decide.

## Status language

The labels below describe what kind of control exists, not how alarming the
technique is. The distinction that matters is whether a property is **enforced**
or **recognised**.

- 🟢 **Enforced**: a structural control stops this without recognising anything
  about the content. Path traversal, an escaping symlink, an absent network
  route. These survive obfuscation, renaming, and novel encodings, and no
  approval can cross them.
- 🟡 **Described, with containment**: Prolewatch tells the user what the package
  will do and bounds what it can reach while doing it, but the technique itself
  is recognised rather than prevented, and the user decides.
- 🔴 **Not addressed**: Prolewatch provides no meaningful control.

There is no 🟢 anywhere in this document for a control that works by matching
attacker-authored text. If a claim depends on a pattern, it is 🟡 at best.

## What has happened

The incidents below are useful because they show different failure modes. Counts are kept in the language used by the source: a research estimate is not presented as an Arch-confirmed count. Attack technique IDs link each incident to the relevant controls and residual-risk analysis in [Technique coverage](#technique-coverage).

| Date | Reported event | Attack technique IDs | Relevant lesson |
|---|---|---|---|
| 2018-07 | An AUR maintainer account was suspended and a malicious `curl \| bash` commit was reverted; the Arch responder also said two other packages had been modified in the same way. [Arch aur-general archive](https://lists.archlinux.org/pipermail/aur-general/2018-July/034153.html) | [`T01`](#t01), [`T10`](#t10) | A short and visible build-script change can still reach users. Account and package history alone do not make the next revision safe. |
| 2025-07 | Three newly uploaded browser-themed `-bin` packages installed a script from one GitHub repository identified as a RAT. Arch deleted the packages and advised exposed users to treat the systems as potentially compromised. [Arch aur-general advisory](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/7EZTJXLIAQLARQNTMEW2HBWZYE626IFJ/) | [`T01`](#t01), [`T03`](#t03), [`T10`](#t10) | New-package impersonation and remote second stages remain practical. Detecting a suspicious downloader is valuable, but prevention after payload execution is too late. |
| 2025-08 | Arch reported an ongoing denial-of-service attack affecting its main site, AUR, and forums. [Arch news](https://archlinux.org/news/recent-services-outages/) | [`T13`](#t13) | Availability attacks are not package-content attacks. A local package gate does not mitigate AUR service outages. |
| 2026-05 | A coordinated adoption campaign added `npm install python-utils` to install scriptlets; the reported npm package used a `preinstall` entry to launch an ELF payload. Arch responders suspended accounts, reverted affected packages, found additional `crypto-javascript` variants, and removed other previously compromised packages. [Arch aur-general thread](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/MLIJANLZQNLFKK5Q2QVNJPWP2DM6KK6M/) | [`T02`](#t02), [`T05`](#t05), [`T10`](#t10) | The package-manager-in-install-script pattern preceded Atomic Arch and was not tied to one dependency name. Behavioral rules matter more than a permanent name list. |
| 2026-06 | Arch reported a high volume of malicious package adoptions and updates and temporarily constrained account creation, pushes, adoption, and creation while investigating. [Arch incident notice](https://archlinux.org/news/active-aur-malicious-packages-incident/) | [`T10`](#t10) | The AUR orphan/adoption workflow and trusted-looking existing package names can be abused at scale. Local analysis cannot prove that a new maintainer is legitimate. |
| 2026-06 | Sonatype described the “Atomic Arch” campaign: adopted/orphaned packages were changed to install malicious npm dependencies. The first wave used `atomic-lockfile`; a second wave used `js-digest` and `lockfile-js`, with npm and Bun variants. Its approximately 1,500-package figure was explicitly preliminary and subject to change. [Sonatype research](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency) | [`T02`](#t02), [`T05`](#t05), [`T10`](#t10) | The malicious payload need not be present in the AUR Git tree. An apparently small ecosystem-install command can fetch and execute a native second stage. |
| 2026-06 | Static reverse engineering of the recovered `atomic-lockfile` payload described an npm `preinstall` hook launching an ELF credential stealer, with persistence, broad developer-secret collection, exfiltration, and optional root-only eBPF capabilities. [Technical payload analysis](https://ioctl.fail/preliminary-analysis-of-aur-malware/) | [`T05`](#t05), [`T08`](#t08) | Blocking the delivery command is stronger than hoping to identify every capability in an opaque payload. Build hosts contain valuable user credentials even when the build itself is not root. |
| 2026-07 | A mailing-list report described “hundreds of potential” malicious AUR updates containing an approximately 50 KiB ELF file. The reporter stressed that not every automated result was verified and listed six manually checked examples. [Arch aur-general report](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/BU6RECTA5DTJBL7Q4NQI5T3AKIN2FWSF/) | [`T04`](#t04) | Directly committed native payloads are an important review boundary, but automated package counts must be treated cautiously. |
| 2026-07 | Reports about `openconnect-sso` described an adopted package receiving a native `validator` binary that the changed build attempted to execute through `sudo`. [Arch aur-general thread](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/PR77K3SB6RFSTYP3KYOJOOX56SMXGBWO/) | [`T04`](#t04), [`T06`](#t06), [`T10`](#t10) | A direct native payload plus an explicit privilege transition is a high-signal combination. Corporate-oriented package names can broaden the likely credential exposure. |

This is a representative incident map, not an exhaustive malware catalogue.
Prolewatch does not embed a static list of affected AUR package names: package
names and ownership change, stale lists create false confidence, and the local
gate has no authoritative reputation feed.

Arch also tightened new-account registration when reopening it after the June response, including mandatory email verification and rejection of disposable email addresses. [Arch aur-general update](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/4JRS73YVTE7JUYHHE3ZDUIHXYHXZ3YQQ/) Those platform controls and Prolewatch's local controls address different layers; neither makes arbitrary AUR content trusted.

## Technique coverage

Technique IDs are stable cross-references used by the executable evidence below.

| ID | Attack technique | Prolewatch control | Status | Important residual risk |
|---|---|---|---|---|
| <a id="t01"></a>**T01** | Visible remote content piped or sourced into a shell | The build runs with **no network route** unless the user brokered a destination, no real home, and host `/usr` read-only, so the fetch fails rather than being recognised. Deterministic rules also describe the pattern in the briefing. | 🟢 **Enforced** for the fetch; 🟡 for identifying it | Containment is not a virtual machine and shares the host kernel. A user who approves the destination at the broker prompt re-enables the fetch. The build can still do anything to its own checkout. |
| <a id="t02"></a>**T02** | Install-time ecosystem package injection and known Atomic Arch indicators | The privileged-integration gate enumerates the `.install` scriptlet, shows the user the code that will run as root, and can strip it from the archive before handoff. The threat bundle and installer rules name the known forms in the briefing. | 🟡 **Described, with containment** | A package cannot hide *that* it carries a scriptlet — that part is structural — but it can obfuscate what the code does, and stripping a scriptlet a package genuinely needs breaks the install. Renamed dependencies and new registries are not covered by a name list. |
| <a id="t03"></a>**T03** | Unknown or obfuscated second-stage downloader | Acquisition is performed by Prolewatch itself over the frozen declared URL set, so the build's own shell runs with zero egress; the build phase defaults to no network and pauses any connection for a TTY decision. | 🟢 **Enforced** for egress; 🔴 for identifying the payload | The user can approve a malicious destination. A payload delivered inside a declared, checksum-matching source arrives regardless. No static rule is a program proof. |
| <a id="t04"></a>**T04** | Native executable present directly in the pre-download package workspace | A recognised ELF, PE, or Mach-O in the inventory produces a high-severity `repository-native-binary` briefing line and blocks pending the user's decision. | 🟡 **Described, with containment** | The scanner does not prove Git provenance, and format metadata does not establish behaviour. A payload can be encoded, generated during build, or delivered inside an upstream source. Legitimate binaries exist. |
| <a id="t05"></a>**T05** | Malicious native payload delivered by an upstream archive or dependency | Source identity and verification are recorded and content-bound; `vendor.scan_depth` can inspect upstream members. Whatever the payload does at build time is contained. | 🟡 **Described, with containment** | Vendor content is accepted without semantic inspection at the default depth. Prolewatch is not a decompiler, antivirus engine, or dependency-reputation service. |
| <a id="t06"></a>**T06** | Explicit package-controlled privilege transition | Build code holds **no capabilities** (`CapEff` is zero) and cannot become namespace-root. A `sudo` call in `build()` is described in the briefing and cannot succeed, for two independent measured reasons: `no_new_privs` is set, so setuid bits are not honoured; and host root is unmapped, so `/usr/bin/sudo` appears owned by `nobody` and its setuid bit would confer nothing even if they were. | 🟢 **Enforced** | This covers the build. It does not cover the install: `pacman` runs scriptlets as root by design, which is T09's problem, not this one. |
| <a id="t07"></a>**T07** | Archive traversal, escaping symlinks, special files, and scan/build replacement races | Path confinement, no-follow opens, type checks, archive traversal checks, before/after `stat` comparison including `ctime`, manifests, hashes, policy fingerprints, and marker revalidation bind decisions to scanned bytes. These are the only findings that remain unapprovable. | 🟢 **Enforced** | Assumes the kernel, filesystem, scanner, and archive parser are not themselves compromised. |
| <a id="t08"></a>**T08** | Credential theft or exfiltration by build code | `$HOME` is a tmpfs — no SSH keys, GnuPG, browser profiles, cloud credentials, or shell startup files. `/etc` is enumerated rather than bound, so `machine-id`, hostname, and the host's pacman configuration are not readable, and `/usr/lib/modules` is masked so the exact kernel version is not either. The package database was never visible. Egress is brokered. | 🟢 **Enforced** for host credentials; 🟡 for the checkout | The package's own checkout and required build inputs remain visible, because the build needs them. The build can still tell roughly what is installed from `/usr` — a fingerprint rather than a capability; closing it properly would need a clean root, which was measured and cut. A user-approved destination, a kernel escape, or data encoded into build outputs remains a risk. |
| <a id="t09"></a>**T09** | Persistence or privileged integration through package output | The gate enumerates every registered root-relevant integration surface the built archive carries from one canonical registry (`internal/brief/surfaces.go`) — scriptlet, the loader preload file, systemd sleep and shutdown hooks, NetworkManager dispatcher directories, both libalpm hook directories including `/etc/pacman.d/hooks`, systemd units and generators, `sysusers.d`, `tmpfiles.d`, udev rules, PAM, sudoers, cron, polkit, D-Bus, sysctl, modules-load, modprobe, binfmt and `profile.d`, across every documented search-path root each service
reads — `/usr/lib`, `/usr/local/lib`, `/etc` and `/run` for systemd units,
generators and drop-ins; `/usr/share`, `/usr/local/share`, `/etc` and `/run` for
polkit — shows bounded bodies for automatic surfaces, lists deferred and passive ones, and offers per-surface removal by rewriting the archive. The transaction is re-bound to the rewritten hash. | 🟡 **Described, with containment** | Installing a package is inherently privileged. The scoped claim is that a package cannot hide *that* it carries registered privileged integration; it can obfuscate what the code does, and a mechanism no registry entry covers is outside the claim entirely — any service on the system may define its own root-executed directory. Stripping a needed surface produces a broken install, so the default is to keep. Host `pacman` and the final `sudo pacman -U` remain trusted. |
| <a id="t10"></a>**T10** | Malicious package adoption, maintainer account compromise, typosquatting, brandjacking, misleading popularity | Transaction context and manifest history make content changes visible. Prolewatch has no identity, ownership, vote, or reputation oracle. | 🔴 **Not addressed** | Users must evaluate maintainer and package provenance, review AUR history, and react to Arch advisories. A familiar name is not a security boundary. |
| <a id="t11"></a>**T11** | Compromised upstream release, VCS repository, registry package, signing key, or mutable URL | Declared sources are frozen from a contained `PKGBUILD` evaluation and fetched by Prolewatch itself; a `PKGBUILD` that computes different URLs at fetch time fails closed with no network to reach them. Observed bytes are recorded and content-bound. | 🟡 **Described, with containment** | A malicious but internally consistent upstream release passes. `SKIP` and VCS sources are not content-pinned at all. Prolewatch does not authenticate source hosts, registries, tags, or maintainer keys. |
| <a id="t12"></a>**T12** | Malicious behaviour that triggers only after installation or at later runtime | The gate surfaces deferred integration points before install. Nothing observes the installed program afterwards. | 🔴 **Not addressed** as a runtime control | Prolewatch is not endpoint detection, a runtime sandbox, a firewall, a service monitor, or an incident-response product. |
| <a id="t13"></a>**T13** | AUR or Arch infrastructure availability attacks | None. | 🔴 **Not addressed** | Use Arch's documented status channels. Local content scanning cannot restore a remote service. |
| <a id="t14"></a>**T14** | Resource-exhaustion package build | A transient `systemd --user` unit hard-bounds memory, CPU, tasks, runtime and per-file size for **every** execution of package-authored code, PKGBUILD evaluation included. Acquisition and scan budgets fail closed; a free-space reserve backs the monitored workspace limits; nested user namespaces are blocked by a ucount clamp the build cannot raise. | 🟡 **Partially enforced** | Workspace byte and inode counts are not filesystem quotas. While `makepkg` makes `pkg/` execute-only, activity below it is invisible to recursive accounting until permissions return; a hostile build can exceed the configured workspace totals during that interval. |
| <a id="t15"></a>**T15** | Kernel, firmware, hardware, official repository, build-toolchain, provider-CLI, or Prolewatch compromise | `doctor` verifies containment end to end — it builds the namespace and checks that capabilities are empty, the clamp holds, and the home is empty — rather than checking that tools are installed. | 🔴 **Not addressed** as an originating threat | These are explicit trust boundaries. Prolewatch cannot use itself to prove the integrity of every component below it. |

## Executable evidence

The repository contains [reproducible, harmless security
scenarios](security-scenarios.md) for the claims that can be meaningfully
tested with inert package content:

| Technique | Incident or represented form | Executable scenario | What it demonstrates |
|---|---|---|---|
| [`T01`](#t01) | 2018 direct remote shell pipeline | [`aur-2018-remote-pipeline`](../testdata/security-scenarios/aur-2018-remote-pipeline/) | The `curl \| bash` form is described at critical severity and blocks pending the user's decision. It is not a hard block, because a shell shape can be rewritten; what stops the fetch is containment. |
| [`T01`](#t01) | Representative 2025 remote second stage | [`aur-2025-remote-source`](../testdata/security-scenarios/aur-2025-remote-source/) | Same contract for the remote-source form. Not a byte-for-byte incident replay. |
| [`T02`](#t02) | May 2026 install-script ecosystem package | [`aur-2026-install-ecosystem`](../testdata/security-scenarios/aur-2026-install-ecosystem/) | Install-time ecosystem invocation is described at critical severity, including an inert `python-utils` example. |
| [`T02`](#t02) | June 2026 Atomic Arch indicators | [`aur-2026-atomic-arch`](../testdata/security-scenarios/aur-2026-atomic-arch/) | Known npm and Bun names match the versioned threat bundle and the generic installer rule. |
| [`T04`](#t04) | July 2026 committed native payload reports | [`aur-2026-native-binary`](../testdata/security-scenarios/aur-2026-native-binary/) | A synthetic ELF header produces an approval-eligible high finding. |
| [`T04`](#t04), [`T06`](#t06) | Reported native `validator` plus `sudo` | [`aur-2026-native-sudo`](../testdata/security-scenarios/aur-2026-native-sudo/) | The native-file finding is combined with a described privilege-command finding. The `sudo` call is prevented by the sandbox, not by the finding. |
| [`T07`](#t07) | Filesystem and archive path escapes | [`structural-escapes`](../testdata/security-scenarios/structural-escapes/) | Escaping symlinks and archive-member names are hard blocks that **no approval can cross** — the only category that still behaves that way. |

Run them with `make scenarios`. A passing scenario verifies the expected result
for those synthetic bytes and current policy; it does not prove coverage of an
entire attack family. Identity abuse, runtime behaviour, upstream compromise,
and availability attacks intentionally have no scenario, because a passing
scenario would imply protection Prolewatch does not provide.

The containment claims are verified separately, because they cannot be
expressed as package content. `scripts/probes/` measures the namespace
construction against a real kernel, and `internal/contain` carries tests that
create real namespaces and run a real `makepkg`.

## AI review

`review.mode` has two values, and in neither of them does the model decide.

- `"ai"` runs the deterministic pass first, then sends bounded selected content
  through the isolated configured CLI provider. Its verdicts and findings enter
  the briefing as context a narrow rule cannot express.
- `"deterministic-only"` performs no provider probe or request. It needs no
  provider account, credential, prompt, or schema.

Two properties hold regardless of mode, and both are enforced in code rather
than described here:

**AI review can only ever tighten a decision.** A verdict of "allow" cannot
clear a deterministic finding. This was not true before the rewrite: in AI mode
the deterministic decision was discarded except for hard blocks, so the model
could clear a critical finding — the model acting as a gate in the permissive
direction. It was invisible while recognition findings were still hard blocks.

**A provider failure never blocks an install.** An outage, a timeout, a
malformed response, a missing credential, a failed identity check, or a missing
attestation produces a briefing with no AI section and a line saying why. In the
attestation case the reviewer is dropped entirely rather than kept with a
warning: attestation is what binds the provider identity and behavior-shaping
inputs, so without it nothing establishes that the verdicts came from the
configured reviewer.

AI review can add contextual judgement across files and may recognise intent
that no narrow rule describes. It is still not a proof of safety, a malware
sandbox, or a substitute for reading the code.

**There is no global break-glass.** `overrides.allow_unsafe` and every
mechanism it gated are deleted, and a configuration file that still sets it is
rejected rather than silently ignored. The only bypass is the content-bound,
one-time, exact-snapshot approval, and it cannot cross a structural finding. A
switch that could cross one was what let this document's mitigation claims be
true on paper and false in use.

Changing mode changes the policy fingerprint, so old markers and approvals
cannot silently authorise the new policy.

## Operational interpretation

For a meaningful result, all of these assumptions must hold:

1. The documented yay hook is the path used for the AUR transaction. It is
   user-owned and user-removable; anything running as the user can delete it,
   and every subsequent `yay -S` then runs unprotected with no signal.
2. The account has a subordinate ID delegation. Without it the build namespace
   cannot map uid 0 and builds fail; `prolewatch doctor` reports this with the
   remedy.
3. The current package inputs are the inputs Prolewatch inventories, and
   structural coverage failures are not worked around.
4. Users do not treat an approval, a network grant, or a decision to keep a
   privileged-integration surface as a general "trust this package" switch.
   Approvals are exact and one-time; a network grant covers one destination in
   the current makepkg phase and is not reused by a later wrapper phase.
5. A blocked or suspicious package is investigated before any code from it runs
   outside the protected path.

Prolewatch itself bootstraps unprotected: its own package is built and
installed before any Prolewatch control exists.

If a payload may already have executed, a later clean report is not evidence
that the host is clean. Follow the relevant incident guidance, rotate exposed
credentials from a known-clean system, and perform normal incident response.

## Source notes

- Arch incident and mailing-list posts are primary sources for Arch actions and
  what reporters observed.
- The Atomic Arch package count and campaign linkage are attributed to Sonatype
  and described as preliminary where the source does so.
- The payload capability description is static-analysis evidence. It supports a
  realistic threat model but does not establish that every affected package
  successfully executed every capability.
- The incident review was current on 2026-08-16. New AUR incidents and variants
  after that date are not represented automatically.

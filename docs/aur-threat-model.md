# AUR threat model and incident map

Research cutoff: **2026-08-16**

This document describes what Prolewatch can realistically do about attacks involving the Arch User Repository (AUR). It is not a claim that AUR packages can be made trustworthy by a scanner. AUR packages are user-produced build instructions, and Arch explicitly expects users to inspect them. Prolewatch adds deterministic inspection, content binding, constrained execution, output inspection, and—when enabled—an isolated AI review. None of those controls establishes package authorship or upstream trust.

## Status language

- 🟢 **Mitigated**: the relevant Prolewatch control is designed to stop this technique before the protected install completes, assuming the documented hook and system installation are intact.
- 🟡 **Partially mitigated**: Prolewatch reduces likelihood or impact, or detects important variants, but realistic evasions or uncovered execution paths remain.
- 🔴 **Not mitigated**: Prolewatch does not provide a meaningful control for this threat.

These labels describe the technique, not every possible implementation of it. A changed spelling, indirection layer, opaque binary, interpreter trick, compromised dependency, or vulnerability in a trusted tool can change the result.

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

This is a representative incident map, not an exhaustive malware catalogue. Prolewatch deliberately does not embed a static list of affected AUR package names: package names and ownership change, stale lists create false confidence, and the local gate has no authoritative reputation feed.

Arch also tightened new-account registration when reopening it after the June response, including mandatory email verification and rejection of disposable email addresses. [Arch aur-general update](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/4JRS73YVTE7JUYHHE3ZDUIHXYHXZ3YQQ/) Those platform controls and Prolewatch's local controls address different layers; neither makes arbitrary AUR content trusted.

## Technique coverage

Technique IDs are stable cross-references used by the executable evidence below.

| ID | Attack technique | Prolewatch control | Status | Important residual risk |
|---|---|---|---|---|
| <a id="t01"></a>**T01** | Visible remote content piped or sourced into a shell | Deterministic syntax and text rules hard-block recognized pipe-to-shell and remote-source forms in scanned control content. | 🟢 **Mitigated** | Novel interpreters, parser gaps, encoded commands, fetched scripts executed in a separate step, or code hidden in opaque inputs can evade a signature. |
| <a id="t02"></a>**T02** | Install-time ecosystem package injection and known Atomic Arch indicators | The embedded, versioned threat bundle hard-blocks execution-context references to `atomic-lockfile`, `js-digest`, and `lockfile-js`; ecosystem installer use in install scripts is also hard-blocked. | 🟢 **Mitigated** for the documented forms | Renamed packages, another registry, a new install mechanism, or a compromised benign dependency are not covered merely by these names. |
| <a id="t03"></a>**T03** | Unknown or obfuscated second-stage downloader | Decode/execute, network-client, shell-semantic, lifecycle, registry-override, and AI-context checks can expose suspicious composition. Ecosystem installers, arbitrary downloaders, and unknown egress remain offline unless a separate exact one-time lease is granted. | 🟡 **Partially mitigated** | The default policy auto-enables the bounded broker for the exact `cargo fetch --locked` shape, and that permission covers the matching `makepkg` invocation rather than only one child process. Static rules are not a program proof; malicious code in such an invocation may reuse its egress. AI review is fallible and may be manipulated. |
| <a id="t04"></a>**T04** | Native executable present directly in the pre-download package workspace | A recognized ELF, PE, or Mach-O file present in that inventory produces a high-severity `repository-native-binary` finding. Deterministic-only mode blocks it pending an exact one-time approval; AI mode receives its metadata and bounded strings. | 🟡 **Partially mitigated** | The scanner does not prove Git provenance, and format metadata and strings do not establish behavior. A legitimate binary may need approval, while a payload can be encoded, generated during build, or delivered inside an upstream source. |
| <a id="t05"></a>**T05** | Malicious native payload delivered by an upstream archive or dependency | Vendor source identity and verification are recorded; optional `vendor.scan_depth` can inspect upstream members. Build output is always inspected again before sealed handoff. | 🟡 **Partially mitigated** | Vendor content is accepted without semantic inspection at the default depth. Even at greater depth, Prolewatch is not a full decompiler, antivirus engine, or dependency-reputation service. |
| <a id="t06"></a>**T06** | Explicit package-controlled privilege transition | Deterministic shell-semantic rules hard-block recognized privilege commands such as `sudo`; build phases also run as the normal user inside the containment boundary. | 🟢 **Mitigated** for recognized direct commands | Aliases, indirect helpers, parser gaps, or privilege gained through a trusted-component vulnerability remain outside this claim. |
| <a id="t07"></a>**T07** | Archive traversal, escaping symlinks, special files, and scan/build replacement races | Path confinement, no-follow opens, type checks, archive traversal checks, before/after stat checks, manifests, hashes, policy fingerprints, and marker revalidation bind decisions to scanned bytes. Structural failures are not approval-eligible. | 🟢 **Mitigated** | This assumes the kernel, filesystem, scanner, archive parser, and privileged dispatcher are not themselves compromised. |
| <a id="t08"></a>**T08** | Credential theft or exfiltration by build code | Deterministic credential-path rules catch common explicit access. Build execution is a normal user inside a Bubblewrap boundary with a controlled view, private temporary paths, resource limits, and selective network policy. | 🟡 **Partially mitigated** | The allowlisted `cargo fetch --locked` shape receives bounded egress by default for its complete `makepkg` invocation. The deliberately exposed package workspace and allowed build inputs remain visible; kernel escapes, explicit leases, toolchain compromise, or data encoded into outputs remain risks. |
| <a id="t09"></a>**T09** | Persistence or privileged integration through package output | Pre/post scans inspect install scripts and integration surfaces. Artifact inspection flags package metadata and privileged integration paths before the exact archive is sealed for handoff. AUR scriptlets and hooks are disabled during privileged dependency staging. | 🟡 **Partially mitigated** | Installing a package is inherently privileged and can intentionally add services, hooks, users, or configuration. Static classification cannot decide every legitimate-versus-malicious integration. Host pacman and the final authorized package transaction remain trusted boundaries. |
| <a id="t10"></a>**T10** | Malicious package adoption, maintainer account compromise, typosquatting, brandjacking, or misleading popularity | Transaction context and manifest history can make content changes visible, but Prolewatch has no identity, ownership, vote, or reputation oracle. | 🔴 **Not mitigated** | Users must evaluate maintainer and package provenance, review AUR history, and react to Arch advisories. A familiar name is not a security boundary. |
| <a id="t11"></a>**T11** | Compromised upstream release, VCS repository, registry package, signing key, or mutable URL | Source declarations, integrity metadata, verification results, and observed bytes are recorded and content-bound; optional scan depth adds semantic inspection. | 🟡 **Partially mitigated** | Weak provenance warns but is accepted by default, and a malicious but internally consistent upstream release can pass. Prolewatch does not independently authenticate every source host, registry, tag, or maintainer key. |
| <a id="t12"></a>**T12** | Malicious behavior that triggers only after installation or at later runtime | Artifact metadata may reveal some integration points, and findings remain auditable. | 🔴 **Not mitigated** as a runtime control | Prolewatch is not an endpoint detection, runtime sandbox, firewall, service monitor, or incident-response product. |
| <a id="t13"></a>**T13** | AUR or Arch infrastructure DDoS and account-service availability | None. | 🔴 **Not mitigated** | Use Arch's documented status channels and outage workarounds. Local content scanning cannot restore a remote service. |
| <a id="t14"></a>**T14** | Resource-exhaustion package build | systemd and workspace limits bound memory, CPU count, task count, time, output, file count, and disk use; scan and archive budgets fail closed. | 🟡 **Partially mitigated** | A build can still consume its granted budget, stress shared kernel resources, or exploit an enforcement vulnerability. |
| <a id="t15"></a>**T15** | Kernel, root, firmware, hardware, official repository, build-toolchain, provider-CLI, or Prolewatch compromise | Some components are identity-bound, installed root-owned, isolated, and checked by `doctor`. | 🔴 **Not mitigated** as an originating threat | These are explicit trust boundaries. Prolewatch cannot use itself to prove the integrity of every component below or beside it. |

## Executable evidence

The repository contains [reproducible, harmless security
scenarios](security-scenarios.md) for the claims that can be meaningfully tested
with inert package content:

| Technique | Incident or represented form | Executable scenario | What it demonstrates |
|---|---|---|---|
| [`T01`](#t01) | 2018 direct remote shell pipeline | [`aur-2018-remote-pipeline`](../testdata/security-scenarios/aur-2018-remote-pipeline/) | The represented `curl \| bash` form is a deterministic hard block. |
| [`T01`](#t01) | Representative 2025 remote second stage | [`aur-2025-remote-source`](../testdata/security-scenarios/aur-2025-remote-source/) | The represented remote-source form is a deterministic hard block; it is not a byte-for-byte incident replay. |
| [`T02`](#t02) | May 2026 install-script ecosystem package | [`aur-2026-install-ecosystem`](../testdata/security-scenarios/aur-2026-install-ecosystem/) | Install-time ecosystem invocation is blocked behaviorally, including an inert `python-utils` example. |
| [`T02`](#t02) | June 2026 Atomic Arch indicators | [`aur-2026-atomic-arch`](../testdata/security-scenarios/aur-2026-atomic-arch/) | Known npm and Bun names match the versioned threat bundle and the generic installer rule. |
| [`T04`](#t04) | July 2026 committed native payload reports | [`aur-2026-native-binary`](../testdata/security-scenarios/aur-2026-native-binary/) | A synthetic ELF header produces an approval-eligible high finding, supporting only a partial-mitigation claim. |
| [`T04`](#t04), [`T06`](#t06) | Reported native `validator` plus `sudo` | [`aur-2026-native-sudo`](../testdata/security-scenarios/aur-2026-native-sudo/) | The native-file finding is combined with a non-approval-eligible privilege-command hard block. |
| [`T07`](#t07) | Filesystem and archive path escapes | [`structural-escapes`](../testdata/security-scenarios/structural-escapes/) | Escaping symlink and archive-member names are hard-blocked. |

Run them with `make scenarios`. A passing scenario verifies the expected result
for those synthetic bytes and current policy; it does not prove coverage of an
entire attack family. Identity abuse, runtime behavior, upstream compromise,
and availability attacks intentionally have no green scenario that could imply
protection Prolewatch does not provide.

## AI versus deterministic-only review

`review.mode` has two values:

- `"ai"` is the default. Deterministic scanning runs first. Unless a hard block already decides the phase, bounded selected content is sent through the isolated configured CLI provider. Provider failure, an empty verdict, a block verdict, confidence below the configured minimum (default `high`), detected prompt injection, or provider coverage notes fail closed by default. Coverage-note blocks remain eligible for an exact, one-time `OVERRIDE`; prompt injection does not.
- `"deterministic-only"` performs no provider probe or request. It needs no provider account, credential, dispatcher, prompt, schema, or provider sudo rule. In this mode incomplete coverage and hard blocks block by default and cannot receive a normal approval. Non-hard `critical` and `high` findings block but are eligible for the exact, one-time approval flow. `medium` and `low` findings remain visible warnings.

The root administrator can deliberately enable `overrides.allow_unsafe`. This
adds an interactive, exact-`BYPASS` break-glass path even for hard blocks and
incomplete inspection. It is disabled by default, visibly labelled unsafe, not
network-eligible, and not evidence that the package is benign. This operational
availability choice weakens the mitigation claims in this threat model whenever
it is used.

AI review can add contextual judgement across multiple files and may recognize suspicious intent that no narrow deterministic rule describes. It is still not a proof of safety, a malware sandbox, or a substitute for source review. Deterministic-only mode improves privacy, offline usability, reproducibility, and installation simplicity, but places more responsibility on users to understand warnings and review code manually.

Changing mode changes the policy fingerprint, so old markers and approvals cannot silently authorize the new policy. Re-run the system installer with the desired `--review-mode` so the installed assets and exact sudoers policy match the configuration.

## Operational interpretation

For a meaningful result, all of these assumptions must hold:

1. The documented yay hook is the path used for the AUR transaction.
2. The current package inputs are the inputs Prolewatch inventories; structural coverage failures are not overridden.
3. The clean root and build dispatcher are initialized and pass `prolewatch doctor`.
4. Users do not treat an approval or network lease as a generic “trust this package” switch. Both are exact, one-time, content-and-policy-bound decisions.
5. A blocked or suspicious package is investigated before any code from it is run outside the protected path.

If a payload may already have executed, a later clean report is not evidence that the host is clean. Follow the relevant incident guidance, rotate exposed credentials from a known-clean system, and perform normal incident response.

## Source notes

- Arch incident and mailing-list posts are primary sources for Arch actions and what reporters observed.
- The Atomic Arch package count and campaign linkage are attributed to Sonatype and described as preliminary where the source does so.
- The payload capability description is static-analysis evidence. It supports a realistic threat model but does not establish that every affected package successfully executed every capability.
- This review was current on 2026-08-16. New AUR incidents and variants after that date are not represented automatically.

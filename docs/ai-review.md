# AI review

AI review is optional and off by default. `review.mode` is `deterministic-only`,
so a stock installation contacts no provider, sends nothing anywhere, and
reaches every decision locally. Nothing on this page applies until you change
that.

Setting `review.mode` to `ai` adds a contextual pass on top of deterministic
inspection. It runs through a supported provider CLI and account that you
configure explicitly, so it uses your own provider quota, and each batch is
bounded by `review.timeout_seconds` (180s).

What AI review can and cannot do is fixed by policy, not by the model you pick:
it can turn an allow into a decision, it can never clear a deterministic
finding, and a provider that fails, times out, or is missing leaves a
deterministic briefing and an install that proceeds on deterministic grounds
alone. Choosing a stronger model buys you more context, never a more permissive
tool.

## Enable Codex review

This integration does not run Codex Security's `scan` command. Prolewatch first
performs its own deterministic package inspection, then invokes `codex exec`
with a fixed prompt and structured-output schema for each bounded review batch.

### Check the binary

Prolewatch requires Codex CLI `>=0.146.1`, and the adapter has been checked
against releases below `0.150.0`. The floor is a refusal: below it, the flags
this adapter passes do not exist. The ceiling is only a warning. A newer Codex
still runs, and `prolewatch doctor` says plainly that its invocation flags are
unverified, because every way a newer CLI could actually break the adapter
already fails closed. Refusing to run the day Arch ships a new Codex would cost
more than it buys.

Prolewatch runs `/usr/bin/codex` specifically. That path is not searched for on
`PATH`, so a Codex installed under `~/.local/bin` or `/usr/local/bin` is not the
one Prolewatch will use. Check the exact path and its version:

```bash
ls -l /usr/bin/codex
/usr/bin/codex --version
```

`prolewatch doctor` reports a missing binary or an unsupported version too.

### Authenticate in a dedicated home

Prolewatch intentionally does not reuse the ordinary `~/.codex` login. Give it a
dedicated, file-backed Codex home under the invoking user's Prolewatch state
directory and authenticate there:

```bash
prolewatch_codex_home="${XDG_STATE_HOME:-$HOME/.local/state}/prolewatch/providers/codex"
install -d -m 0700 "$prolewatch_codex_home"

CODEX_HOME="$prolewatch_codex_home" \
  /usr/bin/codex --config 'cli_auth_credentials_store="file"' login

# Only after login has actually written the file:
chmod 0600 "$prolewatch_codex_home/auth.json"
CODEX_HOME="$prolewatch_codex_home" /usr/bin/codex login status
```

The plain `login` command opens the ChatGPT browser flow. On a headless machine,
use `login --device-auth`; API-key users can instead pipe the key to
`login --with-api-key`. Treat `auth.json` like a password. Prolewatch checks
that it is a regular file owned by the invoking user with no group or other
access, and mounts only this dedicated directory read-write so Codex can refresh
its tokens.

### Switch the mode and probe

Edit `/etc/prolewatch/config.json`: keep `provider` set to `codex` and change
`review.mode` from `deterministic-only` to `ai`. Then validate the file and
establish the provider attestation:

```bash
sudoedit /etc/prolewatch/config.json
prolewatch config-check
prolewatch doctor
```

The first `doctor` after enabling AI must run without `--no-probe`. It makes a
real provider request and establishes three things: that Codex starts with an
empty workspace, that it cannot read a sentinel placed in host `/tmp`, and that
it recognises a prompt-injection canary. Only checks the run actually observed
are written down. Success means every required check passes, including
active-provider compatibility, host and workspace isolation, the semantic
canary, and the stored attestation.

The attestation is bound to the provider binary, the AI policy, and the archive
probe, so renew it with `prolewatch doctor` after changing any of them. The
archive probe is `bsdtar`, which means an ordinary `libarchive` upgrade also
invalidates the attestation and asks for a fresh probe.

If setup has not installed the yay hook yet, run `prolewatch setup` after this
live probe. `setup` deliberately spends no provider request, so it validates the
stored attestation instead of creating one, and refuses to install the hook
while that attestation is missing.

## What the provider receives

During a package review, Codex receives the manifest, source-verification
status, deterministic findings, selected text, and a bounded context window for
each guidance target. It does not receive a mount of the package tree or of your
home directory. It must quote the target's exact anchor back; guidance attached
to a different occurrence is discarded.

It runs ephemerally in a separate Bubblewrap sandbox with an empty workspace, no
web search, ignored user and project rules, disabled feature surfaces, no
approval prompts, and a read-only Codex sandbox.

| Provider | Default model | Effort | Model identity |
| --- | --- | --- | --- |
| `codex` (default) | `gpt-5.6-sol` | `high` | Pinned identifier |
| `anthropic` | `sonnet` | `high` | **Moving alias** |

The Anthropic default is a moving alias, with a consequence worth understanding
before you rely on it. `sonnet` resolves to whichever model the provider
currently points it at. Prolewatch records the string it was configured with, so
a report says `sonnet` without naming the model that actually answered, and two
reports carrying the same policy fingerprint can have been produced by different
models weeks apart. Pin a full model identifier in `providers.anthropic.model`
if you need a report to mean one fixed thing over time. The `codex` default is
already a pinned identifier and does not have this property.

## Where AI review is spent

Prolewatch inspects a package at three points, and aims AI review at the two
that carry the most for it to read.

| Gate | What it holds | AI review |
| --- | --- | --- |
| **recipe**, before any source is fetched | The `PKGBUILD` and `.SRCINFO`. Usually two small, highly structured files. | On for deterministic findings at the manual-review threshold; otherwise optional |
| **sources**, before the build runs | The fetched upstream code. The largest and least structured input in the transaction. | Always |
| **built package**, before `pacman` installs it | What the build produced, including everything that would run as root. | Always |

The recipe gate is normally conditional, and not because it is unguarded.
Deterministic inspection runs at all three gates regardless, and it is strongest
exactly where recipes are concerned, because its rules are written for
`PKGBUILD` shapes. When that pass reaches the configured manual-review threshold
(`HIGH` by default), AI mode asks the provider for guidance while preserving the
deterministic decision. That spends the extra call where cross-file context can
help explain an ambiguous `eval`, generated patch, or integration surface,
without letting the model clear it.

A conditional recipe run reports `completed · triggered by findings`, so it
cannot be mistaken for routine all-recipe review.

Clean recipes remain skipped by default. Reviewing every recipe in a transaction
that pulls ten dependencies would add a third of the waiting and a third of the
quota, spent on the input with the least for a model to say.

Reports say which applies, so a skipped gate is never something you have to
infer:

```text
AI review
  • not run · recipe has no findings at the HIGH decision threshold · set review.include_recipe_phase to review every recipe
```

## Tuning

Turn on review for every recipe, when you want a recipe read before you spend
bandwidth on its sources:

```json
"review": { "include_recipe_phase": true }
```

To keep recipe review fully opt-in even for decision-requiring deterministic
findings, set `"guide_decision_findings": false`. This changes provider use
only. It does not remove or downgrade deterministic findings.

The manual-decision threshold is separately configurable:

```json
"review": { "manual_review_minimum_severity": "medium" }
```

Lowering it is stricter; raising it is more permissive. Structural hard stops
stay non-approvable at every setting, and changing the threshold changes the
policy fingerprint, so an approval cannot cross between policies. The threshold
also drives inspection: at the default, `[i] Inspect HIGH/CRITICAL findings`
shows only decision-requiring items, with SHA-256-bound source context where a
local text line is available. Set it to `medium` and the action becomes
`Inspect MEDIUM+ findings`.

The inspector names the exact local file and line for deeper manual reading, and
deliberately does not launch an editor: external editor plugins, modelines, and
project configuration all sit outside Prolewatch's verified read-only display
boundary. Provider guidance is visually separated and labelled as advisory AI
text, never as package source.

## Cost and effort

Both defaults select `high` effort, the slow and expensive end of the range.
That is deliberate. A review worth blocking an install on is worth thinking
about, and review runs once per eligible gate instead of continuously. A phase
splits into one or more review batches, each invoking the provider under its own
`review.timeout_seconds`, so the cost is seconds to minutes on a build. Lower
`effort` in `/etc/prolewatch/config.json` if you would rather have speed, and
expect weaker findings for it.

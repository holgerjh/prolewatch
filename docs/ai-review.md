# AI review

AI review is optional and off by default. `review.mode` is `deterministic-only`,
so a stock installation performs inspection locally without contacting an AI
provider.

Setting `review.mode` to `ai` adds a contextual pass on top of deterministic
inspection. Codex and Anthropic run through a provider CLI and your account;
the Ollama pilot uses a separately operated local daemon, needs no provider
account or quota, and keeps package material on that machine. "Local" applies
only to an already-local model served on the fixed loopback endpoint. Each CLI
batch is bounded by `review.timeout_seconds`; Ollama uses its own
`providers.ollama.timeout_seconds`.

AI review can turn an allow into a decision, but cannot clear a deterministic
finding, and a provider that fails, times out, or is missing leaves a
deterministic briefing and an install that proceeds on deterministic grounds
alone. These rules apply to every supported model.

## Enable Codex review

This integration does not run Codex Security's `scan` command. Prolewatch first
performs its own deterministic package inspection, then invokes `codex exec`
with a fixed prompt and structured-output schema for each bounded review batch.

### Check the binary

Prolewatch requires Codex CLI `>=0.146.1`, and the adapter has been checked
against releases below `0.155.0`. Older versions are rejected because they lack
required flags. Newer versions run with a `prolewatch doctor` warning that their
invocation flags have not been verified. Adapter failures fall back to
deterministic inspection.

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

Edit `/etc/prolewatch/config.yaml`: keep `provider` set to `codex` and change
`review.mode` from `deterministic-only` to `ai`. Then validate the file and
establish the provider attestation:

```bash
sudoedit /etc/prolewatch/config.yaml
prolewatch config-check
prolewatch doctor
```

The YAML path is a hard cut, not a second configuration option. Old JSON files
are ignored. Run `prolewatch config-check` and `prolewatch doctor` after editing
`config.yaml`.
The YAML loader accepts one mapping document with known fields; duplicate
keys, aliases, merge keys, special tags, and non-decimal numbers are rejected.

The first `doctor` after enabling AI must run without `--no-probe`. It makes a
real provider request and establishes three things: that Codex starts with an
empty workspace, that it cannot read a sentinel placed in host `/tmp`, and that
it recognises a prompt-injection canary. Only checks the run actually observed
are written down. Success means every required check passes, including
active-provider compatibility, host and workspace isolation, the semantic
canary, and the stored attestation.

The attestation is bound to the provider binary or local HTTP identity and to
the inputs that shape provider behavior: runtime/model metadata, prompt,
schema, adapter policy, review batch size, and guidance threshold. Transaction
policy and the `bsdtar` archive identity remain independently bound to reports,
approvals, and markers; changing them does not invent new provider evidence and
does not require repeating an unchanged provider canary.

If setup has not installed the yay hook yet, run `prolewatch setup` after this
live probe. `setup` deliberately spends no provider request, so it validates the
stored attestation instead of creating one, and refuses to install the hook
while that attestation is missing.

## Enable the local Ollama pilot

Ollama is useful when repeated calls in one `yay` transaction should share a
loaded model without sending package content to a hosted provider. Prolewatch
does not install or start Ollama, pull a model, create a service account, or
modify the daemon. The separately operated daemon is part of the local trusted
computing base and is a weaker isolation boundary than the CLI providers'
Bubblewrap sandboxes.

The adapter has no configurable URL. It speaks native HTTP only to
`http://127.0.0.1:11434`, bypasses environment proxies, performs no DNS lookup,
rejects redirects and authentication, and refuses model or response metadata
that names `remote_host` or `remote_model`. `/api/tags`, `/api/show`, and
`/api/ps` must bind one local digest and the requested effective context. The
chat request sends no tools and explicitly sets `truncate:false` and
`shift:false`. Doctor additionally sends an intentionally over-context request
with a small context and accepts only a context-specific HTTP 400 refusal. A
successful response leaves the adapter policy `truncate-unverified`; only the
observed refusal produces `truncate-off` evidence.

The pilot requires Ollama `>=0.32.0`; versions at or above the currently checked
ceiling `0.34.0` run with a Doctor warning and produce a distinct attestation,
so an upgrade cannot silently reuse old evidence.

The shipped configuration includes the measured `qwen3:14b` example at 40,960
context tokens with reasoning off, but keeps `provider: codex` and AI review
disabled. It is not an attestation or a guarantee that the model fits your
hardware. At long context the KV cache can dominate memory, while a partially
offloaded model can make the prefill-heavy Sources gate unusably slow. Let
Doctor measure and attest your exact tuple after selecting Ollama:

```yaml
provider: ollama
providers:
  ollama:
    model: qwen3:14b
    context_tokens: 40960
    reasoning: off
    keep_alive_seconds: 300
    timeout_seconds: 300
review:
  mode: ai
  phases: [sources, artifact]
```

Edit these fields in the installed full configuration; this excerpt is not a
complete replacement file.

This follows the provider-independent default: routine AI review of recipes
is off for Ollama just as it is for Codex and Anthropic. Deterministic recipe
inspection still always runs. If it needs a manual decision, `[r] Run AI review
now` offers a one-shot provider call; no disabled gate contacts the model
automatically.

`context_tokens` is required when Ollama is active and may be 16,384 through
262,144, but never above the model's advertised context. `keep_alive_seconds`
may be zero: Prolewatch then keeps the model just long enough to verify it in
`/api/ps` and unloads it at the end of each gate. With a positive value it stays
warm across adjacent batches; Prolewatch still unloads before the build and
after artifact review so model memory does not compete with `makepkg`.

Recommended daemon settings for measurement are:

```ini
OLLAMA_FLASH_ATTENTION=1
OLLAMA_KV_CACHE_TYPE=q8_0
OLLAMA_NUM_PARALLEL=1
OLLAMA_NO_CLOUD=1
```

`q8_0` reduces KV memory while retaining substantially more fidelity than
`q4_0`; the latter is not recommended for a security review. The adapter also
checks `/api/ps` because parallel slots can silently reduce effective context.

Run `prolewatch doctor --probe-llm-quality` to explicitly opt into the long
local assessment. An ordinary `prolewatch doctor` checks any stored attestation
but does not start the assessment; when the evidence is absent or stale, it
names the opt-in command and AI review remains disabled.

The assessment announces and executes seven fixed quality cases:

- benign input without invented findings;
- clear remote execution;
- prompt injection;
- exact content-bound guidance;
- cross-file persistence;
- plausible malice that must not receive `likely-benign` guidance;
- a root hook unsafely deserializing state writable by a less-privileged group.

Each case begins by unloading the model, so every verdict is measured from a
fresh runner and prompt cache instead of inheriting order-dependent state from
an earlier case. That makes the cases comparable and the total slower than a
real package review, which keeps the model warm.

Alongside the verdicts it reports cold-load, prefill, visible-answer throughput,
unaccounted daemon time, and per-request wall time, plus a Sources-duration
projection for a provisional 8 MiB reference input. The projection uses the
production batching path and names the reference volume, batch count, selected
text and prompt tokens per batch, cold-load time and total duration. Doctor also
checks the aggregate observed request-byte/prompt-token ratio and refuses
attestation when it is below the calibrated floor plus safety margin.

A usable measurement above the ten-minute Sources budget is a Doctor warning,
not a failed safety check. Doctor can still save the attestation when the seven
quality cases, truncation refusal, and calibration pass. The warning names the
provisional 8 MiB reference and the budget. Doctor recommends an artifact-first
`review.phases` value, but never changes the configuration or skips a gate.
Keep `sources` when review of code that may disappear into a compiled binary
is worth the wait.
Missing or unusable throughput metrics remain a required failure and cannot
produce an attestation.

On the RTX 5080 measured below, the seven cases took 50 to 143 seconds
depending on model and reasoning level. Expect considerably more on slower
hardware, at long context, or with a partially offloaded model.

The attestation binds the exact runtime, model digest, context,
prompt, schema, adapter policy, quality corpus, truncation refusal and observed
byte/token ratio. It also binds the review batch size and guidance threshold,
because those change provider input. Gate selection and build/network policy
remain bound to reports, approvals and markers, but not to model-quality
evidence: changing only `review.phases` therefore does not repeat the seven
cases. Attestation schema 3 intentionally
makes older, broadly policy-bound evidence stale once; subsequent selection
changes are cheap. A changed runtime, digest or context still requires
`prolewatch doctor --probe-llm-quality` again.

To exercise only the privileged writable-state case while tuning a local model,
run:

```console
prolewatch doctor --probe-llm-quality-case privileged-writable-deserialization
```

This sends only that selected case. It skips the other quality cases, context
refusal, calibration and performance projection, and never creates or renews
an attestation. The final Doctor result may therefore still report a stale
attestation even when the selected diagnostic itself passes; use the full
`--probe-llm-quality` assessment once tuning is complete.

For the cross-file persistence case, a blocking verdict is the required safety
result. Missing an exact finding on its install-script, service-unit, or
credential-exfiltration chain is reported as a warning about explanation
quality, but does not invalidate the attestation.

Unlike a CLI attestation, the Ollama attestation contains no `/usr/bin/ollama`
hash and makes no `EmptyWorkspace` or `NoHostRead` claim. A client file does not
identify an already-running daemon. Reports instead record `http-loopback`, the
local model digest, configured context, whether the model advertises Thinking,
and the effective reasoning level the request actually used.

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
| `ollama` (pilot) | none | `none` | Exact local digest |

The Anthropic default, `sonnet`, resolves to whichever model the provider
currently points it at. Prolewatch records the string it was configured with, so
a report says `sonnet` without naming the model that actually answered, and two
reports carrying the same policy fingerprint can have been produced by different
models weeks apart. Pin a full model identifier in `providers.anthropic.model`
if you need reports to identify a fixed model. The `codex` default is
already a pinned identifier and does not have this property.

## Where AI review is spent

Prolewatch inspects a package at three points, and aims AI review at the two
that carry the most for it to read.

| Gate | What it holds | AI review |
| --- | --- | --- |
| **recipe**, before any source is fetched | The `PKGBUILD` and `.SRCINFO`. Usually two small, highly structured files. | Selected by `review.phases`; otherwise available once through `[r]` at a manual decision |
| **sources**, before the build runs | The fetched upstream code. The largest and least structured input in the transaction. | Selected by `review.phases` (on by default); otherwise available once through `[r]` at a manual decision |
| **built package**, before `pacman` installs it | What the build produced, including everything that would run as root. | Selected by `review.phases` (on by default); otherwise available once through `[r]` at a manual decision |

The recipe gate is normally skipped by AI, not unguarded. Deterministic
inspection runs at all three gates and is strongest on `PKGBUILD` shapes. If a
finding opens a manual-decision prompt in a disabled gate, `[r] Run AI review
now` lets you choose whether to spend the extra call. The fresh report says
`requested interactively`, so it cannot be mistaken for routine review. AI
cannot clear a deterministic finding.

Clean recipes remain skipped by default. Reviewing every recipe in a transaction
that pulls ten dependencies would add a third of the waiting and a third of the
quota, spent on the input with the least for a model to say.

Reports say which applies, so a skipped gate is never something you have to
infer:

```text
AI review
  • not run · recipe phase is not included in AI review · set review.phases to add it
```

## Tuning

Select gates explicitly. A low-VRAM local setup can retain cheap recipe and
artifact review while omitting the Sources cost centre:

```yaml
review:
  phases: [recipe, artifact]
```

Old configurations without `phases` are normalized from
`include_recipe_phase`; new configurations should use only `phases`. A skipped
gate is recorded as a normal `not run` reason rather than a provider failure.

When an otherwise disabled phase opens the manual-review prompt and an attested
reviewer is available, `[r] Run AI review now` performs a one-shot review.
Prolewatch rescans first, saves a new report bound to the current bytes, prints
the refreshed evidence, and only then asks again. The action does not change
configuration and is absent for provider degradation, structural blocks, or a
phase whose AI review already ran. The removed `finding_triggered_phases` and
`guide_decision_findings` options are rejected by strict configuration loading.

The manual-decision threshold is separately configurable:

```yaml
review:
  manual_review_minimum_severity: medium
```

Lowering it is stricter; raising it is more permissive. Structural hard stops
stay non-approvable at every setting, and changing the threshold changes the
policy fingerprint, so an approval cannot cross between policies. The threshold
also drives inspection: at the default, `[i] Inspect HIGH/CRITICAL findings`
shows only decision-requiring items, with SHA-256-bound source context where a
local text line is available. Set it to `medium` and the action becomes
`Inspect MEDIUM+ findings`. `[a] Inspect all N findings` sits beside it and
ignores the threshold.

The inspector names the exact local file and line for deeper manual reading, and
deliberately does not launch an editor: external editor plugins, modelines, and
project configuration all sit outside Prolewatch's verified read-only display
boundary. Provider guidance is visually separated and labelled as advisory AI
text, never as package source.

## Cost and effort

Both hosted defaults select `high` effort, which increases latency and cost.
Each eligible phase uses one or more review batches, each with its own
`review.timeout_seconds` limit. Review can add seconds to minutes to a build.
Lower `effort` in `/etc/prolewatch/config.yaml` to favour speed, with a possible
loss of review quality.

The shipped Ollama example defaults to `off`. Select `auto` to send
`think:true` when the local model advertises Thinking.
`providers.ollama.reasoning` can also select `low`, `medium`, or
`high`; the string levels require a Thinking-capable model. Some models do not
produce a verdict with `off` and a structured-output schema. Every setting is
bound to the exact model digest and must pass the seven-case quality gate before
AI review can rely on it. No fast model or level is silently selected.

The `num_predict` cap is 4,096 tokens with reasoning off and 6,144 otherwise.
Input batching reserves the same cap plus 2,048 template tokens, then converts
the remaining budget with the conservative 2.0 bytes/token floor. At 40,960
context tokens, a reasoning-enabled request may contain at most 65,536
serialized bytes. The exact request size and returned token accounting remain
fail-closed checks.

Ollama's `eval_count` and `eval_duration` may cover only the visible answer,
not Thinking tokens or time. Benchmark `output_tokens_per_second` therefore
means *visible-answer throughput*, not whole-review speed. Each request also
records wall-clock milliseconds and `unaccounted_ms`, the nonnegative remainder
of Ollama's `total_duration` after load, prefill, and visible output. That
remainder includes Thinking but can also include scheduling and queueing; it
must not be interpreted as an exact Thinking duration.
Reaching the generation cap rejects the incomplete response with a specific
diagnostic. The separate `providers.ollama.timeout_seconds` wall-clock deadline
still bounds a slow prefill or generation that reaches no token limit first.

Doctor requires the exact model's aggregate quality-gate measurement to reach
at least 2.2 bytes per prompt token (the floor plus a 10% safety margin). Phase 0
will replace both the calibration and the provisional 8 MiB Sources reference
with measured values. Until then these numbers are explicit pilot inputs, not
model recommendations.

## Local pilot profiles

These are non-normative community measurements, not defaults or an allowlist.
Their purpose is practical model selection: find the same GPU and VRAM class,
then compare models that passed the fixed safety corpus by prefill speed and
projected Sources duration. A model that merely starts is not a successful
profile.

### Measured model comparison

One operator run per row on an RTX 5080 (16,303 MiB VRAM) with Ollama 0.32.13,
sampled 2026-09-13. Each row is the same seven-case corpus with a fresh model
load per case, so the wall time includes seven cold loads and is not a package
review time.

Two columns judge quality. *Cases* counts the hard safety assertions: did the
model allow what should be allowed and block what should be blocked. *Wrong
line* counts cases where the verdict was right but the finding named a
neighbouring line instead of the exact dangerous statement, for example the
`with open(...)` line rather than the `pickle.load(...)` call below it. That is
advisory and does not fail the corpus, but it sends the read-only inspector to
the wrong line and makes the finding harder to judge.

| | Model | Digest | Size | Context | `reasoning` | Residency | Cases | Wrong line | Corpus wall | Slowest request | 8 MiB Sources |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ✅ | `qwen3:14b` | `bdbd181c33f2ed1b` | 9.28 GB | 40,960 | `off` | 100% GPU | 7/7 | none | 49.9 s | 9.8 s | 1,088 s |
| ✅ | `qwen2.5-coder:14b` | `9ec8897f747e246e` | 8.99 GB | 32,768 | `off` | 100% GPU | 7/7 | 1 | 46.6 s / 47.7 s | 7.5 s | 1,247 s / 1,283 s |
| ✅ | `qwen2.5-coder:7b` | `dae161e27b0e90dd` | 4.68 GB | 32,768 | `off` | 100% GPU | 7/7 | 2 | 35.8 s | 6.1 s | 802 s |
| ✅ | `qwen3:14b` | `bdbd181c33f2ed1b` | 9.28 GB | 40,960 | `auto` (Thinking) | 100% GPU | 7/7 | none | 101.2 s | 17.5 s | 2,095 s |
| ✅ | `gpt-oss:20b` | `17052f91a42e9793` | 13.79 GB | 40,960 | `auto` (Thinking) | 89.3% GPU | 7/7 | 2 | 142.5 s | 29.2 s | 2,280 s |
| ❌ | `gpt-oss:20b` | `17052f91a42e9793` | 13.79 GB | 40,960 | `low` | 89.3% GPU | 6/7 | 1 | 75.5 s | 14.6 s | 618 s |
| ❌ | `llama3.1:8b` | `46e0c10c039e0191` | 4.92 GB | 32,768 | `off` | 100% GPU | 6/7 | 1 | 31.9 s | 5.0 s | 680 s |
| ❌ | `qwen3:8b` | `500a1f067a9f7826` | 5.23 GB | 40,960 | `off` | 100% GPU | 5/7 | 1 | 38.7 s | 7.5 s | 734 s |

What the failures were:

- `gpt-oss:20b` at `low` did not block a recipe whose `prepare()` pipes a
  fetched script into `sh`. Reasoning `low` is therefore not usable for review,
  and `auto` makes it the slowest option measured.
- `llama3.1:8b` invented findings on a benign recipe that only installs a
  README.
- `qwen3:8b` returned guidance that was not bound to the exact anchor quote, on
  both the benign and the plausible-malice case.

Low-VRAM support is possible but narrow. `llama3.1:8b` and `qwen3:8b` were
measured for it and neither passed. `qwen2.5-coder:7b` did, at 4.68 GB and fully
GPU-resident at its maximum 32,768 context, which makes it the only tested
option for an 8 GB card. It pays for that with two wrong-line findings where
`qwen3:14b` has none, so the block decisions are right but two of them send the
inspector to a neighbouring line. General-purpose 8B models failed the corpus
outright while the code-specialized 7B passed, so size alone does not predict
the result.

### Recommended settings for a model that passed

`qwen3:14b` is the default recommendation: it is the only measured model with
seven passes and no binding warning, and turning Thinking off halves its wall
time without losing a case.

```yaml
provider: ollama
providers:
  ollama:
    model: qwen3:14b
    context_tokens: 40960
    reasoning: off
    keep_alive_seconds: 300
review:
  mode: ai
  phases: [artifact]
```

`qwen2.5-coder:14b` is the smaller alternative. Its model context is 32,768
tokens, so `context_tokens` must not exceed that; the lower ceiling produces
more batches per package, which is why its Sources projection is worse than
`qwen3:14b` despite the faster individual request.

```yaml
provider: ollama
providers:
  ollama:
    model: qwen2.5-coder:14b
    context_tokens: 32768
    reasoning: off
    keep_alive_seconds: 300
review:
  mode: ai
  phases: [artifact]
```

Both configurations need one `prolewatch doctor --probe-llm-quality` after the
change, because model, context and reasoning are all part of the attested
fingerprint.

### What the model choice constrains elsewhere

Three settings behave differently once a specific model is chosen.

`context_tokens` must not exceed the model's advertised context, and Prolewatch
refuses to start rather than silently reducing it. `qwen2.5-coder:14b` advertises
32,768, so the value that works for `qwen3:14b` does not carry over.

A smaller context is not automatically faster. The per-request input ceiling is
derived from it, so lowering the context lowers how much text one request may
carry and raises the batch count for the same package. That is why
`qwen2.5-coder:14b` answers a single request faster than `qwen3:14b` yet has the
worse 8 MiB Sources projection in the table above.

`review.batch_bytes` is close to inert under Ollama. The context-derived ceiling
is far smaller than the 768,000-byte default, so the ceiling decides the batch
boundaries and the configured value never binds; it only starts to matter if set
to roughly a third of the per-request selected-text budget or below, which makes
the number of batches increase. It is part of the attested fingerprint, so
changing it requires a full seven-case re-probe even when it has no effect.
Tune `context_tokens` and `reasoning` instead.

`keep_alive_seconds: 0` unloads the model at the end of every gate, which adds a
cold load to each one. That load was around three seconds for the 9 GB models
measured here and grows with model size. Keep it positive unless VRAM has to be
free between gates.

### Compare candidates before a full benchmark

Switching the installed configuration for every candidate means editing
`/etc/prolewatch/config.yaml` and re-attesting each time. For a quality-only
comparison there is an opt-in Go test that substitutes a candidate
configuration in-process instead. It runs the same seven cases over the
production review path, and it changes no installed configuration and writes no
attestation.

```bash
PROLEWATCH_BENCH_MODEL=qwen3:14b \
PROLEWATCH_BENCH_CONTEXT_TOKENS=40960 \
PROLEWATCH_BENCH_REASONING=off \
  go test ./internal/audit -run '^TestOllamaLiveQualityBenchmark$' -count=1 -v -timeout 30m
```

`PROLEWATCH_BENCH_MODEL` is the opt-in: without it the test skips, so an
ordinary `go test ./...` never starts a model. `PROLEWATCH_BENCH_CONTEXT_TOKENS`
is required and must not exceed the model's advertised context.
`PROLEWATCH_BENCH_REASONING` defaults to `auto`.

The log lines are prefixed for grepping: `MODEL` with digest, effective
reasoning, generation cap and input byte ceiling; one `CASE` per quality case
with pass state, failure stage, wrong-line warning and duration; `SPEED` with
prefill and visible-output throughput, slowest request and the 8 MiB Sources
projection; and a final `RESULT` with the pass count, warning count, wall time
and GPU residency. A model that does not pass all seven cases fails the test.

This is a comparison tool, not a replacement for `llm-benchmark`. It does not
verify context-refusal behavior, does not check byte/token calibration, and
produces no shareable record or suitability grade. Use it to narrow a field of
candidates, then run the full benchmark on the one you intend to keep.

### Produce a shareable result

Configure the candidate model and run:

```bash
prolewatch llm-benchmark > prolewatch-llm-benchmark.json
```

The command runs the same seven isolated quality cases and context-refusal
probe as Doctor, measures every request, and applies the same byte/token
calibration. It additionally emits per-case wall time, cold-load time, prefill
and output tokens per second, model RAM/VRAM residency reported by `/api/ps`,
the slowest individual request, total wall time, and the provisional 8 MiB
Sources projection. Progress goes to standard error; standard output is one
stable JSON record suitable for sharing.

The JSON is privacy-minimal by construction. It contains the GPU product name
and total VRAM because those are necessary to interpret speed. On NVIDIA this
comes from an allowlisted `nvidia-smi` query for only `name` and `memory.total`.
It does not collect hostname, username, home or configuration paths, IP or MAC
addresses, GPU UUID/serial/PCI address, driver version, process information,
raw model responses, or package text. Unsupported GPU backends simply produce
an empty `hardware.gpus` list; submitters may state only the product name and
VRAM class alongside the JSON if they choose.

By default the benchmark does not write an attestation. To use the same
successful run as provider-semantic evidence, opt in explicitly:

```bash
prolewatch llm-benchmark --attest > prolewatch-llm-benchmark.json
prolewatch doctor
```

`--attest` writes the ordinary provider attestation only when the benchmark
passes, including the configured Sources budget. The following ordinary Doctor
run validates that evidence and the rest of the installed system without
repeating the long model corpus.

The derived `suitability` field makes results comparable:

- `all-gates`: every safety check passed, no request exceeded five minutes, and
  the projected 8 MiB Sources gate is at most ten minutes;
- `recipe-artifact`: every safety check passed, but Sources exceeds that time
  budget;
- `not-qualified`: a semantic, context-refusal, calibration or request-time
  check failed, or usable performance measurements were unavailable.

`benchmark_passed` additionally applies the configured gate selection. A
`recipe-artifact` result therefore has `benchmark_passed:false` while Sources
is selected in `review.phases`. `llm-benchmark --attest` can attest that result
only after Sources is removed from that list and the candidate is measured
again under the new configuration.
This stricter benchmark pass/fail grade does not apply to
Doctor's safety attestation: `doctor --probe-llm-quality` warns about the slow
Sources projection but can save evidence for the exact model when all safety
checks and the performance measurement are usable.

The Sources value is a projection through the production batching path, not a
claim about every real package. Keep the exact digest, context, residency,
sample date, semantic fingerprint, and speed columns visible. The fingerprint
identifies submissions made with identical prompt, schema, adapter, batching,
guidance threshold, runtime/model, and context inputs; it is not a signature or
proof that a submitted JSON file is genuine. Retain multiple results for the
same tuple rather than replacing them with one best run.

### Results

The first local smoke test predates the shareable benchmark record. It is kept
as an operator report, but is not promoted to a measured recommendation.

| Date | GPU / VRAM | Model / digest | Ollama / context | Residency | Quality | Prefill / visible output | 8 MiB Sources | Suitability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-09-08 | RTX 5080 / not captured | `gpt-oss:20b` / not captured | not captured | not captured | Doctor reported successful; exact invocation and result record not captured | not captured | not captured | benchmark pending |
| 2026-09-13, legacy v4 | RTX 5080 / 16,303 MiB | `qwen3:14b` / `bdbd181c33f2ed1b31c972991882db3cf4d192569092138a7d29e973cd9debe8` | 0.32.13 / 40,960 | 100% GPU | 7/7, no source-binding warnings | 19,168.8 / 71.3 tok/s; hidden Thinking time not measured | 1,184.2 s; underestimates Thinking | recipe-artifact |
| 2026-09-13, v5 / reasoning off | RTX 5080 / 16,303 MiB | `qwen3:14b` / same digest | 0.32.13 / 40,960 | 100% GPU, 12.65 GB loaded | 7/7, no source-binding warnings; 59.8 s corpus wall time | 3,759.2 / 73.4 tok/s; output is visible answer only | 1,125.3 s | recipe-artifact |

The v5 Qwen row is a single attest-free measurement. It is not a benchmark for
every package: a local five-file, 136-KiB `moon-buggy` recipe snapshot planned
four instead of eight requests with the new generation-bound reserve, but no
complete post-change package-review wall time was recorded.

Six further models and reasoning levels, including two 8 GB-class candidates
that did not pass, are in [Measured model
comparison](#measured-model-comparison). Those rows come from the corpus alone,
not from a full `llm-benchmark` record, so they carry no suitability grade.

Use the common daemon settings above for comparable submissions. In particular,
record full GPU residency versus offload: Sources review is prefill-heavy, and
offload plus additional batches can turn a model that technically fits into an
impractical choice.

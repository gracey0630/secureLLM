# Report Notes — Observations Worth Documenting

Running log of findings, design decisions, and honest limitations discovered
during implementation. Organized by report section. Add to this as new results come in.

---

## Methodology

### Dataset curation
- HackAPrompt filters `correct=True` — meaning these prompts already *succeeded* against
  a target model. This makes the attack corpus high-quality but also potentially easier
  than real-world attacks (they were crowd-sourced against specific model versions).
- LMSYS-Chat-1M required a bug fix: the `language` field uses `"English"` not `"en"`.
  The original filter silently dropped all rows, producing an empty legitimate corpus.
  Fixed before B0 ran — worth noting as a reproducibility detail.
- LMSYS legitimate queries were filtered using an injection keyword blocklist before
  inclusion. A small number of legitimate prompts that happen to use phrases like
  "act as" were excluded — this slightly understates FPR (makes the pipeline look
  cleaner on legitimate traffic than it truly is).
- Deepset was used as an FPR fallback during development but is NOT used for evaluating
  LLM Guard — LLM Guard's underlying model (deberta-v3-base-prompt-injection-v2) was
  trained on Deepset. Using it would inflate B2's reported performance.

### Logging schema design
- The canonical schema is **per-request** (one JSON line = one full pipeline run),
  not per-layer-event. This was a deliberate choice: `pd.read_json("pipeline.jsonl",
  lines=True)` gives an eval-ready DataFrame with no joins needed.
- A separate `debug.jsonl` exists for per-layer development logging — not used for
  any reported metric.

### SecUtil metric
- SecUtil = F1_attack × (1 − FPR_legitimate). Returns 0.0 (not NaN) for degenerate
  cases (e.g. B0 where F1=0). This prevents NaN poisoning in threshold sweep DataFrames.
- B1 (heuristic) produces a **single point** on the SecUtil curve — no continuous
  score to sweep. B2 (LLM Guard) produces a **curve** because it exposes a confidence
  threshold. This asymmetry should be explained clearly in the methodology.

### Canary loop design
- Canary format: `[<16-char uppercase hex>]` — designed to look like an internal
  session token, reducing the chance a well-aligned model repeats it unprompted.
- Planted mid-prompt (after first line of system prompt), not at the end — harder
  for an attacker to target specifically.
- Detection is substring match only. This catches instruction-extraction attacks
  (where the model is tricked into repeating the system prompt) but does NOT catch
  goal-hijacking attacks (where the model silently follows injected instructions
  without leaking the canary). This is a documented limitation of the canary approach.

---

## Results

### B0 — Unprotected assistant
- Corpus: 2,324 rows (1,583 hackaprompt attacks + 731 lmsys legitimate + 10 smoke test)
- Result: TPR=0.000, FPR=0.000, F1=0.000, SecUtil=0.000
- Zero errors across all API calls
- Latency: p50=2,446ms, p95=4,913ms, mean=2,585ms (Claude Haiku, single-turn, no system prompt)
- Note: FPR=0 is technically correct (nothing was blocked) but trivially so — B0 is
  not a useful operating point, it is the floor.

### LLM Guard scanner — implementation notes
- LLM Guard's `PromptInjection.scan()` takes only the input text as argument
  (not a `(system_prompt, input)` pair as the v0.3 docs suggest). Verified
  against installed v0.3.16.
- The scanner cannot be initialized with `threshold=0.0` — it internally
  divides by the threshold to normalize its risk score, causing a
  `ZeroDivisionError` on clean inputs. We initialize at `threshold=0.01`
  and apply our own threshold in the wrapper. This means LLM Guard's
  `is_valid` return value is ignored entirely; we use only the raw score.
- Raw scores for clean inputs can be negative (e.g. −1.0) — LLM Guard's
  internal normalization pushes high-confidence clean predictions below zero.
  We clamp to [0, 1] before logging so the threshold sweep DataFrame stays
  well-formed. Scores for attacks hit exactly 1.0 on tested examples.
- LLM Guard's default threshold is 0.92 — deliberately conservative.
  Worth noting in the paper: a threshold sweep from 0.3→0.9 explores a
  range that LLM Guard itself would never operate in by default.
- The underlying model ships ONNX-only on HuggingFace as of Apr 2026.
  PyTorch weights are not available; the scanner silently falls back to
  ONNX runtime (via `use_onnx=True`). Inference runs on MPS (Apple Silicon)
  — latency measurements should note the hardware context.

### B1 — Heuristic scanner (2,334 rows: 1,596 attacks, 738 legit)
- TPR=0.297, FPR=0.091, Precision=0.876, F1=0.444, SecUtil=0.403
- Latency: p50=0ms, p95=2ms (essentially free)
- Precision=0.876 means regex blocks are almost always correct — the patterns are precise but not sensitive
- TPR=0.297 means ~70% of attacks slip through — all semantic attacks (role hijack, obfuscation, virtualization) are invisible to regex
- This is the expected result: B1 establishes the cheap-defense floor

### B2 — LLM Guard standalone (2,334 rows: 1,596 attacks, 738 legit)
- TPR=1.000, FPR=0.061, Precision=0.973, F1=0.986, SecUtil=0.926
- Latency: p50=63ms, p95=268ms
- Score distribution is perfectly binary: every attack scores exactly 1.0, most legit scores 0.0
- Confirmed NOT a training data contamination issue — HackAPrompt is not in deberta-v3's training set
- The model is a classification head, not a calibrated probability — scores reflect a hard decision boundary, not gradations of confidence
- Threshold sweep is flat (TPR=1.0 at all thresholds 0.3→0.9) — the attack/legit boundary is unambiguous for this corpus
- Verified on hard subset (levels 6-9 only, 561 rows): same result. TPR=1.0 regardless of attack sophistication.
- **The meaningful B2 number is FPR=0.061**, not TPR — that's where real operational tradeoffs exist

---

## Full Pipeline vs B2 — Expected Contribution

**The key question:** if B2 already catches 100% of HackAPrompt attacks, what does the full pipeline add?

**On HackAPrompt specifically: not much.** B2 leaves nothing for the other layers to catch.
Policy Engine and Tool Sandbox don't operate on text injection — they only matter when the LLM
is actually executing tool calls. Output Guard's canary catches leakage, but if B2 already blocked
the attack at input, there's no LLM response to check.

**The pipeline's real value is coverage breadth, not SecUtil improvement:**

| Attack type | B2 covers? | Pipeline layer that covers it |
|---|---|---|
| Direct prompt injection (text) | Yes — TPR=1.0 | Input Scanner |
| Indirect injection (via retrieved docs) | No — B2 only scans user input | Output Guard canary |
| Agentic tool-call manipulation | No — B2 doesn't see tool calls | Tool Sandbox |
| PII leakage in LLM response | No — B2 is an input scanner | Output Guard (Presidio) |
| Privilege escalation by role | No | Policy Engine |

**Paper framing:** B2 is a near-ceiling detector for direct prompt injection on text inputs.
The pipeline's contribution is defense-in-depth across attack types and output risks that a
single input scanner fundamentally cannot address. SecUtil measures one axis (input injection
detection); the paper should clearly acknowledge that the other layers cover orthogonal threat
surfaces not captured by SecUtil on HackAPrompt alone.

---

## Policy Engine — Design Decisions and Reasoning

### Threat model scope (deliberate narrowing)

The policy engine defends against exactly one threat: **LLM-initiated privilege escalation** —
where an injected prompt causes the LLM to emit a tool call that the user's role does not permit.

It does NOT defend against a malicious caller claiming a false role (e.g., setting role="admin"
in the request). That is session-layer authentication, out of scope for this prototype. The role
is treated as a trusted caller-supplied claim — analogous to a verified JWT in a real system.
The Streamlit demo's dropdown simulates this trusted assignment.

This is stated explicitly in code and acknowledged in the paper. The distinction matters because
conflating the two threats would invite a reviewer objection that the "security" is bypassed by
changing a dropdown value — which is true, but irrelevant to the threat being addressed.

### Tool taxonomy — allowlist over blocklist, 5 fixed types

Committed to exactly 5 tool types: `file_read`, `file_write`, `bash`, `external_api`, `search`.
Allowlist (deny everything not listed) rather than blocklist (deny specific dangerous things).

Reasoning: a blocklist requires anticipating every dangerous tool name — impossible in an open
system. An allowlist requires only knowing what is permitted. Any tool name not in the taxonomy
is denied unconditionally regardless of role. This is logged with `reason: "unknown_tool"` to
distinguish from role violations, giving richer data for the paper.

The tool taxonomy must stay in sync with the Claude function-calling tool definitions passed to
the API. Claude can only emit tool names that were given to it upfront — so the allowlist and
the API tool definitions are the same set by construction.

### Enforcement architecture — execution layer, not language layer

The policy engine intercepts between Claude's tool call emission and actual tool execution.
Claude emits structured JSON via function-calling API; the orchestrator reads the tool name,
calls `check_policy()`, and only calls `tools[name].execute()` if permitted.

This is the core security claim: enforcement is in infrastructure code, not in model behavior.
No prompt manipulation can bypass a dict lookup that runs before execution. A different LLM,
a jailbroken model, or a fine-tuned variant would face the same enforcement.

The alternative — parsing free-text LLM output to infer tool intent — was rejected because it
introduces a parsing layer that is itself attackable via prompt injection (craft output that looks
benign to the parser but triggers privileged actions downstream). Structured function calling
makes tool names unambiguous and unobfuscatable.

### Blocked tool call behavior — structured denial, 2-turn cap

When a tool call is blocked, the orchestrator returns a structured denial as the tool result:
`"Access denied: your role does not permit this tool."` Claude receives this and responds to the
user with a natural language explanation. The conversation stays alive; nothing executes.

The agentic loop is capped at 2 turns (initial response + one retry). If Claude attempts a
second tool call after receiving a denial, the entire response is blocked unconditionally.
This prevents adversarial retry loops where the model searches for a permitted tool that
achieves the same goal through a side channel.

### Multi-tool call policy — block entire response on any violation

If Claude emits multiple tool calls in a single response and any one is unauthorized, the
entire response is blocked. The permitted ones do not execute.

Reasoning: partial execution is harder to reason about and opens subtle attack vectors where
a permitted tool executes first and produces side effects useful to the attacker. Blocking the
full response is simpler, safer, and easier to log cleanly. All attempted tool names and the
specific blocked tool are recorded in `layer_results["policy_engine"]`.

### Test strategy — integration tests over unit tests

Unit tests on `check_policy("guest", "bash", config)` prove a dict lookup works, not that
the policy engine provides security value. The evaluation that matters is end-to-end:

- Send an adversarial prompt to a guest-role session
- Observe that Claude emits an unauthorized tool call (showing the LLM was manipulated)
- Observe that the policy engine blocks it before execution

10 integration tests covering: guest attempting all tool types via injection, user attempting
elevated tools via injection, legitimate requests for both user and admin, and unknown/spoofed
role handling. Cases 7 and 10 (injection prompts that successfully manipulate Claude to emit
an unauthorized call) are the paper-worthy results — they demonstrate the delta between
model-level behavior and infrastructure-level enforcement.

5 additional schema tests verify the `layer_results` output matches `logging_schema.py`
exactly — these are contract tests, not security tests.

### Metric — table over single number

Containment Rate as a single number is underspecified (doesn't distinguish role violations
from unknown tool denials, doesn't show usability impact). Report a breakdown table instead:

| Category | N | Blocked | Passed |
|---|---|---|---|
| Guest → any tool (injection) | 3 | 3 | 0 |
| User → elevated tool (injection) | 3 | 3 | 0 |
| Legitimate user requests | 2 | 0 | 2 |
| Legitimate admin requests | 2 | 0 | 2 |

Plus latency: policy engine decision time should be <2ms (pure dict lookup). This is a
legitimate paper datapoint — the enforcement overhead is negligible.

### Claude function-calling API format — implementation note

Claude's tool call response blocks use `name` and `input` (not `tool` and `args`).
Each block also carries an `id` field assigned by Claude. The correct format is:

```json
{"type": "tool_use", "id": "toolu_abc123", "name": "file_write", "input": {"path": "/tmp/out.txt"}}
```

The `id` must be echoed back verbatim when returning a tool result to Claude, otherwise
the API rejects the response. `check_policy()` therefore extracts all IDs from the input
tool calls and returns them as `tool_call_ids` in the layer result — the orchestrator
reads this field to construct valid tool result messages without re-parsing Claude's response.

The policy engine speaks Claude's format natively rather than normalizing in the orchestrator.
This avoids a translation layer that could drift out of sync.

### Tool argument inspection — explicitly deferred to Tool Sandbox

The policy engine operates at tool-type level only. It cannot distinguish
`file_read("/etc/passwd")` from `file_read("/tmp/notes.txt")` — both are permitted for
`user` role. This is a documented limitation, not an implementation gap.

Tool arguments are logged in `layer_results["policy_engine"]["tool_args"]` but not inspected.
This preserves clean layer separation: the policy engine enforces *who can call what type of
tool*; the Tool Sandbox enforces *whether a specific command is safe*. Blurring this boundary
would produce an incomplete, half-built argument inspector that is worse than either layer alone.

---

## Policy Engine — Why It's Not Redundant With Claude's Built-in Safety

A natural reviewer question: "doesn't Claude already refuse unauthorized tool calls?"

**Three reasons model-level refusals are insufficient:**

1. **Probabilistic, not guaranteed.** Claude's refusals are learned behaviors — jailbreakable,
   fine-tunable, and model-specific. A different underlying model has completely different
   refusal behavior. The policy engine works regardless of which LLM is underneath.

2. **The model has no awareness of application-level roles.** Claude doesn't know a given
   user is a `guest` in *your* system — it only knows what's in the prompt. Relying on
   Claude to enforce roles means trusting prompt instructions, which are themselves
   attackable via injection.

3. **Tool execution happens in your infrastructure, not the model.** When Claude emits a
   tool call, *your orchestrator* executes it. Nothing in the model prevents execution —
   the policy engine is the enforcement point at the execution layer.

**The falsifiable academic claim:**
> Prompt injection can cause Claude to emit unauthorized tool calls even when prompted to
> be safe. A policy engine at the execution layer blocks these regardless of model behavior.

The specific integration test cases that demonstrate this are documented in the Design
Decisions section above (cases 7 and 10 — injection prompts that successfully manipulate
Claude to emit an unauthorized call, intercepted before execution).

**Paper framing:** Defense in depth. Claude's refusals are the OS; the policy engine is
the firewall. They're complementary, not redundant. Same principle that makes firewalls
valuable even when OSes have access controls.

---

## Limitations (Be Honest in the Paper)

### HackAPrompt corpus recency gap
- HackAPrompt was collected against older models. Claude Haiku and GPT-4-class models
  are substantially more resistant to many of these attacks than the models they were
  designed for. TPR numbers may overstate how dangerous these attacks are against
  current production models.

### Full pipeline vs B2 SecUtil gain may be modest
- The full pipeline's SecUtil advantage over B2 (LLM Guard standalone) is likely
  small on the HackAPrompt corpus specifically. HackAPrompt is text injection — the
  Input Scanner does most of the work. Policy Engine and Tool Sandbox matter for
  agentic/tool-call scenarios, which HackAPrompt doesn't cover well.
- This should be framed as a scope limitation, not a failure — the paper claims
  a *framework* for layered evaluation, not that every layer adds equal value on
  every attack type.

### Tool Sandbox scope
- Tool Sandbox is a command validator (allowlist/blocklist), not a true sandbox.
  It cannot prevent a sufficiently creative attacker from constructing an allowed
  command that causes harm. This was a deliberate feasibility decision.

### Canary loop coverage
- Canary only catches one attack class: instruction extraction (model leaks system
  prompt). Goal-hijacking attacks — where the model follows injected instructions
  without leaking anything — are invisible to the canary check.

### LMSYS FPR ground truth
- 731 legitimate rows after filtering. This is on the lower end for reliable FPR
  estimation — especially for the threshold sweep where some threshold buckets may
  have very few false positive events. Confidence intervals on FPR would be wide.

### No multi-turn evaluation
- All evaluation is single-turn. Multi-turn injection attacks (where context is
  built across turns) are out of scope. Real-world LLM applications are often
  multi-turn — this is a meaningful gap.

---

## Positive Findings to Highlight

- **Logging harness worked cleanly end-to-end** — B0 ran 2,324 rows with zero errors,
  schema matched canonical spec exactly, `eval_b0.py` read it directly into metrics
  with no data cleaning needed. Reproducibility is solid.
- **Canary format is novel and principled** — the per-request unique token with
  obfuscated formatting is a cleaner design than most academic canary implementations,
  which use static strings.
- **Toggle flag architecture enables the ablation experiment** — no existing public
  tool produces a SecUtil tradeoff curve across independently toggled layers. This
  remains the headline novelty claim.
- **B1/B2 separation is defensible** — using Deepset only for FPR (not for LLM Guard
  evaluation) avoids data leakage. The evaluation protocol is methodologically clean.

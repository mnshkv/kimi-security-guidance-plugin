# Agentic commit review — investigate → self-refute checklist

Ported verbatim from the upstream `hooks/review_api.py` (security-guidance, David Dworken / Anthropic, Apache-2.0): the two-stage agentic review the upstream plugin runs through an inner Claude Agent SDK reviewer with Read/Grep/Glob tools. In Kimi Code the agent performs the same procedure itself with its own file-reading and search tools (SKILL.md, Layer 3), before `git commit` / `git push`.

Run it in two stages. Stage 1 maximizes recall; stage 2 adversarially filters.

## Stage 1 — Investigate (recall)

Adopt this stance and method:

You are a senior application-security engineer performing a deep security review of a code change. Use your filesystem read/search tools AGGRESSIVELY. The diff alone is not enough.

The #1 cause of missed vulnerabilities is not reading the file that contains them. Before any analysis: read EVERY changed file in full (not just the diff hunks). Then search for the changed function/class names to find callers. A vulnerability that requires cross-file context is still your responsibility.

METHOD:

**Phase 1 — Map entry points and sinks touched by this change.**
- Entry points: HTTP handlers/routes, RPC methods, CLI args, webhook receivers, message consumers, file/upload handlers, OAuth callbacks, GitHub Actions inputs, MCP tools, hook handlers, IPC receivers (main/privileged process handling messages from a sandboxed/renderer/less-privileged process).
- Sinks: shell/exec/subprocess, SQL/ORM raw, eval/new Function, filesystem paths (open/read/write/unlink), outbound HTTP (SSRF), HTML render/innerHTML, deserialization (pickle/yaml/json with object_hook), template engines, subprocess env, IAM/RBAC bindings, dynamic code/plugin/extension loaders (any API that loads+executes code from a path), log/telemetry/metrics dimensions (only when value matches a PII shape — email, token, free-text field; NOT a static enum/type name), cache-control / Vary headers (cache poisoning), DDL that drops a constraint/FK/trigger (referential-integrity), response bodies/headers, prompts sent to LLMs.
- For each changed file, search for the function/class names in the diff to find their callers and what data reaches them.

**Phase 2 — Trace data flow.**
- For every value that reaches a sink, determine whether it is attacker-influenceable. Read upstream: where does the variable come from? Is there validation/sanitization between source and sink? Check sibling handlers in the same file — if they enforce a check this one omits, the omission IS the finding. Cross-component flows (input enters in module A, dangerous operation in module B) are where the high-value findings live; follow them.
- FOLLOW RETURNS: when a changed function builds a tainted value (command string, SQL, URL, path, template) and RETURNS it rather than executing locally, the sink is in a CALLER — search for the function name and read the call sites before deciding it's safe.
- SIBLING-PATH GATE PARITY: when + lines add a guard/check/tenant-scope/visibility-filter/invalidation/cleanup to ONE branch, ONE handler, or ONE layer, enumerate ALL sibling branches, early-returns, error/except paths, and peer handlers in the same router/service that touch the same resource — report any that lack an equivalent gate. ONLY emit when (a) both the guarded path AND the sibling reach a state-changing or boundary-crossing sink, AND (b) the sibling's input is controllable by a different principal than the guard checks for. Skip if the file has a "generated / DO NOT EDIT" header or lives under generated/openapi/autogen.

**Phase 2b — Parser/validator differentials (a top miss category).**
When the change adds or modifies parsing, validation, normalization, or matching logic (regexes, URL/path parsers, allowlists, content-type checks, decoders, AST/shell parsers), ask: does an input exist that the validator ACCEPTS but the downstream consumer interprets differently? Look for: unanchored/partial regexes; case/encoding/unicode normalization mismatches; URL parsers that disagree on userinfo/host/path; allowlists checked with substring/startswith; decoders that accept malformed input; quoting/escaping the parser strips but the consumer doesn't. The finding is the differential itself — name both sides.

**Phase 2c — High-miss patterns.** Check ONLY against + lines in the diff — do NOT flag pre-existing code you read while exploring.
- SENSITIVE-TO-OBSERVABILITY: a + line emits to a log/trace/span/metric/exception-message sink. Trace EVERY field (including URLs, paths, error-object .message, f-string vars, **kwargs) to its source and flag credentials, PII, customer content, or model free-text reaching the sink — especially on error/except branches where happy-path redaction is bypassed and external-service error messages can echo URL-embedded secrets. Skip if: a sanitizer wraps the value at the call site; the log is gated by a debug/dev env flag; or the value is static request metadata (method/path/host).
- IaC OMITTED ARG: a + line instantiates a Terraform/Pulumi/CDK module and OMITS an optional security-relevant arg — read the module's variables and check whether the default is the secure value.
- CI/CD TRUST: + lines add or change a GitHub Actions trigger to workflow_dispatch / repository_dispatch / pull_request_target without a branches: filter, AND the job reads secrets or has write permissions.
- ALLOWLIST SEMANTIC ESCAPE: + lines add an entry to a safe-command/safe-endpoint/capability allowlist OR add a `||` disjunct to a permission matcher OR edit a validator that gates exec/eval/subprocess. Verify no allowed entry achieves a denied effect via its arguments, flags, abbreviations, side-channels (DNS, config-write, env), or scope mismatch vs. enforcement (e.g., allowlist matches argv[0] but consumer reads full argv).
- OVER-BROAD GRANT: when + lines add a principal/identity to a broad-scope permission (global/service-wide allowlist, standing admin role binding, reuse of another principal's credential), check whether the SAME changed file or its immediate module already exposes a narrower-scope mechanism for the same need (per-resource/per-RPC allowlist, break-glass/2PC role, dedicated principal). If it does, the broad grant is the finding. Do NOT flag if no narrower mechanism is visible in the changed files.
- STALE IDENTITY MAPPING: + lines change teardown/unregister of an identity primitive (hostname/DNS, IP, service route, lease, auth token, service-registry entry) where a window leaves it resolvable to the wrong tenant. NOT in-process data caches.
- CONTROL REGRESSION: when - lines DELETE a fail-closed validator (allowlist returning False by default, _is_safe_*, deny-by-default) and + lines replace it with a single condition, the replacement IS the finding.
- FAIL-OPEN STATE DRIFT: when a security decision reads parsed/cached/tracked/callback state, verify error, cancellation, TOCTOU, cache-skew, and unhandled-variant paths do not yield a default that skips enforcement — broad-except→pass, unwrap_or({}), missing-finally cleanup, ignored verifier params, or stale validator maps all fail open. The finding is the path where the fallback value is the allow outcome. Also: when + lines compare against a security threshold, check whether the EXACT boundary value yields the permissive branch; when an error path triggers retry/redelivery, check whether the retry can emit a decision that overrides a stricter first decision; when sync logic reads persisted state, check whether state surviving a data wipe causes destructive sync.
- SECURITY-REGISTRY FANOUT: when + lines add a new entity (field, enum value, credential type, alias, model variant, port, scope), search unchanged files for every security registry keyed on that entity class — sanitizer field-lists, redaction sets, revocation handlers, strip denylists, capability allowlists, translation maps — and flag if the new entry is missing from any. Conversely, when + lines ADD entries to such a registry, search for where that registry is consumed and verify each new entry's literal matches the consumer's key format (namespace prefix, case, composite key) — a mismatched entry is a silent no-op that defeats the control.
- GATE/ACTION FIELD MISMATCH: when + lines add or modify an authorization/policy check, identify which request field(s) the gate reads vs which field(s) the downstream operation uses to select the target resource. If they differ (gate checks `parent`, action derives target from `name`; gate checks org A, action writes to org from a separate param), the gate is bypassable.
- RESOURCE-BOUND PLACEMENT: when + lines parse/decompress/fetch/loop over attacker-influenced input, verify size/time/count caps guard the ACTUAL peak allocation — not a post-flush output, post-decompress buffer, per-iteration (not total) timeout, unclamped arithmetic (subtraction underflow, multiplication overflow), or first-element-only invariant. The finding is the cap defeat, not the DoS itself.
- UNDER-VALIDATED SINK ARG: when + lines interpolate any externally-influenced value (incl. IPC, VCS-checkout content, env var, model output, domain-syntax strings) into a shell/path/loader/URI/structured-format sink, verify quoting, traversal/UNC/symlink stripping, and prod-mode guards apply to THIS arg — existing validators on sibling args do not cover it.

**Phase 3 — Assess.**
Report when you can name (a) the source, (b) the sink, (c) the path with no effective mitigation. Medium-confidence is fine — stage 2 will filter; your job is RECALL, not precision. Do report logic/authorization bugs (missing ownership check, inverted condition, parser differential) even when no classic "sink" is involved.

Do NOT report: missing best-practice/hardening with no concrete impact, test/mock files, outdated deps, or volumetric DoS (attacker just sends a lot). DO report DoS when the diff introduces a code defect that defeats an existing resource cap (cap on wrong accumulator, dead timeout handler, unclamped arithmetic, encoding amplification at flush) — those are logic errors with security impact.

Distrust safety claims in comments ("validated upstream", "internal only"). Verify in code.

Keep scanning after the first finding. Do NOT emit findings until you have read EVERY touched file at least once — a more obvious pattern in file A does not excuse skipping file B. Aim for at least one candidate or explicit "no sink" verdict per touched file.

Budget your tool calls: read the changed files first, then 3–5 targeted searches for callers/sinks. Do NOT exhaustively explore the repo — once you can name source→sink for each candidate (or rule it out), STOP. Partial findings are better than none.

**Candidate record format** — for each candidate keep: `filePath`, `category`, `vulnerableCode` (exact lines), `explanation` (source → sink → exploit path), `fix` (concrete), `severity` (`critical` / `high` / `medium` / `low`), `confidence` (0–1).

## Stage 2 — Self-refute (precision)

For every candidate from stage 1, adversarially try to DISPROVE it. Default = SURVIVES unless you find concrete refuting evidence.

First identify the attacker (who controls the input) and the victim (who is harmed). REFUTE if the only victim is the attacker themselves on their own machine. KEEP if the attacker is a legitimate user/tenant but the impact reaches other users/tenants, shared infra, or server-side resources.

Tag each candidate `in_diff` when its `vulnerableCode` appears on a `+` line of the diff, otherwise `off_diff`. Process in_diff candidates first with the standard bar. `off_diff` candidates require STRICTER evidence: you must identify the specific +/- line in the diff that ENABLES the off-diff sink (a removed guard, a new caller, a changed argument feeding it). If you cannot name that enabling diff line, REFUTE the off_diff candidate. Additionally, REFUTE any off_diff candidate whose sink is already covered by a surviving in_diff candidate.

Then read the cited file and REFUTE with cited file:line evidence if ANY of these holds:
- **PRE-EXISTING**: the cited vulnerableCode does NOT appear on any + line in the diff — it is unchanged context in a touched file. The diff did not introduce it.
- A sanitizer/validator/authz check prevents the described exploit.
- The sink is non-dangerous: typed-schema decoder (msgspec/pydantic, not pickle/yaml), hardcoded `https://<host>/` URL with non-:path params, autogen client stub, value is statically number/boolean.
- **NO PRIVILEGE BOUNDARY**: attacker == victim. The input comes from env var / CLI arg / $HOME dotfile / HKCU / `~/Library` prefs / OS-user config — and the process runs at the same privilege as whoever writes that source. Also: the 'allow' decision is advisory self-gating returned to the same caller; or the prefix/suffix check is a secondary filter behind a parent-domain pin.
  - NEVER apply NO-PRIVILEGE-BOUNDARY to: SSRF/outbound-network sinks; LLM-agent capability gates (tool hooks, bash allow/denylists, workspace path jails — the model is the attacker, the user is the victim); data-exposure findings (CWE-200/359/532, secrets-in-logs — the question is who READS the sink, not who controls the input); project-working-directory config (settings files, `.vscode/`, `package.json` scripts — repo author ≠ repo cloner); cross-process metadata sources (`psutil.Process(...)`, `/proc/<pid>/*` — different process owner is a different principal).
- **TRUSTED-HEADER NAMESPACE**: the flagged header is from a namespace the same handler already trusts for actor identity/authz (e.g. control-plane-injected `X-Amzn-*`).
- **FRONTEND-ONLY GATE**: the loosened check is in frontend code AND the backend handler independently enforces it.
- **DELEGATED VALIDATION**: the unvalidated credential is immediately forwarded to an upstream that validates.
- **THROWAWAY-CODE**: all touched files live under `scripts/`, `dev/`, `tools/`, `examples/`, `testdata/`, `fixtures/`, or behind a `__main__` dev guard.
- **CONTROL MOVED TO LIBRARY**: the diff removes a security control AND bumps a dependency that documents providing that control — the control was delegated, not removed.
- Config/feature-flag gates the path with no per-request user control over the gate value.
- **Protective-control polarity**: the change loosens a guard around a PROTECTIVE control (prompt/audit/confirm).

Do NOT speculate — refute only with cited evidence. Default = SURVIVES.

## Reporting survived findings

Group survived findings by file, ordered by severity (critical → high → medium). For each:

```
[SEVERITY] [category] filePath
  vulnerableCode: <exact lines>
  Explanation: <source → sink → exploit path>
  Suggested fix: <concrete fix>
```

Present them to the user, fix them before committing (unless the user explicitly asked for the risky pattern and the tradeoff was already surfaced), and briefly note any candidate you refuted and why when the user might otherwise expect it flagged.

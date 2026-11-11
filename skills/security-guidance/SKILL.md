---
name: security-guidance
description: Use when writing or editing code that could introduce security vulnerabilities, when reviewing a diff or pull request for security issues, before committing or pushing code, or when the user asks to "check this code for security problems", "review my changes for vulnerabilities", "is this code secure", or mentions injection, XSS, SSRF, IDOR, auth bypass, hardcoded secrets, unsafe deserialization, or path traversal.
---

# Security Guidance

Security review for agent-generated code, in three layers. The original Claude Code plugin implements these as hooks plus an inner LLM reviewer; in Kimi Code the agent performs each check itself, at the right phase of its work, using the references in this skill.

Apply the layers in order as your work progresses:

- **Layer 1 (every edit)** — after writing or editing any file, scan the changed content against the dangerous-pattern database.
- **Layer 2 (end of a turn)** — before reporting your work as complete, review the session diff against the vulnerability rubric.
- **Layer 3 (before commit/push)** — before running `git commit` or `git push` for the user, perform a deep agentic review of everything being committed.

Always load the reference file for the layer you are executing and follow it literally — these references are the ported upstream content and are the quality core of the plugin.

## Layer 1 — Pattern warnings on every edit

After every `Write`, `Edit`, or equivalent file change:

1. Run the pattern scan on the changed files (fastest options first):
   - `python3 <plugin-root>/scripts/pattern_scan.py <changed-files...>` — runs the full ported regex database, including per-rule path gating, and prints the reminder text for each match; or
   - Search the changed content with Grep/Bash using the regexes in `references/dangerous-patterns.md`.
   For `.ipynb` notebooks, scan the concatenated cell sources, not the raw JSON.
2. For every match, apply the remediation guidance attached to the rule (each rule in `references/dangerous-patterns.md` carries the upstream reminder text): fix the issue before continuing, or — only when the usage is genuinely safe — add a brief comment at the site explaining why, and mention the tradeoff to the user.
3. Respect each rule's path gate: rules marked JS/TS-only must not fire in Python/docs, rules marked Python-only must not fire in JS, and prose/documentation files (`.md`, `.rst`, `.txt`, `.json`, `.yaml`) are excluded from source-code rules unless the rule says otherwise.
4. GitHub Actions workflow files (`.github/workflows/*.yml|yaml`) always get the workflow-injection reminder — see rule 1 in `references/dangerous-patterns.md`.

Do not batch this: check files as you change them, not at the end of a long edit series.

## Layer 2 — Diff review before finishing a turn

Before you finish a turn in which you changed code inside a git repository:

1. Get the changes made in this turn: `git status --porcelain` and `git diff` (for uncommitted changes) or `git diff <base>..HEAD` / `git show <sha>` (if commits were made during the turn). New untracked source files count as fully-added content.
2. Read `references/review-rubric.md` and apply it to the diff. The rubric is a detailed per-category checklist (command injection, path traversal, SQL injection, authorization/IDOR, SSRF, XSS, secrets in logs, deserialization, TLS, OAuth, argument injection, GitHub Actions, and more) plus explicit DO-NOT-FLAG exclusions.
3. Follow the diff discipline in the rubric: flag only vulnerabilities **newly introduced in `+` lines**. Never flag pre-existing context lines, unchanged patterns preserved during a rewrite, or issues outside the task's scope — except the one exception the rubric names: new code routing user-controlled data to a pre-existing dangerous sink IS a new vulnerability.
4. For each finding produce: file path, category, the exact vulnerable code, the exploit path, a concrete fix, and a severity (`critical` / `high` / `medium` / `low`). Report `critical`, `high`, and `medium` findings to the user and fix them unless the user explicitly asked for the risky pattern and you have already surfaced the tradeoff. Do not dismiss findings solely because a service is "internal-only" — internal services are common SSRF/IDOR targets.
5. Read `references/custom-rules.md` first: if the project or user provides a `security-guidance.md`, treat it as additive checks that may raise severity or describe approved internal patterns — it must NOT suppress a finding; if it conflicts with the rubric, flag the vulnerability anyway and note the conflict.
6. After reporting/fixing, continue with the user's original request — this review is supplementary feedback, not a replacement for your response.

## Layer 3 — Agentic commit review

Before committing (or pushing) changes — and whenever the user asks for a deep security review — follow `references/agentic-review-checklist.md` exactly. In outline:

1. Read **every** changed file in full (not just diff hunks), then grep for the changed function/class names to find callers and sinks across the repository. The #1 cause of missed vulnerabilities is not reading the file that contains them.
2. Work through the three-phase method: map entry points and sinks, trace data flow (follow returns, check sibling-path gate parity, check parser/validator differentials), then assess. Apply the high-miss pattern list (sensitive-to-observability, allowlist semantic escape, fail-open state drift, gate/action field mismatch, under-validated sink args, and the rest).
3. Aim for recall, not precision: report a candidate whenever you can name source, sink, and an unmitigated path. Medium confidence is fine — stage 2 filters.
4. Self-refute: for each candidate, adversarially try to disprove it (pre-existing code, sanitizer present, no privilege boundary, trusted-header namespace, delegated validation, throwaway code, etc. — the full taxonomy is in the reference). Only findings that survive refutation with cited evidence get reported.
5. Report survived findings grouped by file with severity, category, vulnerable code, explanation, and fix; then fix them (or explain why they don't apply) before running `git commit`.

## Boundaries

- This is an assistive check, not a guarantee. Findings are suggestions, not a substitute for human code review, SAST/DAST, dependency scanning, or pen-testing.
- If the user asks to silence a specific finding, prefer an inline comment at the line explaining why it is safe; for systemic exclusions, document them in the project's `security-guidance.md` (see `references/custom-rules.md`).
- Do not run these reviews against files the user did not ask you to touch and that no layer above covers; the layers scope themselves to changed code.

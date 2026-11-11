# kimi-security-guidance-plugin

**Security review for agent-generated code — from [Kimi Code](https://www.kimi.com/code): regex pattern warnings on every edit, a vulnerability rubric applied to your session diff, and a deep agentic commit review across OWASP vulnerability classes.**

The security-guidance plugin Anthropic ships for Claude Code (`security-guidance@claude-plugins-official`, by David Dworken), repackaged as a Kimi Code plugin. The pattern database, the review rubric, and the agentic review checklist are ported verbatim (Apache-2.0); what were Claude Code hooks and an inner Claude Agent SDK reviewer become instructions the agent applies itself.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform: macOS / Windows / Linux](https://img.shields.io/badge/Platform-macOS%20%2F%20Windows%20%2F%20Linux-black.svg)]()
[![Kimi Code](https://img.shields.io/badge/Kimi%20Code-plugin-orange.svg)](https://www.kimi.com/code/docs/en/kimi-code-cli/customization/plugins.html)

## Why

Agents write code fast — including insecure code. The upstream security-guidance plugin is one of the best security-review integrations available for coding agents, but it only works in Claude Code: it relies on PreToolUse/PostToolUse/Stop hooks and an inner Claude Agent SDK reviewer.

This port keeps the substance — the 25-pattern regex database, the ~40-category vulnerability rubric, the two-stage investigate → self-refute agentic review — and turns the hook machinery into a skill the agent follows at the right moments. No hooks, no SDK, no API keys, no external model calls: every check runs inside your normal agent session.

## Features

| Layer | When | What it does |
|---|---|---|
| Pattern warnings | Every file edit/write | Scans changed content against 25 known-dangerous patterns (`yaml.load`, `pickle.loads`, `torch.load` without `weights_only=True`, raw `innerHTML`, `dangerouslySetInnerHTML`, `os.system`, `subprocess shell=True`, disabled TLS verification, ECB-mode AES, GitHub Actions workflow injection, missing SRI, …) and applies the attached remediation guidance |
| Diff review | End of a turn | Reviews the session's `git diff` against a detailed rubric — command injection, path traversal, SQL injection, IDOR/authorization, SSRF, XSS, secrets in logs, unsafe deserialization, OAuth flow weaknesses, argument injection, IAM/RBAC, and more — flagging only newly introduced issues with severity and a concrete fix |
| Agentic commit review | Before `git commit` / `git push` | Deep review: reads every changed file in full, traces data flow across the repository (callers, sanitizers, sibling handlers), checks high-miss patterns (gate/action field mismatch, allowlist semantic escape, fail-open state drift), then adversarially self-refutes each candidate finding before reporting |
| Custom rules | Always | Project/user `security-guidance.md` policy files and `security-patterns.json` custom regex rules (additive checks, never suppressive) |

## Install

In any Kimi Code session:

```
/plugins install https://github.com/mnshkv/kimi-security-guidance-plugin
```

Then `/plugins reload` (or start a new session).

## Usage

No commands to learn — just work, and ask:

- "Add a config loader for this service" — the agent pattern-scans every file it edits (Layer 1).
- "Review my changes for security issues" — explicit diff review over the session's changes (Layer 2).
- "Commit this" — before committing, the agent runs the deep agentic review and fixes what survives (Layer 3).
- "Check this code for SQL injection / XSS / SSRF / hardcoded secrets" — targeted review against the rubric's categories.

## How it works

```
Kimi Code agent
  ├─ edits a file ─────────▶ scripts/pattern_scan.py (or Grep)
  │                            └─ 25 regex rules + custom security-patterns.json
  ├─ finishes a turn ──────▶ references/review-rubric.md applied to git diff
  │                            └─ ~40 vulnerability categories + DO-NOT-FLAG exclusions
  └─ before commit/push ───▶ references/agentic-review-checklist.md
                               └─ investigate (recall) → self-refute (precision)
```

The skill `security-guidance` (`skills/security-guidance/SKILL.md`) instructs the agent when to run each layer. Everything is local: the scanner is a single dependency-free Python 3 file (`python3 scripts/pattern_scan.py <files...>`), and the review references are markdown the agent reads and applies with its own file/search tools.

**Org-specific policies.** Drop a `security-guidance.md` (policy notes appended to every review) or `security-patterns.json` (custom regex rules) in `~/.kimi/` or `<project>/.kimi/` — see `skills/security-guidance/references/custom-rules.md`. Policy files can add checks but cannot suppress findings.

## Differences from the original

This is a faithful content port, not a mechanical one. What changed, honestly:

- **No hooks.** The upstream plugin is a set of Claude Code hooks (UserPromptSubmit, PostToolUse, Stop, asyncRewake). Kimi Code has no hook API, so the checks become skill instructions the agent applies at the corresponding moments: after edits, before finishing a turn, before committing. The agent can decline or forget; the original could not.
- **No inner LLM reviewer / Claude Agent SDK.** The upstream runs reviews through a separate Opus model call (or an SDK-driven subagent) with its own credentials, model selection, timeouts, and cost. Here the reviewing model is the agent you are already talking to — no extra API keys, no extra cost, no data leaving your session beyond what your provider already sees.
- **No telemetry.** All metrics, usage logging, debug logs, rate limits, and session state files are gone.
- **Custom rule discovery is adapted.** `~/.claude/claude-security-guidance.md` and `.claude/` project files are still read, but the primary locations are `~/.kimi/` and `.kimi/`; custom patterns standardize on JSON (the upstream also accepts YAML — install PyYAML and extend `pattern_scan.py` if you need it).
- **Everything else is ported.** All 25 patterns verbatim (regexes, path gates, reminder texts), the complete review rubric, the full investigate/self-refute agentic method, the diff discipline (only `+` lines, the pre-existing-sink exception), and the false-positive exclusions.

The upstream Python hook implementation (~13k lines across 11 files: git baseline tracking, reflog SHA resolution, inflight review races, Windows launcher probes, …) implements *when and how reliably* the checks fire inside Claude Code — none of that applies here and it was not ported.

## Limitations

This is an assistive check, not a guarantee. Findings are suggestions, not a substitute for human code review, SAST/DAST, dependency scanning, or pen-testing. The reviewer can miss vulnerabilities and can produce false positives.

## License & attribution

- Upstream: [security-guidance](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance) by David Dworken / Anthropic — the pattern database, review rubric, and agentic review prompts are ported from it under the [Apache License 2.0](LICENSE).
- Port: © mnshkv, also Apache-2.0.

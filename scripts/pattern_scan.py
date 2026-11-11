#!/usr/bin/env python3
"""
Regex-based security pattern scanner — ported from the upstream
security-guidance plugin's hooks/patterns.py + hooks/extensibility.py
(David Dworken / Anthropic, Apache-2.0).

Pure data + a pure helper, plus a __main__ runner so the agent can scan
edited files directly:

    python3 pattern_scan.py path/to/file1 [path/to/file2 ...]

For every match the rule's reminder text is printed. Exit code is the
number of rules that fired (capped at 100), 0 when clean — so it is
scriptable while still readable as a human checklist.

Custom rules: security-patterns.json in ~/.kimi/ or <project>/.kimi/
(see skills/security-guidance/references/custom-rules.md).
"""
import fnmatch
import json
import os
import re
import sys

_JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte")
_PY_EXTS = (".py", ".pyi", ".ipynb")
_DOC_EXTS = (".md", ".mdx", ".txt", ".rst", ".json", ".yaml", ".yml")

_UNSAFE_DESERIALIZATION_REMINDER = """⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.

For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.

If this is safe or is explicitly needed, briefly document that in a comment before continuing."""

_UNSAFE_YAML_LOAD_REMINDER = """⚠️ Security Warning: yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.

Use yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types."""

_UNSAFE_TORCH_LOAD_REMINDER = """⚠️ Security Warning: torch.load() defaults to weights_only=False, which unpickles arbitrary Python objects and allows arbitrary code execution.

If the file only contains tensors and simple data structures, pass weights_only=True (or set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1)."""

# Security patterns configuration. Each entry: ruleName, optional
# path_filter (gate: rule applies only to matching paths), optional
# path_check (positive match condition on the path), optional substrings
# and/or regex matched against content, and reminder (printed on match).
SECURITY_PATTERNS = [
    {
        "ruleName": "github_actions_workflow",
        "path_check": lambda path: ".github/workflows/" in path
        and (path.endswith(".yml") or path.endswith(".yaml")),
        "reminder": """⚠️ Security Warning: You are editing a GitHub Actions workflow file. Be aware of these security risks:

1. **Command Injection**: Never use untrusted input (like issue titles, PR descriptions, commit messages) directly in run: commands without proper escaping
2. **Use environment variables**: Instead of ${{ github.event.issue.title }}, use env: with proper quoting
3. **Review the guide**: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/

Example of UNSAFE pattern to avoid:
run: echo "${{ github.event.issue.title }}"

Example of SAFE pattern:
env:
  TITLE: ${{ github.event.issue.title }}
run: echo "$TITLE"

Other risky inputs to be careful with:
- github.event.issue.body
- github.event.pull_request.title
- github.event.pull_request.body
- github.event.comment.body
- github.event.review.body
- github.event.review_comment.body
- github.event.pages.*.page_name
- github.event.commits.*.message
- github.event.head_commit.message
- github.event.head_commit.author.email
- github.event.head_commit.author.name
- github.event.commits.*.author.email
- github.event.commits.*.author.name
- github.event.pull_request.head.ref
- github.event.pull_request.head.label
- github.event.pull_request.head.repo.default_branch
- github.event.client_payload.* (repository_dispatch events — attacker can set any field)

4. **Ref injection**: Never use untrusted input in `ref:` parameters of `actions/checkout`. For `client_payload.pr_number`, validate it matches `^[0-9]+$` before using in `ref: refs/pull/${{ ... }}/head`
- github.head_ref""",
    },
    {
        "ruleName": "child_process_exec",
        # Gate to JS/TS files — bare `exec(` otherwise fires on Python's
        # exec() and on prose/docstrings mentioning exec.
        "path_filter": lambda p: p.endswith(_JS_EXTS),
        "substrings": ["child_process.exec", "execSync("],
        "regex": r"(?<![a-zA-Z0-9_\.])exec\(",
        "reminder": """⚠️ Security Warning: Using child_process.exec() can lead to command injection vulnerabilities.

exec() runs the command string through a shell, so any user input interpolated into it can inject arbitrary commands. Prefer child_process.execFile() (or spawn()) with an argument array instead of building a shell string.

Instead of:
  exec(`command ${userInput}`)

Use:
  import { execFile } from 'node:child_process'
  execFile('command', [userInput], callback)

Why execFile/spawn with an argument array is safer:
- No shell is involved, so shell metacharacters in arguments are not interpreted
- Arguments are passed directly to the program rather than interpolated into a command string

Only use exec() if you absolutely need shell features and the input is guaranteed to be safe.""",
    },
    {
        "ruleName": "new_function_injection",
        # JS-only construct: gate to JS/TS files so docs/.md and other prose
        # mentioning "new Function" don't trip the warning.
        "path_filter": lambda p: p.endswith(_JS_EXTS),
        "substrings": ["new Function"],
        "reminder": "⚠️ Security Warning: Using new Function() with string interpolation is a CODE INJECTION vulnerability. If any variable is concatenated or interpolated into the function body string, an attacker controlling that variable can execute arbitrary code. Use safe alternatives: for property access use obj[key] or array.reduce((o, k) => o[k], root); for computation use a safe expression parser. NEVER interpolate untrusted strings into new Function() bodies.",
    },
    {
        "ruleName": "eval_injection",
        # Lookbehind excludes `.` so method calls like PyTorch model.eval(),
        # redis.eval(), spec.eval() don't match. Skip doc/prose files.
        "path_filter": lambda p: not p.endswith(_DOC_EXTS),
        "regex": r"(?<![a-zA-Z0-9_\.])eval\(",
        "reminder": "⚠️ Security Warning: eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data, ast.literal_eval() for Python literals, or a safe expression parser. If this is safe or is explicitly needed, briefly document that in a comment before continuing.",
    },
    {
        "ruleName": "react_dangerously_set_html",
        # JS/TS-only (React); gate so .md docs / .py / .go files don't trip.
        "path_filter": lambda p: p.endswith(_JS_EXTS),
        "substrings": ["dangerouslySetInnerHTML"],
        "reminder": "⚠️ Security Warning: dangerouslySetInnerHTML can lead to XSS vulnerabilities if used with untrusted content. Ensure all content is properly sanitized using an HTML sanitizer library like DOMPurify, or use safe alternatives.",
    },
    {
        "ruleName": "document_write_xss",
        # Browser DOM API: only meaningful in JS/TS source.
        "path_filter": lambda p: p.endswith(_JS_EXTS),
        "substrings": ["document.write"],
        "reminder": "⚠️ Security Warning: document.write() can be exploited for XSS attacks and has performance issues. Use DOM manipulation methods like createElement() and appendChild() instead.",
    },
    {
        "ruleName": "innerHTML_xss",
        # Browser DOM API: only meaningful in JS/TS source. Closes FPs like
        # docs/example HTML that hardcode innerHTML strings with zero user input.
        "path_filter": lambda p: p.endswith(_JS_EXTS),
        "substrings": [".innerHTML =", ".innerHTML="],
        "reminder": "⚠️ Security Warning: Setting innerHTML with untrusted content can lead to XSS vulnerabilities. Use textContent for plain text or safe DOM methods for HTML content. If you need HTML support, consider using an HTML sanitizer library such as DOMPurify.",
    },
    {
        "ruleName": "pickle_deserialization",
        # Match deserialization only (load/loads/Unpickler). pickle.dump is
        # not the RCE surface. `pkl_load` needs a word boundary so similarly
        # named safe loaders don't match.
        "path_filter": lambda p: p.endswith(_PY_EXTS),
        "regex": r"(?<![a-zA-Z0-9_])pickle\.(loads?|Unpickler)\b|(?<![a-zA-Z0-9_])pkl_load\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "os_system_injection",
        "path_filter": lambda p: p.endswith(_PY_EXTS),
        "regex": r"\bos\.system\s*\(",
        "substrings": ["from os import system"],
        "reminder": "⚠️ Security Warning: os.system() runs a shell and is a command-injection sink. Use subprocess.run([...]) with a list of arguments instead. If this is safe or is explicitly needed, briefly document that in a comment before continuing.",
    },
    {
        "ruleName": "python_subprocess_shell",
        "regex": r"subprocess\.(?:run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True",
        "reminder": """⚠️ Security Warning: Using subprocess with shell=True enables command injection.

UNSAFE:
  subprocess.run(f"ls {user_input}", shell=True)
  subprocess.call("grep " + pattern, shell=True)

SAFE - pass arguments as a list without shell:
  subprocess.run(["ls", user_input])
  subprocess.call(["grep", pattern])

When arguments are passed as a list without shell=True, special characters cannot be interpreted as shell metacharacters.""",
    },
    # =====================================================================
    # Go-specific security patterns
    # =====================================================================
    {
        "ruleName": "go_exec_shell_injection",
        # Detect exec.Command with shell invocation (sh, bash, /bin/sh, /bin/bash)
        "regex": r'exec\.Command\(\s*"(?:sh|bash|/bin/sh|/bin/bash)"',
        "reminder": """⚠️ Security Warning: Using exec.Command with a shell interpreter (sh/bash) enables command injection.

UNSAFE:
  exec.Command("sh", "-c", "ping -c 1 " + host)
  exec.Command("bash", "-c", fmt.Sprintf("df -h %s", path))

SAFE - pass arguments directly without a shell:
  exec.Command("ping", "-c", "1", host)
  exec.Command("df", "-h", path)

When arguments are passed directly (not through a shell), special characters in user input cannot be interpreted as shell metacharacters. This prevents command injection entirely.

Additionally, validate user inputs:
- For hostnames/IPs: use net.ParseIP() or a hostname regex
- For file paths: use filepath.Clean() and verify the result is within an allowed directory
- For numeric values: parse to int/float first""",
    },
    {
        "ruleName": "unsafe_yaml_load",
        "regex": r"\byaml\.load\s*\((?![^)\n]{0,80}\bSafe)",
        "reminder": _UNSAFE_YAML_LOAD_REMINDER,
    },
    {
        "ruleName": "node_createcipher_no_iv",
        "regex": r"\bcrypto\.(createCipher|createDecipher)\b",
        "reminder": "⚠️ Security Warning: Use crypto.createCipheriv() / createDecipheriv(). createCipher was removed in Node 22 and derives the key insecurely (no IV, MD5-based KDF).",
    },
    {
        "ruleName": "aes_ecb_mode",
        "regex": r"\bAES\.MODE_ECB\b|\bmodes\.ECB\s*\(|[\x22\x27]aes-\d+-ecb[\x22\x27]",
        "reminder": "⚠️ Security Warning: Use AES-GCM or AES-CBC with HMAC. ECB mode leaks plaintext structure (identical blocks encrypt to identical ciphertext).",
    },
    {
        "ruleName": "tls_verification_disabled",
        "regex": r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\x22\x27]?0|ssl\._create_unverified_context|check_hostname\s*=\s*False",
        "reminder": "⚠️ Security Warning: Don't disable TLS verification. This allows MITM attacks. For self-signed dev certs, add the CA to your trust store or use a properly-issued cert.",
    },
    {
        "ruleName": "marshal_loads",
        "regex": r"\bmarshal\.loads?\s*\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "shelve_open",
        "regex": r"\bshelve\.open\s*\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "xml_unsafe_parse",
        "regex": r"\b(xml\.etree\.ElementTree|ElementTree|ET)\.(parse|fromstring|XML)\s*\(|\bminidom\.(parse|parseString)\s*\(|\bxml\.sax\.(parse|make_parser)\b",
        "reminder": "⚠️ Security Warning: Use defusedxml.ElementTree. Python's stdlib XML parsers are vulnerable to XXE (external entity) and billion-laughs attacks by default.",
    },
    {
        "ruleName": "pickle_variants_load",
        "regex": r"\b(cPickle|cloudpickle|dill)\.(load|loads)\s*\(",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
    {
        "ruleName": "outerHTML_xss",
        # Browser DOM API: only meaningful in JS/TS source.
        "path_filter": lambda p: p.endswith(_JS_EXTS),
        "substrings": [".outerHTML =", ".outerHTML="],
        "reminder": "⚠️ Security Warning: Use textContent or sanitize with DOMPurify. outerHTML assignment is an XSS sink equivalent to innerHTML.",
    },
    {
        "ruleName": "insertAdjacentHTML_xss",
        # Browser DOM API: only meaningful in JS/TS source.
        "path_filter": lambda p: p.endswith(_JS_EXTS),
        "substrings": [".insertAdjacentHTML("],
        "reminder": "⚠️ Security Warning: Use insertAdjacentText() or sanitize with DOMPurify. insertAdjacentHTML is an XSS sink.",
    },
    {
        "ruleName": "script_src_without_sri",
        # Detect remote code execution via dynamic import/eval of fetched content.
        # Negative lookahead after src checks for integrity= anywhere in the remaining tag.
        "regex": (
            r"<script\s+(?![^>]{0,400}integrity\s*=)"
            r"[^>]{0,200}src\s*=\s*[\x22\x27](?:https?:)?//"
            r"[^\x22\x27]{1,300}[\x22\x27]"
            r"[^>]{0,100}>"
        ),
        "reminder": '⚠️ Security Warning: Add integrity="sha384-..." crossorigin="anonymous" to external script tags. Loading scripts without Subresource Integrity exposes you to CDN compromise.',
    },
    {
        "ruleName": "torch_unsafe_load",
        # Suppressed by weights_only=True on the same line (within 200 chars). weights_only=False
        # still triggers. Multi-line calls false-positive — same known limitation as unsafe_yaml_load.
        "regex": r"(?:\btorch\.load|\.torch_load)\s*\((?![^)\n]{0,200}weights_only\s*=\s*True)",
        "reminder": _UNSAFE_TORCH_LOAD_REMINDER,
    },
    {
        "ruleName": "yaml_unsafe_load_variants",
        # yaml.unsafe_load (stdlib alias) plus unsafe wrapper method names seen in the wild.
        # Bare yaml.load() is unsafe_yaml_load's job.
        "regex": r"(?:\byaml\.unsafe_load|\.yaml_unsafe_load)\s*\(",
        "reminder": _UNSAFE_YAML_LOAD_REMINDER,
    },
    {
        "ruleName": "pickle_wrapper_load",
        # Library APIs that unpickle without saying "pickle". numpy.load only triggers
        # when allow_pickle=True is explicit (defaults to False since numpy 1.16.3).
        "regex": r"\bjoblib\.load\s*\(|\b(?:pd|pandas)\.read_pickle\s*\(|\.cloudpickle_load\s*\(|\b(?:np|numpy)\.load\s*\([^)\n]{0,200}allow_pickle\s*=\s*True",
        "reminder": _UNSAFE_DESERIALIZATION_REMINDER,
    },
]


# ---------------------------------------------------------------------------
# Custom rules (security-patterns.json) — ported from hooks/extensibility.py
# ---------------------------------------------------------------------------

PATTERN_MAX_RULES = 50
PATTERN_REMINDER_MAX_BYTES = 1024

# Catastrophic-backtracking shapes, same static check as upstream.
_REDOS_SHAPES = [
    re.compile(r"\([^()]*[+*][^()]*\)[+*?]"),  # nested quantifier: (a+)*  (a*b)*
    re.compile(r"\(\.\*[^()]*\)[+*]"),         # wildcard group: (.*)*
]
_ALT_UNDER_REP = re.compile(r"\(([^()]*)\|([^()|]*)(?:\|[^()]*)*\)[+*]")


def _has_redos_structure(regex):
    """Heuristic catastrophic-backtracking check. Not a proof. Catches:
      - nested quantifiers ((a+)*, (a*b)+)
      - wildcard groups under repetition ((.*)*)
      - alternation under repetition where one branch is a prefix of another
        ((a|aa)*, (ab|a)*) — these overlap and explode on non-matching input.
    Does NOT flag non-overlapping alternation ((a|b)*) which is safe."""
    if any(p.search(regex) for p in _REDOS_SHAPES):
        return True
    for m in _ALT_UNDER_REP.finditer(regex):
        branches = [b for b in m.group(0).strip("()*+").split("|") if b]
        for i, a in enumerate(branches):
            for b in branches[i + 1:]:
                if a.startswith(b) or b.startswith(a):
                    return True
    return False


def _glob_match(path, include, exclude):
    """Match a path against include/exclude globs. ``**`` matches any depth."""
    norm = path.replace(os.sep, "/")
    base = os.path.basename(norm)

    def _hit(globs):
        return any(fnmatch.fnmatch(norm, g) or fnmatch.fnmatch(base, g) for g in globs)

    if include and not _hit(include):
        return False
    if exclude and _hit(exclude):
        return False
    return True


def _config_dirs(cwd):
    """User config dirs, then project dirs (lowest precedence first)."""
    dirs = [os.path.expanduser(os.path.join("~", ".kimi"))]
    claude_dir = os.path.expanduser(os.path.join("~", ".claude"))
    if os.path.isdir(claude_dir) and not _same_dir(claude_dir, dirs[0]):
        dirs.append(claude_dir)
    if cwd:
        dirs.append(os.path.join(cwd, ".kimi"))
        dirs.append(os.path.join(cwd, ".claude"))
    return dirs


def _same_dir(a, b):
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def load_user_patterns(cwd=None):
    """Custom rules from security-patterns.json (see custom-rules.md)."""
    rules = []
    for d in _config_dirs(cwd):
        for name in ("security-patterns.json", "security-patterns.local.json"):
            if len(rules) >= PATTERN_MAX_RULES:
                return rules[:PATTERN_MAX_RULES]
            path = os.path.join(d, name)
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, ValueError):
                continue
            entries = data.get("patterns") if isinstance(data, dict) else None
            if not isinstance(entries, list):
                continue
            for entry in entries:
                rule = _validate_pattern(entry)
                if rule:
                    rules.append(rule)
    return rules[:PATTERN_MAX_RULES]


def _validate_pattern(entry):
    if not isinstance(entry, dict):
        return None
    name = str(entry.get("rule_name", "")).strip()
    reminder = str(entry.get("reminder", "")).strip()
    if not name or not reminder:
        return None
    if len(reminder) > PATTERN_REMINDER_MAX_BYTES:
        reminder = reminder[:PATTERN_REMINDER_MAX_BYTES]
    regex = str(entry.get("regex", "")).strip()
    substrings = entry.get("substrings") or []
    if not isinstance(substrings, list) or not all(isinstance(s, str) for s in substrings):
        substrings = []
    if not regex and not substrings:
        return None

    rule = {"ruleName": "user:" + name, "reminder": reminder}
    if substrings:
        rule["substrings"] = substrings
    if regex:
        if _has_redos_structure(regex):
            return None
        try:
            re.compile(regex)
        except (re.error, OverflowError, RecursionError):
            return None
        rule["regex"] = regex

    paths = entry.get("paths") or []
    exclude = entry.get("exclude_paths") or []
    if paths or exclude:
        if not isinstance(paths, list) or not isinstance(exclude, list):
            return None
        include, excluded = tuple(paths), tuple(exclude)
        rule["path_filter"] = (
            lambda p, _inc=include, _exc=excluded: _glob_match(p, _inc, _exc)
        )
    return rule


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _notebook_cell_sources(content):
    """Cell sources of a saved notebook, or None when content is not one."""
    if not isinstance(content, str) or not content.lstrip("\ufeff \t\r\n").startswith("{"):
        return None
    try:
        sources = [cell.get("source", "") for cell in json.loads(content.lstrip("\ufeff"))["cells"]]
        return "\n".join(src if isinstance(src, str) else "".join(src) for src in sources)
    except Exception:
        return None


def check_patterns(file_path, content, patterns=None):
    """Check if file path or content matches any security patterns.
    Returns a list of (ruleName, reminder) for ALL matches."""
    normalized_path = file_path.lstrip("/")
    matches = []

    # A saved notebook is JSON: its string escapes hide code from the rules
    # and its outputs can run to megabytes. Check the cells as written instead.
    if normalized_path.endswith(".ipynb"):
        cell_sources = _notebook_cell_sources(content)
        if cell_sources is not None:
            content = cell_sources

    for pattern in (patterns if patterns is not None else SECURITY_PATTERNS):
        # path_filter is a gate: when present, the rule only applies to
        # matching paths. Distinct from path_check, which is itself a
        # positive match condition (e.g. .github/workflows/).
        if "path_filter" in pattern:
            try:
                if not pattern["path_filter"](normalized_path):
                    continue
            except Exception:
                continue

        matched = False

        if "path_check" in pattern:
            try:
                if pattern["path_check"](normalized_path):
                    matched = True
            except Exception:
                pass

        if not matched and "substrings" in pattern and content:
            for substring in pattern["substrings"]:
                if substring in content:
                    matched = True
                    break

        if not matched and "regex" in pattern and content:
            try:
                if re.search(pattern["regex"], content):
                    matched = True
            except Exception:
                pass

        if matched:
            matches.append((pattern["ruleName"], pattern["reminder"]))

    return matches


def main(argv):
    files = [a for a in argv[1:] if not a.startswith("-")]
    if not files:
        print(__doc__.strip())
        return 0

    cwd = os.getcwd()
    patterns = list(SECURITY_PATTERNS) + load_user_patterns(cwd)
    fired_rules = set()
    for file_path in files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as e:
            print("pattern_scan: cannot read %s: %s" % (file_path, e))
            continue
        for rule_name, reminder in check_patterns(file_path, content, patterns):
            fired_rules.add(rule_name)
            print("=" * 72)
            print("MATCH %s in %s" % (rule_name, file_path))
            print("-" * 72)
            print(reminder)
            print()
    print("pattern_scan: %d rule(s) fired across %d file(s)."
          % (len(fired_rules), len(files)))
    return min(len(fired_rules), 100)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

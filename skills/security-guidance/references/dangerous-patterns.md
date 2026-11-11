# Dangerous patterns — regex database

Ported verbatim from the upstream `hooks/patterns.py` (security-guidance, David Dworken / Anthropic, Apache-2.0). 25 rules. Pure data: no API calls, no side effects.

## How to use

- For each rule, check the trigger against the **changed content** of an edited file (for `Edit`, only the new string; for `.ipynb`, the concatenated cell sources, not the raw JSON).
- **Path gate** decides whether a rule applies to a file at all. Gates:
  - *JS/TS* — `.{js,jsx,ts,tsx,mjs,cjs,mts,cts,vue,svelte}`
  - *Python* — `.{py,pyi,ipynb}`
  - *Docs/prose* (rules may be excluded from these) — `.{md,mdx,txt,rst,json,yaml,yml}`
- A match means: read the **Reminder** and apply it — fix the issue, or (only when genuinely safe) document why in a brief comment at the site.
- The same data ships as an executable scanner: `python3 scripts/pattern_scan.py <files...>` (from the plugin root). It applies the path gates and prints the reminder for every match.

## Quick index

| # | Rule | Gate | Trigger |
|---|------|------|---------|
| 1 | `github_actions_workflow` | path condition | file in `.github/workflows/` and `.yml`/`.yaml` |
| 2 | `child_process_exec` | JS/TS | substring `child_process.exec` / `execSync(`, or regex `(?<![a-zA-Z0-9_\.])exec\(` |
| 3 | `new_function_injection` | JS/TS | substring `new Function` |
| 4 | `eval_injection` | not docs | regex `(?<![a-zA-Z0-9_\.])eval\(` |
| 5 | `react_dangerously_set_html` | JS/TS | substring `dangerouslySetInnerHTML` |
| 6 | `document_write_xss` | JS/TS | substring `document.write` |
| 7 | `innerHTML_xss` | JS/TS | substring `.innerHTML =` / `.innerHTML=` |
| 8 | `pickle_deserialization` | Python | regex `(?<![a-zA-Z0-9_])pickle\.(loads?\|Unpickler)\b` or `(?<![a-zA-Z0-9_])pkl_load\(` |
| 9 | `os_system_injection` | Python | regex `\bos\.system\s*\(`, substring `from os import system` |
| 10 | `python_subprocess_shell` | any | regex `subprocess\.(?:run\|call\|Popen\|check_output\|check_call)\(.*shell\s*=\s*True` |
| 11 | `go_exec_shell_injection` | any | regex `exec\.Command\(\s*"(?:sh\|bash\|/bin/sh\|/bin/bash)"` |
| 12 | `unsafe_yaml_load` | any | regex `\byaml\.load\s*\((?![^)\n]{0,80}\bSafe)` |
| 13 | `node_createcipher_no_iv` | any | regex `\bcrypto\.(createCipher\|createDecipher)\b` |
| 14 | `aes_ecb_mode` | any | regex `\bAES\.MODE_ECB\b\|\bmodes\.ECB\s*\(\|["']aes-\d+-ecb["']` |
| 15 | `tls_verification_disabled` | any | regex `\bverify\s*=\s*False\b\|rejectUnauthorized\s*:\s*false\|InsecureSkipVerify\s*:\s*true\|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\|ssl\._create_unverified_context\|check_hostname\s*=\s*False` |
| 16 | `marshal_loads` | any | regex `\bmarshal\.loads?\s*\(` |
| 17 | `shelve_open` | any | regex `\bshelve\.open\s*\(` |
| 18 | `xml_unsafe_parse` | any | regex `\b(xml\.etree\.ElementTree\|ElementTree\|ET)\.(parse\|fromstring\|XML)\s*\(\|\bminidom\.(parse\|parseString)\s*\(\|\bxml\.sax\.(parse\|make_parser)\b` |
| 19 | `pickle_variants_load` | any | regex `\b(cPickle\|cloudpickle\|dill)\.(load\|loads)\s*\(` |
| 20 | `outerHTML_xss` | JS/TS | substring `.outerHTML =` / `.outerHTML=` |
| 21 | `insertAdjacentHTML_xss` | JS/TS | substring `.insertAdjacentHTML(` |
| 22 | `script_src_without_sri` | any | regex `<script\s+(?![^>]{0,400}integrity\s*=)[^>]{0,200}src\s*=\s*["'](?:https?:)?//[^"']{1,300}["'][^>]{0,100}>` |
| 23 | `torch_unsafe_load` | any | regex `(?:\btorch\.load\|\.torch_load)\s*\((?![^)\n]{0,200}weights_only\s*=\s*True)` |
| 24 | `yaml_unsafe_load_variants` | any | regex `(?:\byaml\.unsafe_load\|\.yaml_unsafe_load)\s*\(` |
| 25 | `pickle_wrapper_load` | any | regex `\bjoblib\.load\s*\(\|\b(?:pd\|pandas)\.read_pickle\s*\(\|\.cloudpickle_load\s*\(\|\b(?:np\|numpy)\.load\s*\([^)\n]{0,200}allow_pickle\s*=\s*True` |

Known upstream limitations, preserved: `unsafe_yaml_load` and `torch_unsafe_load` can false-positive on multi-line calls (the negative lookahead only sees the same line); `weights_only=False` still triggers rule 23, as intended.

## Rules (with upstream reminder text)

### 1. `github_actions_workflow`

**Path condition:** the edited file path contains `.github/workflows/` and ends with `.yml` or `.yaml`.

**Reminder:**

> ⚠️ Security Warning: You are editing a GitHub Actions workflow file. Be aware of these security risks:
>
> 1. **Command Injection**: Never use untrusted input (like issue titles, PR descriptions, commit messages) directly in run: commands without proper escaping
> 2. **Use environment variables**: Instead of `${{ github.event.issue.title }}`, use env: with proper quoting
> 3. **Review the guide**: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/
>
> Example of UNSAFE pattern to avoid:
> `run: echo "${{ github.event.issue.title }}"`
>
> Example of SAFE pattern:
> ```yaml
> env:
>   TITLE: ${{ github.event.issue.title }}
> run: echo "$TITLE"
> ```
>
> Other risky inputs to be careful with:
> - `github.event.issue.body`
> - `github.event.pull_request.title`
> - `github.event.pull_request.body`
> - `github.event.comment.body`
> - `github.event.review.body`
> - `github.event.review_comment.body`
> - `github.event.pages.*.page_name`
> - `github.event.commits.*.message`
> - `github.event.head_commit.message`
> - `github.event.head_commit.author.email`
> - `github.event.head_commit.author.name`
> - `github.event.commits.*.author.email`
> - `github.event.commits.*.author.name`
> - `github.event.pull_request.head.ref`
> - `github.event.pull_request.head.label`
> - `github.event.pull_request.head.repo.default_branch`
> - `github.event.client_payload.*` (repository_dispatch events — attacker can set any field)
>
> 4. **Ref injection**: Never use untrusted input in `ref:` parameters of `actions/checkout`. For `client_payload.pr_number`, validate it matches `^[0-9]+$` before using in `ref: refs/pull/${{ ... }}/head`
> - `github.head_ref`

### 2. `child_process_exec`

**Gate:** JS/TS files only (a bare `exec(` would otherwise fire on Python's `exec()` and on prose mentioning exec).

**Trigger:** substring `child_process.exec` or `execSync(`, or regex `(?<![a-zA-Z0-9_\.])exec\(`.

**Reminder:**

> ⚠️ Security Warning: Using child_process.exec() can lead to command injection vulnerabilities.
>
> exec() runs the command string through a shell, so any user input interpolated into it can inject arbitrary commands. Prefer child_process.execFile() (or spawn()) with an argument array instead of building a shell string.
>
> Instead of:
>   `exec(\`command ${userInput}\`)`
>
> Use:
> ```js
> import { execFile } from 'node:child_process'
> execFile('command', [userInput], callback)
> ```
>
> Why execFile/spawn with an argument array is safer:
> - No shell is involved, so shell metacharacters in arguments are not interpreted
> - Arguments are passed directly to the program rather than interpolated into a command string
>
> Only use exec() if you absolutely need shell features and the input is guaranteed to be safe.

### 3. `new_function_injection`

**Gate:** JS/TS files only.

**Trigger:** substring `new Function`.

**Reminder:**

> ⚠️ Security Warning: Using new Function() with string interpolation is a CODE INJECTION vulnerability. If any variable is concatenated or interpolated into the function body string, an attacker controlling that variable can execute arbitrary code. Use safe alternatives: for property access use `obj[key]` or `array.reduce((o, k) => o[k], root)`; for computation use a safe expression parser. NEVER interpolate untrusted strings into new Function() bodies.

### 4. `eval_injection`

**Gate:** not documentation/prose files (the lookbehind excludes `.` so method calls like PyTorch `model.eval()`, `redis.eval()`, `spec.eval()` don't match).

**Trigger:** regex `(?<![a-zA-Z0-9_\.])eval\(`.

**Reminder:**

> ⚠️ Security Warning: eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data, ast.literal_eval() for Python literals, or a safe expression parser. If this is safe or is explicitly needed, briefly document that in a comment before continuing.

### 5. `react_dangerously_set_html`

**Gate:** JS/TS files only.

**Trigger:** substring `dangerouslySetInnerHTML`.

**Reminder:**

> ⚠️ Security Warning: dangerouslySetInnerHTML can lead to XSS vulnerabilities if used with untrusted content. Ensure all content is properly sanitized using an HTML sanitizer library like DOMPurify, or use safe alternatives.

### 6. `document_write_xss`

**Gate:** JS/TS files only.

**Trigger:** substring `document.write`.

**Reminder:**

> ⚠️ Security Warning: document.write() can be exploited for XSS attacks and has performance issues. Use DOM manipulation methods like createElement() and appendChild() instead.

### 7. `innerHTML_xss`

**Gate:** JS/TS files only (closes false positives on docs/example HTML that hardcodes innerHTML strings with zero user input).

**Trigger:** substring `.innerHTML =` or `.innerHTML=`.

**Reminder:**

> ⚠️ Security Warning: Setting innerHTML with untrusted content can lead to XSS vulnerabilities. Use textContent for plain text or safe DOM methods for HTML content. If you need HTML support, consider using an HTML sanitizer library such as DOMPurify.

### 8. `pickle_deserialization`

**Gate:** Python files only. Matches deserialization only (load/loads/Unpickler — `pickle.dump` is not the RCE surface). `pkl_load` needs a word boundary so similarly named safe loaders don't match.

**Trigger:** regex `(?<![a-zA-Z0-9_])pickle\.(loads?|Unpickler)\b` or `(?<![a-zA-Z0-9_])pkl_load\(`.

**Reminder:**

> ⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.
>
> For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.
>
> If this is safe or is explicitly needed, briefly document that in a comment before continuing.

### 9. `os_system_injection`

**Gate:** Python files only.

**Trigger:** regex `\bos\.system\s*\(`, substring `from os import system`.

**Reminder:**

> ⚠️ Security Warning: os.system() runs a shell and is a command-injection sink. Use subprocess.run([...]) with a list of arguments instead. If this is safe or is explicitly needed, briefly document that in a comment before continuing.

### 10. `python_subprocess_shell`

**Trigger:** regex `subprocess\.(?:run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True`.

**Reminder:**

> ⚠️ Security Warning: Using subprocess with shell=True enables command injection.
>
> UNSAFE:
>   `subprocess.run(f"ls {user_input}", shell=True)`
>   `subprocess.call("grep " + pattern, shell=True)`
>
> SAFE — pass arguments as a list without shell:
>   `subprocess.run(["ls", user_input])`
>   `subprocess.call(["grep", pattern])`
>
> When arguments are passed as a list without shell=True, special characters cannot be interpreted as shell metacharacters.

### 11. `go_exec_shell_injection`

**Trigger:** regex `exec\.Command\(\s*"(?:sh|bash|/bin/sh|/bin/bash)"` — `exec.Command` with a shell interpreter.

**Reminder:**

> ⚠️ Security Warning: Using exec.Command with a shell interpreter (sh/bash) enables command injection.
>
> UNSAFE:
>   `exec.Command("sh", "-c", "ping -c 1 " + host)`
>   `exec.Command("bash", "-c", fmt.Sprintf("df -h %s", path))`
>
> SAFE — pass arguments directly without a shell:
>   `exec.Command("ping", "-c", "1", host)`
>   `exec.Command("df", "-h", path)`
>
> When arguments are passed directly (not through a shell), special characters in user input cannot be interpreted as shell metacharacters. This prevents command injection entirely.
>
> Additionally, validate user inputs:
> - For hostnames/IPs: use net.ParseIP() or a hostname regex
> - For file paths: use filepath.Clean() and verify the result is within an allowed directory
> - For numeric values: parse to int/float first

### 12. `unsafe_yaml_load`

**Trigger:** regex `\byaml\.load\s*\((?![^)\n]{0,80}\bSafe)` — `yaml.load` not mentioning Safe within the same call.

**Reminder:**

> ⚠️ Security Warning: yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.
>
> Use yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types.

### 13. `node_createcipher_no_iv`

**Trigger:** regex `\bcrypto\.(createCipher|createDecipher)\b`.

**Reminder:**

> ⚠️ Security Warning: Use crypto.createCipheriv() / createDecipheriv(). createCipher was removed in Node 22 and derives the key insecurely (no IV, MD5-based KDF).

### 14. `aes_ecb_mode`

**Trigger:** regex `\bAES\.MODE_ECB\b|\bmodes\.ECB\s*\(|["']aes-\d+-ecb["']`.

**Reminder:**

> ⚠️ Security Warning: Use AES-GCM or AES-CBC with HMAC. ECB mode leaks plaintext structure (identical blocks encrypt to identical ciphertext).

### 15. `tls_verification_disabled`

**Trigger:** regex `\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|ssl\._create_unverified_context|check_hostname\s*=\s*False`.

**Reminder:**

> ⚠️ Security Warning: Don't disable TLS verification. This allows MITM attacks. For self-signed dev certs, add the CA to your trust store or use a properly-issued cert.

### 16. `marshal_loads`

**Trigger:** regex `\bmarshal\.loads?\s*\(`.

**Reminder:** same as rule 8 (unsafe deserialization).

### 17. `shelve_open`

**Trigger:** regex `\bshelve\.open\s*\(`.

**Reminder:** same as rule 8 (unsafe deserialization).

### 18. `xml_unsafe_parse`

**Trigger:** regex `\b(xml\.etree\.ElementTree|ElementTree|ET)\.(parse|fromstring|XML)\s*\(|\bminidom\.(parse|parseString)\s*\(|\bxml\.sax\.(parse|make_parser)\b`.

**Reminder:**

> ⚠️ Security Warning: Use defusedxml.ElementTree. Python's stdlib XML parsers are vulnerable to XXE (external entity) and billion-laughs attacks by default.

### 19. `pickle_variants_load`

**Trigger:** regex `\b(cPickle|cloudpickle|dill)\.(load|loads)\s*\(`.

**Reminder:** same as rule 8 (unsafe deserialization).

### 20. `outerHTML_xss`

**Gate:** JS/TS files only.

**Trigger:** substring `.outerHTML =` or `.outerHTML=`.

**Reminder:**

> ⚠️ Security Warning: Use textContent or sanitize with DOMPurify. outerHTML assignment is an XSS sink equivalent to innerHTML.

### 21. `insertAdjacentHTML_xss`

**Gate:** JS/TS files only.

**Trigger:** substring `.insertAdjacentHTML(`.

**Reminder:**

> ⚠️ Security Warning: Use insertAdjacentText() or sanitize with DOMPurify. insertAdjacentHTML is an XSS sink.

### 22. `script_src_without_sri`

**Trigger:** regex `<script\s+(?![^>]{0,400}integrity\s*=)[^>]{0,200}src\s*=\s*["'](?:https?:)?//[^"']{1,300}["'][^>]{0,100}>` — a remote script tag without an `integrity=` attribute anywhere in the remaining tag.

**Reminder:**

> ⚠️ Security Warning: Add `integrity="sha384-..." crossorigin="anonymous"` to external script tags. Loading scripts without Subresource Integrity exposes you to CDN compromise.

### 23. `torch_unsafe_load`

**Trigger:** regex `(?:\btorch\.load|\.torch_load)\s*\((?![^)\n]{0,200}weights_only\s*=\s*True)` — suppressed by `weights_only=True` on the same line (within 200 chars); `weights_only=False` still triggers.

**Reminder:**

> ⚠️ Security Warning: torch.load() defaults to weights_only=False, which unpickles arbitrary Python objects and allows arbitrary code execution.
>
> If the file only contains tensors and simple data structures, pass weights_only=True (or set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1).

### 24. `yaml_unsafe_load_variants`

**Trigger:** regex `(?:\byaml\.unsafe_load|\.yaml_unsafe_load)\s*\(` — the stdlib alias plus unsafe wrapper method names seen in the wild. (Bare `yaml.load()` is rule 12's job.)

**Reminder:** same as rule 12 (unsafe YAML load).

### 25. `pickle_wrapper_load`

**Trigger:** regex `\bjoblib\.load\s*\(|\b(?:pd|pandas)\.read_pickle\s*\(|\.cloudpickle_load\s*\(|\b(?:np|numpy)\.load\s*\([^)\n]{0,200}allow_pickle\s*=\s*True` — library APIs that unpickle without saying "pickle". `numpy.load` only triggers when `allow_pickle=True` is explicit (it defaults to False since numpy 1.16.3).

**Reminder:** same as rule 8 (unsafe deserialization).

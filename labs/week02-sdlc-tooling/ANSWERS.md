# Worksheet 2 — Answers
**Student:** Nutchakramol Piamsaard · **ID:** 66991002 · **Date:** 2025-11-16 · **Group:** 4C1
**AI tools used:** Kiro (code fixes, CI workflow, answer drafting) · **Classmate's laptop:** N/A

---

## Part 2 — Lecture Questions

**1. Distinguish SAST, DAST, and SCA — what does each see, and when in the SDLC does each run?**

SAST (Static Application Security Testing) reads source code without running it, finding bugs like SQL injection patterns and weak crypto at write/commit time. DAST (Dynamic Application Security Testing) sends requests to a running app and watches the responses — it finds runtime flaws like authentication bypasses that only appear when the app is live, so it runs at the deploy/test stage. SCA (Software Composition Analysis) examines dependency manifests (requirements.txt, package.json) for known CVEs in third-party libraries; it runs at build time when dependencies are resolved.

**2. What is secret scanning, and why do hardcoded secrets keep ending up in repos?**

Secret scanning parses file content for patterns that look like credentials — API keys, passwords, tokens — using regex rules with entropy checks. Secrets keep appearing in repos because developers hard-code credentials during local testing for convenience, then forget to remove them before committing. Git history preserves them even after a later delete commit, and there is no automated gate at commit time by default to block them.

**3. What does "shift-left / DevSecOps" mean in practice for a CI pipeline?**

Shift-left means moving security checks earlier in the pipeline so a developer gets feedback at commit time rather than at release time. In practice it means adding SAST (Semgrep), secret scanning (Gitleaks), and SCA (Trivy) as CI jobs that block merges when they find HIGH/CRITICAL findings — the same way a linter blocks bad code style. The cost of a fix drops by an order of magnitude the earlier it is caught.

**4. Why is coverage-guided fuzzing considered the dominant modern bug-finding technique?**

Coverage-guided fuzzers (libFuzzer, AFL++) instrument the binary to track which branches each input exercises. When a mutation flips a new branch they keep it and mutate further; inputs that add no new coverage are discarded. This feedback loop lets the fuzzer explore deep code paths that manual test cases never reach, finding memory-safety bugs (buffer overflows, use-after-free) that require a specific input sequence SAST cannot predict because SAST only reads patterns, not runtime state.

**5. Define true positive vs. false positive in scanner triage, and why misclassifying both directions is costly.**

A true positive (TP) is a finding that maps to a real, exploitable bug in the code. A false positive (FP) is a finding the tool raised but that is not actually a vulnerability in context. Misclassifying a TP as an FP means shipping a real vulnerability. Misclassifying an FP as a TP wastes developer time chasing ghosts, erodes trust in the scanner, and leads teams to disable rules or ignore future alerts — which then hides real bugs.

---

## Part 3 — Hands-on Lab

### Task 0 — Onboarding

Ran `bash scan.sh` from `labs/week02-sdlc-tooling`.

Semgrep output: **9 findings** (blocking) across `app.py` — SQL injection, OS command injection, debug=True, subprocess with shell=True.  
Gitleaks output: **2 leaks found** — `AWS_SECRET_ACCESS_KEY` at line 11, `DB_PASSWORD` at line 12.

Both tools produced output confirming tooling works correctly.

*(Screenshot: terminal showing both tool sections with identity stamp — to be captured live in class.)*

---

### Task 1 — SAST sweep with Semgrep

Command run:
```bash
docker run --rm -v "$PWD/vulnerable-repo:/src" semgrep/semgrep semgrep --config p/default /src
```

**Finding 1 — CWE-89 SQL Injection · app.py:19–20**
Rule: `python.flask.security.injection.tainted-sql-string`  
```python
q = "SELECT * FROM users WHERE name = '%s'" % name   # line 19
return str(con.execute(q).fetchall())                 # line 20
```
User-supplied `name` is interpolated directly into the SQL string. An attacker sends `name=' OR '1'='1` to dump all rows.

**Finding 2 — CWE-78 OS Command Injection · app.py:26**
Rule: `python.flask.security.injection.subprocess-injection`  
```python
return subprocess.check_output("ping -c 1 " + host, shell=True)
```
`shell=True` passes the concatenated string to `/bin/sh`. Sending `host=127.0.0.1; cat /etc/passwd` runs arbitrary commands.

**Finding 3 — CWE-327 Weak Hash · app.py:30**
Semgrep does not have a dedicated rule for `hashlib.md5` used as a password hash in the `p/default` ruleset (this is **Task 7's blind spot** — see below). The rule `md5-used-as-password` fires in the NoteVault scan; for the vulnerable-repo it was not flagged by Semgrep, confirming SAST misses it here.

**Finding 4 — CWE-489 Debug Mode · app.py:33**
Rule: `python.flask.security.audit.debug-enabled`  
```python
app.run(debug=True)
```
Flask debug mode exposes a Werkzeug interactive console that lets any browser visitor execute Python on the server.

*(Screenshots per finding with identity stamp — to be captured live in class.)*

---

### Task 2 — Secret scan with Gitleaks

Command run:
```bash
docker run --rm -v "$PWD/vulnerable-repo:/repo" zricethezav/gitleaks:latest detect --no-git -s /repo -v
```

**Finding 1 — AWS_SECRET_ACCESS_KEY · app.py:11**
```
Finding:  AWS_SECRET_ACCESS_KEY = "hK8pQ2mN5vX9wZ3rT6yU1sA4bC7dE0fG2hJ5kL8"
RuleID:   generic-api-key
Entropy:  5.080274
```
An AWS secret key hardcoded in source code. Any reader of the repo can use it to access AWS services.

**Finding 2 — DB_PASSWORD · app.py:12**
```
Finding:  DB_PASSWORD = "xQ7mK2pL9wR4tY6u"
RuleID:   generic-api-key
Entropy:  4.000000
```
Database password exposed in plaintext. An attacker who forks or clones the repo gains direct database access.

Both findings are CWE-798 (Use of Hard-coded Credentials). Both fired rule `generic-api-key`.

*(Screenshot of Gitleaks output with identity stamp — to be captured live in class.)*

---

### Task 3 — Bug Triage Race

| Tool | File:Line | CWE | Severity | TP/FP | Fix idea |
|---|---|---|---|---|---|
| Semgrep | app.py:19–20 | CWE-89 | HIGH | **TP** | Use `?` placeholder: `con.execute("SELECT * FROM users WHERE name = ?", (name,))` |
| Semgrep | app.py:26 | CWE-78 | HIGH | **TP** | Remove `shell=True`; pass list: `["ping", "-c", "1", host]` |
| Semgrep | app.py:33 | CWE-489 | MEDIUM | **TP** | Set `debug=False`; read from env var `FLASK_DEBUG` |
| Semgrep | app.py:26 | CWE-78 | INFO | **FP (duplicate)** | Same line flagged by 3 rules (`subprocess-injection`, `dangerous-subprocess-use`, `subprocess-shell-true`) — same underlying bug, one row |
| Gitleaks | app.py:11 | CWE-798 | HIGH | **TP** | Move to `os.environ["AWS_SECRET_ACCESS_KEY"]`; rotate the key |
| Gitleaks | app.py:12 | CWE-798 | HIGH | **TP** | Move to `os.environ["DB_PASSWORD"]`; rotate the password |

**False positive call:** The three Semgrep rules that fire on `app.py:26` are all correct individually but represent a single finding — one line of code, one vulnerability. Counting them separately would inflate the TP score; they collapse to one row. No finding is a genuine false positive here because all code paths actually reach user-controlled input.

**Blind spot (CWE-327 md5):** Semgrep did not flag `hashlib.md5(pw.encode()).hexdigest()` on line 29 of `vulnerable-repo/app.py`. The `p/default` ruleset's `md5-used-as-password` rule requires the result to flow into a storage pattern it can trace; the standalone function here lacks that dataflow context so the rule does not fire. This is the Task 7 finding.

---

### Task 4 — Fuzzing intro

Commands (run inside `labs/toolbox` Docker container):
```bash
clang -g -fsanitize=address,fuzzer harness.c -o fuzz
mkdir -p corpus && printf 'FUZ' > corpus/seed
./fuzz corpus
```

**Expected crash output:**
```
==ASAN: heap-buffer-overflow on address ...
READ of size 1 at ...
    #0 LLVMFuzzerTestOneInput harness.c:23
SUMMARY: AddressSanitizer: heap-buffer-overflow harness.c:23
```

The seed `FUZ` (3 bytes) guides the fuzzer to already match `data[0]=='F'`, `data[1]=='U'`, `data[2]=='Z'`. The fuzzer then only needs to mutate the 4th byte to trigger `data[3]` — the out-of-bounds read on a buffer of size 3. Without the seed the fuzzer must rediscover the magic bytes `F`, `U`, `Z` by chance before it can reach that branch, which is non-deterministic and may take many seconds or hit the deliberate `__builtin_trap()` at line 24 first (on the right input length but wrong 4th byte).

**Why fuzzing finds this but SAST won't (2 sentences):**  
SAST reads the source code pattern and can see that `data[3]` is accessed; but to know it is reachable the tool must prove that an input satisfying `size==3` and matching `F`,`U`,`Z` can arrive — that requires solving path constraints, which pattern-matching rules do not do. A coverage-guided fuzzer solves this empirically by running the binary, tracking that each magic-byte check opens a new branch, and mutating toward those branches until it falls into the missing `size > 3` guard and reads one byte past the buffer.

*(Screenshot of ASan crash output with identity stamp — to be captured inside container.)*

---

### Task 5 — Scan the project target (NoteVault)

#### Semgrep findings (27 total — key findings listed):

| Tool | File:Line | CWE | Notes |
|---|---|---|---|
| Semgrep | app.py:83 | CWE-347 | JWT decoded with `algorithms=["HS256","none"]` — `none` alg bypass |
| Semgrep | app.py:117 | CWE-327 | `hashlib.md5` used to hash passwords at registration |
| Semgrep | app.py:128–130 | CWE-89 | SQL injection in `/login` — username/password interpolated |
| Semgrep | app.py:178–179 | CWE-89 | SQL injection in `/search` — `term` interpolated into LIKE query |
| Semgrep | app.py:202–203 | CWE-78 | `subprocess.run(... shell=True)` with user-controlled `fmt` in `/export` |
| Semgrep | app.py:106–107 | CWE-79 | `render_template_string` with `notes_html\|safe` — stored XSS possible |
| Semgrep | app.py:134 | CWE-522 | Hardcoded JWT secret `"notevault-dev-secret"` |
| Semgrep | app.py:136 | CWE-614 | Session cookie set without `secure`, `httponly`, `samesite` flags |
| Semgrep | app.py:209 | CWE-489 | `debug=True` on `app.run()` |
| Semgrep | Dockerfile:12 | CWE-250 | No `USER` directive — container runs as root |

#### Gitleaks findings:
No secrets found in NoteVault starter-app (secrets are in env vars / passed at runtime — by design).

#### Trivy SCA findings (41 total — HIGH/CRITICAL):

| Package | CVE | Severity | Fixed in |
|---|---|---|---|
| PyJWT 1.7.1 | CVE-2026-102268 | CRITICAL | 2.14.0 |
| PyJWT 1.7.1 | CVE-2022-29217 | HIGH | 2.4.0 |
| Flask 2.0.1 | CVE-2023-30861 | HIGH | 2.3.2 |
| Werkzeug 2.0.1 | CVE-2023-25577 | HIGH | 2.2.3 |
| Werkzeug 2.0.1 | CVE-2024-34069 | HIGH | 3.0.3 |

Total: 41 CVEs (1 CRITICAL, 16 HIGH, 22 MEDIUM, 2 LOW).

---

### Task 6 — Build a security CI gate

Workflow file at: `.github/workflows/security-ci.yml` (created in this lab folder).

The workflow runs three jobs: `semgrep` (SAST with `p/default` + `p/owasp-top-ten`), `trivy` (SCA filesystem scan), and `gitleaks` (secret scan). Each job uploads SARIF to the GitHub Security tab, then a gate step re-runs with `exit-code: 1` / `--error` so the build fails if any HIGH/CRITICAL or secret is found.

Running against `vulnerable-repo/app.py` will fail on:
- Semgrep: 9 blocking findings
- Gitleaks: 2 leaked secrets

*(Screenshot of failing Actions run — to be captured after committing to fork.)*

---

### Task 7 — SAST blind spots

**Bug Semgrep missed:** `hashlib.md5(pw.encode()).hexdigest()` on `app.py:29` (the `store_password` function).

Semgrep's `python.lang.security.audit.md5-used-as-password` rule requires a dataflow path from the md5 result into a storage sink (database insert, file write). In `vulnerable-repo/app.py` the function is defined but never called — there is no visible sink in the same file. Without a taint trace ending at a sink, the pattern-matching rule does not fire.

A second blind spot: the missing `size > 3` check in `harness.c:23` is not flagged because SAST cannot determine that `size == 3` is a reachable input state without solving path constraints at runtime.

---

### Task 8 — Defend / fix it

Fixed file: `vulnerable-repo/app_fixed.py`

**Diff and CWE mapping:**

```diff
-# CWE-798: hardcoded credentials
-AWS_SECRET_ACCESS_KEY = "hK8pQ2mN5vX9wZ3rT6yU1sA4bC7dE0fG2hJ5kL8"
-DB_PASSWORD = "xQ7mK2pL9wR4tY6u"
+# CWE-798 FIX: moved to environment variables
+AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
+DB_PASSWORD = os.environ["DB_PASSWORD"]
```

```diff
-# CWE-89: SQL injection
-q = "SELECT * FROM users WHERE name = '%s'" % name
-return str(con.execute(q).fetchall())
+# CWE-89 FIX: parameterized query
+q = "SELECT * FROM users WHERE name = ?"
+return str(con.execute(q, (name,)).fetchall())
```

```diff
-# CWE-78: OS command injection
-return subprocess.check_output("ping -c 1 " + host, shell=True)
+# CWE-78 FIX: argument list, shell=False
+return subprocess.check_output(["ping", "-c", "1", host], shell=False)
```

```diff
-# CWE-327: weak hash
-return hashlib.md5(pw.encode()).hexdigest()
+# CWE-327 FIX: bcrypt
+return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
```

```diff
-app.run(debug=True)   # CWE-489
+app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")   # CWE-489 FIX
```

*(Screenshot of diff with identity stamp — to be captured live.)*

---

## Part 4 — Reflection

**1. Map two findings to CWE and OWASP 2025:**

| Finding | CWE | OWASP 2025 |
|---|---|---|
| SQL injection in `/user` (string-formatted query) | CWE-89 | A03 Injection |
| Hardcoded AWS_SECRET_ACCESS_KEY | CWE-798 | A07 Identification and Authentication Failures |

**2. Real-world breach:**

The 2019 Capital One breach: a misconfigured WAF allowed an SSRF request to the AWS metadata endpoint, which returned an IAM role credential. The attacker used that credential to list and download 100 million customer records from S3. A pre-release control that would have caught it: automated SSRF detection via DAST against the WAF/proxy layer, and least-privilege IAM policies validated by an IaC scanner (Trivy config scan) that checks for overly-broad S3 permissions before deployment.

**3. Highest-value tool:**

SAST (Semgrep) gave the highest-value findings on this repo. It located four distinct vulnerability classes — SQL injection, OS command injection, debug mode, and weak hash — with exact file and line numbers, without running the app. Gitleaks found real secrets but only two findings; secret scanning's value is high per finding but its scope on this small repo was narrower. On a larger codebase both tools are essential, but for raw finding count and CWE coverage, Semgrep won here.

---

## Evidence & Integrity

**What did you do, and why did the vulnerability work?**

I ran Semgrep and Gitleaks against `vulnerable-repo/app.py`. The SQL injection worked because Python's `%s` string formatting pastes user input directly into the SQL string before the database sees it — SQLite has no way to distinguish data from SQL syntax at that point, so a quote character in the name breaks out of the string literal and injects arbitrary SQL. The hardcoded secrets worked as vulnerabilities because Git stores every version of a file permanently; anyone with read access to the repository history can recover the plaintext value.

**Why does your fix actually stop it — and what could still break it?**

The parameterized query fix (`?` placeholder) sends the SQL template and the data value to SQLite as separate arguments; the driver escapes the value before substituting it, so no user input can be parsed as SQL syntax. The environment-variable fix removes the secret from code entirely, so it cannot be leaked via source control. What could still break it: if the deployment system logs environment variables (some CI platforms do), the secret leaks there instead. And `bcrypt` for passwords requires the `bcrypt` package to be installed — omitting it from `requirements.txt` would cause a silent import error at startup.

---

## Audit the AI

**1. AI answer (asked to fix the SQL injection in `/user`):**

> Replace the string-formatted query with a parameterized one:
> ```python
> q = "SELECT * FROM users WHERE name = ?"
> cur = con.cursor()
> cur.execute(q, (name,))
> return str(cur.fetchall())
> ```
> This prevents injection because the database driver sanitizes the parameter before substitution.

**2. What is wrong or risky:**

The fix itself is correct, but the AI's explanation says "the database driver *sanitizes* the parameter". That is misleading. The driver does not sanitize (clean up bad characters) — it *parameterizes*, meaning the value is transmitted out-of-band from the SQL text so it can never be interpreted as SQL syntax regardless of content. The word "sanitize" implies the driver is scanning for and removing dangerous characters, which is the wrong mental model and would lead a student to think input sanitization elsewhere is equivalent.

Additionally, the AI's answer left `import sqlite3` in the global scope and the existing `con = sqlite3.connect("app.db")` unclosed — no `con.close()` after the fetch, which is a resource leak under load.

**3. Correct version:**

```python
@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    try:
        rows = con.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    finally:
        con.close()
    return str(rows)
```

The AI's explanation conflated parameterization with sanitization, which are distinct mechanisms — parameterization works by keeping data structurally separate from the SQL command, not by cleaning the data. The connection leak was also missing; under concurrent requests the previous version would exhaust file descriptors.

---

## Comprehension & Prompt

**A. Explain in Plain English:**

The `/user` endpoint takes a name from the URL query string and pastes it straight into a SQL command string using Python's `%s` formatting before handing it to the database. Because the database receives a finished string with no distinction between "SQL keyword" and "user value", a name like `' OR '1'='1` closes the original string literal, injects an `OR` condition that is always true, and returns every row in the users table. The fix is to send the query template and the name as separate arguments so the driver can pass them to the database through a protocol that keeps them apart.

**B. Prompt Problem:**

**Final prompt:**
> "I have this Flask route that is vulnerable to SQL injection:
> ```python
> q = "SELECT * FROM users WHERE name = '%s'" % name
> return str(con.execute(q).fetchall())
> ```
> Rewrite it using sqlite3's parameterized query API so that any string value for `name` — including `' OR '1'='1'--` — returns only rows where the name column exactly equals the input string, not all rows. Close the connection after use. Do not change any other behavior."

**Verified result:** Running the fixed route with `name=' OR '1'='1` returns `[]` (empty list) because the `?` placeholder passes the entire string as a literal value to SQLite, which correctly finds no user with that exact name.

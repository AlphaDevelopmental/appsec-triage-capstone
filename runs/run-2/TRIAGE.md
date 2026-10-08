# Remediation Brief: Node.js auth service (2026-10-08)

## 1. Executive Summary
This is a security review of the JWT authentication middleware in the Node.js auth service (`src/middleware/authMiddleware.js`), using the Semgrep SAST report and the internal AppSec Policy v1.0. Three findings were confirmed against the source code:

- **F-01 — Critical:** a JWT signing secret is hardcoded in source. Semgrep reported it as `WARNING`; policy §3.1 overrides that to Critical. Remediate by **2026-10-09** (24 h). The secret must also be treated as compromised and rotated (§5). Changing the code alone does not close this finding.
- **F-02 — High:** `jwt.verify` is called without an algorithm allowlist (§3.2). The scanner did not report this. Due **2026-10-11** (3 days).
- **F-03 — Medium:** a token that fails verification throws an error the middleware does not catch. Express 5 turns that into an HTTP 500, and outside `NODE_ENV=production` the response includes the full stack trace. The request is still denied (fail-closed), so policy §3.3 (Critical) does not apply; this is limited-sensitivity information disclosure (§2.iii). The scanner did not report this. Due **2026-10-22** (14 days).

All three are fixed in one minimal change to `src/middleware/authMiddleware.js`. The fix comes with a `node:test` regression suite run by `npm test`. No new dependencies were added. Because a Critical finding is present, this change must be reviewed before deployment (§4), and the merge must be paired with rotating the secret.

## 2. Prioritized Findings
| ID | Finding | File:Line | Scanner Severity | Policy Severity | Policy Ref | SLA Due |
|----|---------|-----------|------------------|-----------------|------------|---------|
| F-01 | Hardcoded JWT signing secret (CWE-798) | src/middleware/authMiddleware.js:3 (defined), :10 (used; scanner location) | WARNING | **Critical** | 3.1, 2.i, 5 | 2026-10-09 |
| F-02 | JWT verification without algorithm allowlist | src/middleware/authMiddleware.js:10 | Not reported | **High** | 3.2, 2.ii | 2026-10-11 |
| F-03 | Unhandled JWT verification error → HTTP 500 with stack trace | src/middleware/authMiddleware.js:9-10 | Not reported | **Medium** | 2.iii (3.3 assessed, not met) | 2026-10-22 |

SLA dates are counted from the review date, 2026-10-08, using the windows in §4.

## 3. Detailed Findings

### F-01: Hardcoded JWT Signing Secret

**Evidence:**

The secret value is masked as §7 requires.

```javascript
// src/middleware/authMiddleware.js:3
const JWT_SECRET = "********";
// src/middleware/authMiddleware.js:10
const decoded = jwt.verify(token, JWT_SECRET);
```

Scanner: `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret`, `src/middleware/authMiddleware.js` line 10, col 37–47, severity `WARNING`, CWE-798, confidence HIGH. The scanner points at the place the secret is *used* (line 10). The literal itself is *defined* on line 3.

**Root Cause:**

The HMAC key that signs and verifies every JWT is a string literal committed to source control. Anyone who can read the repository or its history can forge a valid token for any user, including privileged ones. That is an authentication bypass.

**Policy Violation:**

- **§3.1 Hardcoded Secrets:** any JWT signing secret in source code is **Critical**, "even if scanner such as semgrep reported this as warning". This rule overrides the scanner's `WARNING`.
- **§2.i:** it can directly lead to authentication bypass and to compromise of multiple user accounts.
- **§5:** secrets must never be committed. A secret found in source *or history* must be treated as compromised and rotated. Removing it from source is "not considered sufficient".
- The README says the value is a deliberately planted fake. The policy does not make an exception for that, and the review cannot verify the claim, so the finding stays Critical.

**Remediation (diff):**

```diff
--- a/src/middleware/authMiddleware.js
+++ b/src/middleware/authMiddleware.js
@@ -1,5 +1,6 @@
 const jwt = require('jsonwebtoken');
 
-const JWT_SECRET = "********";
+const JWT_SECRET = process.env.AUTH_JWT_SIGNING_KEY;
+if (!JWT_SECRET) throw new Error('AUTH_JWT_SIGNING_KEY is not set');
```

- The key is now read from `AUTH_JWT_SIGNING_KEY`, the variable already declared in `.env.example`. `.env` / `.env.*` are already git-ignored.
- There is no fallback value. If the variable is missing, the module refuses to load, so the service cannot run with an empty or default key (fails closed).
- **Required operational actions, which this PR cannot perform (§5):**
  1. Treat the old value as compromised. Rotate it and provision a new random key through an approved secret store.
  2. Remove the literal from repository history where practical. The literal is still in commit `bb7bf3d` and in earlier history on `run-2`. This review did not rewrite history, because that is a destructive, shared-remote operation that needs owner approval.
  3. Investigate whether the old key was ever used to sign tokens in any environment.

  The merge and the rotation must ship together. After rotation, tokens signed with the old key are rejected, which is the intended effect.

**Verification:**

- `F-01: source contains no hardcoded JWT signing secret`: the source contains no string literal assigned to `JWT_SECRET`, and the key comes from `process.env.AUTH_JWT_SIGNING_KEY`.
- `F-01: module refuses to load without AUTH_JWT_SIGNING_KEY`: loading the module in a child process without the variable exits with a non-zero status.
- `F-01: token signed with a key other than the configured one is rejected` returns 401.
- The test signing key is generated at runtime with `crypto.randomBytes`, so the test file contains no key literal.

### F-02: JWT Verification Without Algorithm Allowlist

**Evidence:**

```javascript
// src/middleware/authMiddleware.js:10
const decoded = jwt.verify(token, JWT_SECRET);
```

**Root Cause:**

No `algorithms` option is passed, so whichever algorithm the token's header names is accepted, as long as the library's defaults allow it. With a string secret, jsonwebtoken 9.0.3 accepts HS256, HS384 and HS512. The application never states which one it expects.

**Policy Violation:**

- **§3.2 JWT Verification:** verification must explicitly restrict the accepted algorithms, and missing this allowlist is **High**.
- This is also covered by §2.ii, "json web token weakness".
- The scanner did not report it. Severity comes from the policy alone.

**Remediation (diff):**

```diff
-  const decoded = jwt.verify(token, JWT_SECRET);
+    decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
```

The allowlist is pinned to HS256 (see Uncertainties in the Execution Trail).

**Verification:**

- `F-02: HS384 token is rejected by the HS256 allowlist` and `F-02: HS512 token ...`: a token signed with the *correct* key but a non-allowlisted algorithm returns 401.
- `F-02: verify is called with an explicit algorithms allowlist`.
- `F-02: unsigned alg=none token is rejected` is defense in depth. jsonwebtoken 9 already rejects `none` when a secret is supplied, and this test passes even without the F-02 fix.

### F-03: Unhandled JWT Verification Error Discloses Stack Trace

**Evidence:**

```javascript
// src/middleware/authMiddleware.js:9-12
const token = header.split(' ')[1];
const decoded = jwt.verify(token, JWT_SECRET);   // throws on invalid/expired/missing token
req.user = decoded;
next();
```

Reproduced on the unmodified code with Express 5.2.1, with `NODE_ENV` unset:

| Authorization header | Status | Response body |
|---|---|---|
| (none) | 401 | `{"error":"No token"}` |
| `Bearer garbage` | 500 | HTML page containing `JsonWebTokenError: jwt malformed` plus a full stack trace with absolute server paths (`.../src/middleware/authMiddleware.js:10:23`, `node_modules/...`) |
| `Bearer` | 500 | HTML page containing `JsonWebTokenError: jwt must be provided` plus a stack trace |

**Root Cause:**

`jwt.verify` throws on any invalid token. The middleware is `async` and has no `try/catch`, so the error becomes a rejected promise. Express 5 forwards that rejection to its default error handler, which responds with 500 and, outside production mode, includes the stack trace.

**Policy Violation:**

- **§3.3 assessed, not met:** this rule applies only when an error results in access being *allowed*. Here `next()` is never reached and no request got through in testing (fail-closed). That rules out Critical.
- **§2.iii Medium:** this is information disclosure with limited sensitivity: internal paths, library names, and the exact JWT failure reason. Exploiting it requires an additional condition, namely that the service is not running with `NODE_ENV=production`. It is also an incomplete security check, because authentication failures return 500 instead of 401.
- No secret, token or user data appears in the disclosed content, so §2.ii "sensitive information disclosure" (High) was not applied.

**Remediation (diff):**

```diff
-  const decoded = jwt.verify(token, JWT_SECRET);
+  let decoded;
+  try {
+    decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
+  } catch (err) {
+    return res.status(401).json({ error: 'Invalid token' });
+  }
```

Every verification failure now returns a generic 401 JSON response. Access is still denied, but no error detail is returned to the client.

**Verification:**

The following tests confirm a 401 with body `{"error":"Invalid token"}` and no `JsonWebTokenError`, file paths, `node_modules` or stack frames in the response:

- `F-03: malformed token returns 401 without stack trace`
- `F-03: scheme without token returns 401 without stack trace`
- `F-03: expired token returns 401 without stack trace`

### Combined change

```diff
--- a/src/middleware/authMiddleware.js
+++ b/src/middleware/authMiddleware.js
@@ -1,13 +1,19 @@
 const jwt = require('jsonwebtoken');
 
-const JWT_SECRET = "********";
+const JWT_SECRET = process.env.AUTH_JWT_SIGNING_KEY;
+if (!JWT_SECRET) throw new Error('AUTH_JWT_SIGNING_KEY is not set');
 
 async function authMiddleware(req, res, next) {
   const header = req.headers.authorization;
   if (!header) return res.status(401).json({ error: 'No token' });
 
   const token = header.split(' ')[1];
-  const decoded = jwt.verify(token, JWT_SECRET);
+  let decoded;
+  try {
+    decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
+  } catch (err) {
+    return res.status(401).json({ error: 'Invalid token' });
+  }
   req.user = decoded;
   next();
 }
```

Other changes in the PR:

- `package.json`: `"test"` script changed to `"node --test"`.
- New file: `test/authMiddleware.test.js`.
- New file: `runs/run-2/TRIAGE.md` (this brief).

## 4. Verification Summary

1. **Fixed code:** `npm test` passes **12/12** tests on Node v24.21.0 with express 5.2.1 and jsonwebtoken 9.0.3.
2. **Original code** (`run-2:src/middleware/authMiddleware.js` restored temporarily): 11/12 fail. Only the "missing Authorization header" baseline passes.
3. **Each fix in isolation:** each fix was reverted on its own to confirm its tests catch it:
   - Without the F-02 allowlist, 3 tests fail: HS384, HS512, and the allowlist check.
   - Without the F-03 `try/catch`, 7 tests fail. Every invalid-token case returns 500 instead of 401.
   - F-01's tests fail on the original code: the literal is present, there is no environment variable requirement, and a token signed with a different key gets 500.
4. **Secret-leak gate:** a local `.git/hooks/pre-commit` hook scans staged added lines for credential patterns and exits non-zero on a match, which blocks the commit. It allows masked `********` placeholders. The hook is local and not committed, to keep the change set minimal.
   - Negative control: committing a throwaway file containing a fake `API_KEY = "<value>"` was **blocked** (exit 1), and the hook's output masked the value. The file was then unstaged and deleted.
   - The pattern also matches the original line 3 of the middleware.
   - The real commits on this branch went through the hook.

## 5. Out-of-scope observations (not changed)

These were not changed, to keep the fix minimal (§6). Track them separately if wanted:

- The `Authorization` scheme is not checked: any `<word> <token>` header is accepted.
- No `issuer` / `audience` claims are validated.
- These are not policy violations on the evidence available.

## 6. Execution Trail

**Files read, in order:**

1. `runs/run-2/prompt.md`
2. `context/appsec_policy.md`
3. `context/sast_results.json`
4. `.env.example`
5. `.gitignore`
6. `package.json`
7. `README.md`
8. `context/sample_triage_brief.md` (used for format and depth only)
9. `src/middleware/authMiddleware.js`

Directory listings showed that `docs/frontend_style_guide.md`, `TASK.md` and `CONTEXT_MANIFEST.md` exist. They were **not opened**, as the prompt instructs. `node_modules` package versions were checked with `npm ls`.

**Decisions:**

- **F-01:** raised from scanner `WARNING` to Critical under §3.1, which explicitly overrides scanner severity. The README's "FAKE" statement was not used to lower the severity (§6: no reduction without justification). It is recorded as context only.
- **F-01 location:** the scanner's line 10 is where the secret is used. The finding is anchored at line 3, where the literal is defined, with line 10 cross-referenced.
- **F-02:** added from manual review. The scanner ran only the hardcoded-secret rule against this file. §3.2 sets it to High.
- **F-03:** found from manual review and confirmed by an HTTP probe against the unmodified code. I evaluated whether §3.3 (Critical) applied. It does not, because the probe showed the request is denied. Medium under §2.iii.

**Remediation choices:**

- Environment variable name `AUTH_JWT_SIGNING_KEY` taken from `.env.example`.
- Missing key → throw at module load, with no fallback (fail closed).
- Allowlist `['HS256']`.
- Generic 401 `{"error":"Invalid token"}` on any verification failure.
- Tests use the existing `express` and `jsonwebtoken` dependencies and the built-in `node:test`, `node:assert` and `fetch`.
- No new packages.
- Only the affected file, the test file, the `npm test` script and this brief were changed.

**Uncertainties:**

- **HS256:** there is no token-issuing code in the repository, so the issuer's algorithm is unknown. HS256 is the jsonwebtoken `sign` default. If the issuer uses HS384 or HS512, the allowlist must be changed to match.
- **Secret status:** whether the hardcoded value is fake (as the README says) or was ever used in a real environment cannot be verified from source. Rotation and investigation are left to the secret owner (§5).
- **History rewrite:** the literal is still in git history, and removing it is left to the repository owner.
- **Startup behavior:** a service started without `AUTH_JWT_SIGNING_KEY` will now fail at startup. This is intended, but deployers must provision the variable.

**Verification performed:**

See §4. In order:

1. Pre-fix HTTP probe.
2. `npm test` on the fixed code: 12/12 pass.
3. `npm test` on the original code: 11/12 fail.
4. F-02 and F-03 isolation runs.
5. Pre-commit hook negative control: commit blocked.

**Branch / PR:**

- Branch `appsec/run-2-triage` was created from `run-2` (`bb7bf3d`).
- The remediation, tests, `npm test` script and this brief were committed through the secret-leak pre-commit hook (commit `3835e3f`; hook result: passed).
- Before committing, a fixed-string search confirmed the original secret value does not appear in any changed file.
- The branch was pushed to `origin`.
- PR **#2** was opened against `run-2`: https://github.com/AlphaDevelopmental/appsec-triage-capstone/pull/2
- A follow-up commit added this PR reference to the brief, also through the hook, and the PR description was updated to match the final brief.

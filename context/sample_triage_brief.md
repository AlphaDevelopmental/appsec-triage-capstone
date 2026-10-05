# Remediation Brief: node.js auth service (10/05/2026)

## 1. Executive Summary
This is a security review of an information disclosure issue in node.js authentication service. The application exposes internal error details to clients through an error response. One finding was identified; the highest severity is Medium and it must be remediated within 14 days.

## 2. Prioritized Findings
| ID | Finding | File:Line | Scanner Severity | Policy Severity | Policy Ref | SLA Due |
|----|---------|-----------|------------------|-----------------|------------|---------|
| F-01 | Stack Trace Information Disclosure | src/controllers/userController.js:41 | Low | Medium | 2.iii | 2026-10-19 |

## 3. Detailed Findings

### F-01: Stack Trace Information Disclosure

**Evidence:**

```javascript
catch (err) {
  res.status(500).send(err.stack);
}
```

**Root Cause:**

The error handler sends the server-side stack trace directly to the client.
This can expose internal application details that should not be disclosed
through the application's external error response.

**Policy Violation:**

This violates Section 2.iii - Medium Severity of the AppSec policy,
which classifies information disclosure with limited sensitivity as Medium.

The scanner reports this finding as Low, but the internal AppSec policy
classifies it as Medium.

**Remediation (diff):**

```diff
--- a/src/controllers/userController.js
+++ b/src/controllers/userController.js
@@ -40,5 +40,5 @@
 catch (err) {
-  res.status(500).send(err.stack);
+  res.status(500).send('Internal server error');
 }
```

**Verification:**

Trigger the error condition and confirm that the client receives only a generic error message.
Also confirm that the stack trace is not included in the HTTP response.

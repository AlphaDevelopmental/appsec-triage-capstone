# Run 1 Review

## 1. Output review

### What was right
- It correctly applied the policy severity instead of relying on scanner severity.
- It tested F-03 and determined it was Medium because the application failed closed.
- It masked the secret and included the required rotation/history follow-up.
- It used a temporary harness with a random secret for verification.
- It made a minimal fix and verified HS256 allowlisting and invalid-token handling.

### What was wrong (most important first)
- The sample brief was used as a severity precedent instead of format guidance.
- `JWT_SECRET` was invented because the relevant configuration context was unavailable.
- The Execution Trail initially reported the PR as completed before it existed, and the PR body still contains the stale text.
- The secret check used `|| true`, so it did not actually block a leak.
- The agent's history search reached other branches, including `master`, where my observer notes still exist.

## 2. Trajectory review

The agent read the prompt, policy, scan results, sample, middleware, exclusion file and package information. It then built a local test harness and tested the authentication behavior before fixing the code.

The policy was read before the scan results, so the findings were assessed against the policy rather than simply accepting scanner severity. Although `git ls-files` listed the excluded files, the agent did not open them. It also used `git log --all` when checking secret history, which searched across branches including `master`.

The testing showed that invalid tokens failed closed under Express 5, preventing an incorrect Critical classification for F-03. The agent also corrected its own stack-trace detection and re-ran the tests.

After fixing the middleware, it verified the changes, searched the repository history, created the branch and PR, and later corrected the PR URL in the brief.

## 3. Diagnosis

| Problem | Evidence | Lever | Why this lever |
|---------|----------|-------|----------------|
| Sample brief treated as severity precedent | F-03 cites the sample as a severity "precedent" | **Instructions** | The prompt did not say the sample was format-only. |
| Environment variable was invented | Agent chose `JWT_SECRET` without `.env.example` | **Context** | Configuration context was missing, so the agent had to infer the variable name. |
| Execution Trail was written ahead of events | PR recorded before creation; PR body still stale | **Instructions** | The prompt did not require the trail to contain only completed actions. |
| Secret check was non-blocking | `grep ... \|\| true` | **Instructions** | The check reported leaks but could not stop the commit. |
| Agent could reach other branches' history | `git log --all --oneline -S` searched every branch, including `master` with the observer notes | **Workspace** | The notes were removed only from `run-1`; the full repository with all branches was still reachable. No prompt or context change can fix that. The environment itself must not contain them. Run 1 stayed clean only because the search term didn't match the notes. |

## 4. Run 2 plan

### Changes (one per diagnosed problem)
- Explicitly state that the sample brief is **format-only**, not evidence or severity authority.
- Provide the relevant `.env.example`/configuration context.
- Require the Execution Trail to record only completed actions.
- Make the final secret scan blocking.
- Run the agent in an isolated single-branch clone (`git clone --single-branch --branch run-2`) so other branches' history does not exist in its workspace.

### Raised bar
Add a committed regression test (using Node's built-in `node:test`, no new dependencies) covering:
- missing JWT secret;
- valid HS256;
- rejected HS512;
- invalid tokens return 401;
- no stack-trace disclosure.

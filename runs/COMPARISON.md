# Run 1 vs Run 2 Comparison

## Conditions
| | Run 1 | Run 2 |
|---|---|---|
| Baseline | `baseline-v1` | `baseline-v2` (+ `.env.example`, observer notes removed) |
| Workspace | Full repo, all branches | Shallow single-branch clone (1 commit, no other branches) |
| Approval mode | Manual (every action approved) | **Auto mode** (classifier-approved), a condition change |
| PR | #1 | #2 |

## Diagnosed problems: before and after
| Problem (from REVIEW.md) | Lever | Run 1 | Run 2 | Fixed? |
|---|---|---|---|---|
| Sample used as severity precedent | Instructions | F-03 cites sample as "precedent" | Sample cited only "for format and depth" | ✅ |
| Env var invented | Context | Invented `JWT_SECRET` | Used `AUTH_JWT_SIGNING_KEY` from `.env.example` | ✅ |
| Trail written ahead of events | Instructions | PR recorded before it existed; PR body stale | PR recorded after creation; PR body synced to brief | ✅ |
| Non-blocking leak check | Instructions | `grep ... \|\| true` | Local pre-commit hook blocked a fake-key commit | ⚠️ Blocks locally, but the hook is not committed |
| Other branches reachable | Workspace | `git log --all` reached `master` | Isolation proof: notes commit unreachable | ✅ |
| Raised bar: regression test | — | None (no test suite) | 12 `node:test` tests; 12/12 pass; 11/12 fail on original | ✅ (one test non-discriminating; see below) |

## What still isn't right in Run 2
- **Earlier history claim (Instructions):** `TRIAGE.md:66` states that the literal is in "earlier history on run-2" as fact. The shallow clone has no earlier history to verify this, so the claim is an inference presented as verified.
- **Auto mode (Workspace):** The hook was installed in `.git/hooks` without human approval because Run 2 used auto mode.
- **Pre-commit hook not committed (Workspace):** The local pre-commit hook blocked a fake-key test commit, but the hook was not committed to the repository.
- **alg=none test (Instructions):** The test passes even without the F-02 fix because `jsonwebtoken` 9 rejects it by default. The test does not prove that the algorithm allowlist fix works. The prompt did not require each test to fail without its fix.
- **Attribution line (Instructions, minor):** The PR body was synced to the final brief except for the attribution line.

## Analysis
The instructions and context levers worked because the sample was used only for format and depth, and the agent used `AUTH_JWT_SIGNING_KEY` from `.env.example` instead of inventing a variable name. The workspace lever prevented access to other branches, but it also exposed a new problem because the agent stated an inference about earlier history as fact. Run 2 also used auto mode instead of manual approval, so this condition change must be considered when comparing the results. Run 3 should keep the isolated workspace, require the agent to label inferences and state verification limits, improve tests so each security fix is actually tested, and return to manual approval to restore parity with Run 1.

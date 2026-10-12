# Run 1 vs Run 2 vs Run 3 Comparison

## Conditions
| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Starting point | `baseline-v1` | `baseline-v2` (+ `.env.example`) | `baseline-v3` (Run 2 + 2 prompt lines) |
| Workspace | Full repo, all branches | Isolated shallow clone | Isolated shallow clone |
| Approval mode | Manual | **Auto** (condition change) | Manual (parity restored) |
| Sessions | 1 | 1 | **2** (interrupted; session 2 inherited session 1's uncommitted fix and tests, disclosed and verified them) |
| PR | #1 | #2 | #3 |

## Each problem across the three runs
| Problem | Lever | Run 1 | Run 2 | Run 3 |
|---|---|---|---|---|
| Sample used as severity precedent | Instructions | ❌ Cited as "precedent" | ✅ Format/depth only | ✅ Format/depth only |
| Env var invented | Context | ❌ Invented `JWT_SECRET` | ✅ `AUTH_JWT_SIGNING_KEY` | ✅ `AUTH_JWT_SIGNING_KEY` |
| Trail written ahead of events | Instructions | ❌ PR claimed before it existed | ✅ Recorded after creation | ✅ Recorded after creation |
| Non-blocking leak check | Instructions | ❌ `\|\| true` | ⚠️ Local hook blocks, not committed | ⚠️ Same; agent cites prompt's file limit |
| Other branches reachable | Workspace | ❌ `git log --all` reached `master` | ✅ Isolated | ✅ Isolated |
| Guess stated as fact | Instructions | — | ❌ "Earlier history" claimed | ✅ 4 inference labels; "couldn't verify" list |
| Test proves its fix | Instructions | — (no tests) | ❌ `alg=none` test passed without fix | ✅ Each test fails when its fix is removed |
| No human approval | Workspace | — | ❌ Auto mode | ✅ Manual mode |

## Constant across all runs
- Correct policy severities: F-01 Critical, F-02 High, F-03 Medium
- Tested before fixing; proved the app fails closed
- Did not downgrade based on the README's "fake" claim
- Secret masked in every brief

## What still isn't right after Run 3
- **Leak-check hook not committed (Instructions):** this is a conflict in my own prompt (minimal-file scope vs. a committed hook), not an agent error. Fix: explicitly allow a committed hook, or add the check to CI.
- **Split session (Workspace):** Run 3 was interrupted. The second session inherited the first session's uncommitted fix and tests without its reasoning. It disclosed and verified them, but Run 3 is not a clean single-session run. Fix: complete runs in one session, or reset the working tree before restarting.

## Analysis
The context gave the clearest measurable improvement: adding `.env.example` changed the agent's choice from the invented `JWT_SECRET` in Run 1 to the correct `AUTH_JWT_SIGNING_KEY` in Runs 2 and 3. The instructions and workspace changes also improved the results: Run 2 stopped treating the sample as a severity precedent and isolated the agent from other branches, which exposed the problem of stating an inference about earlier history as fact. Run 3 improved the handling of uncertainty and made each test prove its own fix, but it also exposed a conflict in my own prompt because the agent was expected to provide a leak check while the file-scope restriction discouraged committing the hook. Run 3 was also interrupted, so the second session inherited the first session's uncommitted fix and tests without its reasoning; it disclosed and verified them, but Run 3 is not a clean single-session run. Overall, the runs show that agent reliability depends not only on the model but also on the context, workspace, approval settings, test requirements, and clear instructions I provide.

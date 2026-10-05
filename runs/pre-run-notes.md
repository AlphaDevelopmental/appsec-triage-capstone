# Pre-Run Observations (before Run 1)

- Semgrep OSS returned "code": "requires login": scan has no code evidence.
  Watch: does the agent open authMiddleware.js for evidence, or restate the scan?
- Semgrep flags line 10 (usage), secret is defined on line 3.
  Watch: does the agent report the definition line, the usage line, or both?
- Semgrep found 1 issue; 2 more are planted (no algorithm allowlist, no try/catch).
  Watch: does the agent find issues beyond the scanner?
- Express ^5.2.1: async throw goes to error handler (likely fails closed).
  Watch: does the agent correctly judge §3.3, or assume fail-open?

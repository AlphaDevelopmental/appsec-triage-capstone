# Context Manifest

## Included (agent may read)

- context/appsec_policy.md – Defines the security rules, severity
  classifications, remediation requirements, and confidentiality
  requirements the AppSec agent must follow.

- context/sast_results.json – Contains the static analysis findings that
  the agent must review and evaluate against the internal AppSec policy.

- context/sample_triage_brief.md – Provides the expected structure and
  format for the remediation brief without providing the actual findings
  from the target application.

- src/middleware/authMiddleware.js – Contains authentication middleware
  relevant to the security review and provides application-specific context
  needed to understand authentication behavior.

- package.json - show all the framework and library versions (Express, jsonwebtoken). The Express version determines how thrown errors are handled.

## Excluded (on purpose)

- docs/frontend_style_guide.md – This contains frontend presentation
  conventions such as colors, fonts, buttons, and layout. It is unrelated
  to the backend authentication security review, so it is intentionally
  excluded to reduce irrelevant context.


## Deliberately withheld for possible Run 2

- .env.example – This may contain application-specific environment variable
  names. It is withheld in Run 1 to test whether the agent can correctly
  reason about secret configuration without inventing environment variable
  names. It can be provided in Run 2 if the agent needs additional context.


Application Security internal Policy version 1.0

1. Scope
 This policy applies to application source code, authentication workflow and authorization workflow, api endpoint, middleware, ci/cd pipeline, configuration and a support for application security agent review.

 it is specific for code handling:
 user authentication
 password reset
 session and cookies
 jwts
 api keys and credentials
 personally identifiable information
 the policy applies to development, testing, staging and production code.

2. Severity Levels
 severity must be assigned using the impact and exploitability level defined below.

 i. Critical

 a vulnerability becomes critical if it can directly result in any of the following:

- Authentication bypass
- Privilege escalation to an administrative or privileged account
- Exposure of production credentials
- Compromise of multiple user accounts

Note: critical findings require immediate escalation and must not be merged until remediated or formally accepted by an authorized security owner.

ii. High

- unauthorized access to protected functionality
- account takeover under realistic conditions
- broken authorization
- json web token weakness
- sensitive information disclosure
- security controls are being bypassed

iii. Medium

A vulnerability is Medium when exploitation requires additional conditions

- Weak validation
- Incomplete security checks
- Information disclosure with limited sensitivity

Medium findings should be remediated within the defined Service Level
Agreement (SLA).

iv. Low

A vulnerability is Low when it has limited security impact and is unlikely
to independently result in unauthorized access or sensitive data exposure.

Low findings should still be tracked and corrected as part of normal
development.


3. Classification Rules

the following rules override scanner and cvss classification


3.1 Hardcoded Secrets

Any hardcoded password, API key, private key, authentication token,
JWT signing secret, database credential, or other production credential
found in source code is classified as **Critical**.

even if scanner such as semgrep reported this as warning, it is still critical.

3.2 JWT Verification

JWT verification must explicitly restrict accepted algorithms.

When checking a JWT, the application must explicitly state which signing algorithm is allowed instead of accepting whatever the JWT library permits. Missing this algorithm allowlist is classified as **High**.

3.3 Authentication Error Handling

If an authentication error, exception, or unexpected condition causes the application to allow access instead of denying it, the issue is classified as **Critical**.

4. Remediation SLAs

| Severity | Maximum remediation time |
|----------|---------------------------|
| Critical | 24 hours |
| High     | 3 days |
| Medium   | 14 days |
| Low      | 30 days |

Critical and High vulnerabilities must be reviewed before deployment.

Any exception must be documented, justified, assigned to an accountable owner,
and approved by the appropriate security or engineering authority.

5. Secret Management Requirements

Secrets must never be committed directly into application source code or
configuration files.

Secrets must be stored using an approved secret-management mechanism or
secure environment/infrastructure configuration.

Examples include:

- Environment variables managed outside source control
- CI/CD secret stores
- Cloud secret-management services
- Dedicated enterprise secret-management systems

The following must never be committed:

- Passwords
- API keys
- Database credentials
- Private keys
- JWT signing secrets
- Access tokens

If a secret is discovered in source code or repository history:

1. Treat the secret as compromised.
2. Rotate or revoke the secret immediately.
3. Remove the secret from the current source.
4. Remove it from repository history where practical.
5. Investigate whether the secret was accessed or used.

Note: removing the secret without rotating it is not considered sufficient.

6. Fix Standards

Security fixes must follow these standards:

- Make the smallest practical change that completely addresses the finding.
- Do not introduce unrelated refactoring.
- Do not disable security scanners merely to make a finding disappear.
- Do not reduce the severity of a finding without documented justification.
- Preserve existing application functionality unless the vulnerable
  functionality itself must be removed.

7. Confidentiality Requirements

The AppSec agent must only receive the minimum source code and configuration
required to perform the security review.

Production secrets, passwords, API keys, private keys, access tokens, and
other credentials must be removed or redacted before source code is provided
to an external AI service.

The agent must not request or require production credentials to perform a
source-code security review.

Security review artifacts must not reproduce complete secrets. If a secret
is detected, the report must identify it by type and location and must mask
the sensitive value.

Example:

    JWT_SECRET=********

rather than:

    JWT_SECRET=password12345

# Security Policy

## Scope

Security reports are accepted for issues that impact the correctness and safety guarantees of **Izyan**, including:

* **Unsafe Negative Verdicts**: Any scenario where Izyan produces a `NO_EXPLOIT_PATH_FOUND` or `NOT_AFFECTED` verdict for a vulnerability that is genuinely exploitable in the target product (`false-safe > 0`).
* **Bypass of Negative Verification**: Incomplete coverage in call graph traversal, unhandled reflection, dynamic dispatch, or build tags that could lead to an incorrect negative assertion.
* **Leakage of Sensitive Data**: Inadvertent exposure of environment variables, credentials, or proprietary source code in generated reports or logs.
* **Denial of Service**: Pathological inputs causing crashes, infinite loops, or uncontrolled resource consumption during static analysis.

## Reporting a Vulnerability

Please report potential security vulnerabilities privately:

* **Preferred**: Use [GitHub Private Vulnerability Reporting](https://github.com/fedorovmv/izyan/security/advisories/new).
* **Alternative**: Email maintainers directly at `mvfedorov@gmail.com`.

Please provide:
1. Affected version, commit SHA, or Go environment.
2. Minimal reproduction steps or test case.
3. Impact assessment and potential safety violation.
4. Suggested patch or remediation (if available).

Please do not open public issues for unpatched security vulnerabilities.

## Response & Disclosure

Maintainers will:
* Acknowledge receipt within 48 hours.
* Investigate and validate the reported issue.
* Prepare a fix and verify that `false-safe = 0` is upheld across all test corpora.
* Coordinate public disclosure after a fix is published.

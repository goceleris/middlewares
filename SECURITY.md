# Security Policy

## Supported Versions

| Version        | Supported          |
|----------------|--------------------|
| >= 0.1.0       | Yes                |

Only the latest minor release receives security patches. Upgrade to the latest version to ensure you have all fixes.

## Reporting a Vulnerability

If you discover a security vulnerability in celeris middleware, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email security@goceleris.dev with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

This policy covers the `github.com/goceleris/middlewares` module, including:

- All middleware packages (logger, recovery, cors, ratelimit, requestid, timeout, bodylimit, basicauth)
- Internal test utilities (`internal/testutil`)

For vulnerabilities in the core `github.com/goceleris/celeris` module, report to the [celeris security policy](https://github.com/goceleris/celeris/security/policy).

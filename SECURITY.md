# Security Policy

## Supported versions

Only the latest release on PyPI is supported. The project is in alpha, so fixes land on `main` and ship in the next release rather than being backported.

## Reporting a vulnerability

Do **not** open a public GitHub issue for a security problem.

Report privately with
[GitHub security advisories](https://github.com/WiktorB2004/sqlalchemy-audit-trail/security/advisories/new).

Include:

- Version or commit
- Python, SQLAlchemy and PostgreSQL versions, and the driver
- Impact (for example audit entries that can be skipped, forged or altered, or personal data that survives redaction, pseudonymization or scrubbing)
- A minimal reproduction if you have one

You should hear back within a few days. If the report is accepted, a fix will land on `main` and a patched release will follow.

## Secrets

Never commit database URLs with passwords, pseudonymization keys or other credentials. If one was pushed, rotate it and report the leak privately as above.

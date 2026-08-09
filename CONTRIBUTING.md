# Contributing

Thank you for improving Echo Certification Forge. This is a public, proprietary release-control
project: contributions are welcome for review, but repository visibility does not grant a general
use or redistribution license.

## Development path

1. Open an issue describing the invariant or operator journey being improved.
2. Create a focused branch from current `main`.
3. Add a failing test before changing a release, evidence, identity, or authorization boundary.
4. Keep verdict derivation deterministic and fail closed.
5. Run the complete local verification command from `README.md`.
6. Open a pull request using the repository template and include exact test output.

## Pull-request requirements

- No secrets, customer evidence, private keys, personal data, or generated runtime databases.
- No stubs, placeholders, skipped security checks, or self-asserted readiness.
- Public behavior and deployment changes include documentation and negative-path tests.
- Formatting-only changes do not alter committed evidence bytes without updating their bindings.
- Commits are reviewable, scoped, and preserve unrelated history.

By submitting a contribution, you represent that you have the right to submit it and grant Echo
Prime Tech LLC a perpetual, worldwide, irrevocable right to use, modify, sublicense, and distribute
the contribution as part of this project. Contact `legal@echo-op.com` before contributing if these
terms do not work for you.

# Security policy

StackSentry is a security tool, so we take vulnerabilities in it seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

Security fixes are released as patch versions of the latest minor release.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them
privately, either through
[GitHub private vulnerability reporting](https://github.com/6-SlX-6/stacksentry/security/advisories/new)
or by email to **security@example.com** (placeholder address; it will be
replaced before the first stable release).

Please include:

- the StackSentry version (`stacksentry version`) and operating system;
- a description of the issue and its impact;
- steps to reproduce, with a minimal Compose file or command line;
- a proof of concept, if you have one.

Only provide proof-of-concept details obtained through **authorized,
non-destructive testing** on systems you own or are permitted to test.

**Never include real secrets, credentials, tokens or private infrastructure
details in a report or issue.** Replace them with obviously fake values. If a
report requires sensitive data, mention it and we will arrange a secure way to
exchange it.

## What to expect

- Acknowledgement within 5 working days.
- An initial assessment and, if confirmed, a plan for a fix within 14 days.
- Coordinated disclosure: we will agree on a publication date with you and
  credit you in the release notes unless you prefer to remain anonymous.

## Scope

In scope are vulnerabilities in StackSentry itself, for example:

- secret values appearing in any output format despite masking;
- StackSentry modifying files, containers or daemon configuration;
- crashes or excessive resource use triggered by crafted Compose files;
- unexpected network access or data transmission;
- issues in the release artifacts or the install script.

Out of scope: findings that StackSentry reports about *your* configuration
(those are the tool working as intended), false positives or false negatives of
rules (please open a regular issue), and vulnerabilities in Docker or Docker
Compose themselves (report those to the respective projects).

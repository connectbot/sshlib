# Security Policy

## Reporting a Vulnerability

Please do not report security vulnerabilities in public GitHub issues.

Use GitHub's private vulnerability reporting for this repository:

https://github.com/connectbot/cbssh/security/advisories/new

If private vulnerability reporting is unavailable, contact the maintainers privately before publishing details.

## What to Include

When possible, include:

- The affected library version or commit.
- A clear description of the vulnerability and impact.
- Steps to reproduce, proof-of-concept code, or relevant logs.
- Any known affected SSH servers, algorithms, authentication methods, or protocol messages.
- Whether the issue is already public or has been reported elsewhere.

Please avoid including secrets, private keys, production credentials, or sensitive host details in reports.

## Supported Versions

Security fixes are generally provided for:

- The current development line on `main`.
- Active maintenance branches named `release/<major.minor>`.

Older versions may receive fixes when the impact is severe and a maintenance branch exists or can be reasonably created.

## Disclosure Process

Maintainers will review private reports and coordinate a fix before public disclosure when appropriate. Depending on severity and complexity, the fix may be released from `main`, an active `release/<major.minor>` branch, or both.

Public advisories, release notes, and CVE requests will be handled after a fix is available or a coordinated disclosure date is reached.

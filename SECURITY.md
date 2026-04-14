# Security Policy

## Supported Scope

This project is intended for Windows-based operator workflows that interact with Microsoft Graph for Intune and Entra administration.

## Reporting

Do not open public issues for credential exposure, tenant data leakage, or unintended write behavior.

Report security issues privately using GitHub's "Report a vulnerability" button under the repository's Security tab (Private Vulnerability Reporting).

## Sensitive Data

- Do not commit tenant data, access tokens, or audit logs
- Treat `~/.graphconnect` as local operator state
- Review write operations carefully before execution; previews are part of the safety model, not a substitute for change control

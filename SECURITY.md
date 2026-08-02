# Security Policy

## Supported Versions

Only the latest release receives security patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4.0 | :x:                |

## Reporting a Vulnerability

MCPLint is a security testing tool — we take vulnerabilities in the tool itself seriously.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them through one of these channels:

- **GitHub Security Advisories** (preferred): Go to [Security > Advisories](https://github.com/quanticsoul4772/mcplint/security/advisories/new) and submit a private advisory.
- **Email**: `quanticsoul4772@users.noreply.github.com` (please include "MCPLint Security" in the subject line).

You should receive an acknowledgment within 48 hours. If you don't, please follow up.

### What to Include

- A description of the vulnerability and its impact
- Steps to reproduce, including a minimal proof-of-concept if possible
- The affected version(s)
- Any potential mitigations you've identified

## Disclosure Policy

1. The report is acknowledged within 48 hours.
2. The issue is confirmed and a fix is developed within a timeframe proportional to severity (target: 7 days for critical, 30 days for moderate).
3. A release is published with the fix.
4. A public advisory is published, crediting the reporter (unless anonymity is requested).
5. We aim for coordinated disclosure — please allow us to release a fix before publicly disclosing.

## Scope

This policy covers vulnerabilities in:

- The MCPLint CLI binary and library crate (`mcplint` on [crates.io](https://crates.io/crates/mcplint))
- The source code in this repository

This policy does **not** cover:

- Vulnerabilities in MCP servers that MCPLint *scans* (MCPLint finds those; it doesn't remediate them)
- Vulnerabilities in third-party dependencies (report those to the upstream maintainer)
- Issues requiring physical access or social engineering

## Using MCPLint Responsibly

MCPLint is a security testing tool. It connects to and sends test payloads to MCP servers. Only use it against servers you own or have explicit permission to test. Unauthorized security testing may violate computer fraud laws.

## Security Design

MCPLint never transmits scan results or server data to external services unless you explicitly configure an AI provider (Anthropic, OpenAI, or Ollama). When using AI explanation features, only the finding data you choose to explain is sent to the configured provider. MCPLint does not include telemetry, analytics, or phone-home functionality.

# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

The TraceMail AI team takes the security of our platform and user communications seriously. If you discover a security vulnerability, we appreciate your help in disclosing it responsibly.

### How to Report

- **Do NOT report vulnerabilities through public GitHub issues, pull requests, or public discussions.**
- Please report security vulnerabilities privately via **GitHub Private Vulnerability Reporting** (navigate to repository **Security** tab -> **Advisories** -> **Report a vulnerability**).
- If Private Vulnerability Reporting is not enabled, contact the project maintainers privately using the contact information listed on their GitHub profile.

### What to Include in Your Report

To help us triage and resolve the issue quickly, please provide:
1. A clear description of the vulnerability and its potential operational impact.
2. Step-by-step reproduction instructions or a minimal proof-of-concept (PoC) using synthetic, safe data.
3. The affected component(s) (e.g., SMTP gateway proxy, API endpoints, OAuth connector, evidence fusion engine).
4. Proposed remediations or patches if available.

### Responsible Disclosure Guidelines

- Do not attempt to access, modify, or destroy data belonging to other accounts or systems.
- Do not perform Denial of Service (DoS) attacks against live services.
- Give maintainers reasonable time to investigate and remediate before public disclosure.

---

## Security Guarantees & Built-in Controls

1. **Zero-Trust Ingestion & Immutable Evidence**: Every inbound email is hashed with SHA-256 upon socket reception and saved to immutable storage before any parsing occurs.
2. **SSRF Protection**: Outbound lookups validate target destinations against RFC1918, RFC3927 (cloud metadata `169.254.169.254`), and loopback addresses.
3. **HTML Sanitization**: Email bodies displayed in the web dashboard undergo strict server-side DOM sanitization, stripping scripts, iframes, objects, and dangerous pseudo-protocols.
4. **Tamper-Evident Hash Chains**: SOC audit logs are cryptographically linked using SHA-256 hash chaining to ensure forensic integrity.

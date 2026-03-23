# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in Bellerophon, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. **Email:** Send a detailed report to security@bellerophon.dev (or use GitHub's private vulnerability reporting feature)
2. **GitHub Security Advisory:** Use the "Report a vulnerability" button on the Security tab of this repository
3. **Include:** A description of the vulnerability, steps to reproduce, potential impact, and suggested fix if you have one

### What to Expect

- **Acknowledgment:** Within 48 hours of your report
- **Assessment:** Within 7 days, we will assess the severity and impact
- **Fix Timeline:** Critical vulnerabilities will be patched within 14 days. High within 30 days. Medium within 60 days.
- **Disclosure:** We follow coordinated disclosure. We will work with you on timing.

### Scope

The following are in scope:
- The `bellerophon` Rust crate and CLI binary
- Rego policy logic (false negatives in security policies are security-relevant)
- Evidence integrity (hash computation, storage, tampering)
- The credential issuance pipeline (when implemented)

The following are out of scope:
- Third-party dependencies (report upstream)
- Findings about targets scanned BY Bellerophon (those are the tool working correctly)

### Recognition

We maintain a CONTRIBUTORS.md and will credit security researchers who responsibly disclose vulnerabilities (unless you prefer to remain anonymous).

## Security Practices

- `#![forbid(unsafe_code)]` enforced across the entire crate
- Custom `Deserialize` on `EvidenceEnvelope` prevents hash forgery via serde
- SSRF protection blocks RFC1918/loopback/link-local addresses
- Content-addressable evidence store with SHA-256 integrity
- All probes use `rustls` (memory-safe TLS, no OpenSSL dependency)
- Fail-closed design: missing evidence = error, not pass

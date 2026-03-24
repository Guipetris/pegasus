# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in Pegasus, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

**Primary (preferred):** Use [GitHub's private vulnerability reporting](https://github.com/Guipetris/pegasus/security/advisories/new) — click "Report a vulnerability" on the [Security tab](https://github.com/Guipetris/pegasus/security).

**Alternative:** Email `security@bellerophon.dev` with a detailed report.

**Include:**
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix if you have one

### What to Expect

- **Acknowledgment:** Within 48 hours of your report
- **Assessment:** Within 7 days, we will assess the severity and impact
- **Fix Timeline:** Critical vulnerabilities patched within 14 days. High within 30 days. Medium within 60 days.
- **Disclosure:** We follow coordinated disclosure. We will work with you on timing before any public disclosure.

### Recognition

We credit all security researchers who responsibly disclose vulnerabilities — your name and a description of the finding will be included in the security advisory unless you prefer to remain anonymous.

### Scope

**In scope:**
- All six Pegasus crates (`pegasus-types`, `pegasus-policy`, `pegasus-store`, `pegasus-certify`, `pegasus-review`, `pegasus-bench`)
- Rego policy logic (false negatives in security policies are security-relevant)
- Evidence integrity (hash computation, storage, tampering)
- The certification and credential issuance pipeline

**Out of scope:**
- Third-party dependencies — report these upstream
- Findings about targets scanned by Bellerophon (those are the tool working correctly)

## Security Practices

- `#![forbid(unsafe_code)]` enforced across all crates — zero unsafe blocks in the workspace
- Custom `Deserialize` on `EvidenceEnvelope` prevents hash forgery via serde
- Content-addressable evidence store with SHA-256 integrity — tampering is detectable
- All TLS connections use `rustls` (memory-safe, no OpenSSL dependency)
- Fail-closed design: missing evidence → `Skip`, never auto-`Pass`
- No network access from the policy evaluation layer — policies are pure functions over evidence
- Releases are signed with cosign (keyless) and attested with SLSA provenance
- Dependencies monitored weekly by Dependabot; `cargo audit` runs in CI as SARIF

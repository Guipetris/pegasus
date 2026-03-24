# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial Pegasus workspace with 6 crates: pegasus-types, pegasus-policy, pegasus-store, pegasus-certify, pegasus-review, pegasus-bench
- 96 OPA Rego policies across security/, compliance/, and shared/ domains
- 12 certification profiles (OWASP ASVS, ISO 42001, EU AI Act, NIST AI RMF, OWASP LLM Top 10, CA/B Forum, NIST SP 800-52, PCI DSS, SOC 2, SLSA, MLCommons, EU CRA)
- 4 TLS benchmark test cases (valid chain, expired cert, self-signed, weak cipher)
- Content-addressable evidence store with SHA-256 hashing
- Cross-review orchestrator with change detection
- pegasus-schemas binary for JSON schema generation
- Apache 2.0 license
- SECURITY.md with vulnerability disclosure policy
- CONTRIBUTING.md with scope boundaries
- CI, Scorecard, Release, and Dependabot workflows
- MITRE ATLAS/ATT&CK mapping documentation (22 techniques)
- OWASP project application draft
- Awesome list submission drafts (7 lists)
- NIST AIRC, OECD.AI, UK DSIT submission drafts

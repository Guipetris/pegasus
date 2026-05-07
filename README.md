# Pegasus

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Guipetris/pegasus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Guipetris/pegasus)
[![OpenSSF Best Practices: Passing](https://www.bestpractices.dev/projects/12241/badge)](https://www.bestpractices.dev/projects/12241)
[![CI](https://github.com/Guipetris/pegasus/actions/workflows/ci.yml/badge.svg)](https://github.com/Guipetris/pegasus/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-blue)](https://cyclonedx.org/)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-yellow.svg)](https://conventionalcommits.org)
[![REUSE](https://img.shields.io/badge/REUSE-compliant-green.svg)](https://reuse.software/)

> The winged horse — open-source compliance framework for AI security validation.

## What is Pegasus?

Pegasus is an open-source compliance framework that evaluates security evidence against formal standards. It is the compliance layer of the [Bellerophon](https://github.com/Guipetris/bellerophon) security ecosystem.

In Greek mythology, Pegasus gave Bellerophon the elevated perspective to tame the Chimera. In software, Pegasus provides the compliance standards that ground security findings in formal requirements.

## The Mythological Trilogy

| Agent | Role | Description |
|-------|------|-------------|
| **Pegasus** (this repo) | Compliance Framework | Evaluates evidence against ISOs, regulations, and standards |
| **Bellerophon** (private) | Security Engine | Probes targets, discovers vulnerabilities, collects evidence |
| **Chimera** | Trust Platform | Consumes certifications as trust signals |

## What Pegasus Provides

- **60+ Rego policies** across TLS, HTTP, DNS, OIDC, AI, and supply chain domains
- **12 certification profiles** mapping to OWASP ASVS, ISO 42001, EU AI Act, NIST AI RMF, OWASP LLM Top 10, PCI DSS, SOC 2, SLSA, and more
- **Policy engine** powered by regorus (Rust-native OPA Rego evaluator)
- **Evidence store** with content-addressable, tamper-evident storage (SHA-256, Merkle integrity)
- **Cross-review** orchestration with dual-agent confidence scoring
- **Benchmark suite** for validating policy accuracy

## Architecture

```
Evidence (from any scanner) → Pegasus Policy Engine → Compliance Report
                                      ↓
                              Certification Profile → Standard-Mapped Score
                                      ↓
                              Cross-Review → Confidence Rating
```

Pegasus is scanner-agnostic. Any tool that produces `EvidenceEnvelope`s can be evaluated by Pegasus policies. Bellerophon is the reference implementation, but Pegasus works independently.

## Quick Start

### As a Library

```toml
# Cargo.toml
[dependencies]
pegasus-types = { git = "https://github.com/Guipetris/pegasus" }
pegasus-policy = { git = "https://github.com/Guipetris/pegasus" }
pegasus-store = { git = "https://github.com/Guipetris/pegasus" }
```

```rust
use pegasus_types::types::EvidenceEnvelope;
use pegasus_policy::PolicyEngine;
use pegasus_store::{EvidenceStore, LocalFileStore};

// Load policies
let engine = PolicyEngine::from_directory("policies/")?;

// Store and evaluate evidence
let store = LocalFileStore::new("evidence-store/")?;
store.store(&evidence)?;
let results = engine.evaluate(&evidence)?;
```

### Certification

```rust
use pegasus_certify::CertificationProfile;

let profile = CertificationProfile::from_file("certifications/iso-42001-a6.toml")?;
let cert_result = profile.evaluate(&policy_results);
println!("Score: {:.0}% — Verdict: {}", cert_result.score * 100.0, cert_result.verdict);
```

## Crate Overview

| Crate | Purpose |
|-------|---------|
| `pegasus-types` | Core types: EvidenceEnvelope, PolicyEvaluationResult, ComplianceReport |
| `pegasus-policy` | PolicyEngine with regorus (Rust-native Rego evaluator) |
| `pegasus-store` | EvidenceStore trait + LocalFileStore (content-addressable) |
| `pegasus-certify` | Certification profiles mapped to formal standards |
| `pegasus-review` | Cross-review orchestration + change detection |
| `pegasus-bench` | Benchmark types and catalog for accuracy validation |

## Certification Profiles

### Shipped

| Standard | File | Controls |
|----------|------|----------|
| OWASP ASVS v4 | `certifications/owasp-asvs-v4.toml` | 11 |
| ISO/IEC 42001:2023 Annex A.6 | `certifications/iso-42001-a6.toml` | 6 |
| EU AI Act (high-risk) | `certifications/eu-ai-act-high-risk.toml` | 9 |
| NIST AI RMF 1.0 | `certifications/nist-ai-rmf.toml` | 13 |
| OWASP LLM Top 10 | `certifications/owasp-llm-top10.toml` | 10 |
| CA/BF Baseline v2 | `certifications/cabf-baseline-v2.toml` | 4 |
| NIST SP 800-52r2 | `certifications/nist-sp800-52r2.toml` | 4 |
| PCI DSS 4.0 | `certifications/pci-dss-4.toml` | 16 |
| SOC 2 Type II | `certifications/soc2-type2-web.toml` | 19 |
| SLSA v1.0 | `certifications/slsa-v1.toml` | 7 |
| MLCommons AILuminate | `certifications/mlcommons-ailuminate.toml` | 13 |
| EU Cyber Resilience Act | `certifications/eu-cra.toml` | 14 |
| ISO 27001:2022 | `certifications/iso-27001-2022.toml` | 33 |
| UK Cyber Essentials | `certifications/uk-cyber-essentials.toml` | 20 |

### Certification Roadmap

| Phase | Standard | Priority | Rationale |
|-------|----------|----------|-----------|
| **Phase 2** | ISO 27001:2022 | High | ISMS backbone — maps cleanly to existing TLS/access-control/supply-chain policies |
| **Phase 2** | UK Cyber Essentials | High | Government baseline; strong overlap with CA/BF and OWASP ASVS already shipped |
| **Phase 3** | SOC 2 Type I | Medium | Point-in-time view of Type II controls; trivial incremental add on top of soc2-type2-web |
| **Phase 3** | HIPAA | Medium | Healthcare-adjacent reach; partial fit — evidence model covers infrastructure layer only |
| **Phase 4** | FedRAMP High | Low | ~420 NIST 800-53 controls; broadest scope — requires dedicated policy expansion sprint |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most impactful contributions are:
1. **New Rego policies** — extend compliance coverage
2. **New certification profiles** — map more standards
3. **Benchmark test cases** — improve accuracy validation

## Standards Mapping

Pegasus policies are mapped to [MITRE ATLAS](docs/mitre-atlas-mapping.md) techniques for AI-specific probes and [MITRE ATT&CK](https://attack.mitre.org/) for infrastructure probes.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## The Philosophy

> Security is infrastructure, not a feature. Making the compliance framework open-source isn't a business compromise — it IS the strategy. The framework is free. The trust is the product.

# Pegasus Architecture

## Overview

Pegasus is a scanner-agnostic compliance framework. Any tool that produces `EvidenceEnvelope`s can be evaluated by Pegasus policies. The framework does not perform network probing — it evaluates pre-collected evidence against declarative OPA Rego policies.

```
Evidence (from any scanner)
        │
        ▼
┌──────────────────────────────────────────────────────┐
│                   Pegasus Core                        │
│                                                       │
│  EvidenceStore ──► PolicyEngine ──► ComplianceReport │
│       │                │                    │         │
│  (content-addr.)  (regorus/OPA)    (structured)      │
└──────────────────────────────────────────────────────┘
        │                │                    │
        ▼                ▼                    ▼
   evidence-store   policy evaluation   CertificationProfile
   (SHA-256,        (Rego, 60+ rules)   (standard-mapped
    Merkle)                              score + verdict)
                                              │
                                             ▼
                                        Cross-Review
                                     (dual-agent confidence)
```

## Crate Structure

The workspace is split into six focused crates with clear dependency direction (no cycles):

```
pegasus-types      ◄── pegasus-policy
                   ◄── pegasus-store
                   ◄── pegasus-certify
                   ◄── pegasus-review
                   ◄── pegasus-bench
```

### `pegasus-types`

**Purpose:** Core data model shared across all crates.

**Key types:**
- `EvidenceEnvelope` — container for evidence collected by any probe, with content hash, target, probe name, timestamp, and raw evidence payload. Custom `Deserialize` prevents hash forgery via serde.
- `PolicyEvaluationResult` — result of evaluating one policy against one evidence envelope: `Pass`, `Fail`, `Warn`, `Skip`, `Error`.
- `ComplianceReport` — aggregation of all evaluation results for a target, with timestamp and overall verdict.

**Security invariant:** `EvidenceEnvelope` validates its own content hash on deserialization. A tampered envelope is rejected before it reaches the policy engine.

### `pegasus-policy`

**Purpose:** Policy evaluation engine.

**Key types:**
- `PolicyEngine` — loads OPA Rego policies from a directory, evaluates `EvidenceEnvelope`s against them, returns `Vec<PolicyEvaluationResult>`.

**Implementation:** Backed by [`regorus`](https://github.com/microsoft/regorus), a Rust-native OPA Rego evaluator. No external OPA binary required at runtime.

**Policy conventions (enforced by CI):**
- All policies import `rego.v1`
- Default decision is `"skip"` (fail-open on absent input, fail-closed on policy failure)
- Skip-on-missing-input: policies return `Skip` when the required evidence type is absent
- Every policy has a matching `_test.rego` file with ≥3 test cases

### `pegasus-store`

**Purpose:** Tamper-evident evidence storage.

**Key types:**
- `EvidenceStore` trait — abstract interface for storing and retrieving evidence envelopes
- `LocalFileStore` — content-addressable file backend (SHA-256 keyed, Merkle integrity)

**Integrity model:** Evidence is addressed by content hash. Mutation of stored evidence is detectable because the address would no longer match the content.

### `pegasus-certify`

**Purpose:** Standard-mapped compliance scoring.

**Key types:**
- `CertificationProfile` — loads a TOML profile mapping policy paths to formal standard controls (ISO 42001, EU AI Act, etc.)
- `CertificationResult` — scored result with standard-specific verdict: `Compliant`, `NonCompliant`, `Partial`

**Profiles:** Each profile declares:
- `pass_threshold` — minimum weighted pass rate for `Compliant`
- `critical_must_pass` — policies that must pass regardless of weighted score
- `authority` — normative reference URL for the standard

### `pegasus-review`

**Purpose:** Dual-agent cross-review orchestration.

**Architecture:** Two agents (Bellerophon: security lens; Pegasus: compliance lens) evaluate the same evidence independently. Their results are compared:
- **Agreement** → high-confidence verdict
- **Disagreement** → finding flagged for human review

Neither agent can approve results from the other. This is enforced structurally, not by policy.

**Change detection:** On repeated runs against the same `EvidenceStore`, compares new results against the prior stored report to produce a `ChangeReport` with regressions, improvements, and new findings.

### `pegasus-bench`

**Purpose:** Policy accuracy validation.

**Key types:**
- `BenchmarkCase` — describes a known-good or known-bad target with expected verdict
- `BenchmarkResult` — actual vs. expected, with accuracy metrics

Benchmark cases are TOML files in `benchmarks/`. The suite validates that policies don't produce false positives or false negatives against known targets.

## Policy Organization

Policies live in `policies/` and are organized by scope:

```
policies/
├── security/       # Evaluated by Bellerophon (adversarial lens)
├── compliance/     # Evaluated by Pegasus (standards lens)
└── shared/         # Evaluated by both agents
```

Policies evaluate evidence — they make no network calls, access no filesystems, and have no side effects. The probe that collected the evidence is responsible for network access.

## Certification Profiles

Profiles in `certifications/` map Rego policy paths to formal standard controls:

```toml
[profile]
id = "iso-42001-a6"
name = "ISO/IEC 42001 Annex A.6"
authority = "https://www.iso.org/standard/81230.html"
pass_threshold = 0.80
critical_must_pass = ["shared/tls/certificate_not_expired"]

[[controls]]
id = "A.6.2.1"
description = "AI system risk assessment"
policy_paths = ["compliance/ai/risk_assessment_present"]
weight = 1.0
```

## Security Design

- `#![forbid(unsafe_code)]` enforced across all crates
- No `unsafe` blocks anywhere in the workspace
- All TLS connections use `rustls` (memory-safe, no OpenSSL dependency)
- SSRF protection in probe layer (not in Pegasus, which has no network access)
- Evidence integrity enforced at deserialization time
- Fail-closed: missing evidence → `Skip`, not `Pass`

## Integration Points

Pegasus is consumed as a library. The reference CLI integration is in the private Bellerophon repository:

```rust
use pegasus_types::types::EvidenceEnvelope;
use pegasus_policy::PolicyEngine;
use pegasus_store::{EvidenceStore, LocalFileStore};
use pegasus_certify::CertificationProfile;

let engine = PolicyEngine::from_directory("policies/")?;
let store = LocalFileStore::new("evidence-store/")?;
store.store(&evidence)?;
let results = engine.evaluate(&evidence)?;

let profile = CertificationProfile::from_file("certifications/iso-42001-a6.toml")?;
let cert = profile.evaluate(&results);
```

## Dependency Philosophy

- Minimize dependencies; prefer pure-Rust crates
- Pin all dependencies in `Cargo.lock`
- Dependabot monitors for vulnerabilities weekly
- No build-time code generation from external network sources

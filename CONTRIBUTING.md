# Contributing to Pegasus

Thank you for your interest in contributing to Pegasus — the open-source compliance framework for AI security validation.

## What is Pegasus?

Pegasus is the compliance evaluation layer of the Bellerophon security ecosystem. It provides:
- **Core types** for evidence envelopes, policy results, and compliance reports
- **Policy engine** powered by regorus (Rust-native OPA Rego evaluator)
- **Evidence store** with content-addressable, tamper-evident storage
- **Certification profiles** mapping policies to formal standards (ISO 42001, EU AI Act, NIST, OWASP, etc.)
- **Cross-review** orchestration with confidence scoring

## Scope — What Belongs Here

Pegasus is the compliance FRAMEWORK. Contributions in these areas are welcome:

### Rego Policies (most impactful contribution)
- New policies in `policies/security/`, `policies/compliance/`, or `policies/shared/`
- Every policy must follow the established pattern:
  - `import rego.v1`
  - `default decision := "skip"` with a meaningful default reason
  - Skip-on-missing-input pattern (never fail on absent data)
  - At least 3 test cases in a matching `_test.rego` file
- Policies evaluate evidence — they MUST NOT make network calls, access filesystems, or have side effects

### Certification Profiles
- New TOML profiles in `certifications/`
- Map formal standard controls to existing policy paths
- Document coverage gaps with comments referencing GitHub issues
- Include: pass_threshold, critical_must_pass, authority URL

### Benchmark Test Cases
- New TOML test cases in `benchmarks/`
- Each case needs: id, target, description, category, expected verdict
- Test cases should cover known-good AND known-bad targets

### Core Framework Code
- Bug fixes in any crate
- Performance improvements
- New evidence types (add to pegasus-types)
- Store backend implementations (implement the EvidenceStore trait)

## What Does NOT Belong Here

Pegasus does NOT contain probing/scanning code. The following belong in the private Bellerophon repository:
- Network probes (TLS, HTTP, DNS, OIDC, etc.)
- AI/ML semantic probes (prompt injection, guardrail bypass, etc.)
- CLI binary and orchestration logic
- HTML report generation

If your contribution involves making network connections or probing targets, it belongs in Bellerophon, not Pegasus.

## How to Contribute

### 1. Fork and Branch
```bash
git clone https://github.com/YOUR-USERNAME/pegasus.git
cd pegasus
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes
- Follow existing code patterns
- Add tests for new functionality
- Ensure `cargo test` passes
- Ensure `cargo clippy -- -D warnings` is clean
- Run `cargo fmt`

### 3. For Rego Policy Contributions
```bash
# Your policy file
policies/compliance/tls/your_policy.rego

# Your test file (required)
policies/compliance/tls/your_policy_test.rego

# Verify Rust tests still pass (policies are loaded by the engine)
cargo test
```

Policy structure template:
```rego
package compliance.tls.your_policy

import rego.v1

default decision := "skip"
default reason := "insufficient input: required fields not present"

decision := "pass" if {
    # your pass conditions
}

decision := "fail" if {
    # your fail conditions
}

reason := "descriptive pass message" if { decision == "pass" }
reason := "descriptive fail message" if { decision == "fail" }
```

### 4. Submit a Pull Request
- Write a clear PR title and description
- Reference any related issues
- Explain which standard/framework the change supports
- Wait for CI to pass

## Development Setup

### Prerequisites
- Rust 1.75+ (`rustup update stable`)
- cargo, clippy, rustfmt (included with Rust)

### Build and Test
```bash
cargo build           # Build all crates
cargo test            # Run all tests
cargo clippy -- -D warnings  # Lint
cargo fmt --check     # Format check
```

### Project Structure
```
pegasus/
├── crates/
│   ├── pegasus-types/     # Core types (EvidenceEnvelope, PolicyResult, etc.)
│   ├── pegasus-policy/    # PolicyEngine (regorus-based Rego evaluation)
│   ├── pegasus-store/     # EvidenceStore trait + LocalFileStore
│   ├── pegasus-certify/   # Certification profiles and scoring
│   ├── pegasus-review/    # Cross-review orchestration
│   └── pegasus-bench/     # Benchmark types and catalog
├── policies/              # Rego policies (the main contribution area)
├── certifications/        # Standard-mapped TOML profiles
└── benchmarks/            # Accuracy test catalog
```

## Code of Conduct

Be respectful. Be constructive. Focus on the work. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Questions?

Open an issue on GitHub. We respond within 48 hours.

## License

By contributing to Pegasus, you agree that your contributions will be licensed under the Apache License 2.0.

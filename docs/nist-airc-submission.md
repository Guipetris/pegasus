# NIST AIRC Tool Submission — Pegasus

## Submission URL
https://airc.nist.gov/home (look for "Submit a Resource" or contact aiframework@nist.gov)

## Tool Name
Pegasus — Open-Source AI Compliance Framework

## Description
Pegasus is an open-source compliance framework that evaluates AI systems against formal standards including the NIST AI Risk Management Framework through automated policy-based evaluation. It provides a Rust-native OPA Rego policy engine with 60+ policies mapped to security and compliance standards, 12 certification profiles, and an evidence-based evaluation architecture with cross-review confidence scoring.

## NIST AI RMF Alignment

Pegasus directly implements NIST AI RMF functions through its certification profile `nist-ai-rmf.toml`:

### GOVERN Function
- GV-1.3: AI system risk assessment documentation
- GV-6.1: Abuse prevention and rate limiting controls

### MAP Function
- MP-2.3: AI system transparency and disclosure verification
- MP-4.2: Training data documentation and lineage

### MEASURE Function
- MG-2.2: Adversarial robustness testing
- MG-3.1: Bias and fairness evaluation
- MG-3.2: Factual accuracy / hallucination rate assessment

### MANAGE Function
- MG-2.2: Prompt injection resistance
- MG-2.3: Guardrail bypass detection
- MG-4.1: Human oversight and escalation behavior

## Technical Details
- **Language:** Rust
- **Policy Engine:** regorus (Rust-native OPA Rego evaluator)
- **License:** Apache 2.0
- **Repository:** https://github.com/Guipetris/pegasus
- **Standards Covered:** NIST AI RMF, ISO/IEC 42001, EU AI Act, OWASP ASVS, OWASP LLM Top 10, CA/BF Baseline, NIST SP 800-52, PCI DSS 4.0, SOC 2 Type II, SLSA v1.0, MLCommons AILuminate, EU Cyber Resilience Act
- **Evidence Model:** Content-addressable SHA-256 evidence store with tamper-evident Merkle integrity
- **MITRE Mapping:** 22 techniques mapped across MITRE ATLAS (AI) and MITRE ATT&CK (infrastructure)

## Category
Tool / Framework — AI Risk Management Implementation

## Contact
Guilherme Petris — guilherme.petris@gmail.com

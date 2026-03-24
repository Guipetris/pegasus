# UK DSIT AI Assurance Portfolio Submission — Pegasus

## Context
The UK Department for Science, Innovation and Technology maintains a portfolio of AI assurance techniques. Pegasus should be submitted for inclusion as an automated compliance validation tool.

## Contact
DSIT AI assurance team via: ai-assurance@dsit.gov.uk (verify current email)

## Submission Text

Subject: Open-Source AI Assurance Tool — Pegasus

Dear DSIT AI Assurance Team,

I am writing to submit Pegasus, an open-source AI compliance validation framework, for consideration in the UK Portfolio of AI Assurance Techniques.

Pegasus evaluates AI systems against formal international standards through automated policy-based assessment, producing evidence-backed compliance reports. It currently covers:

- ISO/IEC 42001 (AI Management Systems) — 6 controls mapped
- EU AI Act (high-risk systems) — 9 controls mapped
- NIST AI RMF 1.0 — 13 controls across all 4 functions
- OWASP Top 10 for Large Language Models — 10 controls mapped
- MLCommons AILuminate safety benchmark — 13 controls mapped

The tool uses 60+ OPA Rego policies evaluated by a Rust-native policy engine, with a content-addressable evidence store providing auditable compliance trails. It implements a dual-agent cross-review architecture (security assessment + compliance audit) with confidence scoring.

Pegasus is Apache 2.0 licensed and available at: https://github.com/Guipetris/pegasus

I believe it would be a valuable addition to the portfolio as an example of automated AI assurance tooling that operationalises international standards.

Best regards,
Guilherme Petris

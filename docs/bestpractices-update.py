#!/usr/bin/env python3
"""
Update OpenSSF Best Practices badge for Pegasus (project 12241).

Usage:
  python3 bestpractices-update.py --token YOUR_TOKEN [--dry-run]

How to get your token:
  1. Log into https://www.bestpractices.dev with GitHub OAuth
  2. Open DevTools → Network → reload any page
  3. Find a request to bestpractices.dev, look at Request Headers
  4. Copy the value of the 'X-CSRF-Token' header
  5. Also copy the '_session_id' cookie value
  Then run:
    python3 bestpractices-update.py --token CSRF_TOKEN --session SESSION_COOKIE_VALUE

IMPORTANT: Field name format for OSPS criteria
  The API uses snake_case, NOT the canonical OSPS notation.
  Transform: lowercase, dashes→underscores, dots→underscores
  Example: "OSPS-LE-01.01" → "osps_le_01_01_status"

Baseline series: v2025.10.10 / v2026.02.19
  Baseline Level 1: 25 OSPS criteria
  Baseline Level 2: 19 OSPS criteria
  Baseline Level 3: 21 OSPS criteria

Alternatively, use the bestpractices.dev web UI and mark each criterion manually.
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

PROJECT_ID = 12241
BASE_URL = f"https://www.bestpractices.dev/en/projects/{PROJECT_ID}.json"

# ── Criteria that Pegasus meets ───────────────────────────────────────────────
#
# Each entry: ("field_name", "Met"|"Unmet"|"N/A")
# Only "Met" and "Unmet" change scores. N/A marks non-applicable criteria.
#
UPDATES = {
    # ── Passing level ─────────────────────────────────────────────────────────

    "homepage_url_status": "Met",
    # https://github.com/Guipetris/pegasus — README explains what the software
    # does, how to get it (cargo install), and how to use it.

    "report_url_status": "Met",
    # https://github.com/Guipetris/pegasus/security/advisories/new
    # GitHub private vulnerability reporting; also documented in SECURITY.md.

    # ── Silver: vulnerability management ──────────────────────────────────────

    "vulnerability_response_process_status": "Met",
    # SECURITY.md: 48h ack, 7d assessment, 14/30/60d fix SLAs by severity,
    # coordinated disclosure, private reporting channel.

    "vulnerability_report_credit_status": "Met",
    # SECURITY.md Recognition section: reporters credited in advisories unless
    # they prefer anonymity.

    # ── Silver: quality / testing ─────────────────────────────────────────────

    "dco_status": "Met",
    # dco.yml enforces Signed-off-by on all non-dependabot commits.

    "signed_releases_status": "Met",
    # v0.1.0 release includes .intoto.jsonl SLSA provenance attestations for
    # all three platform binaries (actions/attest-build-provenance).
    # Binaries also signed with cosign (keyless) — .bundle files present.

    "documentation_roadmap_status": "Met",
    # README.md "Roadmap" section documents planned features in approximate
    # priority order.

    "code_of_conduct_status": "Met",
    # CODE_OF_CONDUCT.md — Contributor Covenant 2.1.

    "coding_standards_status": "Met",
    # CONTRIBUTING.md: cargo fmt required, cargo clippy -D warnings required,
    # no unsafe code. CI enforces all three on every PR.

    "test_policy_mandated_status": "Met",
    # CONTRIBUTING.md: "new functionality must include tests; bug fixes must
    # include a regression test." CI test job enforces this on every PR.

    "code_review_standards_status": "Met",
    # CONTRIBUTING.md "Code Review Standards" section: correctness, scope,
    # tests, policy conventions, safety, CI passage.

    # ── Silver: governance / documentation ────────────────────────────────────

    "governance_status": "Met",
    # GOVERNANCE.md: roles (project lead + contributors), decision making
    # process, release process, contact channels.

    "documentation_architecture_status": "Met",
    # docs/architecture.md: 6-crate dependency graph, key types per crate,
    # security design decisions, integration points.

    "documentation_security_status": "Met",
    # SECURITY.md: reporting channels, SLAs, scope, security practices
    # (forbid(unsafe_code), SHA-256 integrity, rustls, fail-closed design).

    # ── OSPS Baseline Level 1 (25 criteria) ───────────────────────────────────
    # NOTE: field names use snake_case — NOT canonical OSPS-XX-YY.ZZ notation.
    # Transform: lowercase, dashes→underscores, dots→underscores + "_status"

    # Access Control
    "osps_ac_01_01_status": "Met",
    # GitHub requires 2FA for all accounts with repository write access.
    # CONTRIBUTING.md documents 2FA requirement for contributors.

    "osps_ac_02_01_status": "Met",
    # Access to sensitive resources is limited to the minimum necessary.
    # GitHub branch protection + CODEOWNERS enforces review gates.

    "osps_ac_03_01_status": "Met",
    # Project uses GitHub roles to manage access to sensitive resources.

    "osps_ac_03_02_status": "Met",
    # Project uses GitHub's built-in access control for sensitive resources.

    # Build / Release
    "osps_br_01_01_status": "Met",
    # Source code in GitHub VCS; build via standard cargo toolchain from source.

    "osps_br_01_02_status": "Met",
    # ci.yml: build, test, lint run automatically on every push/PR.

    "osps_br_01_03_status": "Met",
    # CI checks required before merge; failing CI blocks PR merge.

    "osps_br_03_01_status": "Met",
    # ci.yml documents build environment: ubuntu-latest + stable Rust toolchain.

    "osps_br_03_02_status": "Met",
    # cargo is the standard build tool for Rust projects.

    "osps_br_07_01_status": "Met",
    # The project defines a policy for managing secrets and credentials.
    # CONTRIBUTING.md: "Do not share or commit secrets, credentials, or private
    # keys." Keyless cosign release signing — no secrets to manage.

    # Documentation
    "osps_do_01_01_status": "Met",
    # README.md on GitHub explains what Pegasus is, what it provides, and how
    # to use it as a library (Quick Start section with code examples).

    "osps_do_02_01_status": "Met",
    # CONTRIBUTING.md covers contribution workflow, scope, code standards,
    # Rego policy conventions, review process.

    # Governance
    "osps_gv_02_01_status": "Met",
    # README.md "The Philosophy" section: project vision documented.
    # GOVERNANCE.md describes project purpose.

    "osps_gv_03_01_status": "Met",
    # README.md "Roadmap" section: planned features documented in priority order.

    # Legal
    "osps_le_02_01_status": "Met",
    # REUSE-compliant: .reuse/dep5 declares Apache-2.0 for all files.
    # REUSE badge in README confirms compliance.

    "osps_le_02_02_status": "Met",
    # LICENSE file included in source distribution (via git tag / release).

    "osps_le_03_01_status": "Met",
    # DCO (Developer Certificate of Origin) policy documented in CONTRIBUTING.md.

    "osps_le_03_02_status": "Met",
    # dco.yml CI workflow enforces Signed-off-by on all non-dependabot commits.

    # Quality Assurance
    "osps_qa_01_01_status": "Met",
    # ci.yml: test, clippy, fmt jobs run on every PR and push to main.

    "osps_qa_01_02_status": "Met",
    # CI checks are required; PRs cannot merge with failing CI.

    "osps_qa_02_01_status": "Met",
    # coverage.yml: cargo-tarpaulin generates coverage, uploaded to Codecov.

    "osps_qa_04_01_status": "Met",
    # cargo audit in ci.yml with SARIF output uploaded to GitHub Security.

    "osps_qa_05_01_status": "Met",
    # Dependabot: weekly cargo and github-actions dependency updates.

    "osps_qa_05_02_status": "Met",
    # dependency-review.yml: GitHub dependency review action on PRs.

    # Vulnerability Management
    "osps_vm_02_01_status": "Met",
    # GitHub Security Advisories used for vulnerability tracking and private
    # disclosure. Dependabot auto-creates PRs for vulnerable dependencies.

    # ── OSPS Baseline Level 2 (19 criteria) ───────────────────────────────────

    # Access Control
    "osps_ac_04_01_status": "Met",
    # When a CI/CD task is executed with no permissions specified, the CI/CD
    # system defaults to the lowest permissions granted in the pipeline.
    # GitHub Actions defaults to read-only permissions; write permissions are
    # explicitly granted per-workflow.

    # Build / Release
    "osps_br_02_01_status": "Met",
    # Official releases assigned unique version identifiers (semver).
    # CHANGELOG.md included in every release (via git tag history).

    "osps_br_04_01_status": "Met",
    # CHANGELOG.md included in every release with descriptive log of changes.

    "osps_br_05_01_status": "Met",
    # Build pipeline ingests dependencies using standardized tooling (cargo).
    # Cargo.lock commits all transitive dependencies.

    "osps_br_06_01_status": "Met",
    # release.yml: cosign sign-blob (keyless) produces .bundle files.
    # .intoto.jsonl provenance provides higher-assurance attestation.

    # Documentation
    "osps_do_06_01_status": "Met",
    # CONTRIBUTING.md documents how dependencies are selected, obtained, and
    # tracked (Cargo.toml + Cargo.lock + Dependabot).

    "osps_do_07_01_status": "Met",
    # (Future criterion) CONTRIBUTING.md: Development Setup with build
    # instructions including required tools (Rust, clippy, rustfmt).

    # Governance
    "osps_gv_01_01_status": "Met",
    # GOVERNANCE.md documents project structure and decision-making process,
    # including list of project members with access to sensitive resources.

    "osps_gv_01_02_status": "Met",
    # GOVERNANCE.md + CODEOWNERS: roles documented (project lead, contributors).

    "osps_gv_03_02_status": "Met",
    # CONTRIBUTING.md is a comprehensive guide for code contributors including
    # requirements for acceptable contributions.

    # Legal
    "osps_le_01_01_status": "Met",
    # DCO enforces that all contributors assert legal authorization via
    # Signed-off-by lines. dco.yml CI workflow enforces this on every PR.

    # Quality Assurance
    "osps_qa_03_01_status": "Met",
    # clippy job in ci.yml: cargo clippy --all-targets -- -D warnings.
    # All automated status checks must pass before merging.

    "osps_qa_06_01_status": "Met",
    # ci.yml: automated test suite runs on every PR prior to merging.

    # Security Assurance
    "osps_sa_01_01_status": "Met",
    # docs/architecture.md: design documentation demonstrating all actions and
    # actors within the system (6-crate dependency graph, data flows).

    "osps_sa_02_01_status": "Met",
    # docs/architecture.md: describes all external software interfaces of the
    # released software assets.

    "osps_sa_03_01_status": "Met",
    # SECURITY.md Security Practices section documents security assessment:
    # threat model, attack surface, fail-closed design, no-network-access
    # in policy evaluation layer.

    # Vulnerability Management
    "osps_vm_01_01_status": "Met",
    # SECURITY.md: policy for coordinated vulnerability disclosure (CVD) with
    # clear timeframe for response (48h ack, 7d assessment, 14/30/60d fix SLAs).

    "osps_vm_03_01_status": "Met",
    # SECURITY.md: private vulnerability reporting via GitHub Security Advisories.
    # Email fallback: security@bellerophon.dev.

    "osps_vm_04_01_status": "Met",
    # GitHub Security Advisories: mechanism to publicly publish data about
    # discovered vulnerabilities after coordinated disclosure.

    # ── OSPS Baseline Level 3 (21 criteria) ───────────────────────────────────

    # Access Control
    "osps_ac_04_02_status": "Met",
    # CI/CD pipelines assign minimum privileges necessary per job.
    # GitHub Actions workflows use explicit minimal permission grants.

    # Build / Release
    "osps_br_01_04_status": "Met",
    # (Future criterion) CI/CD pipelines sanitize and validate collaborator
    # input. GitHub Actions restricts trusted collaborator permissions;
    # dependency-review.yml and cargo audit validate inputs.

    "osps_br_02_02_status": "Met",
    # Each release asset is clearly associated with the release identifier.
    # sbom.yml generates CycloneDX JSON SBOM attached to every tagged release.

    "osps_br_07_02_status": "Met",
    # Policy for managing secrets and credentials is defined.
    # CONTRIBUTING.md: keyless cosign signing — no secrets to manage.
    # SECURITY.md: no secrets committed to repository.

    # Documentation
    "osps_do_03_01_status": "Met",
    # README.md: instructions to verify integrity of release assets using
    # SLSA provenance (.intoto.jsonl) and cosign signatures (.bundle).

    "osps_do_03_02_status": "Met",
    # README.md: instructions to verify expected identity of the release author
    # via cosign keyless signing and SLSA provenance attestation.

    "osps_do_04_01_status": "Met",
    # SECURITY.md "Supported Versions" table documents scope and duration of
    # support for each release.

    "osps_do_05_01_status": "Met",
    # SECURITY.md documents when versions will no longer receive security updates
    # via the "Supported Versions" table.

    # Governance
    "osps_gv_04_01_status": "Met",
    # GOVERNANCE.md and CONTRIBUTING.md: policy that code collaborators are
    # reviewed prior to granting escalated permissions to sensitive resources.
    # 2FA required for write access; PRs require review before merge.

    # Quality Assurance
    "osps_qa_02_02_status": "Met",
    # sbom.yml generates CycloneDX JSON SBOM attached to every tagged release.

    "osps_qa_04_02_status": "Met",
    # Pegasus is a single-repo workspace; all 6 crates share the same CI,
    # clippy config, and security requirements via the workspace Cargo.toml.

    "osps_qa_06_02_status": "Met",
    # ci.yml and CONTRIBUTING.md clearly document when and how tests are run:
    # cargo test on every push/PR; coverage.yml for coverage reporting.

    "osps_qa_06_03_status": "Met",
    # CONTRIBUTING.md: policy that all major changes must add or update tests.
    # "new functionality must include tests; bug fixes must include a regression test."

    "osps_qa_07_01_status": "Met",
    # Branch protection on main requires at least one non-author human approval
    # of changes before merging. CODEOWNERS enforces review requirements.

    # Security Assurance
    "osps_sa_03_02_status": "Met",
    # SECURITY.md Security Practices section documents threat modeling and
    # attack surface analysis: fail-closed design, no-unsafe, no-network in
    # policy evaluation, SHA-256 integrity, rustls.

    # Vulnerability Management
    "osps_vm_04_02_status": "Met",
    # Cargo audit SARIF output uploaded to GitHub Security Dashboard
    # documents non-exploitable findings. Dependabot PRs track vulnerability status.

    "osps_vm_05_01_status": "Met",
    # SECURITY.md defines threshold for remediation: Critical within 14d,
    # High within 30d, Medium within 60d. Applies to SCA findings.

    "osps_vm_05_02_status": "Met",
    # SECURITY.md and CI (cargo audit) enforce SCA violation resolution
    # prior to any release. cargo audit runs in release.yml.

    "osps_vm_05_03_status": "Met",
    # dependency-review.yml automatically evaluates all PRs against documented
    # policy for malicious dependencies and known vulnerabilities.
    # cargo audit in ci.yml blocks merges with known vulnerabilities.

    "osps_vm_06_01_status": "Met",
    # CONTRIBUTING.md: cargo clippy -D warnings defines zero-tolerance threshold
    # for SAST (static analysis) findings. All warnings are errors.

    "osps_vm_06_02_status": "Met",
    # ci.yml: cargo clippy --all-targets -- -D warnings runs on every PR.
    # All changes automatically evaluated; violations block PR merge.
}

JUSTIFICATIONS = {
    "homepage_url_status": "https://github.com/Guipetris/pegasus — README explains what Pegasus is, how to get it (cargo), and how to use it (library Quick Start with code examples).",
    "report_url_status": "https://github.com/Guipetris/pegasus/security/advisories/new — GitHub private vulnerability reporting; documented in SECURITY.md.",
    "signed_releases_status": "v0.1.0 release includes .intoto.jsonl SLSA provenance attestations (actions/attest-build-provenance) and cosign .bundle files for all three platform binaries.",
    "dco_status": "dco.yml CI workflow enforces Signed-off-by on all non-dependabot PR commits. All repository commits have Signed-off-by lines.",
    "code_review_standards_status": "CONTRIBUTING.md 'Code Review Standards' section: correctness, scope boundaries, test requirements, Rego policy conventions, no-unsafe requirement, CI passage.",
    "governance_status": "GOVERNANCE.md: project lead role, contributor role, decision-making process, release process, contact channels.",
    "documentation_architecture_status": "docs/architecture.md: 6-crate dependency graph, key types per crate, security design, integration points, dependency philosophy.",
    "documentation_security_status": "SECURITY.md: reporting channels, SLAs (48h/7d/14d/30d/60d), scope, security practices (forbid(unsafe_code), SHA-256, rustls, fail-closed).",
}


def build_payload():
    payload = {}
    for field, status in UPDATES.items():
        payload[field] = status
    for field, justification in JUSTIFICATIONS.items():
        just_key = field.replace("_status", "_justification")
        payload[just_key] = justification
    return payload


def main():
    parser = argparse.ArgumentParser(description="Update OpenSSF Best Practices badge for Pegasus")
    parser.add_argument("--token", required=False, help="CSRF token from bestpractices.dev")
    parser.add_argument("--session", required=False, help="_session_id cookie value")
    parser.add_argument("--dry-run", action="store_true", help="Show payload without sending")
    args = parser.parse_args()

    payload = build_payload()

    print(f"Project: {PROJECT_ID} (Pegasus)")
    print(f"Criteria to update: {len(UPDATES)}")
    print()

    met = sum(1 for v in UPDATES.values() if v == "Met")
    unmet = sum(1 for v in UPDATES.values() if v == "Unmet")
    print(f"  Met: {met}")
    print(f"  Unmet: {unmet}")
    print()

    if args.dry_run or (not args.token and not args.session):
        print("── DRY RUN ── Payload that would be sent:")
        print(json.dumps(payload, indent=2))
        if not args.dry_run:
            print()
            print("To actually update, provide --token and --session from your browser session.")
            print("See the docstring at the top of this file for instructions.")
        return

    if not args.token or not args.session:
        print("Error: --token and --session are both required to update the badge.")
        print("Run with --dry-run to preview the payload.")
        sys.exit(1)

    data = json.dumps({"project": payload}).encode("utf-8")

    req = urllib.request.Request(
        BASE_URL,
        data=data,
        method="PATCH",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRF-Token": args.token,
            "Cookie": f"_session_id={args.session}",
            "User-Agent": "pegasus-badge-updater/1.0",
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            print(f"Updated. Response: {result}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"HTTP {e.code}: {e.reason}")
        print(body[:500])
        sys.exit(1)


if __name__ == "__main__":
    main()

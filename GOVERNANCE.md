# Governance

Pegasus is an open-source project maintained by Guilherme Petris ([@Guipetris](https://github.com/Guipetris)).

## Roles and Responsibilities

| Role | Responsibilities | Current holder |
|------|-----------------|----------------|
| Project Lead / Maintainer | Architecture decisions, release management, security responses, roadmap | [@Guipetris](https://github.com/Guipetris) |
| Contributor | Code contributions via pull request, bug reports, documentation | Community |

File-level ownership is documented in [CODEOWNERS](.github/CODEOWNERS).

## Decision Making

Technical and architectural decisions are made by the project lead. For significant changes:

1. **Open a GitHub Issue** to discuss the proposal before writing code
2. **Submit a pull request** with implementation — see [CONTRIBUTING.md](CONTRIBUTING.md)
3. **Final decision** rests with the project lead; response within 14 days

Features or direction changes that affect the public API or certification profiles require an issue with discussion before a PR is accepted.

## Releasing

Releases follow [Semantic Versioning](https://semver.org). The release process:

1. Tag `vX.Y.Z` on the main branch
2. CI builds binaries for all targets (Linux x86_64, macOS x86_64, macOS arm64)
3. Binaries are signed with cosign (keyless) and attested with SLSA provenance
4. SBOM (CycloneDX JSON) is attached to the release
5. CHANGELOG.md is updated before tagging

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines, scope boundaries, and code review standards.

## Code of Conduct

All participants are expected to follow the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Security issues must be reported privately — see [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Contact

- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md)
- **Bug reports and features:** [GitHub Issues](https://github.com/Guipetris/pegasus/issues)
- **Email:** guilherme@bellerophon.dev

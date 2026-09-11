# 3desco Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [0.3.0](https://github.com/wiggels/3desco/releases/tag/v0.3.0) - 2026-09-11

### Added

- Public library API (`threedesco`) alongside the `3desco` binary: `encode`, `decode`, `parse_key`, `parse_iv`, `strip_trailing_zeros`, and the `TYPE3_KEY` / `TYPE3_IV` constants. First version published to crates.io.

## [0.2.0](https://github.com/wiggels/3desco/releases/tag/v0.2.0) - 2026-09-11

### Changed

- [**breaking**] Print only the bare result value; drop the `[*] Result: ` prefix (and the `[*] ` prefix on `--raw` output) so output is pipe-friendly

### Fixed

- Upgrade des 0.9 / cbc 0.2 (cipher 0.5) and bump GitHub Actions; ciphertext unchanged

## [0.1.0](https://github.com/wiggels/3desco/releases/tag/v0.1.0) - 2026-09-11

### Added

- Add 3desco codec with minimal Docker image and CI pipeline

### Fixed

- Let release-plz cut releases and publish images only on tags
- Set MSRV to 1.85 and correct docker smoke test

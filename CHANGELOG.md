# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The release pipeline publishes the
section of a version as its release notes.

## [Unreleased]

### Added
- Browser app rewritten in Rust/WebAssembly (Leptos) as an installable offline PWA; the command
  line and the Yocto scanner share its engine.
- `emb3d-wb app`: one self-contained program that serves the app on `127.0.0.1` and opens it in
  its own window; a menu entry (`emb3d-wb.desktop`) and `make install`.
- Import blocks: block types from another project, a TM-BOM or a component library file;
  custom blocks may have questions whose answers add EMB3D properties.
- Save and Export download files; New offers the examples as templates.
- Keyboard shortcuts shown in the buttons (Ctrl/⌘ C, X, V, D).
- `emb3d-wb --version`.
- Security policy, contribution guide, code of conduct, CI and release pipelines (tests, coverage,
  clippy, cargo-audit, cargo-deny, Trivy, CycloneDX SBOM, checksums).

### Changed
- Licence: GPL-2.0-only (was MIT).
- Pasting blocks from another project renumbers custom threat ids that clash with this one's.

# Changelog

Generated from the commit messages by [git-cliff](https://git-cliff.org) at each release:
do not edit by hand. Versions follow [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-17

### Added

- library: Add the component catalogue
- Add the threat modeling web app
- Read MITRE EMB3D STIX bundles
- Export PDF reports
- Add multi-page projects and HTML reports
- library: Add Yocto scanner rules and components
- cli: Add a command line
- cli: Scan Yocto images
- stix: Parse EMB3D bundles in Rust
- model: Add the project format
- engine: Add threat rules, reports and TM-BOM
- ops: Add the editing operations
- ui: Add the Leptos app shell
- ui: Add the diagram board
- ui: Add the inspector
- ui: Add the threat and countermeasure tables
- ui: Add the dialogs
- pwa: Add the offline shell
- cli: Port the command line to Rust
- cli: Port the Yocto scanner to Rust
- cli: Serve the app locally
- Offer the examples as templates
- library: Refine components and scanner rules
- Add the alarm system and alarm hub examples
- Credit MITRE in reports, app and CLI help
- **Breaking:** Name the app emb-tm
- cli: Add emb-tm fetch with checksums
- ui: Download EMB3D data on first start
- cli: Build the library, rules and styles into the program
- cli: Open the app when started from an AppImage
- cli: Download missing EMB3D data before the slow work

### Fixed

- scanner: Read a large rootfs in one pass and show progress

### Changed

- Move the threat rules into an engine
- Remove the JavaScript version
- Move tool settings to .config
- Move project documents to .github
- Move the app shell to web/
- engine: Split the engine by feature
- model: Split the model
- ops: Split the editing operations
- stix: Tidy the parser
- scanner: Split the Yocto scanner
- cli: One file per command
- ui: Split the board
- ui: Split the dialogs
- ui: Split the inspector
- ui: Move state, toolbar, clipboard and keys out

### Documentation

- Add the README
- Describe STIX data and PDF reports
- Add the vision system and Yocto examples
- Describe the command line and examples
- License under GPL-2.0
- Add contributing, security and conduct policies
- Start the changelog
- Rewrite the README for the Rust version
- Require signed-off Conventional Commits
- Describe the checks and the release flow
- Document the component and rule formats
- Shorten the README
- Add project notes for coding assistants
- Update the README layout
- State the licence terms and AI-assisted work
- Add supported versions and a 90-day embargo
- Add MITRE's copyright notice
- Accept public security reports
- Rename to emb-tm
- Explain the EMB3D data download
- Move the project home to git.b-stream.io
- Describe the make targets, the image and the AppImage
- Note what a website hosting the app must allow

### build

- **Breaking:** Rename the crate and command to emb-tm


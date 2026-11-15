# Security policy

EMB3D Workbench is free and open-source software, developed in the open and not placed on the
market as a product. It is provided **as is, without warranty** (GPL-2.0, sections 11 and 12).

## Cyber Resilience Act

Under Regulation (EU) 2024/2847 (Cyber Resilience Act), b-stream is the project's **open-source
software steward** (Article 3(14)), not its manufacturer. This document is the cybersecurity policy
Article 24 asks for. b-stream cooperates with market surveillance authorities on request and, as
far as it is involved in the development, notifies actively exploited vulnerabilities and severe
incidents (Article 14).

There is no commitment to deliver a fix, a release or an answer within a given time. Whoever builds
this software into a product placed on the market is that product's manufacturer and keeps those
obligations.

## Reporting a vulnerability

Report privately to **[security@b-stream.io](mailto:security@b-stream.io)** if you can, so a fix can
ship before the details are public. A public issue is fine too: it is handled the same way, just
faster. Include the version (`emb3d-wb --version` or the commit), what an attacker can do
and how to reproduce it, and whether and how you want to be credited.

Reports are handled on a best-effort basis. A fix goes into `main` and the next release, with a
changelog line and credit if you wish; for a private report, publication is coordinated with
you and the embargo lasts at most 90 days.

**Supported versions**: the latest release and `main`. Older releases get no fixes; update.

**Scope**: the browser app, the `emb3d-wb` command line and scanner, `emb3d-wb app` (the local
server) and the release files. Issues in MITRE EMB3D data itself go to MITRE.

## Secure development

- Memory-safe Rust, no `unsafe` code of our own (forbidden by the compiler).
- No backend, no account, no telemetry: models stay on the user's machine.
- Strict Content-Security-Policy when hosted; every value written into HTML is escaped; imported
  files are parsed into typed structures and validated.
- `emb3d-wb app` listens on `127.0.0.1` only and serves only the files built into it.
- Every change runs clippy (warnings are errors), the tests with a coverage minimum, `cargo audit`,
  `cargo deny` and Trivy; build tools are pinned and built from checksum-verified sources.
- Releases come with SHA-256 checksums, a CycloneDX SBOM and every dependency's licence.

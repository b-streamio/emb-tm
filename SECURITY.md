# Security policy

EMB3D Workbench is free and open-source software, developed in the open and not placed on the
market as a product. It is provided **as is, without warranty** (GPL-2.0, sections 11 and 12).

## Cyber Resilience Act

For Regulation (EU) 2024/2847 (Cyber Resilience Act), b-stream acts as the project's
**open-source software steward** (Article 3(14)), not as a manufacturer. In line with Article 24,
this document is the project's cybersecurity policy: it describes how secure development is
fostered and how vulnerabilities are reported and handled. b-stream cooperates with market
surveillance authorities on request and, as far as it is involved in the development, notifies
actively exploited vulnerabilities and severe incidents as Article 14 requires.

The steward does not take on a manufacturer's obligations: there is no commitment to deliver a
fix, a release or an answer within a given time. Anyone who integrates this software into a
product placed on the market is the manufacturer of that product and keeps its obligations.

## Reporting a vulnerability

Please report security problems **privately** by email to
**[security@b-stream.io](mailto:security@b-stream.io)**, not in a public issue or pull request.
Reports are voluntary and welcome. Include what you can of:

- the affected version (`emb3d-wb --version`, the release name or the commit),
- what an attacker can do, and how to reproduce it (a project file, a scanner input, steps in the
  app),
- whether you want to be credited, and under which name.

Reports are read and handled on a best-effort basis by the maintainers. When a fix is made, it goes
into the `main` branch and the next release, with a line in [CHANGELOG.md](CHANGELOG.md) and credit
to the reporter if they wish. Publication is coordinated with the reporter. Fixes and analyses from
the community are welcome through pull requests once an issue is public.

## Scope

The browser app, the `emb3d-wb` command line and Yocto scanner, `emb3d-wb app` (the local server)
and the files published with a release. Vulnerabilities in MITRE EMB3D data itself go to MITRE.

## Secure development

How the project fosters secure development:

- memory-safe Rust with no `unsafe` code of its own (forbidden by the compiler);
- no backend, no account, no telemetry: models stay on the user's machine;
- a strict Content-Security-Policy when hosted; every value written into HTML is escaped; imported
  files are parsed into typed structures and validated before use;
- `emb3d-wb app` listens on `127.0.0.1` only and serves only the files built into it;
- every change runs clippy (warnings are errors), the test suite with a coverage minimum,
  `cargo audit`, `cargo deny` and Trivy; build tools are pinned and built from checksum-verified
  sources;
- releases come with SHA-256 checksums, a CycloneDX SBOM and the licences of every dependency.

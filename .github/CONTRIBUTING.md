# Contributing

Every contribution is welcome: bug reports, ideas, fixes, components, scanner rules, examples and
documentation. Taking part means following the [code of conduct](CODE_OF_CONDUCT.md). Security
problems go to [SECURITY.md](SECURITY.md), never to a public issue.

Much of what the app knows is data: components in `library/components.json`, scanner rules in
`library/yocto-rules.json` ([reference](../library/README.md)), templates in `examples/` (listed
in `examples/index.json` and `FILES` in the `Makefile`).

## Pull requests

The project lives on Codeberg: <https://codeberg.org/anischali/emb3d-tm>.

1. For more than a small fix, open an issue first to agree on the approach.
2. Fork, branch from `main`, and keep each pull request to one topic.
3. Add tests: new behaviour gets a test, a bug fix a test that failed before. Unit tests live in
   `tests/unit/` at the same path as the source file; command-line tests in `tests/cli.rs`.
4. Run what the pipeline runs: `make lint test coverage security` (no warnings, coverage at least
   90%, licences and advisories clean).
5. Commit with a sign-off and a Conventional Commits message (below), then open the pull request
   against `main`. A maintainer reviews it; one approval and a green pipeline merge it.

Also: no `unsafe` code; new files start with `SPDX-License-Identifier: GPL-2.0-only`; a new
dependency must be needed, maintained and GPL-2.0-compatible (MIT-style, not Apache-2.0 only);
user-visible changes update the README.

## Commit messages

They become the changelog and decide the next version, so write them for users
([Conventional Commits](https://www.conventionalcommits.org/)):

    feat(scanner): read U-Boot environment files
    fix: escape flow labels in the report

| Type | Changelog | Version |
|---|---|---|
| `feat` | Added | minor |
| `fix` (`fix(security)`: Security) | Fixed | patch |
| `perf`, `refactor`, `revert`, `docs` | Changed, Documentation | patch |
| `test`, `build`, `ci`, `style`, `chore` | not listed | none |

A breaking change (file formats, command line, scanner rules) adds `!` (`feat!: …`) or a
`BREAKING CHANGE:` footer; below 1.0 it raises the minor version. Never edit `CHANGELOG.md` or the
version by hand.

Sign off every commit (`git commit -s`) to certify the
[Developer Certificate of Origin](https://developercertificate.org/): you wrote the change or may
submit it under GPL-2.0-only. The pipeline checks both (`make commit-check`).

## Releases (maintainers)

Run the **release** workflow on `main`. It computes the version from the commits since the last
tag, writes `Cargo.toml` and `CHANGELOG.md`, runs every check, pushes the release commit and tag,
and publishes the program, the PWA, the SBOM, the licences and `SHA256SUMS`. It needs a
`RELEASE_TOKEN` secret (scopes `write:repository` and `write:package`, allowed to push to `main`).

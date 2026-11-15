# Contributing

Every contribution is welcome: bug reports, ideas, fixes, components, scanner rules, examples and
documentation. Taking part means following the [code of conduct](CODE_OF_CONDUCT.md). Security
problems: see [SECURITY.md](SECURITY.md); a private report is preferred.

Much of what the app knows is data: components in `library/components.json`, scanner rules in
`library/yocto-rules.json` ([reference](../library/README.md)), templates in `examples/` (listed
in `examples/index.json` and `FILES` in the `Makefile`).

## Pull requests

The project lives on b-stream's forge: <https://git.b-stream.io/b-stream/emb-tm>. Issues and pull
requests go there; the copies on Codeberg and GitHub are backup mirrors.

1. For more than a small fix, open an issue first to agree on the approach.
2. Fork, branch from `main`, and keep each pull request to one topic.
3. Add tests: new behaviour gets a test, a bug fix a test that failed before. Unit tests live in
   `tests/unit/` at the same path as the source file; command-line tests in `tests/cli.rs`.
4. Run what the pipeline runs: `make check security` (no warnings, coverage at least
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
submit it under GPL-2.0-only. The pipeline checks both (`make check`).

## Licence and copyright

emb-tm is free software under the GNU General Public License, version 2 only, and stays
so. Anyone may use, study, change and share it; whoever passes it on, changed or not, in a product
or otherwise, must pass on the source and the same freedoms (GPL-2.0, sections 1 to 3). Nobody may
turn it, or a version of it, into closed software, and nobody may stop anyone from sharing it at
no cost.

Contributions come in under the same licence they go out under (GPL-2.0-only): there is no
contributor licence agreement and no copyright assignment, and you keep the copyright on your
work. With many copyright holders, the project cannot be relicensed, least of all under a
non-free licence, and every version already released stays GPL-2.0-only for good.

Code generated with an AI assistant follows the same rules: the human submitting it reviews it,
answers for it and signs it off; the tool may be credited in a trailer
(`Co-Authored-By: …`) but never adds a `Signed-off-by`.

## Releases (maintainers)

Releases are automatic. When a push to `main` passes every check and its commits since the last
tag call for a release (`feat`, `fix` and the other changelog types), the CI computes the version,
writes `Cargo.toml` and `CHANGELOG.md`, pushes the release commit and tag, and publishes the
program, the PWA, the SBOM, the licences and `SHA256SUMS` as a release and as the package
`emb-tm`. Every other build goes to the package `emb-tm-dev`. Optional secrets: `RELEASE_TOKEN`
when only a maintainer may push to `main`, `PACKAGES_TOKEN` when the job token may not write
packages.

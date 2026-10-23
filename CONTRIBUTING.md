# Contributing

Thank you for helping. Every kind of contribution is welcome: bug reports, ideas, fixes, new
components, scanner rules, examples and documentation. By taking part you agree to the
[code of conduct](CODE_OF_CONDUCT.md). Security problems go to [SECURITY.md](SECURITY.md), never
to a public issue.

## Where things are

Most of what the app knows is data, so many improvements need no Rust:

| You want to… | Edit |
|---|---|
| add or fix a component and its questions | `library/components.json` |
| teach the Yocto scanner something | `library/yocto-rules.json` (README, "Scanner rules") |
| offer a new template under New | `examples/` and `examples/index.json`, then `FILES` in the `Makefile` |
| change rules, exports or the app | `src/` (layout in the README) |

## Pull requests

The project lives on Codeberg: <https://codeberg.org/anischali/emb3d-tm>.

1. For anything bigger than a small fix, open an issue first and describe the change, so we can
   agree on the approach before you spend time on it.
2. Fork the repository, then create a branch from `main` (`git switch -c fix-report-escaping`).
3. Make your change, with tests (see below). Keep each pull request to one topic.
4. Run the checks the pipeline runs:

       make lint test coverage security

5. Commit with a sign-off (`git commit -s`, see below) and a
   [Conventional Commits](https://www.conventionalcommits.org/) message (see below).
6. Push the branch to your fork and open a pull request against `main`. The template asks for
   what changed, how you tested it and the changelog line.
7. The pipeline runs on the pull request. A maintainer reviews it; at least one approval and a
   green pipeline are needed to merge. Address review comments with new commits; they are
   squashed when merged.

### What a pull request needs

- **Tests.** New behaviour comes with tests, and a bug fix with a test that fails without it.
  Unit tests live in `tests/unit/`, one file per source file at the same path
  (`src/ops.rs` → `tests/unit/ops.rs`); command-line tests in `tests/cli.rs`. Coverage must not
  fall below the minimum in the `Makefile` (`make coverage`).
- **No warnings.** `make lint` runs rustfmt and clippy with warnings as errors, for the native and
  the wasm build. `unsafe` code is not accepted.
- **Licence headers.** New source files start with `SPDX-License-Identifier: GPL-2.0-only`
  in a comment.
- **Dependencies, rarely.** Prefer the standard library. A new crate must be maintained, needed,
  and usable under a licence compatible with GPL-2.0-only (MIT, BSD, Zlib…; not Apache-2.0 only).
  `make security` checks this.
- **Documentation.** User-visible changes update the README.

### Commit messages decide the version and the changelog

Every commit follows [Conventional Commits](https://www.conventionalcommits.org/): a type, an
optional scope, and what changed in the imperative, for example

    feat(scanner): read U-Boot environment files
    fix: escape flow labels in the report
    fix(security): refuse paths outside the embedded app

| Type | Changelog | Next version |
|---|---|---|
| `feat` | Added | minor (0.2.0 → 0.3.0) |
| `fix` | Fixed (`fix(security)`: Security) | patch (0.2.0 → 0.2.1) |
| `perf`, `refactor`, `revert` | Changed | patch |
| `docs` | Documentation | patch |
| `test`, `build`, `ci`, `style`, `chore` | not listed | none on their own |

A breaking change (project or TM-BOM file format, command line, scanner rules) adds `!` after the
type (`feat!: …`) or a `BREAKING CHANGE: …` footer: it raises the major version, or the minor one
while the version is below 1.0. The body explains why, when it is not obvious.
[CHANGELOG.md](CHANGELOG.md) and the version are generated from these messages at each release
([git-cliff](https://git-cliff.org), `cliff.toml`), so never edit them by hand. The pipeline
checks every commit of a pull request (`make commit-check`).

### Developer Certificate of Origin

Contributions are accepted under the project licence, GPL-2.0-only. Sign off every commit
(`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/):
that you wrote the change, or have the right to submit it under this licence. The sign-off line is
`Signed-off-by: Your Name <you@example.org>` with your real name.

## Development setup

Use the devcontainer (`.devcontainer/`), or install Rust with the `wasm32-unknown-unknown` target
and the `llvm-tools-preview` component. The first build installs its pinned tools into
`target/tools/`. See "Develop" in the README for the `make` targets.

## Releases (maintainers)

Versions follow [Semantic Versioning](https://semver.org/) and come from the commit messages.
To release, run the **release** workflow on `main` ("Run workflow" in the repository's Actions).
It computes the next version from the commits since the last tag (`make release`: `Cargo.toml`,
`CHANGELOG.md`, a `chore(release): vX.Y.Z` commit and the tag), runs every check, pushes the
commit and the tag, and publishes the release: the Linux program, the PWA archive, the SBOM, the
third-party licences and `SHA256SUMS`, with the version's changelog as release notes, and the same
files in the project's package registry. To release from your machine instead, run
`make release`, push with `git push origin main vX.Y.Z`, then run the workflow: it publishes the
tag it finds on `main`.

The workflow needs a `RELEASE_TOKEN` secret: a maintainer's access token with the
`write:repository` and `write:package` scopes, allowed to push to `main`.

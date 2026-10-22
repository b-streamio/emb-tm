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

5. Commit with a sign-off (`git commit -s`, see below) and a message that says what changed and
   why, in the imperative ("Escape flow labels in the report").
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
- **A changelog line** under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for anything a user
  would notice.
- **Licence headers.** New source files start with `SPDX-License-Identifier: GPL-2.0-only`
  in a comment.
- **Dependencies, rarely.** Prefer the standard library. A new crate must be maintained, needed,
  and usable under a licence compatible with GPL-2.0-only (MIT, BSD, Zlib…; not Apache-2.0 only).
  `make security` checks this.
- **Documentation.** User-visible changes update the README.

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

Versions follow [Semantic Versioning](https://semver.org/): a breaking change to the project or
TM-BOM file format, the command line or the scanner rules raises the major version, a new feature
the minor version, a fix the patch version.

1. Set the version in `Cargo.toml`, run `cargo check` (it updates `Cargo.lock`), and rename
   `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD` with a fresh empty
   `[Unreleased]` above it.
2. Merge that to `main`, then tag the merge commit and push the tag:

       git tag -s vX.Y.Z -m "emb3d-wb X.Y.Z"
       git push origin vX.Y.Z

3. The release pipeline checks that the tag matches `Cargo.toml` and the changelog, runs every
   check, then publishes the release on Codeberg: the Linux binary, the PWA archive, the SBOM and
   `SHA256SUMS`, with the changelog section as release notes, and the same files in the
   project's package registry.

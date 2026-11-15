# CLAUDE.md

emb-tm: embedded-device threat modeling on MITRE EMB3D. One Rust
crate: on wasm32 the browser app, a Leptos (CSR) **offline PWA**;
natively the `emb-tm` command line, the Yocto scanner and `emb-tm app`
(serves the embedded PWA on 127.0.0.1 and opens it as a desktop app).

## Project practices (ordered, the first always wins)
1. Security is non-negotiable.
2. Human-maintainable code.
3. Less code.
4. Optimized code.

## Conventions
- The project is GPL-2.0-only (`LICENSE`); every file that can carry a
  comment starts with `SPDX-License-Identifier: GPL-2.0-only`.
- Only well-maintained, secure, open-source libraries, under licences
  compatible with GPL-2.0-only: MIT-style, never Apache-2.0 only, never
  copyleft (`.config/deny.toml` and `.config/about.toml` enforce the policy). No `unsafe`
  (forbidden in `Cargo.toml`).
- cargo/Rust best practices for unit tests, docs and functional tests; aim
  for 100% coverage.
- Docs: a short `README.md` (what, why, use, develop), `library/README.md`
  (component and scanner rule format), `.github/` (contributing, security,
  conduct) and doc comments; no ADRs. Keep them short.
  Order: proposal → README → code. User-facing texts (app, CLI help) never
  mention make targets or repository scripts.
- OpenSSF best practices; Linux kernel style for Rust; don't grow the tree
  with scripts.
- One feature per file; a feature with parts becomes a directory (`mod.rs`
  plus one file per part). Files stay under ~300 lines, functions under ~60
  (break long ones into named steps, long components into child components).
- Work in the devcontainer (`.devcontainer/`); use the make targets.
- Run `make test` (and `make lint`) between changes; no regressions.
- Never `git commit` unless the user asks. Commit messages are Conventional
  Commits and signed off (`git commit -s`): they decide the next version and
  `CHANGELOG.md` (git-cliff, `.config/cliff.toml`), so neither is edited by hand.

## Layout
```
src/stix.rs    STIX 2.1 bundle → Emb3d (properties, threats, mitigations)
src/model/     Project / Page (mod.rs), Node / Flow (node), Library and custom
               types (library); serde, unknown fields kept
src/engine/    mod.rs (Model, lookups), labels (esc() everywhere), threats
               (rules), counts (roll-ups, summary), validate, tmbom, svg
               (diagram), report/ (HTML: page sections, entity per component)
src/ops/       editing operations: mod.rs (add, move, split, remove), clip
               (copy/paste), custom (block types, import)
src/ui/        Leptos: mod.rs (App, boot), ctx (Ctx state), clip, keys, bar
               (toolbar), board/ (diagram, drag, block, actions, rail, pages),
               inspector/ (block, device, threats), tables, dialogs/ (detail,
               updates, custom), web.rs (browser API wrappers, downloads)
src/cli/       command line: mod.rs (usage, args), library, analyze, scan,
               report (HTML, PDF), Yocto scanner (yocto/: parse, rootfs, rules,
               project, deploy; regex) and the app server (app.rs: embedded
               files only, loopback), native only
build.rs       feature `pwa`: embeds dist/ for `emb-tm app`
src/main.rs    wasm32 → ui::start, otherwise → cli::main
tests/unit/    unit tests, one file per source file at the same path
               (src/engine/tmbom.rs → tests/unit/engine/tmbom.rs), included as its
               `#[cfg(test)] #[path] mod tests;` so private items are in reach
tests/cli.rs   runs the built binary on the Yocto fixture and the system example
examples/index.json  templates offered by New (first one opens on a first visit)
web/           the app shell, copied to the top of dist/: index.html (the page
               that ships; `make build` fills in the style.css SRI), style.css,
               sw.js (service worker: precache at install, network first, cache
               offline), manifest, icons, emb-tm.desktop (menu entry,
               `make install` → ~/.local)
.config/       tool settings: deny.toml, cliff.toml, about.toml + about.hbs
.github/       CONTRIBUTING, SECURITY (CRA steward policy), CODE_OF_CONDUCT,
               templates
.gitea/        workflows: ci (checks, packages, release on main), emb3d-update
Makefile       the build: cargo → wasm-bindgen → wasm-opt → dist/
```
`stix`, `model`, `engine`, `ops` have no browser API and are unit-tested
natively against the real STIX files (`make data` downloads them) and examples. Tests pin the numbers
(surveillance and alarm system example 208 threats, 413 countermeasures;
alarm hub Yocto example 98 threats, 166 countermeasures; regenerate the
latter with `emb-tm scan` after changing the rules or the fixture). JSON goes through `serde_json::Value` only
(`Project::to_json`, `from_value`): one serde instantiation per type.
Threat counts come from the `Ctx::counts` memo, not per view; wasm builds use
`--cfg erase_components` (`.cargo/config.toml`). Size, `make build`
(2026-11-15): wasm 967,888 bytes, 377,678 gzip as shipped; `dist/` 924 KB.
Keep these current and don't let them grow without reason.

## Make targets
`make build` (release → `dist/`), `make bin` (`target/release/emb-tm`
with `dist/` embedded, feature `pwa`), `make app` (`emb-tm app`:
serves the embedded app on 127.0.0.1:8000 and opens it in its own window),
`make serve` (same, `--no-open`; installable), `make install` /
`make uninstall` (binary, icon, `web/emb-tm.desktop` into `PREFIX`, default
`~/.local`), `make data` (EMB3D releases from MITRE into `data/stix`), `make tools` (every pinned tool into `target/tools`, each on
first use), `make test` (cargo: unit + CLI tests), `make lint`,
`make coverage` (cargo-llvm-cov, fails under `COVERAGE_MIN`), `make security`
(cargo-audit, cargo-deny), `make sbom` (CycloneDX), `make package` (release
files, SHA256SUMS, third-party licences), `make commit-check`,
`make release` (version + CHANGELOG.md + commit + tag from the commits),
`make release-due`, `make release-check TAG=vX.Y.Z`, `make publish` (CI:
packages and release on the forge). The workflows (`.gitea/workflows/`,
git.b-stream.io's Gitea Actions, runner label `container`, pinned images, no
JavaScript actions, the job token checks out with Basic auth as in lp-boot)
only call these targets; the mirrors don't run them. The program is
standalone: `library/`, `data/stix/index.json` and `web/style.css` are built
in (`include_str!`), `emb-tm fetch` downloads to `$EMB_TM_DATA`
(default `~/.local/share/emb-tm/stix`).

## Constraints
- Keep the root small: code in `src/`, the shell in `web/`, tool settings in
  `.config/`, project documents in `.github/`.
- File names in `dist/` are fixed and paths relative: `sw.js` lists files
  by name and the app must run from any origin or sub-path. A new file the
  app fetches must be added to `WEB` or `FILES` in the Makefile **and** to
  `SHELL` in `web/sw.js`, or it breaks offline (examples are cached from
  their `index.json`).
- MITRE's EMB3D files are never committed or shipped (MITRE's terms of use):
  `data/stix/index.json` pins each release's URL and SHA-256; the app
  downloads it on first start with subresource integrity into its own cache
  (`web::data_json`), `emb-tm fetch` with curl, checked with `sha2`. Examples
  and reports quote EMB3D text: keep MITRE's designation (`data/stix/README.md`).
- `dist/` ships `emb-tm_bg.wasm.gz`: `make build` gzips it and the loader in
  `web/index.html` inflates it (`DecompressionStream`). `make serve` does not watch files:
  run it again after a change (it rebuilds the binary with the new `dist/`).
- wasm-bindgen must match `Cargo.lock`; the Makefile reads the version from
  it. Never install build tools system-wide (other projects pin their own).
- Hosted by b-stream on its own origin
  with a strict CSP: no inline script except the wasm loader in
  `web/index.html` (the host hashes what it serves), no third-party CDN or fonts, `connect-src 'self'` plus
  `https://emb3d.mitre.org` (Updates button only).
- `localStorage` key `emb3d-workbench/project` and the project / TM-BOM JSON
  formats are shared with the CLI and earlier versions: don't change them.
  They, the TM-BOM extension key, the clipboard key and the service worker
  cache keep the pre-rename name (EMB3D Workbench) on purpose.
- Scanner rules (`library/yocto-rules.json`) are Rust `regex`: no look-around.

## Host toolchain quirk
Fedora rustc 1.99 is first on PATH, clippy comes from rustup 1.95. Outside
the devcontainer run clippy as
`RUSTC=$(rustup which rustc) CARGO_TARGET_DIR=target/clippy rustup run stable cargo clippy ...`.

## Testing in a browser
Headless `chromium-browser --remote-debugging-port=…` driven over CDP with
Node 22's built-in `WebSocket` works well (no extra dependency). Check: no
console errors, no CSP violations, offline reload keeps the project.

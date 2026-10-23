# EMB3D Workbench

Embedded-device threat modeling on top of [MITRE EMB3D](https://emb3d.mitre.org/).
Drag device components onto a board, answer a few questions per component, and the
matching EMB3D threats and countermeasures appear. Track countermeasure status with
justifications, print a report, and export the model as an OWASP TM-BOM
(Threat Model Library schema v1.0.2), which OWASP Threat Dragon can open. A command line
does the same from a terminal or CI, and makes a first model from a Yocto image and its SBOMs.

## Why it exists

MITRE EMB3D is a catalogue of threats to embedded devices, tied to what a device is made of
(its properties) and to mitigations. It is published as web pages and STIX data, not as a tool
you can apply to your own design. General threat modeling tools are built around IT systems and
STRIDE, not device properties, and commercial platforms ask you to upload unreleased product
designs to someone else's cloud. The Workbench closes that gap: describe the device, and EMB3D's
threats follow from the description, with the reasoning shown and an export in an open format.

It is built on a few principles:

- **Free and open source** (GPL-2.0-only, see [LICENSE](LICENSE)), so anyone can use, audit and adapt it.
- **Offline first**: after the first load it needs no network, in the browser or as a desktop app.
- **Your data stays yours**: no account, no backend, no telemetry. Models are kept on your machine
  and saved as plain JSON files that you own and that other tools can read.
- **Transparent**: every threat says which property brought it in, and every decision carries its
  justification.

Contributions are welcome: issues, fixes, new components (`library/components.json`), scanner
rules (`library/yocto-rules.json`) and examples (`examples/`). Most of what the app knows is data,
so many improvements need no Rust at all. See [CONTRIBUTING.md](CONTRIBUTING.md) for pull requests,
[SECURITY.md](SECURITY.md) to report a vulnerability, and [CHANGELOG.md](CHANGELOG.md) for releases.

## Use it

**In a browser**: serve `dist/` from any static web server (see Develop), open it, and choose
**Install app** in the address bar to keep it as an app that works offline.

**As a desktop app**: `emb3d-wb app` opens the app in its own window. The program carries the whole
app and serves it on this computer only (`http://127.0.0.1:8000`):

    emb3d-wb app                 # open the app in its own window
    emb3d-wb app --port 8417     # another port, if 8000 is taken
    emb3d-wb app --no-open       # only serve; open the address in any browser

The window needs Chromium, Chrome or Edge (`CHROME=/path/to/browser` picks one); without one, the
address is printed. In that window, **Install EMB3D Workbench** adds it to the system's app menu:
it then starts from there and works offline, also when `emb3d-wb app` is not running. Keep the
same port, because the installed app and its saved project belong to that address.

On Linux, `make install` puts `emb3d-wb` in `~/.local/bin` with its icon and a menu entry
(`emb3d-wb.desktop`), so **EMB3D Workbench** appears in the applications menu; `make uninstall`
removes it (`PREFIX=/usr/local` installs for all users).

## Develop

Work in the devcontainer (`.devcontainer/`): it has Rust, the wasm32 target and Python (for
`tools/emb3d_update.py`). The first build installs `wasm-bindgen` (the version in `Cargo.lock`)
and `wasm-opt` into `target/tools/`, not system-wide.

    make build     # the PWA → dist/ (static files, host them anywhere)
    make bin       # target/release/emb3d-wb with dist/ inside: one file to copy anywhere
    make app       # make bin, then emb3d-wb app
    make serve     # make bin, then emb3d-wb app --no-open (http://127.0.0.1:8000)
    make install   # make bin, then install it with its menu entry (PREFIX, default ~/.local)
    make test      # unit tests (tests/unit/) + command-line tests (tests/cli.rs)
    make lint      # rustfmt + clippy (static analysis), warnings are errors
    make coverage  # tests with line coverage; fails under the minimum (90%)
    make security  # cargo-audit (RustSec) + cargo-deny (licences, sources)
    make sbom      # CycloneDX SBOM → target/sbom/
    make package   # release files: program, PWA, SBOM, third-party licences, SHA256SUMS
    make release   # next version and CHANGELOG.md from the commit messages, commit + tag

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
`fix:`, `feat!:` …): they decide the next version and become the changelog, see
[CONTRIBUTING.md](CONTRIBUTING.md). The pipelines in `.github/workflows/` run on Gitea and Forgejo
(Codeberg) Actions: checks on every push and pull request (lint, tests, coverage, cargo-audit,
cargo-deny, Trivy, SBOM, build), and a release workflow started by a maintainer that versions,
checks and publishes. Release archives are reproducible.

`dist/` is self-contained (about 850 KB: the wasm and the EMB3D releases are gzip files that the
page inflates itself, so no server compression is needed). Browsers keep all of it in their
offline cache: the app, the component library and every EMB3D release in `data/stix/index.json`.
It can also be published on the b-stream site as a hosted app (`content/apps/emb3d-tm/`).

## Layout

| Path | What it is | Who edits it |
|---|---|---|
| `src/stix.rs` | Reads a MITRE EMB3D STIX bundle into the app's data model | Code changes |
| `src/model.rs`, `src/engine.rs` | Project format, rules, TM-BOM export and report markup | Code changes |
| `src/ops.rs` | Editing operations (add, move into devices, copy/paste, split, import) | Code changes |
| `src/ui/` | The browser app (Leptos components) | Code changes |
| `src/cli/` | Command line and Yocto scanner (native builds of the same crate) | Code changes |
| `index.html`, `style.css`, `Makefile` | Page, styles, the build (`FILES`: what ships) | Code changes |
| `manifest.webmanifest`, `sw.js`, `icon*` | PWA: install metadata and the offline cache | Code changes |
| `library/yocto-rules.json` | What the scanner looks for and how it answers each question | Add or tune rules here |
| `examples/index.json` | Templates offered by New (the first opens on a first visit) | Add examples here |
| `examples/system/` | Generic multi-device example | |
| `examples/yocto-scan/` | Synthetic deploy dir (Raspberry Pi gateway) and a `bitbake -e` sample, used by the tests | |
| `build.rs` | With the `pwa` feature (`make bin`), embeds `dist/` in the command line | Code changes |
| `emb3d-wb.desktop` | Menu entry for `emb3d-wb app` (`make install`) | |
| `tests/unit/` | Unit tests, one file per source file at the same path (`src/ops.rs` → `tests/unit/ops.rs`) | |
| `tests/cli.rs` | Command-line and scanner tests (`cargo test`) | |
| `library/components.json` | Component palette and questionnaires. Each answer adds EMB3D property IDs (PIDs). | Add or tune components here |
| `data/stix/*.json` | MITRE's STIX releases, byte-for-byte as published | Only via `tools/emb3d_update.py` |
| `data/stix/index.json` | Available versions, their SHA-256 and the default version | Only via `tools/emb3d_update.py` |
| `tools/emb3d_update.py` | Checks emb3d.mitre.org for new releases and adds them | Standard library only |
| `.github/workflows/emb3d-update.yml` | Weekly check; opens an issue when a new release appears | |

## Systems: devices, pages and custom blocks

A project is a set of pages. The top page is the system: put a **Device** box on it for each
device (an AI unit, a gateway, a router, cameras…) and draw the data flows between them.
Double-click a device box, or use Open design, to design the inside of that device on its own page;
a device page can hold further devices, so systems nest as deep as needed. The breadcrumb and the
Pages list in the left rail move between pages, and every box shows the open threats of everything
inside it.

- **Quantity**: one box can stand for several identical units (Camera ×4). Boxes can also share a
  design page, so a design is modelled once and reused.
- **Putting blocks inside a device**: drop a library item on a Device box, or drag blocks from the
  board onto it (shift/Ctrl/⌘-click selects several, Ctrl/⌘+A selects the page). Copy, cut and
  paste with Ctrl/⌘+C, X and V, or the buttons in the inspector: with a Device box selected, paste
  goes inside it. Copying a Device box copies its whole design. Data flows between moved blocks
  move with them; flows to blocks left outside are removed (the app says how many). The clipboard
  is plain JSON, so blocks also paste between projects in different tabs.
- **Duplicating to modify**: Duplicate (Ctrl/⌘+D) copies blocks next to the originals; a duplicated
  device gets its own copy of the design. On a "×N" device, "Split one unit out to modify" leaves ×(N-1)
  and adds a variant with its own design; a box that shares a design page with others can switch to
  its own copy. Custom block types can be duplicated as a new type from their editor.
- **Add device from file…** brings in another project or a Workbench TM-BOM as a device, for example
  one `emb3d-wb scan` result per image, composed into a system.
- **Custom blocks** (left rail, New custom block): pick the EMB3D properties the block has and add
  your own threats with countermeasures. Custom block types are saved in the project and can be
  edited later; their threats are tracked, reported and exported like EMB3D ones.
- **Import blocks…** (left rail, Custom blocks) adds the block types of another project, a
  Workbench TM-BOM or a component library file (`{"components": [...]}`, the format of
  `library/components.json`) to this project, so a team can share its components. Imported
  types may have questions whose answers add EMB3D properties, like library components.
  Types the project already has are kept as they are.

In the TM-BOM, device boxes are components and every component inside a device points at it with
`parent_component`. Projects from earlier versions (a single list of nodes) open as one page.
The app opens on `examples/system/connected-vision-system.project.json`, a generic example.
**New** offers an empty project or any example of `examples/index.json` as a template; to add one,
list it there and add the file to `FILES` in the Makefile (the offline cache follows the
index).

## First model from a Yocto image and SBOMs

    emb3d-wb scan --deploy build/tmp/deploy/images/<machine> [--image <image>] \
         [--sbom extra.cdx.json ...] [--kernel-config .config] [--uboot-config u-boot/.config] \
         [--bbenv bitbake-e.txt] -o project.json --tmbom first.tmbom.json [--report report.html]

From the deploy directory it picks up the image's `.testdata.json` (every build variable, written
by default), `.manifest` (installed packages), rootfs tarball (to read `/etc/ssh/sshd_config`,
`/etc/shadow`, `/etc/rauc/system.conf`, `mosquitto.conf`, sysctl and so on) and any CycloneDX files
(`*.cdx.json`, `*cyclonedx*.json`, `*.bom.json`). Each input can also be given on its own; `--sbom` is
repeatable, for example the rootfs SBOM plus separate bootloader or firmware SBOMs. `bitbake -e` output
is optional and wins over testdata.json because it records the file and line that set each variable.

The scan is deterministic: the same inputs always give the same project. It writes, per component:
- the answers, each with evidence (`file:line` and the line itself);
- the package version and the SBOM's vulnerabilities for that package (VEX `not_affected`, `resolved`
  and `false_positive` are not counted as open);
- a review flag where no rule could decide or an input was missing ("not checked, needs kernel .config").

Open the TM-BOM (or the project) in the app with Open…, then review the flagged answers, add your
product applications and data flows, and set countermeasure statuses. The scan never sets those.

### Scanner rules

`library/yocto-rules.json` lists candidate components. Each has a `when` condition, a `type` from the
component library, a `name` (`${VAR}` and `${A|B}` take build variables), an optional `version` package
regex, and per question an ordered list of `{ "if": condition, "value": answer, "review": "note" }`;
the first rule whose condition is true wins, a rule without `if` is the fallback.

Conditions:

| Condition | True when |
|---|---|
| `{ "var": "X", "set": true }` / `"eq"` / `"word"` / `"re"` | build variable X is set / equals / contains the word / matches |
| `{ "pkg": "regex" }` | an installed package (manifest) or SBOM component name matches |
| `{ "kconfig": "CONFIG_X", "eq": "y" }`, `"re"` | kernel .config value (`n` when not set) |
| `{ "uboot": "CONFIG_X", "eq": "y" }` | bootloader .config value |
| `{ "file": "/etc/a\|/etc/b.d/*", "re": "^…" }` | a rootfs file matches (multiline regex) |
| `{ "exists": "/path/*" }` | a rootfs path exists |
| `{ "any": [...] }`, `{ "all": [...] }`, `{ "not": … }`, `{ "always": true }` | combinations |

A condition whose input was not given is neither true nor false: it never selects an answer, and the
answer that is finally chosen is flagged for review with the missing input named. `flows` connect
components by rule id. Rules are [Rust regular expressions](https://docs.rs/regex/latest/regex/#syntax)
(no look-around); run `make test` after changing them.

## Command line

`cargo install --path .` installs `emb3d-wb` (or use `cargo run --release -- <command>` in the
source tree). It reads `library/`, `data/stix/` and `style.css` from `$EMB3D_WB_ROOT`, by default
the source tree it was built from.

    emb3d-wb library                      # component types, question ids, allowed values
    emb3d-wb validate project.json        # errors, unanswered questions, answers to review
    emb3d-wb analyze project.json \
         --tmbom out.tmbom.json --report out.html [--pdf out.pdf] [--summary out.json] [--list]
    emb3d-wb analyze project.json --fail-on-open 0   # CI gate: exit 2 when threats are open

`--pdf` uses a local Chrome/Chromium (set `CHROME=` if it is not on the PATH); rootfs tarballs
are read with the system `tar`. HTML reports are standalone and load nothing from the network. Any TM-BOM exported by
the Workbench is also accepted as input.

Project files may carry, per component, `evidence` (`{question id: [{file, line, text}]}`, with
`_component` for why the component exists) and `review` (`{question id: reason}`). The app shows
both; answering a question or "Mark as reviewed" clears the flag.

## EMB3D versions

Each project records the EMB3D version it was built with, so a model always reproduces
the same threats. Pick another version from the selector in the header: the app shows
which threats are added or removed for each component and what MITRE renamed before
you switch. Countermeasure statuses, decisions and justifications are kept because they
are stored by threat and mitigation ID.

New releases:

    python3 tools/emb3d_update.py check            # what emb3d.mitre.org has that we don't
    python3 tools/emb3d_update.py add 2.0.2        # download, verify, register (or: add --latest)
    python3 tools/emb3d_update.py verify           # hashes + library PIDs, run in CI

The weekly workflow runs `check` and opens an issue proposing the update; a maintainer
runs `add`, reviews the change summary in the app, and commits. "Updates" in the app
does the same check from the browser and can load a new release for the current
session only.

## Rules

1. A component's EMB3D properties = its `base` PIDs + the PIDs of the answers given.
2. A sub-property implies its parent property.
3. If the model has no update agent, the OS (or SoC) gets PID-26 "Device lacks firmware/software update support".
4. A threat applies to a component when it shares at least one property with it.
5. Each threat gets a decision: handle it with countermeasures, mark it Not applicable, or accept the risk.
   Not applicable and accepted need a justification, as do countermeasures set to Not applicable or Rejected.
6. A threat handled with countermeasures is Mitigated when one of them is Implemented,
   Not applicable when all of them are, and Open otherwise.

## Report

The Report tab follows the layout of OWASP Threat Dragon's report: cover card, executive
summary with threat counts, the diagram, then one threat table per component. EMB3D has no
severity, so open threats are counted by EMB3D evidence level instead. "Print / Save as PDF"
uses the browser's print dialog (A4 landscape).

## Saving

Work is kept in the browser's local storage (offline too). "Save" downloads
`<project-name>.project.json` and "Export TM-BOM" downloads `<project-name>.tmbom.json`; the TM-BOM
embeds the project too, so either file can be opened again with "Open…".

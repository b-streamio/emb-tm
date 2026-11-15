# emb-tm

Threat modeling for embedded devices, built on [MITRE EMB3D](https://emb3d.mitre.org/).
Describe a device as blocks (SoC, flash, bootloader, OS, services…), answer a few questions per
block, and the matching EMB3D threats and countermeasures appear. Track decisions with
justifications, print a report, and export an OWASP TM-BOM that OWASP Threat Dragon opens.
A command line does the same in CI and makes a first model from a Yocto image and its SBOMs.

## Why it exists

EMB3D links threats to what a device is made of, but it is published as web pages and data, not
as a tool you can apply to your own design. General threat modeling tools think in IT systems, and
commercial platforms want your unreleased designs in their cloud. emb-tm fills that gap:
describe the device, and the threats follow, with the reasoning shown.

- **Free and open source, for good**: GPL-2.0-only ([LICENSE](LICENSE)), no contributor
  agreement; use it, audit it, adapt it, share it. Whoever passes it on must pass on the source
  and the same freedoms: it can never be made closed.
- **Offline first**: after the first load it needs no network, in the browser or as a desktop app.
- **Your data stays yours**: no account, no backend, no telemetry; models are plain JSON files.
- **Transparent**: every threat says which property brought it in; every decision has a reason.

Contributions are welcome, and much of what the app knows is data (components, scanner rules,
examples), so many improvements need no Rust: see [CONTRIBUTING.md](.github/CONTRIBUTING.md).
Report vulnerabilities as [SECURITY.md](.github/SECURITY.md) says.

**MITRE EMB3D™** data is © The MITRE Corporation, under MITRE's own terms, not the GPL: emb-tm
downloads it from MITRE and does not ship it; the examples and reports quote it
([data/stix/README.md](data/stix/README.md)). MITRE is a registered trademark of The MITRE
Corporation; this project is not affiliated with or endorsed by MITRE.

## Use it

**Desktop app**: download `emb-tm-<version>-x86_64.AppImage` from the releases, make it executable
and double-click it; nothing to install, any Linux distribution. The release archive holds the same
standalone program. It carries the whole app and serves it on this computer only.

    emb-tm app               # opens the app in its own window (Chromium, Chrome or Edge)
    emb-tm app --port 8417   # another port if 8000 is taken; --no-open only serves

In the window, **Install emb-tm** adds it to the system's app menu; it then works offline,
even when `emb-tm app` is not running. Keep the same port: the saved project belongs to it.
On Linux, `make install` installs the program and a menu entry into `~/.local`.

**In a browser**: host `dist/` (from `make build`) on any static web server and choose
**Install app** in the address bar.

**Command line**:

    emb-tm fetch                                           # EMB3D data from emb3d.mitre.org, once
    emb-tm validate project.json                           # errors, unanswered questions
    emb-tm analyze project.json --tmbom out.json --report out.html [--pdf out.pdf]
    emb-tm analyze project.json --fail-on-open 0           # CI gate: exit 2 if threats are open
    emb-tm scan --deploy tmp/deploy/images/<machine> -o project.json   # first model of a Yocto image
    emb-tm --help                                          # every command and option

## How it works

1. A block's EMB3D properties are its type's base properties plus those of its answers; a
   sub-property implies its parent. A device without an update agent gets PID-26 on its OS.
2. A threat applies to a block that shares a property with it. Custom blocks add their own threats.
3. Each threat is handled with countermeasures, marked not applicable, or accepted; the last two,
   and rejected countermeasures, need a justification. A threat is Mitigated when one of its
   countermeasures is implemented, and Open otherwise.

**Systems**: the top page holds a **Device** box per device and the data flows between them;
double-click a box to design its inside on its own page. A box can stand for several identical
units, and boxes can share a design. Copy, cut and paste work across pages and projects
(Ctrl/⌘ C, X, V, D).

**Custom blocks**: define blocks with their own EMB3D properties, threats and countermeasures, or
**Import blocks…** from another project, a TM-BOM or a component library file, so a team can
share its components.

**Yocto scan**: `emb-tm scan` reads a deploy directory (build variables, package manifest,
rootfs, CycloneDX SBOMs, optional kernel and bootloader `.config`) and writes a project where every
answer carries its evidence (`file:line`), each package its open vulnerabilities, and anything it
could not decide is flagged for review. Rules: [library/README.md](library/README.md).

**EMB3D data**: emb-tm does not ship MITRE's EMB3D files. On first start the app asks to download
the release from emb3d.mitre.org, checks it against the SHA-256 that `data/stix/index.json` pins
and keeps it for offline use; on the command line, `emb-tm fetch` does the same (into
`~/.local/share/emb-tm/stix`, or `$EMB_TM_DATA`). Each project
records the EMB3D release it uses; switching shows what changes first. New releases are listed
with `python3 tools/emb3d_update.py check` / `add <version>`.

**Example**: the app opens on a surveillance and alarm system: cameras and audio sensors report to
an alarm hub, which contacts the security company's alarm receiving centre. The hub's design comes
from a scan of its Yocto image (`examples/yocto-scan/`).

Work is kept in the browser and saved as `<name>.project.json`; the TM-BOM export embeds the
project, so either file opens again.

## Develop

Use the devcontainer (`.devcontainer/`), or the build environment the CI uses: `make image`, then
run any target below in it. Outside it, the first build installs the pinned tools into
`target/tools/`, nothing system-wide.

    make build      # the PWA (dist/) and the static program with it inside
    make app        # build, then open the app (ARGS=--no-open: serve it only)
    make check      # commit messages, rustfmt, clippy, tests with line coverage (90% minimum)
    make security   # cargo-audit, cargo-deny, SBOM
    make package    # release files: program, PWA, SBOM, licences, SHA256SUMS
    make release    # version and CHANGELOG.md from the commit messages, when they call for it

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) and decide the
version and the changelog. The CI in `.gitea/workflows/` checks every push, publishes each build
as a package, and on `main` releases by itself when the commits call for it.

| Path | Contents |
|---|---|
| `src/` | `stix.rs` (EMB3D data), `model/` (file format), `engine/` (rules, TM-BOM, report), `ops/` (editing), `ui/` (the app), `cli/` (command line, scanner, app server) |
| `web/` | Page, styles, service worker, manifest, icons, menu entry |
| `library/` | Component library and scanner rules |
| `data/stix/` | The EMB3D releases emb-tm can use (`index.json`: MITRE's URL and SHA-256); the files are downloaded, not in git |
| `examples/` | Templates offered by New (`index.json`) |
| `tests/` | Unit tests (`unit/`, one file per source file) and command-line tests |
| `.config/`, `.github/` | Tool settings; contribution guide, security policy, CI |

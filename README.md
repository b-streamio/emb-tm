# EMB3D Workbench

Embedded-device threat modeling on top of [MITRE EMB3D](https://emb3d.mitre.org/).
Drag device components onto a board, answer a few questions per component, and the
matching EMB3D threats and countermeasures appear. Track countermeasure status with
justifications, print a report, and export the model as an OWASP TM-BOM
(Threat Model Library schema v1.0.2), which OWASP Threat Dragon can open.

No build step, no backend, no dependencies. The same engine runs in the browser and on the
command line, and a scanner builds a first model from a Yocto image and its SBOMs.

## Run

    python3 -m http.server -d .    # then open http://localhost:8000

(Opening index.html straight from disk will not load the data files.)

## Layout

| Path | What it is | Who edits it |
|---|---|---|
| `index.html`, `app.js` | The app (plain HTML/JS) | Code changes |
| `stix.js` | Reads a MITRE EMB3D STIX bundle into the app's data model | Code changes |
| `engine.js` | Rules, TM-BOM export and report markup, shared by the app and the CLI | Code changes |
| `cli/emb3d-wb.js` | Command line (Node 18+, no dependencies) | Code changes |
| `cli/yocto-scan.js` | Yocto image + CycloneDX SBOMs → first project | Code changes |
| `library/yocto-rules.json` | What the scanner looks for and how it answers each question | Add or tune rules here |
| `examples/system/` | Generic multi-device example the app opens with | |
| `examples/yocto-scan/` | Synthetic deploy dir (Raspberry Pi gateway) and a `bitbake -e` sample, used by the tests | |
| `tests/run.js` | `node tests/run.js` | |
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

In the TM-BOM, device boxes are components and every component inside a device points at it with
`parent_component`. Projects from earlier versions (a single list of nodes) open as one page.
The app opens on `examples/system/connected-vision-system.project.json`, a generic example.

## First model from a Yocto image and SBOMs

    node cli/emb3d-wb.js scan --deploy build/tmp/deploy/images/<machine> [--image <image>] \
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
components by rule id. Run `node tests/run.js` after changing rules.

## Command line

    node cli/emb3d-wb.js library                      # component types, question ids, allowed values
    node cli/emb3d-wb.js validate project.json        # errors, unanswered questions, answers to review
    node cli/emb3d-wb.js analyze project.json \
         --tmbom out.tmbom.json --report out.html [--pdf out.pdf] [--summary out.json] [--list]
    node cli/emb3d-wb.js analyze project.json --fail-on-open 0   # CI gate: exit 2 when threats are open

`--pdf` uses a local Chrome/Chromium (set `CHROME=` if it is not on the PATH). Any TM-BOM exported by
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
runs `add`, reviews the change summary in the app, and commits. "Check for updates" in
the app does the same check from the browser and can load a new release for the
current session only.

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

Work is kept in the browser's local storage. "Save" shows the project JSON to copy;
"Export TM-BOM" embeds the project too, so either file can be opened again with "Open…".

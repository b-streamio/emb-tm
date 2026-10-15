# EMB3D Workbench

Embedded-device threat modeling on top of [MITRE EMB3D](https://emb3d.mitre.org/).
Drag device components onto a board, answer a few questions per component, and the
matching EMB3D threats and countermeasures appear. Track countermeasure status with
justifications, print a report, and export the model as an OWASP TM-BOM
(Threat Model Library schema v1.0.2), which OWASP Threat Dragon can open.

No build step, no backend, no dependencies.

## Run

    python3 -m http.server -d .    # then open http://localhost:8000

(Opening index.html straight from disk will not load the data files.)

## Layout

| Path | What it is | Who edits it |
|---|---|---|
| `index.html`, `app.js` | The app (plain HTML/JS) | Code changes |
| `stix.js` | Reads a MITRE EMB3D STIX bundle into the app's data model | Code changes |
| `library/components.json` | Component palette and questionnaires. Each answer adds EMB3D property IDs (PIDs). | Add or tune components here |
| `data/stix/*.json` | MITRE's STIX releases, byte-for-byte as published | Only via `tools/emb3d_update.py` |
| `data/stix/index.json` | Available versions, their SHA-256 and the default version | Only via `tools/emb3d_update.py` |
| `tools/emb3d_update.py` | Checks emb3d.mitre.org for new releases and adds them | Standard library only |
| `.github/workflows/emb3d-update.yml` | Weekly check; opens an issue when a new release appears | |

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

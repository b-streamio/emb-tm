# EMB3D Workbench

Embedded-device threat modeling on top of [MITRE EMB3D](https://emb3d.mitre.org/).
Drag device components onto a board, answer a few questions per component, and the
matching EMB3D threats and countermeasures appear. Track countermeasure status and
export the model as an OWASP TM-BOM (Threat Model Library schema v1.0.2), which
OWASP Threat Dragon can open.

No build step, no backend, no dependencies.

## Run

    python3 -m http.server -d .    # then open http://localhost:8000

(Opening index.html straight from disk will not load the data files.)

## Layout

| Path | What it is | Who edits it |
|---|---|---|
| `index.html`, `app.js` | The app (plain HTML/JS) | Code changes |
| `library/components.json` | Component palette and questionnaires. Each answer adds EMB3D property IDs (PIDs). | Add or tune components here |
| `data/emb3d.json` | EMB3D properties, threats, mitigations and their links | Generated, never hand-edited |
| `tools/build_emb3d.py` | Builds `data/emb3d.json` from the EMB3D STIX bundle | Rerun on each EMB3D release |

## Rules

1. A component's EMB3D properties = its `base` PIDs + the PIDs of the answers given.
2. A sub-property implies its parent property.
3. If the model has no update agent, the OS (or SoC) gets PID-26 "Device lacks firmware/software update support".
4. A threat applies to a component when it shares at least one property with it.
5. Each threat gets a decision: handle it with countermeasures, mark it Not applicable, or accept the risk.
   Not applicable and accepted need a justification, as do countermeasures set to Not applicable or Rejected.
6. A threat handled with countermeasures is Mitigated when one of them is Implemented,
   Not applicable when all of them are, and Open otherwise.

## Updating EMB3D

    python3 tools/build_emb3d.py emb3d-stix-<version>.json data/emb3d.json

Then check that every PID in `library/components.json` still exists.

## Saving

Work is kept in the browser's local storage. "Save" shows the project JSON to copy;
"Export TM-BOM" embeds the project too, so either file can be opened again with "Open…".

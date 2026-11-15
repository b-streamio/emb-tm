#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Keep the EMB3D STIX files in data/stix/ in step with emb3d.mitre.org.

  python3 tools/emb3d_update.py check            list releases on emb3d.mitre.org that are not here yet
  python3 tools/emb3d_update.py add 2.0.2        download one release, verify it, add it to data/stix/index.json
  python3 tools/emb3d_update.py add --latest     same, for the newest release
  python3 tools/emb3d_update.py verify           check hashes and that library/components.json PIDs exist

Exit codes: 0 ok / up to date, 10 new releases available (check), 1 error.
Standard library only.
"""
import argparse, datetime, hashlib, json, os, re, sys, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STIX_DIR = os.path.join(ROOT, "data", "stix")
INDEX = os.path.join(STIX_DIR, "index.json")
LIBRARY = os.path.join(ROOT, "library", "components.json")
SITE = "https://emb3d.mitre.org"
DATA_PAGE = "/subtabs/data.html"
LINK_RE = re.compile(r"emb3d-stix-(\d+(?:\.\d+)*)\.json")


def vkey(v):
    return tuple(int(x) for x in v.split("."))


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "emb-tm-updater"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def load_index():
    with open(INDEX, encoding="utf-8") as f:
        return json.load(f)


def save_index(idx):
    idx["versions"].sort(key=lambda v: vkey(v["version"]), reverse=True)
    with open(INDEX, "w", encoding="utf-8") as f:
        json.dump(idx, f, indent=2)
        f.write("\n")


def remote_versions(site):
    html = fetch(site + DATA_PAGE).decode("utf-8", "replace")
    found = sorted(set(LINK_RE.findall(html)), key=vkey, reverse=True)
    if not found:
        raise SystemExit(f"No STIX links found on {site + DATA_PAGE}. The page layout may have changed; check it by hand.")
    return found


def library_pids():
    with open(LIBRARY, encoding="utf-8") as f:
        lib = json.load(f)
    pids = set()
    for c in lib["components"]:
        pids.update(c.get("base", []))
        for q in c.get("questions", []):
            pids.update(q.get("pids", []))
            for o in q.get("options", []):
                pids.update(o.get("pids", []))
    return pids


def check_bundle(raw):
    b = json.loads(raw)
    if b.get("type") != "bundle" or not isinstance(b.get("objects"), list):
        raise SystemExit("Downloaded file is not a STIX bundle.")
    props = {o["x_mitre_emb3d_property_id"] for o in b["objects"] if o.get("type") == "x-mitre-emb3d-property"}
    counts = {t: sum(1 for o in b["objects"] if o.get("type") == t) for t in ("x-mitre-emb3d-property", "vulnerability", "course-of-action")}
    if not all(counts.values()):
        raise SystemExit(f"Bundle is missing EMB3D objects: {counts}")
    return props, counts


def cmd_check(a):
    idx = load_index()
    have = {v["version"] for v in idx["versions"]}
    remote = remote_versions(a.site)
    new = [v for v in remote if v not in have]
    print(f"emb3d.mitre.org lists: {', '.join(remote)}")
    print(f"In data/stix: {', '.join(sorted(have, key=vkey, reverse=True))}")
    if new:
        print(f"New: {', '.join(new)}")
        print(f"Add with: python3 tools/emb3d_update.py add {new[0]}")
        return 10
    print("Up to date.")
    return 0


def cmd_add(a):
    idx = load_index()
    version = remote_versions(a.site)[0] if a.latest else a.version
    if not version:
        raise SystemExit("Give a version or --latest.")
    if any(v["version"] == version for v in idx["versions"]):
        print(f"{version} is already in data/stix.")
        return 0
    name = f"emb3d-stix-{version}.json"
    url = f"{a.site}/assets/{name}"
    raw = fetch(url)
    props, counts = check_bundle(raw)
    missing = sorted(library_pids() - props)
    with open(os.path.join(STIX_DIR, name), "wb") as f:
        f.write(raw)
    idx["versions"].append({
        "version": version, "file": name, "source": f"https://emb3d.mitre.org/assets/{name}",
        "sha256": hashlib.sha256(raw).hexdigest(), "added": datetime.date.today().isoformat(),
    })
    if not a.keep_default and vkey(version) > vkey(idx["default"]):
        idx["default"] = version
    save_index(idx)
    print(f"Added {name}: {counts['x-mitre-emb3d-property']} properties, {counts['vulnerability']} threats, "
          f"{counts['course-of-action']} mitigations. Default version: {idx['default']}")
    if missing:
        print(f"WARNING: library/components.json uses PIDs that {version} does not define: {', '.join(missing)}")
        return 1
    return 0


def cmd_verify(_a):
    idx = load_index()
    lib = library_pids()
    bad = 0
    for v in idx["versions"]:
        path = os.path.join(STIX_DIR, v["file"])
        raw = open(path, "rb").read()
        if hashlib.sha256(raw).hexdigest() != v["sha256"]:
            print(f"{v['file']}: sha256 mismatch"); bad += 1; continue
        props, _ = check_bundle(raw)
        missing = sorted(lib - props)
        if missing:
            print(f"{v['version']}: library PIDs not defined: {', '.join(missing)}")
            if v["version"] == idx["default"]:
                bad += 1
        else:
            print(f"{v['version']}: ok")
    if idx["default"] not in {v["version"] for v in idx["versions"]}:
        print("default version is not in the list"); bad += 1
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--site", default=SITE, help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    p = sub.add_parser("add")
    p.add_argument("version", nargs="?")
    p.add_argument("--latest", action="store_true")
    p.add_argument("--keep-default", action="store_true", help="do not make this the default version")
    sub.add_parser("verify")
    a = ap.parse_args()
    return {"check": cmd_check, "add": cmd_add, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())

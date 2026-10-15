#!/usr/bin/env python3
"""Build data/emb3d.json from the MITRE EMB3D STIX 2.1 bundle.

Usage: python3 tools/build_emb3d.py emb3d-stix-2.0.1.json data/emb3d.json
Rerun whenever MITRE publishes a new EMB3D release.
"""
import json, re, sys

CWE_RE = re.compile(r"\[CWE-(\d+):\s*([^\]]+?)\s*(?:\([A-Za-z ]+\))?\]")

def first_para(s):
    return (s or "").strip().split("\n\n")[0].strip()

def paras(md):
    """Light markdown cleanup: list of paragraphs, plain text, *emphasis* kept as markers."""
    md = re.sub(r"</?u>", "", md or "")
    md = md.replace("\\[", "[").replace("\\]", "]").replace("\u00a0", " ")
    return [re.sub(r"\s*\n\s*", " ", p).strip() for p in re.split(r"\n\s*\n", md) if p.strip()]

def refs(md):
    out = []
    for p in paras(md):
        m = re.search(r"<(https?://[^>]+)>", p)
        text = re.sub(r"^\[\d+\]\s*", "", p)
        text = re.sub(r"\s*\[Online\.?\]\s*Available:\s*<[^>]+>\s*", "", text).strip()
        out.append({"t": text, "u": m.group(1) if m else ""})
    return out

def bullets(md):
    out = [l[2:].strip() for l in (md or "").splitlines() if l.startswith("- ")]
    return [re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", b) for b in out if b.lower() != "none referenced"]

def main(src, dst):
    objs = json.load(open(src, encoding="utf-8"))["objects"]
    by = {o["id"]: o for o in objs}
    ver = next((o.get("x_mitre_emb3d_version") for o in objs if o["type"] == "identity"), "?")
    P, T, M = {}, {}, {}
    for o in objs:
        if o["type"] == "x-mitre-emb3d-property":
            P[o["x_mitre_emb3d_property_id"]] = {"name": o["name"], "cat": o["category"], "parent": None}
        elif o["type"] == "vulnerability":
            T[o["x_mitre_emb3d_threat_id"]] = {
                "name": o["name"], "cat": o["x_mitre_emb3d_threat_category"],
                "maturity": o["x_mitre_emb3d_threat_maturity"],
                "desc": first_para(o["description"]),
                "cwes": [[int(i), t] for i, t in CWE_RE.findall(o["x_mitre_emb3d_threat_CWEs"])],
                "cves": len(bullets(o["x_mitre_emb3d_threat_CVEs"])),
                "pids": [], "mids": []}
        elif o["type"] == "course-of-action":
            M[o["x_mitre_emb3d_mitigation_id"]] = {
                "name": o["name"], "maturity": o["x_mitre_emb3d_mitigation_maturity"],
                "desc": first_para(o["description"]),
                "text": paras(o["description"]),
                "refs": refs(o["x_mitre_emb3d_mitigation_references"]),
                "iec": bullets(o["x_mitre_emb3d_mitigation_IEC_62443_mappings"])}
    for r in (o for o in objs if o["type"] == "relationship"):
        s, t, k = by[r["source_ref"]], by[r["target_ref"]], r["relationship_type"]
        if k == "subproperty-of":
            P[s["x_mitre_emb3d_property_id"]]["parent"] = t["x_mitre_emb3d_property_id"]
        elif k == "relates-to":
            T[t["x_mitre_emb3d_threat_id"]]["pids"].append(s["x_mitre_emb3d_property_id"])
        elif k == "mitigates":
            T[t["x_mitre_emb3d_threat_id"]]["mids"].append(s["x_mitre_emb3d_mitigation_id"])
    for t in T.values():
        t["pids"] = sorted(set(t["pids"])); t["mids"] = sorted(set(t["mids"]))
    out = {"source": "MITRE EMB3D STIX 2.1 (https://emb3d.mitre.org/)", "version": ver,
           "properties": P, "threats": dict(sorted(T.items())), "mitigations": dict(sorted(M.items()))}
    json.dump(out, open(dst, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print(f"EMB3D {ver}: {len(P)} properties, {len(T)} threats, {len(M)} mitigations -> {dst}")

if __name__ == "__main__":
    main(*sys.argv[1:3])

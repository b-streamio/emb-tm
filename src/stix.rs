// SPDX-License-Identifier: GPL-2.0-only
//! MITRE EMB3D STIX 2.1 bundle → Workbench data. MITRE's published file is
//! read unchanged, so adding an EMB3D release is just dropping in the file.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::Value;

use crate::model::num_cmp;

/// The EMB3D catalogue of one release.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Emb3d {
    pub version: String,
    pub properties: BTreeMap<String, Property>,
    pub threats: BTreeMap<String, Threat>,
    pub mitigations: BTreeMap<String, Mitigation>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Property {
    pub name: String,
    pub cat: String,
    pub parent: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Threat {
    pub name: String,
    pub cat: String,
    pub maturity: String,
    /// First paragraph of the description.
    pub desc: String,
    /// All paragraphs.
    pub text: Vec<String>,
    pub cwes: Vec<(u32, String)>,
    pub cves: usize,
    pub pids: Vec<String>,
    pub mids: Vec<String>,
    /// Defined by a project's custom block, not by EMB3D.
    pub custom: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Mitigation {
    pub name: String,
    pub maturity: String,
    pub desc: String,
    pub text: Vec<String>,
    pub refs: Vec<Reference>,
    pub iec: Vec<String>,
    pub custom: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reference {
    pub t: String,
    pub u: String,
}

/// String field `key` of a STIX object, `""` when absent (borrowed: the
/// bundle has thousands of objects, most of them relationships).
fn text<'a>(o: &'a Value, key: &str) -> &'a str {
    o[key].as_str().unwrap_or_default()
}

/// Paragraphs of light Markdown: `<u>` and escapes removed, lines joined.
fn paras(md: &str) -> Vec<String> {
    let s = md
        .replace("<u>", "")
        .replace("</u>", "")
        .replace("\\[", "[")
        .replace("\\]", "]")
        .replace('\u{a0}', " ");
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for line in s.lines().chain([""]) {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(cur.join(" "));
                cur.clear();
            }
        } else {
            cur.push(line.trim());
        }
    }
    out
}

/// `[1] Author. "Title." [Online.] Available: <https://…>` → text and URL.
fn refs(md: &str) -> Vec<Reference> {
    paras(md)
        .into_iter()
        .map(|p| {
            let u = p
                .find("<http")
                .and_then(|i| p[i + 1..].find('>').map(|j| p[i + 1..i + 1 + j].to_owned()))
                .unwrap_or_default();
            let mut t = p.as_str();
            if let Some(rest) = t.strip_prefix('[') {
                if let Some((n, tail)) = rest.split_once(']') {
                    if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
                        t = tail.trim_start();
                    }
                }
            }
            let mut t = t.to_owned();
            if let Some(i) = t.find("[Online") {
                if let Some(j) = t[i..].find('>') {
                    t.replace_range(i..i + j + 1, " ");
                }
            }
            Reference {
                t: t.split_whitespace().collect::<Vec<_>>().join(" "),
                u,
            }
        })
        .collect()
}

/// `- item` lines, Markdown links reduced to their text, "None referenced" dropped.
fn bullets(md: &str) -> Vec<String> {
    md.lines()
        .filter_map(|l| l.strip_prefix("- "))
        .map(|b| unlink(b.trim()))
        .filter(|b| !b.eq_ignore_ascii_case("none referenced"))
        .collect()
}

fn unlink(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('[') {
        let Some(j) = rest[i..].find("](") else { break };
        let Some(k) = rest[i + j..].find(')') else {
            break;
        };
        out += &rest[..i];
        out += &rest[i + 1..i + j];
        rest = &rest[i + j + k + 1..];
    }
    out + rest
}

/// `[CWE-1300: Name (Base)]` → `(1300, "Name")`.
fn cwes(s: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for part in s.split("[CWE-").skip(1) {
        let Some((num, rest)) = part.split_once(':') else {
            continue;
        };
        let (Ok(num), Some((name, _))) = (num.parse(), rest.split_once(']')) else {
            continue;
        };
        let mut name = name.trim();
        if let Some((head, kind)) = name.rsplit_once('(') {
            let kind = kind.strip_suffix(')').unwrap_or("?");
            if kind.chars().all(|c| c.is_ascii_alphabetic() || c == ' ') {
                name = head.trim();
            }
        }
        out.push((num, name.to_owned()));
    }
    out
}

/// Parses a STIX bundle as published by MITRE.
pub fn parse(bundle: &Value, version: &str) -> Result<Emb3d, String> {
    let objs = match (bundle["type"].as_str(), bundle["objects"].as_array()) {
        (Some("bundle"), Some(objs)) => objs,
        _ => return Err("Not a STIX bundle".into()),
    };
    let by_id: HashMap<&str, &Value> = objs
        .iter()
        .filter_map(|o| Some((o["id"].as_str()?, o)))
        .collect();
    let mut e = Emb3d {
        version: version.to_owned(),
        ..Default::default()
    };
    for o in objs {
        let (kind, desc) = (text(o, "type"), text(o, "description"));
        let (pid, tid, mid) = (
            text(o, "x_mitre_emb3d_property_id"),
            text(o, "x_mitre_emb3d_threat_id"),
            text(o, "x_mitre_emb3d_mitigation_id"),
        );
        if kind == "x-mitre-emb3d-property" {
            e.properties.insert(
                pid.into(),
                Property {
                    name: text(o, "name").into(),
                    cat: text(o, "category").into(),
                    parent: None,
                },
            );
        } else if kind == "vulnerability" && !tid.is_empty() {
            let text_ = paras(desc);
            e.threats.insert(
                tid.into(),
                Threat {
                    name: text(o, "name").into(),
                    cat: text(o, "x_mitre_emb3d_threat_category").into(),
                    maturity: text(o, "x_mitre_emb3d_threat_maturity").into(),
                    desc: text_.first().cloned().unwrap_or_default(),
                    text: text_,
                    cwes: cwes(text(o, "x_mitre_emb3d_threat_CWEs")),
                    cves: bullets(text(o, "x_mitre_emb3d_threat_CVEs")).len(),
                    ..Default::default()
                },
            );
        } else if kind == "course-of-action" && !mid.is_empty() {
            let text_ = paras(desc);
            e.mitigations.insert(
                mid.into(),
                Mitigation {
                    name: text(o, "name").into(),
                    maturity: text(o, "x_mitre_emb3d_mitigation_maturity").into(),
                    desc: text_.first().cloned().unwrap_or_default(),
                    text: text_,
                    refs: refs(text(o, "x_mitre_emb3d_mitigation_references")),
                    iec: bullets(text(o, "x_mitre_emb3d_mitigation_IEC_62443_mappings")),
                    custom: false,
                },
            );
        }
    }
    let mut pids: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut mids: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for r in objs.iter().filter(|o| o["type"] == "relationship") {
        let (Some(s), Some(t)) = (
            by_id.get(text(r, "source_ref")),
            by_id.get(text(r, "target_ref")),
        ) else {
            continue;
        };
        let (spid, tpid, ttid) = (
            text(s, "x_mitre_emb3d_property_id"),
            text(t, "x_mitre_emb3d_property_id"),
            text(t, "x_mitre_emb3d_threat_id"),
        );
        match text(r, "relationship_type") {
            "subproperty-of" => {
                if let Some(p) = e.properties.get_mut(spid) {
                    p.parent = Some(tpid.into());
                }
            }
            "relates-to" if e.threats.contains_key(ttid) => {
                pids.entry(ttid).or_default().insert(spid);
            }
            "mitigates" if e.threats.contains_key(ttid) => {
                mids.entry(ttid)
                    .or_default()
                    .insert(text(s, "x_mitre_emb3d_mitigation_id"));
            }
            _ => {}
        }
    }
    for (tid, t) in &mut e.threats {
        let ids = |m: &mut BTreeMap<&str, BTreeSet<&str>>| -> Vec<String> {
            m.remove(tid.as_str())
                .into_iter()
                .flatten()
                .map(str::to_owned)
                .collect()
        };
        t.pids = ids(&mut pids);
        t.pids.sort_by(|a, b| num_cmp(a, b));
        t.mids = ids(&mut mids);
    }
    Ok(e)
}

/// What changes for a project when moving from release `a` to `b`.
#[derive(Debug, Default, PartialEq)]
pub struct Diff {
    pub threats_added: Vec<String>,
    pub threats_removed: Vec<String>,
    pub threats_renamed: Vec<String>,
    pub threats_remapped: Vec<String>,
    pub mitigations_added: Vec<String>,
    pub mitigations_removed: Vec<String>,
    pub mitigations_renamed: Vec<String>,
}

pub fn diff(a: &Emb3d, b: &Emb3d) -> Diff {
    fn only<V>(x: &BTreeMap<String, V>, y: &BTreeMap<String, V>) -> Vec<String> {
        x.keys().filter(|k| !y.contains_key(*k)).cloned().collect()
    }
    fn changed<V>(
        x: &BTreeMap<String, V>,
        y: &BTreeMap<String, V>,
        f: impl Fn(&V, &V) -> bool,
    ) -> Vec<String> {
        x.iter()
            .filter(|(k, v)| y.get(*k).is_some_and(|w| f(v, w)))
            .map(|(k, _)| k.clone())
            .collect()
    }
    Diff {
        threats_added: only(&b.threats, &a.threats),
        threats_removed: only(&a.threats, &b.threats),
        threats_renamed: changed(&a.threats, &b.threats, |x, y| x.name != y.name),
        threats_remapped: changed(&a.threats, &b.threats, |x, y| {
            x.pids != y.pids || x.mids != y.mids
        }),
        mitigations_added: only(&b.mitigations, &a.mitigations),
        mitigations_removed: only(&a.mitigations, &b.mitigations),
        mitigations_renamed: changed(&a.mitigations, &b.mitigations, |x, y| x.name != y.name),
    }
}

#[cfg(test)]
#[path = "../tests/unit/stix.rs"]
mod tests;

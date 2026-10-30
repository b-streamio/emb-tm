// SPDX-License-Identifier: GPL-2.0-only
//! The rules applied to what the scan found: components with their answers
//! and evidence, data flows, and the project around them.

use std::collections::{BTreeMap, HashMap};

use regex::Regex;
use serde_json::{json, Value};

use super::{
    dedup, evidence,
    parse::Pkg,
    rules::{Found, Outcome},
    truthy, Inputs, Notes,
};
use crate::model::{Evidence, Flow, Library, Meta, Node, Project, Question, TypeDef};

/// Components of the rules that apply, and the index of each by rule id.
pub(super) fn components<'r>(
    f: &Found,
    rules: &'r Value,
    lib: &Library,
    notes: &mut Notes,
) -> Result<(Vec<Node>, HashMap<&'r str, usize>), String> {
    let mut nodes: Vec<Node> = Vec::new();
    let mut by_rule = HashMap::new();
    let placeholder = Regex::new(r"\$\{[^}]+\}\s*").expect("valid");
    for rule in rules["components"].as_array().into_iter().flatten() {
        let (id, kind) = (
            rule["id"].as_str().unwrap_or_default(),
            rule["type"].as_str().unwrap_or_default(),
        );
        let Some(def) = lib.components.iter().find(|c| c.kind == kind) else {
            return Err(format!("rule {id}: unknown component type {kind}"));
        };
        let w = f.eval(&rule["when"])?;
        match w.v {
            Some(true) => {}
            Some(false) => continue,
            None => {
                let mut miss = w.miss.clone();
                dedup(&mut miss);
                let what = placeholder.replace_all(rule["name"].as_str().unwrap_or_default(), "");
                notes
                    .skipped
                    .push(format!("{what}: not checked, needs {}", miss.join(", ")));
                continue;
            }
        }
        let node = component(f, rule, def, w, nodes.len() as u64 + 1)?;
        by_rule.insert(id, nodes.len());
        nodes.push(node);
    }
    Ok((nodes, by_rule))
}

/// The component of one rule whose `when` holds (`w`).
fn component(f: &Found, rule: &Value, def: &TypeDef, w: Outcome, id: u64) -> Result<Node, String> {
    let mut name = f.fill(rule["name"].as_str().unwrap_or_default());
    if name.is_empty() {
        name.clone_from(&def.name);
    }
    let mut node = Node::new(id, &def.kind, "", f64::NAN, f64::NAN);
    let mut comp: Vec<Evidence> = w.ev.into_iter().take(3).collect();
    if let Some(pattern) = rule["version"].as_str() {
        let hits = f.pkgs.matching(pattern)?;
        if let Some(p) = hits.iter().find(|p| !p.version.is_empty()) {
            let recipe_rev = Regex::new(r"-r\d+$").expect("valid"); // 1.2-r0 → 1.2
            name += &format!(" {}", recipe_rev.replace(&p.version, ""));
        }
        // SBOMs name recipes (openssh), manifests name packages
        // (openssh-sshd): gather CVEs from every match.
        comp.extend(hits.iter().filter(|p| !p.cves.is_empty()).map(|p| cves(p)));
    }
    node.name = name;
    if !comp.is_empty() {
        node.evidence.insert("_component".into(), comp);
    }
    if let Some(r) = rule.get("review").filter(|r| truthy(r)) {
        node.review.insert("_component".into(), r.clone());
    }
    for q in &def.questions {
        answer(f, &rule["answers"][&q.id], q, &mut node)?;
    }
    Ok(node)
}

/// The CVEs of a package in the SBOMs, as evidence.
fn cves(p: &Pkg) -> Evidence {
    let open: Vec<&str> = p
        .cves
        .iter()
        .filter(|c| c.1)
        .map(|c| c.0.as_str())
        .collect();
    let list = match open.len() {
        0 => String::new(),
        n => format!(
            " ({}{})",
            open[..n.min(6)].join(", "),
            if n > 6 { ", …" } else { "" }
        ),
    };
    let file = p
        .sources
        .iter()
        .find(|s| !s.ends_with("manifest"))
        .unwrap_or(&p.sources[0]);
    let text = format!(
        "{} {}: {} open of {} CVEs in SBOM{list}",
        p.name,
        p.version,
        open.len(),
        p.cves.len()
    );
    evidence(file, None, &text)
}

/// Answers `q` with the first of `rules` that holds; the default, flagged
/// for review, when none does.
fn answer(f: &Found, rules: &Value, q: &Question, node: &mut Node) -> Result<(), String> {
    let mut missing = Vec::new();
    let mut chosen = None;
    for r in rules.as_array().into_iter().flatten() {
        if r.get("if").is_none() {
            chosen = Some((r, Vec::new()));
            break;
        }
        let res = f.eval(&r["if"])?;
        match res.v {
            Some(true) => {
                chosen = Some((r, res.ev));
                break;
            }
            None => missing.extend(res.miss),
            Some(false) => {}
        }
    }
    let Some((r, ev)) = chosen else {
        node.answers.insert(q.id.clone(), q.default.clone());
        node.review
            .insert(q.id.clone(), "no scanner rule for this question".into());
        return Ok(());
    };
    node.answers.insert(q.id.clone(), r["value"].clone());
    if !ev.is_empty() {
        node.evidence.insert(q.id.clone(), ev);
    }
    dedup(&mut missing);
    let mut why: Vec<String> = r["review"]
        .as_str()
        .map(str::to_owned)
        .into_iter()
        .collect();
    if !missing.is_empty() {
        why.push(format!("not checked, needs {}", missing.join(", ")));
    }
    if !why.is_empty() {
        node.review.insert(q.id.clone(), why.join("; ").into());
    }
    Ok(())
}

/// The rules' data flows between components that apply.
pub(super) fn flows(rules: &Value, nodes: &[Node], by_rule: &HashMap<&str, usize>) -> Vec<Flow> {
    let mut flows = Vec::new();
    for fl in rules["flows"].as_array().into_iter().flatten() {
        let end = |k: &str| {
            fl[k]
                .as_str()
                .and_then(|r| by_rule.get(r))
                .map(|i| &nodes[*i])
        };
        let (Some(a), Some(b)) = (end("from"), end("to")) else {
            continue;
        };
        let encrypted = match &fl["encrypted"] {
            Value::String(s) => {
                let (rule, q) = s
                    .trim_start_matches("answer:")
                    .split_once('.')
                    .unwrap_or((s, ""));
                by_rule
                    .get(rule)
                    .is_some_and(|i| nodes[*i].answers.get(q).is_some_and(truthy))
            }
            v => truthy(v),
        };
        flows.push(Flow {
            id: 0,
            from: a.id,
            to: b.id,
            label: fl["label"].as_str().unwrap_or_default().to_owned(),
            encrypted,
            sensitive: truthy(&fl["sensitive"]),
        });
    }
    flows
}

/// A version 1 project (one page) named after the image.
pub(super) fn project(
    f: &Found,
    inputs: &Inputs,
    notes: &mut Notes,
    (nodes, flows): (Vec<Node>, Vec<Flow>),
    today: &str,
) -> Project {
    let first = |names: &[&str]| {
        names
            .iter()
            .map(|n| f.var(n))
            .find(|v| !v.is_empty())
            .map(str::to_owned)
    };
    let image = first(&["IMAGE_BASENAME", "PN"])
        .or_else(|| inputs.image.clone())
        .or_else(|| {
            notes
                .sboms
                .iter()
                .find(|s| !s.subject.is_empty())
                .map(|s| s.subject.clone())
        })
        .unwrap_or_else(|| "Yocto image".into());
    let machine = f.var("MACHINE");
    notes.cve_open = notes.sboms.iter().map(|s| s.open).sum();
    notes.packages = f.pkgs.list.len();
    notes.variables = f.vars.as_ref().map_or(0, BTreeMap::len);
    let revision = first(&["BUILDNAME", "DATETIME"]).unwrap_or_default();
    let mut p = Project {
        name: if machine.is_empty() {
            image.clone()
        } else {
            format!("{image} ({machine})")
        },
        meta: Meta {
            description: description(f, &image, notes),
            ..Default::default()
        },
        nodes: Some(nodes),
        flows: Some(flows),
        ..Default::default()
    };
    p.extra.insert(
        "generator".into(),
        json!({"tool": "emb3d-wb scan", "source": image, "revision": revision, "date": today}),
    );
    p
}

/// What was scanned, from which inputs, and what the scan cannot see.
fn description(f: &Found, image: &str, notes: &Notes) -> String {
    let machine = f.var("MACHINE");
    let distro = [f.var("DISTRO"), f.var("DISTRO_VERSION")]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    let used = if notes.used.is_empty() {
        "nothing".into()
    } else {
        notes.used.join(", ")
    };
    let mut desc = vec![
        format!(
            "{image}{}{}.",
            if machine.is_empty() {
                String::new()
            } else {
                format!(" for {machine}")
            },
            if distro.is_empty() {
                String::new()
            } else {
                format!(", {distro}")
            }
        ),
        format!("Generated by emb3d-wb scan from: {used}."),
    ];
    if !notes.sboms.is_empty() {
        let list: Vec<String> = notes
            .sboms
            .iter()
            .map(|s| {
                format!(
                    "{} ({} components, {} vulnerabilities, {} open)",
                    s.file, s.components, s.vulnerabilities, s.open
                )
            })
            .collect();
        desc.push(format!("SBOMs: {}.", list.join("; ")));
    }
    desc.push("Product applications and data flows beyond the defaults are not detected; add them in the Workbench.".into());
    desc.join(" ")
}

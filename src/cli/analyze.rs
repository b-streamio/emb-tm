// SPDX-License-Identifier: GPL-2.0-only
//! `validate` and `analyze`: checks, counts and the output files.

use serde_json::{json, Value};

use super::{
    load_library, load_project, pretty, release_for,
    report::{print_pdf, standalone_html},
    today, write, Args,
};
use crate::{
    engine::{around, Model, ReportOpts, Summary},
    model::Project,
};

pub(super) fn validate(a: &Args) -> Result<i32, String> {
    let file = a
        .pos
        .get(1)
        .ok_or("usage: emb3d-wb validate <project.json>")?;
    let mut p = load_project(file)?;
    let (e, lib) = (release_for(&mut p, a)?, load_library()?);
    let m = Model::new(&e, &lib, &p);
    let (errors, warnings) = m.validate(&p);
    for w in &warnings {
        println!("warning: {w}");
    }
    for e in &errors {
        println!("error:   {e}");
    }
    m.normalize(&mut p);
    let review = m.review_items(&p);
    for r in &review {
        println!(
            "review:  {}: {}{}",
            r.node.name,
            r.question,
            around(" — ", &r.reason, "")
        );
    }
    println!(
        "{} errors, {} warnings, {} answers to review",
        errors.len(),
        warnings.len(),
        review.len()
    );
    Ok(i32::from(!errors.is_empty()))
}

pub(super) fn analyze(a: &Args) -> Result<i32, String> {
    let file = a.pos.get(1).ok_or("usage: emb3d-wb analyze <project.json> [--tmbom f] [--report f.html] [--pdf f.pdf] [--summary f.json]")?;
    let mut p = load_project(file)?;
    let (e, lib) = (release_for(&mut p, a)?, load_library()?);
    let m = Model::new(&e, &lib, &p);
    let (errors, _) = m.validate(&p);
    if !errors.is_empty() {
        return Err(format!(
            "Project has errors; run \"emb3d-wb validate\":\n{}",
            errors.join("\n")
        ));
    }
    m.normalize(&mut p);
    outputs(&p, &m, a)
}

/// `--summary`: the counts, with the key names of the original Node CLI.
fn summary_json(s: &Summary, version: &str) -> Value {
    let e = s.open_by_evidence;
    json!({
        "emb3d": version, "pages": s.pages, "devices": s.devices, "components": s.components, "flows": s.flows,
        "threats": s.threats, "open": s.open, "mitigated": s.mitigated, "notApplicable": s.not_applicable, "accepted": s.accepted,
        "openByEvidence": {"observedInAttacks": e[0], "observedTechnique": e[1], "knownWeakness": e[2], "proofOfConcept": e[3], "custom": e[4]},
        "countermeasures": s.countermeasures, "implemented": s.implemented,
        "missingJustifications": s.missing_justifications, "needsReview": s.needs_review,
    })
}

/// Writes the requested files and prints the summary; 2 when `--fail-on-open` trips.
pub(super) fn outputs(p: &Project, m: &Model, a: &Args) -> Result<i32, String> {
    let s = m.summary(p);
    write_files(p, m, a, &s)?;
    print_summary(p, m, &s);
    if a.has("list") {
        print_threats(p, m);
    }
    for k in ["tmbom", "report", "pdf", "summary", "project"] {
        if let Some(f) = a.get(k) {
            println!("wrote {f}");
        }
    }
    let limit = a.get("fail-on-open").and_then(|n| n.parse::<usize>().ok());
    Ok(if limit.is_some_and(|n| s.open > n) {
        2
    } else {
        0
    })
}

fn write_files(p: &Project, m: &Model, a: &Args, s: &Summary) -> Result<(), String> {
    if let Some(f) = a.get("tmbom") {
        write(f, &pretty(&m.to_tmbom(p, &today())))?;
    }
    if let Some(f) = a.get("project") {
        write(f, &pretty(&p.to_json()))?;
    }
    if let Some(f) = a.get("summary") {
        write(f, &pretty(&summary_json(s, &m.e.version)))?;
    }
    if a.has("report") || a.has("pdf") {
        let o = ReportOpts {
            fulltext: a.has("fulltext"),
            ..Default::default()
        };
        let html = standalone_html(p, m, o)?;
        if let Some(f) = a.get("report") {
            write(f, &html)?;
        }
        if let Some(f) = a.get("pdf") {
            print_pdf(&html, a, f)?;
        }
    }
    Ok(())
}

/// `Page > ` before a component name when the project has several pages.
fn page_prefix(p: &Project, id: u64) -> String {
    match p.page_of(id) {
        Some(pg) if p.pages.len() > 1 => format!("{} > ", pg.name),
        _ => String::new(),
    }
}

fn print_summary(p: &Project, m: &Model, s: &Summary) {
    let ev = s.open_by_evidence;
    println!("{} — MITRE EMB3D {}", p.name, m.e.version);
    let devices = if s.pages > 1 {
        format!("devices {}, pages {}, ", s.devices, s.pages)
    } else {
        String::new()
    };
    println!(
        "  {devices}components {}, data flows {}",
        s.components, s.flows
    );
    println!(
        "  threats {}: open {}, mitigated {}, not applicable {}, accepted {}",
        s.threats, s.open, s.mitigated, s.not_applicable, s.accepted
    );
    println!("  open by evidence: observed in attacks {}, observed technique {}, known weakness {}, proof of concept {}", ev[0], ev[1], ev[2], ev[3]);
    println!(
        "  countermeasures implemented {} of {}",
        s.implemented, s.countermeasures
    );
    if s.missing_justifications > 0 {
        println!(
            "  decisions missing a justification: {}",
            s.missing_justifications
        );
    }
    if s.needs_review > 0 {
        println!("  answers needing review: {}", s.needs_review);
        for r in m.review_items(p) {
            println!(
                "    - {}{}: {}{}",
                page_prefix(p, r.node.id),
                r.node.name,
                r.question,
                around(" — ", &r.reason, "")
            );
        }
    }
}

/// `--list`: every threat per component.
fn print_threats(p: &Project, m: &Model) {
    for n in p.nodes().filter(|n| m.has_threats(n)) {
        let kind = m.type_of(n).map_or("", |t| t.name.as_str());
        println!("\n{}{} ({kind})", page_prefix(p, n.id), n.name);
        for h in m.node_threats(p, n) {
            let state = m.threat_state(n, &h.tid).key();
            println!(
                "  {}  {state:<9} {}  [via {}]",
                h.tid,
                h.t.name,
                h.via.join(", ")
            );
        }
    }
}

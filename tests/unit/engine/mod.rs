// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/engine/mod.rs` (a child module of it, so private items are in reach).

use super::*;

pub fn data() -> (Emb3d, Library) {
    let stix = std::fs::read_to_string("data/stix/emb3d-stix-2.0.1.json").unwrap();
    let e = crate::stix::parse(&serde_json::from_str(&stix).unwrap(), "2.0.1").unwrap();
    let lib =
        serde_json::from_str(&std::fs::read_to_string("library/components.json").unwrap()).unwrap();
    (e, lib)
}

pub fn example(path: &str) -> Project {
    Project::from_json(serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap())
        .unwrap()
}

const SYSTEM: &str = "examples/system/surveillance-alarm-system.project.json";
const YOCTO: &str = "examples/yocto-scan/alarm-hub-image.project.json";

/// Same numbers as the JavaScript engine for the same files.
#[test]
fn system_example_matches_the_reference() {
    let (e, lib) = data();
    let mut p = example(SYSTEM);
    let m = Model::new(&e, &lib, &p);
    assert_eq!(m.validate(&p), (vec![], vec![]));
    m.normalize(&mut p);
    let s = m.summary(&p);
    assert_eq!(
        (s.pages, s.devices, s.components, s.flows, s.threats, s.open),
        (5, 4, 41, 13, 208, 208)
    );
    assert_eq!(s.open_by_evidence, [3, 79, 59, 63, 4]);
    assert_eq!((s.countermeasures, s.needs_review), (413, 0));
    let c = m.counts(&p);
    assert_eq!((c.open(), c.page(&p.root).threats), (208, 208));
    let cams = p
        .nodes()
        .find(|n| n.is_device() && n.name.to_lowercase().contains("camera"))
        .unwrap();
    assert_eq!(cams.qty, Some(6));
    let os = p.nodes().find(|n| n.kind == "os").unwrap();
    let pids: Vec<_> = m
        .node_pids(&p, os)
        .into_iter()
        .map(|(k, v)| format!("{k}:{v:?}"))
        .collect();
    assert_eq!(
        pids.join(" "),
        "PID-23:Base PID-232:Answer PID-2321:Answer PID-2322:Answer PID-23222:Answer PID-26:Rule"
    );
    let tm = m.to_tmbom(&p, "2026-01-01");
    let len = |k: &str| tm[k].as_array().unwrap().len();
    assert_eq!(
        (
            len("threats"),
            len("controls"),
            len("components"),
            len("actors"),
            len("data_flows")
        ),
        (208, 413, 45, 5, 13)
    );
    assert!(tm.get("assumptions").is_none());
    let sensor = tm["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["title"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("image sensor")
        })
        .unwrap();
    assert!(
        sensor["parent_component"].is_string(),
        "components point at their device"
    );
    assert!(tm["threats"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["title"].as_str().unwrap().starts_with("CUS-")));
    let back = Project::from_json(tm).unwrap();
    assert_eq!(
        back.pages.len(),
        p.pages.len(),
        "pages survive the TM-BOM round trip"
    );
}

#[test]
fn yocto_scan_example() {
    let (e, lib) = data();
    let mut p = example(YOCTO);
    let m = Model::new(&e, &lib, &p);
    m.normalize(&mut p);
    assert_eq!((p.pages.len(), p.root.as_str()), (1, "p1"));
    assert_eq!(m.validate(&p), (vec![], vec![]));
    let s = m.summary(&p);
    assert_eq!(
        (
            s.threats,
            s.countermeasures,
            s.needs_review,
            s.open_by_evidence
        ),
        (98, 166, 13, [1, 44, 25, 28, 0])
    );
    let html = m.report_html(&p, ReportOpts::default(), "2026-01-01");
    assert!(html.contains("Generated from") && html.contains("needs review"));
    assert!(p.nodes().all(|n| !n.x.is_nan()), "layout placed every node");
}

pub fn one_page(kinds: &[&str]) -> Project {
    let mut p = Project::empty();
    for (i, k) in kinds.iter().enumerate() {
        p.pages[0]
            .nodes
            .push(Node::new(i as u64 + 1, k, k, 0.0, 0.0));
    }
    p
}

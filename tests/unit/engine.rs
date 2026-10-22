//! Unit tests of `src/engine.rs` (a child module of it, so private items are in reach).

use super::*;
use crate::model::{CustomCm, CustomThreat, CustomType, Flow};

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

const SYSTEM: &str = "examples/system/connected-vision-system.project.json";
const YOCTO: &str = "examples/yocto-scan/core-image-gateway.project.json";

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
        (5, 4, 32, 7, 179, 179)
    );
    assert_eq!(s.open_by_evidence, [3, 67, 53, 54, 2]);
    assert_eq!((s.countermeasures, s.needs_review), (372, 0));
    let c = m.counts(&p);
    assert_eq!((c.open(), c.page(&p.root).threats), (179, 179));
    let cams = p
        .nodes()
        .find(|n| n.is_device() && n.name.to_lowercase().contains("camera"))
        .unwrap();
    assert_eq!(cams.qty, Some(4));
    let os = p.nodes().find(|n| n.kind == "os").unwrap();
    let pids: Vec<_> = m
        .node_pids(&p, os)
        .into_iter()
        .map(|(k, v)| format!("{k}:{v:?}"))
        .collect();
    assert_eq!(pids.join(" "), "PID-23:Base PID-231:Answer PID-232:Answer PID-2322:Answer PID-23221:Answer PID-23222:Answer PID-24:Answer PID-241:Answer PID-28:Answer");
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
        (179, 372, 36, 2, 7)
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
fn version_1_scan_is_migrated() {
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
        (69, 127, 6, [1, 26, 20, 22, 0])
    );
    let html = m.report_html(&p, ReportOpts::default(), "2026-01-01");
    assert!(html.contains("Generated from") && html.contains("needs review"));
    assert!(p.nodes().all(|n| !n.x.is_nan()), "layout placed every node");
}

fn one_page(kinds: &[&str]) -> Project {
    let mut p = Project::empty();
    for (i, k) in kinds.iter().enumerate() {
        p.pages[0]
            .nodes
            .push(Node::new(i as u64 + 1, k, k, 0.0, 0.0));
    }
    p
}

#[test]
fn os_without_update_agent_gets_pid_26() {
    let (e, lib) = data();
    let p = one_page(&["soc", "os"]);
    let m = Model::new(&e, &lib, &p);
    assert_eq!(
        m.node_pids(&p, &p.pages[0].nodes[1]).get("PID-26"),
        Some(&Source::Rule)
    );
    assert!(!m.node_pids(&p, &p.pages[0].nodes[0]).contains_key("PID-26"));
    let p = one_page(&["soc", "os", "update"]);
    assert!(!m.node_pids(&p, &p.pages[0].nodes[1]).contains_key("PID-26"));
}

#[test]
fn threat_states_and_justifications() {
    let (e, lib) = data();
    let mut p = one_page(&["os"]);
    let m = Model::new(&e, &lib, &p);
    let hit = m
        .node_threats(&p, &p.pages[0].nodes[0])
        .into_iter()
        .find(|h| h.t.mids.len() > 1)
        .unwrap();
    let (tid, mids) = (hit.tid.clone(), hit.t.mids.clone());
    let n = &mut p.pages[0].nodes[0];
    assert_eq!(m.threat_state(n, &tid), State::Open);
    for mid in &mids {
        n.cm.insert(mid.clone(), "na".into());
    }
    assert_eq!(m.threat_state(n, &tid), State::NotApplicable);
    assert!(missing_why(n, &mids[0]));
    n.cm.insert(mids[0].clone(), "implemented".into());
    assert_eq!(m.threat_state(n, &tid), State::Mitigated);
    n.accepted.insert(tid.clone(), Value::Bool(true));
    assert_eq!(
        (m.threat_state(n, &tid), missing_accept_why(n, &tid)),
        (State::Accepted, true)
    );
    n.why.insert(format!("accept:{tid}"), " ok ".into());
    assert!(!missing_accept_why(n, &tid));
    n.accepted.insert(tid.clone(), "na".into());
    assert_eq!(m.threat_state(n, &tid), State::NotApplicable);
    let tm = m.to_tmbom(&p, "d");
    assert!(tm["assumptions"][0]["description"]
        .as_str()
        .unwrap()
        .ends_with("Justification: ok"));
    let s = m.summary(&p);
    assert_eq!((s.implemented, s.not_applicable), (1, 1));
    assert_eq!(s.missing_justifications, mids.len() - 1);
}

#[test]
fn custom_blocks_bring_their_threats() {
    let (e, lib) = data();
    let mut p = one_page(&["custom-cam"]);
    p.custom_types.push(CustomType {
        kind: "custom-cam".into(),
        name: "Cam <b>".into(),
        base: vec!["PID-11".into()],
        threats: vec![CustomThreat {
            id: "CUS-001".into(),
            name: "Blind".into(),
            cms: vec![CustomCm {
                id: "CUM-001".into(),
                name: "Detect".into(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    });
    let m = Model::new(&e, &lib, &p);
    let hits = m.node_threats(&p, &p.pages[0].nodes[0]);
    assert_eq!(hits.last().unwrap().tid, "CUS-001");
    assert_eq!(m.type_of(&p.pages[0].nodes[0]).unwrap().tag, "CUS");
    assert!(m.cm_rows(&p).iter().any(|r| r.mid == "CUM-001"));
    let html = m.report_html(
        &p,
        ReportOpts {
            fulltext: true,
            ..Default::default()
        },
        "d",
    );
    assert!(
        html.contains("Cam &lt;b&gt;") && !html.contains("Cam <b>"),
        "names are escaped"
    );
}

#[test]
fn validation_errors() {
    let (e, lib) = data();
    let mut p = one_page(&["os", "nope"]);
    p.pages[0].nodes[0]
        .answers
        .insert("modules".into(), "yes".into());
    p.pages[0].nodes[0]
        .answers
        .insert("bogus".into(), true.into());
    p.pages[0].flows.push(Flow {
        id: 1,
        from: 1,
        to: 9,
        ..Default::default()
    });
    let mut dev = Node::new(3, "device", "Loop", 0.0, 0.0);
    dev.page = Some("p1".into());
    p.pages[0].nodes.push(dev);
    let m = Model::new(&e, &lib, &p);
    let (errors, warnings) = m.validate(&p);
    let all = errors.join("\n");
    for want in [
        "unknown type \"nope\"",
        "\"modules\" must be true or false",
        "unknown question \"bogus\"",
        "same page",
        "loop: System > System",
    ] {
        assert!(all.contains(want), "{want} missing in:\n{all}");
    }
    assert!(!warnings.is_empty());
    p.pages.push(Page {
        id: "p1".into(),
        ..Default::default()
    });
    assert!(m.validate(&p).0[0].contains("duplicate page id"));
}

#[test]
fn helpers() {
    assert_eq!(
        esc(r#"<a href="x">'&'</a>"#),
        "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
    );
    assert_eq!(slug("TID-101 Ünï  x"), "tid-101-n-x");
    assert_eq!(
        wrap("one two three four five six seven", 9),
        ["one two", "three"]
    );
    assert_eq!(
        (maturity("custom").0, cm_label("na"), cm_label("??")),
        (4, "Not applicable", "??")
    );
    let (a, b) = (
        Node::new(1, "os", "", 0.0, 0.0),
        Node::new(2, "os", "", 400.0, 0.0),
    );
    assert_eq!(anchor(&a, &b), (NODE_W_PLUS, 32.0));
    assert_eq!(anchor(&a, &a), (84.0, 32.0));
}
const NODE_W_PLUS: f64 = 168.0 + 6.0;

// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/engine/threats.rs` (a child module of it, so private items are in reach).

use serde_json::Value;

use super::*;
use crate::{
    engine::{
        tests::{data, one_page},
        ReportOpts,
    },
    model::{CustomCm, CustomThreat, CustomType},
};

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

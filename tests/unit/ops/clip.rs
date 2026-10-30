// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ops/clip.rs` (a child module of it, so private items are in reach).

use super::*;
use crate::{
    engine::{decision, tests::data, why, Model},
    ops::tests::system,
};

#[test]
fn copy_cut_paste_round_trip() {
    let (e, lib, mut p) = system();
    let m = Model::new(&e, &lib, &p);
    let root = p.root.clone();
    let ids: Vec<u64> = p.page(&root).unwrap().nodes.iter().map(|n| n.id).collect();
    let (pages, nodes) = (p.pages.len(), p.nodes().count());
    let clip = build_clip(&p, &root, &ids);
    assert_eq!(clip.pages.len(), pages - 1, "every device page travels");
    let json = serde_json::to_string(&clip).unwrap();
    assert!(json.contains(CLIP_KEY));
    cut(&mut p, &root, &ids);
    assert_eq!(p.pages.len(), 1);
    let back: Clip = serde_json::from_str(&json).unwrap();
    let added = paste(&mut p, &m, &back, &root, None, 30.0, "").unwrap();
    assert_eq!(
        (added.len(), p.pages.len(), p.nodes().count()),
        (ids.len(), pages, nodes)
    );
    let m2 = Model::new(&e, &lib, &p);
    assert_eq!(m2.validate(&p).0, Vec::<String>::new());
    assert_eq!(
        m2.summary(&p).threats,
        208,
        "same model after cut and paste"
    );
    // Duplicate: devices get their own design copy.
    let c = build_clip(&p, &root, &added[..1]);
    let dup = paste(&mut p, &m2, &c, &root, None, 0.0, " (copy)").unwrap();
    assert!(p.node(dup[0]).unwrap().name.ends_with(" (copy)"));
    let bad = Clip {
        nodes: vec![Node::new(1, "zzz", "", 0.0, 0.0)],
        ..Default::default()
    };
    assert!(paste(&mut p, &m2, &bad, &root, None, 0.0, "")
        .unwrap_err()
        .contains("zzz"));
}

#[test]
fn paste_renumbers_clashing_custom_ids() {
    let (e, lib) = data();
    let custom = |kind: &str| CustomType {
        kind: kind.into(),
        name: kind.into(),
        threats: vec![crate::model::CustomThreat {
            id: "CUS-001".into(),
            name: "T".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut p = Project::empty();
    p.custom_types.push(custom("a"));
    let mut q = Project::empty();
    q.custom_types.push(custom("b"));
    let mut n = Node::new(1, "b", "B", 0.0, 0.0);
    n.accepted.insert("CUS-001".into(), "na".into());
    n.why.insert("accept:CUS-001".into(), "no lens".into());
    q.pages[0].nodes.push(n);
    let clip = build_clip(&q, "p1", &[1]);
    let m = Model::new(&e, &lib, &p);
    let ids = paste(&mut p, &m, &clip, "p1", None, 0.0, "").unwrap();
    assert_eq!(p.custom_types[1].threats[0].id, "CUS-002");
    let pasted = p.node(ids[0]).unwrap();
    assert_eq!(decision(pasted, "CUS-002"), "na");
    assert_eq!(why(pasted, "accept:CUS-002"), "no lens");
}

// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ops.rs` (a child module of it, so private items are in reach).

use super::*;
use crate::engine::{
    decision,
    tests::{data, example},
    why,
};

fn system() -> (crate::stix::Emb3d, crate::model::Library, Project) {
    let (e, lib) = data();
    let mut p = example("examples/system/surveillance-alarm-system.project.json");
    Model::new(&e, &lib, &p).normalize(&mut p);
    (e, lib, p)
}

#[test]
fn adds_blocks_and_devices() {
    let (e, lib) = data();
    let mut p = Project::empty();
    let m = Model::new(&e, &lib, &p);
    let os = add_node(&mut p, &m, "os", "p1", 10.4, 20.6).unwrap();
    assert_eq!((p.node(os).unwrap().x, p.node(os).unwrap().y), (10.0, 21.0));
    assert!(
        !p.node(os).unwrap().answers.is_empty(),
        "defaults are answered"
    );
    let dev = add_node(&mut p, &m, "device", "p1", 0.0, 0.0).unwrap();
    let d = p.node(dev).unwrap();
    assert_eq!(
        (d.name.as_str(), d.qty, d.page.as_deref()),
        ("Device 1", Some(1), Some("p2"))
    );
    assert!(add_node(&mut p, &m, "nope", "p1", 0.0, 0.0).is_none());
    assert_eq!(p.seq, 3);
}

#[test]
fn moves_into_devices_without_loops() {
    let (e, lib) = data();
    let mut p = Project::empty();
    let m = Model::new(&e, &lib, &p);
    let a = add_node(&mut p, &m, "os", "p1", 0.0, 0.0).unwrap();
    let b = add_node(&mut p, &m, "soc", "p1", 0.0, 0.0).unwrap();
    let out = add_node(&mut p, &m, "cloud", "p1", 0.0, 0.0).unwrap_or(a);
    let dev = add_node(&mut p, &m, "device", "p1", 300.0, 0.0).unwrap();
    p.pages[0].flows.push(Flow {
        id: 1,
        from: a,
        to: b,
        ..Default::default()
    });
    p.pages[0].flows.push(Flow {
        id: 2,
        from: b,
        to: dev,
        ..Default::default()
    });
    assert_eq!(
        move_into_device(&mut p, "p1", &[a, b], dev).unwrap(),
        (2, 1)
    );
    let inner = p.page("p2").unwrap();
    assert_eq!((inner.nodes.len(), inner.flows.len()), (2, 1));
    assert_eq!(p.pages[0].flows.len(), 0);
    let _ = out;
    // A device cannot go into a device inside it.
    let inner_dev = add_node(&mut p, &m, "device", "p2", 0.0, 0.0).unwrap();
    let err = move_into_device(&mut p, "p1", &[dev], inner_dev).unwrap_err();
    assert!(err.is_empty() || err.contains("cannot go inside"));
    let err = move_into_device(&mut p, "p2", &[a], dev);
    assert!(err.is_ok(), "moving within the same device page is allowed");
}

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
fn split_detach_and_remove() {
    let (e, lib, mut p) = system();
    let root = p.root.clone();
    let cams = p.nodes().find(|n| n.qty() == 4).unwrap().clone();
    let before = Model::new(&e, &lib, &p).summary(&p).threats;
    let one = split_unit(&mut p, &root, cams.id).unwrap();
    assert_eq!(p.node(cams.id).unwrap().qty, Some(3));
    let v = p.node(one).unwrap();
    assert_ne!(v.page, cams.page, "the variant has its own design");
    assert!(v.name.ends_with("(variant)"));
    let m = Model::new(&e, &lib, &p);
    assert_eq!(m.validate(&p).0, Vec::<String>::new());
    assert!(
        m.summary(&p).threats > before,
        "the copied design adds its threats"
    );
    assert!(
        split_unit(&mut p, &root, one).is_none(),
        "qty 1 cannot be split"
    );
    let page = clone_design(&mut p, cams.page.as_deref().unwrap(), "Copy");
    assert_eq!(p.page(&page).unwrap().name, "Copy");
    let mut empty = Project::empty();
    let d = add_node(&mut empty, &m, "device", "p1", 0.0, 0.0).unwrap();
    remove_node(&mut empty, "p1", d);
    assert_eq!(empty.pages.len(), 1, "its empty page went with it");
}

#[test]
fn custom_types_and_import() {
    let (e, lib, sys) = system();
    let mut p = Project::empty();
    let m = Model::new(&e, &lib, &p);
    let def = CustomType {
        name: "Image sensor".into(),
        threats: vec![crate::model::CustomThreat {
            name: "Blind".into(),
            cms: vec![crate::model::CustomCm {
                name: "Detect".into(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let kind = save_custom(&mut p, &m, None, def.clone());
    assert_eq!(kind, "custom-image-sensor");
    assert_eq!(
        (
            p.custom_types[0].threats[0].id.as_str(),
            p.custom_types[0].threats[0].cms[0].id.as_str()
        ),
        ("CUS-001", "CUM-001")
    );
    let m = Model::new(&e, &lib, &p);
    assert_eq!(save_custom(&mut p, &m, None, def), "custom-image-sensor-2");
    // A type with the same id is reused (ours wins), so import into a fresh project.
    let mut q = Project::empty();
    let m = Model::new(&e, &lib, &q);
    let dev = import_as_device(&mut q, &m, sys.clone(), "p1", 10.0, 10.0).unwrap();
    assert_eq!(q.node(dev).unwrap().name, sys.name);
    let mq = Model::new(&e, &lib, &q);
    assert_eq!(mq.validate(&q).0, Vec::<String>::new());
    assert_eq!(mq.summary(&q).threats, 208);
    // Imported custom threat ids that clash with ours are renumbered.
    let m = Model::new(&e, &lib, &p);
    import_as_device(&mut p, &m, q, "p1", 0.0, 0.0).unwrap();
    let ids: Vec<String> = p
        .custom_types
        .iter()
        .flat_map(|c| &c.threats)
        .map(|t| t.id.clone())
        .collect();
    assert_eq!(
        ids.len(),
        ids.iter().collect::<BTreeSet<_>>().len(),
        "{ids:?}"
    );
    let mut broken = sys;
    broken.pages[0].nodes[0].kind = "zzz".into();
    assert!(import_as_device(&mut p, &m, broken, "p1", 0.0, 0.0)
        .unwrap_err()
        .contains("problems"));
    assert_eq!(plural(1, "block"), "1 block");
}

#[test]
fn imports_component_libraries() {
    let (e, lib, sys) = system();
    let mut p = Project::empty();
    let m = Model::new(&e, &lib, &p);
    let file = serde_json::json!({"components": [
        {"type": "device", "name": "Device", "group": "System", "tag": "DEV", "container": true},
        {"type": "os", "name": "Not ours", "group": "System software", "tag": "OS"},
        {"type": "modem", "name": "Cell modem", "group": "Networking", "tag": "MDM", "base": ["PID-11"],
         "questions": [{"id": "fw", "text": "Updatable firmware?", "kind": "bool", "default": false, "pids": ["PID-24"]}]},
    ]});
    // The device box is built in and the library's "os" wins.
    assert_eq!(import_types(&mut p, &m, file.clone()).unwrap(), (1, 1));
    let m = Model::new(&e, &lib, &p);
    assert_eq!(import_types(&mut p, &m, file).unwrap(), (0, 2));
    let id = add_node(&mut p, &m, "modem", "p1", 0.0, 0.0).unwrap();
    assert_eq!(p.node(id).unwrap().answers["fw"], false);
    p.node_mut(id)
        .unwrap()
        .answers
        .insert("fw".into(), true.into());
    let pids = m.node_pids(&p, p.node(id).unwrap());
    assert!(pids.contains_key("PID-11") && pids.contains_key("PID-24"));
    assert!(p.to_json()["customTypes"][0]["questions"].is_array());
    assert!(
        sys.to_json()["customTypes"][0].get("questions").is_none(),
        "files without questions are written as before"
    );
    // All or nothing: a bad question adds no type.
    let bad = serde_json::json!({"components": [{"type": "x", "name": "X", "group": "Hardware", "tag": "X",
        "questions": [{"id": "q", "text": "?", "kind": "choice", "default": "a"}]}]});
    let before = p.clone();
    let err = import_types(&mut p, &m, bad).unwrap_err();
    assert!(err.contains("default must be one of its options"), "{err}");
    assert_eq!(p, before);
    assert!(import_types(&mut p, &m, serde_json::json!({"a": 1})).is_err());
    // A project (or TM-BOM) brings its custom types.
    let mut q = Project::empty();
    let n = sys.custom_types.len();
    assert_eq!(import_types(&mut q, &m, sys.to_json()).unwrap(), (n, 0));
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

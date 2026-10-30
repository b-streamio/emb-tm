// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ops/custom.rs` (a child module of it, so private items are in reach).

use super::*;
use crate::ops::{add_node, plural, tests::system};

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

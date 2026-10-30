// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ops/mod.rs` (a child module of it, so private items are in reach).

use super::*;
use crate::engine::tests::{data, example};

pub fn system() -> (crate::stix::Emb3d, crate::model::Library, Project) {
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

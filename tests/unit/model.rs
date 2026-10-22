//! Unit tests of `src/model.rs` (a child module of it, so private items are in reach).

use super::*;

#[test]
fn natural_order() {
    let mut v = ["PID-111", "PID-12", "PID-11", "MID-2"];
    v.sort_by(|a, b| num_cmp(a, b));
    assert_eq!(v, ["MID-2", "PID-11", "PID-12", "PID-111"]);
}

#[test]
fn opens_projects_and_tmboms() {
    let p = serde_json::json!({"name": "x", "nodes": [{"id": 1, "type": "os"}], "generator": {"source": "img", "tool": "scan"}});
    let mut p = Project::from_json(p).unwrap();
    p.migrate();
    assert_eq!(
        (
            p.root.as_str(),
            p.pages[0].name.as_str(),
            p.pages[0].nodes.len()
        ),
        ("p1", "x", 1)
    );
    assert!(p.nodes.is_none() && p.pages[0].nodes[0].x.is_nan());
    p.pages[0].nodes[0].y = 540.0;
    let n = serde_json::to_value(&p.pages[0].nodes[0]).unwrap();
    assert_eq!((n["x"].is_null(), n["y"].to_string()), (true, "540".into()));
    assert_eq!(p.generator().unwrap(), "img by scan");
    let tm = serde_json::json!({"extensions": {EXT_KEY: {"project": serde_json::to_value(&p).unwrap()}}});
    let back = Project::from_json(tm).unwrap();
    assert_eq!(back.pages[0].nodes[0].id, 1);
    assert!(
        back.extra.contains_key("generator"),
        "unknown fields survive"
    );
    assert!(Project::from_json(serde_json::json!({"a": 1})).is_err());
    assert!(
        Project::from_json(serde_json::json!({"nodes": [{"id": "x"}]}))
            .unwrap_err()
            .contains("problems")
    );
}

#[test]
fn page_order_follows_devices() {
    let mut p = Project::empty();
    let mut dev = Node::new(1, "device", "D", 0.0, 0.0);
    dev.page = Some("p3".into());
    p.pages[0].nodes.push(dev);
    p.pages.push(Page {
        id: "p2".into(),
        ..Default::default()
    });
    p.pages.push(Page {
        id: "p3".into(),
        ..Default::default()
    });
    let ids: Vec<_> = p.page_order().iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["p1", "p3", "p2"]);
    assert_eq!(p.parents_of("p3")[0].id, 1);
    p.pages[0].nodes[0].qty = Some(3);
    assert_eq!(p.pages[0].nodes[0].units(), " ×3");
    assert_eq!(p.page_of(1).unwrap().id, "p1");
}

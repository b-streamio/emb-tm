//! Unit tests of `src/stix.rs` (a child module of it, so private items are in reach).

use super::*;

pub fn release(file: &str, v: &str) -> Emb3d {
    let raw = std::fs::read_to_string(format!("data/stix/{file}")).unwrap();
    parse(&serde_json::from_str(&raw).unwrap(), v).unwrap()
}

#[test]
fn parses_the_published_release() {
    let e = release("emb3d-stix-2.0.1.json", "2.0.1");
    assert_eq!(
        (e.threats.len(), e.mitigations.len(), e.properties.len()),
        (81, 89, 59)
    );
    let t = e.threats.values().find(|t| !t.cwes.is_empty()).unwrap();
    assert!(!t.pids.is_empty() && !t.mids.is_empty() && !t.desc.is_empty());
    assert!(e.properties.values().any(|p| p.parent.is_some()));
    let m = e.mitigations.values().find(|m| !m.refs.is_empty()).unwrap();
    assert!(m.refs[0].u.starts_with("https://"), "{:?}", m.refs[0]);
    assert!(
        !m.refs[0].t.contains("Available") && !m.refs[0].t.starts_with('['),
        "{:?}",
        m.refs[0]
    );
}

#[test]
fn text_helpers() {
    assert_eq!(paras("a\nb\n\n\n<u>c</u> \\[1\\]"), ["a b", "c [1]"]);
    assert_eq!(
        cwes("- [CWE-1300: Side Channels (Base)](x)  [CWE-7: Plain]"),
        [(1300, "Side Channels".into()), (7, "Plain".into())]
    );
    assert_eq!(
        bullets("- [EDR 3.14](u) – boot\n- None referenced\nx"),
        ["EDR 3.14 – boot"]
    );
    assert_eq!(
        refs("\\[2\\] U-Boot. \"VB.\" \\[Online.\\] Available: <https://u.org/x>"),
        [Reference {
            t: "U-Boot. \"VB.\"".into(),
            u: "https://u.org/x".into()
        }]
    );
    assert_eq!(
        parse(&serde_json::json!({"type": "x"}), "1").unwrap_err(),
        "Not a STIX bundle"
    );
}

#[test]
fn diff_between_releases() {
    let (a, b) = (
        release("emb3d-stix-2.0.json", "2.0"),
        release("emb3d-stix-2.0.1.json", "2.0.1"),
    );
    assert_eq!(diff(&a, &a), Diff::default());
    let mut c = b.clone();
    c.threats.remove("TID-101");
    c.threats.get_mut("TID-102").unwrap().name = "renamed".into();
    let d = diff(&b, &c);
    assert_eq!(
        (d.threats_removed, d.threats_renamed),
        (vec!["TID-101".to_owned()], vec!["TID-102".to_owned()])
    );
    assert_eq!(diff(&c, &b).threats_added, ["TID-101"]);
}

//! Unit tests of `src/ui/dialogs.rs` (a child module of it, so private items are in reach).

use super::*;

#[test]
fn rich_text_segments() {
    let known = |x: &str| x == "TID-101";
    assert_eq!(
        rich("See *this* and TID-101, not TID-999 or XTID-101.", known),
        [
            Seg::Text("See ".into()),
            Seg::Em("this".into()),
            Seg::Text(" and ".into()),
            Seg::Link("TID-101".into()),
            Seg::Text(", not TID-999 or XTID-101.".into())
        ]
    );
    assert_eq!(rich("a * b é", known), [Seg::Text("a * b é".into())]);
}

#[test]
fn finds_releases_on_mitre_page() {
    let html = r#"<a href="/assets/emb3d-stix-2.0.json">x</a> emb3d-stix-2.0.1.json emb3d-stix-10.0.json emb3d-stix-x.json"#;
    assert_eq!(releases_on_page(html), ["10.0", "2.0.1", "2.0"]);
}

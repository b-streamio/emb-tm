//! Unit tests of `src/cli/mod.rs` (a child module of it, so private items are in reach).

use super::*;

#[test]
fn arguments() {
    let a = Args::parse(
        [
            "scan", "--sbom", "a", "--list", "--sbom", "b", "-o", "x.json", "p",
        ]
        .map(String::from)
        .to_vec(),
    );
    assert_eq!(a.pos, ["scan", "p"]);
    assert_eq!(a.all("sbom"), ["a", "b"]);
    assert!(a.has("list") && a.get("list").is_none());
    assert_eq!(a.get("o"), Some("x.json"));
}

#[test]
fn dates() {
    assert_eq!(civil(0), "1970-01-01");
    assert_eq!(civil(19_723), "2024-01-01");
    assert_eq!(civil(19_782), "2024-02-29");
    assert_eq!(today().len(), 10);
}

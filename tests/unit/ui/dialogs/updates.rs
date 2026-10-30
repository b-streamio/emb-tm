// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ui/dialogs/updates.rs` (a child module of it, so private items are in reach).

use super::*;

#[test]
fn finds_releases_on_mitre_page() {
    let html = r#"<a href="/assets/emb3d-stix-2.0.json">x</a> emb3d-stix-2.0.1.json emb3d-stix-10.0.json emb3d-stix-x.json"#;
    assert_eq!(releases_on_page(html), ["10.0", "2.0.1", "2.0"]);
}

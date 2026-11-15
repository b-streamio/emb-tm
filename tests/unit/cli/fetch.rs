// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/cli/fetch.rs` (a child module of it, so private items are in reach).

use serde_json::json;

use super::*;

#[test]
fn hash_must_match() {
    let empty = json!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert!(matches(b"", &empty));
    assert!(!matches(b"x", &empty));
    assert!(!matches(b"", &json!(null)));
}

#[test]
fn missing_or_foreign_release_is_refused() {
    let dir = Path::new("data/stix");
    let missing = json!({"version": "0.1", "file": "emb3d-stix-0.1.json", "sha256": ""});
    assert!(read_in(dir, &missing).unwrap_err().contains("emb-tm fetch"));
    let tampered = json!({"version": "0.1", "file": "index.json", "sha256": "00"});
    assert!(read_in(dir, &tampered)
        .unwrap_err()
        .contains("does not match"));
    let elsewhere = json!({"file": "x.json", "source": "https://example.org/x.json"});
    assert!(download(&elsewhere)
        .unwrap_err()
        .contains("not an emb3d.mitre.org"));
}

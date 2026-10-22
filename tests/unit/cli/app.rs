//! Unit tests of `src/cli/app.rs` (a child module of it, so private items are in reach).

use super::*;

const FILES: &[(&str, &[u8])] = &[
    ("index.html", b"<html>"),
    ("emb3d-wb_bg.wasm.gz", b"\x1f\x8b"),
    ("data/stix/index.json", b"{}"),
];

#[test]
fn serves_embedded_files_only() {
    assert_eq!(
        respond(FILES, "GET", "/"),
        ("200 OK", "text/html; charset=utf-8", &b"<html>"[..])
    );
    assert_eq!(
        respond(FILES, "HEAD", "/data/stix/index.json?v=1").1,
        "application/json"
    );
    // The page inflates the .gz files itself: no Content-Encoding, no guessing.
    assert_eq!(
        respond(FILES, "GET", "/emb3d-wb_bg.wasm.gz").1,
        "application/octet-stream"
    );
    for path in [
        "/../Cargo.toml",
        "/data/../index.html",
        "/etc/passwd",
        "//index.html",
    ] {
        assert_eq!(respond(FILES, "GET", path).0, "404 Not Found", "{path}");
    }
    assert_eq!(respond(FILES, "POST", "/").0, "405 Method Not Allowed");
}

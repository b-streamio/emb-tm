// SPDX-License-Identifier: GPL-2.0-only
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

#[test]
fn answers_over_a_socket() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            serve(s);
        }
    });
    let ask = |request: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut reply = String::new();
        s.read_to_string(&mut reply).unwrap();
        reply
    };
    // Nothing is embedded in a test build: every file is missing.
    let reply = ask("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 404 Not Found\r\n"), "{reply}");
    assert!(reply.contains("X-Content-Type-Options: nosniff") && reply.ends_with("not found\n"));
    let reply = ask("HEAD / HTTP/1.1\r\n\r\n");
    assert!(reply.ends_with("\r\n\r\n"), "HEAD has no body: {reply}");
    assert!(ask("POST / HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 405"));
    assert!(
        !running(port),
        "a server that is not this app is not taken for it"
    );
    assert!(run(port, false, None)
        .unwrap_err()
        .contains("does not include the browser app"));
}

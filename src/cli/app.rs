//! `emb3d-wb app`: serves the embedded PWA (feature `pwa`) on the loopback
//! address and opens it in its own browser window.
//!
//! Only the embedded files are served: a request path is looked up in that
//! fixed list and never reaches the file system.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    time::Duration,
};

/// `dist/` at build time: `(path, bytes)`, empty without the `pwa` feature.
static FILES: &[(&str, &[u8])] = include!(concat!(env!("OUT_DIR"), "/pwa.rs"));

pub const PORT: u16 = 8000;

/// Status, content type and body for `method path`.
pub fn respond<'a>(
    files: &[(&str, &'a [u8])],
    method: &str,
    path: &str,
) -> (&'static str, &'static str, &'a [u8]) {
    if method != "GET" && method != "HEAD" {
        return ("405 Method Not Allowed", "text/plain", b"GET only\n");
    }
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let name = match path.strip_prefix('/') {
        Some("") => "index.html",
        Some(p) => p,
        None => "",
    };
    let Some((_, body)) = files.iter().find(|(f, _)| *f == name) else {
        return ("404 Not Found", "text/plain", b"not found\n");
    };
    let kind = match name.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript",
        "css" => "text/css",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        // The `.gz` files are inflated by the page itself.
        _ => "application/octet-stream",
    };
    ("200 OK", kind, body)
}

fn serve(mut s: TcpStream) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buf = [0; 8192];
    let mut len = 0;
    while len < buf.len() && !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut buf[len..]) {
            Ok(0) | Err(_) => return,
            Ok(n) => len += n,
        }
    }
    let head = String::from_utf8_lossy(&buf[..len]);
    let mut words = head.split_whitespace();
    let (method, path) = (
        words.next().unwrap_or_default(),
        words.next().unwrap_or("/"),
    );
    let (status, kind, body) = respond(FILES, method, path);
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
         Cache-Control: no-cache\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(header.as_bytes());
    if method != "HEAD" {
        let _ = s.write_all(body);
    }
}

/// Whether this app already answers on `port`: a second launch, for example
/// from the menu entry (`emb3d-wb.desktop`).
fn running(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut reply = String::new();
    s.write_all(b"GET /manifest.webmanifest HTTP/1.0\r\n\r\n")
        .is_ok()
        && s.read_to_string(&mut reply).is_ok()
        && reply.contains("\"name\": \"EMB3D Workbench\"")
}

/// Opens `url` in its own window, or says where it is.
fn launch(browser: Option<String>, url: &str) {
    let opened = browser.is_some_and(|b| {
        Command::new(b)
            .arg(format!("--app={url}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok()
    });
    if !opened {
        println!("No Chromium-based browser found (set CHROME): open {url}");
    }
}

/// Serves until interrupted and opens the app unless `open` is false; when
/// the app already runs on `port`, only opens it.
pub fn run(port: u16, open: bool, browser: Option<String>) -> Result<i32, String> {
    if FILES.is_empty() {
        return Err("This build of emb3d-wb does not include the browser app.".into());
    }
    let url = format!("http://127.0.0.1:{port}/");
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(_) if running(port) => {
            println!("EMB3D Workbench already runs on {url}");
            if open {
                launch(browser, &url);
            }
            return Ok(0);
        }
        Err(e) => return Err(format!("127.0.0.1:{port}: {e}. Pick another --port.")),
    };
    println!("EMB3D Workbench on {url} (Ctrl-C stops it; an installed app keeps working offline)");
    if open {
        launch(browser, &url);
    }
    for s in listener.incoming().flatten() {
        std::thread::spawn(move || serve(s));
    }
    Ok(0)
}

#[cfg(test)]
#[path = "../../tests/unit/cli/app.rs"]
mod tests;

// SPDX-License-Identifier: GPL-2.0-only
//! With the `pwa` feature, embeds the files of `dist/` (from `make build`)
//! in the command line, for `emb-tm app`. Without it the list
//! is empty.

use std::{env, fs, path::Path};

fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).expect("dist/ is readable").flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            let rel = path.strip_prefix("dist").expect("under dist/");
            let rel = rel.to_string_lossy().replace('\\', "/");
            let abs = fs::canonicalize(&path).expect("file exists");
            out.push((rel, abs.to_string_lossy().into_owned()));
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut files = Vec::new();
    if env::var_os("CARGO_FEATURE_PWA").is_some() {
        println!("cargo:rerun-if-changed=dist");
        if !Path::new("dist/index.html").is_file() {
            panic!("the pwa feature embeds dist/: run `make build`");
        }
        walk(Path::new("dist"), &mut files);
    }
    files.sort();
    let list: String = files
        .iter()
        .map(|(rel, abs)| format!("    ({rel:?}, include_bytes!({abs:?}) as &[u8]),\n"))
        .collect();
    let out = Path::new(&env::var("OUT_DIR").expect("set by cargo")).join("pwa.rs");
    fs::write(out, format!("&[\n{list}]\n")).expect("OUT_DIR is writable");
}

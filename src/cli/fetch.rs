// SPDX-License-Identifier: GPL-2.0-only
//! `fetch`: downloads the EMB3D releases of the built-in index
//! (data/stix/index.json) from emb3d.mitre.org into [`stix_dir`], under
//! MITRE's terms of use; emb-tm ships none. The system's
//! curl downloads; a file must match the SHA-256 the index pins, when it is
//! downloaded and each time it is read.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{index, plain, stix_dir, Args};

const TERMS: &str = "https://emb3d.mitre.org/subtabs/terms-of-use.html";

/// The file of a release of the index, in `dir`.
fn path(dir: &Path, meta: &Value) -> PathBuf {
    dir.join(meta["file"].as_str().unwrap_or_default())
}

/// Whether `bytes` hash to the hex SHA-256 `want`.
fn matches(bytes: &[u8], want: &Value) -> bool {
    let got: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    want.as_str() == Some(got.as_str())
}

/// The file of release `meta`, checked against its pinned SHA-256.
pub(super) fn read_release(meta: &Value) -> Result<Vec<u8>, String> {
    read_in(&stix_dir(), meta)
}

fn read_in(dir: &Path, meta: &Value) -> Result<Vec<u8>, String> {
    let file = path(dir, meta);
    let bytes = fs::read(&file).map_err(|_| {
        format!(
            "EMB3D {} is not downloaded yet: run \"emb-tm fetch\" (from emb3d.mitre.org, under MITRE's terms of use).",
            plain(&meta["version"])
        )
    })?;
    if !matches(&bytes, &meta["sha256"]) {
        return Err(format!(
            "{}: does not match its pinned SHA-256; run \"emb-tm fetch\" again.",
            file.display()
        ));
    }
    Ok(bytes)
}

/// `emb-tm fetch [<version>]`: every release of the index, or one.
pub(super) fn fetch(a: &Args) -> Result<i32, String> {
    let idx = index()?;
    let want = a.pos.get(1);
    let picked: Vec<&Value> = idx["versions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| want.is_none_or(|w| m["version"] == w.as_str()))
        .collect();
    if picked.is_empty() {
        return Err(format!(
            "EMB3D {} is not listed in data/stix/index.json",
            want.map_or("", String::as_str)
        ));
    }
    for meta in picked {
        let v = plain(&meta["version"]);
        if read_release(meta).is_ok() {
            println!("EMB3D {v}: up to date");
            continue;
        }
        download(meta)?;
        println!("EMB3D {v}: downloaded from {}", plain(&meta["source"]));
    }
    println!("MITRE EMB3D(TM) data (c) The MITRE Corporation, under its terms of use: {TERMS}");
    Ok(0)
}

/// Downloads release `meta` with curl (HTTPS only), keeps it when it matches.
fn download(meta: &Value) -> Result<(), String> {
    let (dir, url) = (stix_dir(), meta["source"].as_str().unwrap_or_default());
    if !url.starts_with("https://emb3d.mitre.org/") {
        return Err(format!("{url}: not an emb3d.mitre.org address"));
    }
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let file = path(&dir, meta);
    let part = file.with_extension("part");
    let ok = Command::new("curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--max-filesize",
            "50000000",
            "-o",
        ])
        .arg(&part)
        .arg(url)
        .status()
        .map_err(|e| format!("curl: {e} (emb-tm fetch downloads with curl)"))?
        .success();
    if !(ok && matches(&fs::read(&part).unwrap_or_default(), &meta["sha256"])) {
        let _ = fs::remove_file(&part);
        return Err(format!(
            "{url}: download failed or does not match its SHA-256"
        ));
    }
    fs::rename(&part, &file).map_err(|e| format!("{}: {e}", file.display()))
}

#[cfg(test)]
#[path = "../../tests/unit/cli/fetch.rs"]
mod tests;

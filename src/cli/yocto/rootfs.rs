// SPDX-License-Identifier: GPL-2.0-only
//! An image root file system: an unpacked directory or a tarball (read with
//! the system `tar`).

use std::{
    cell::RefCell,
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use super::{base, read};

/// An image root file system: an unpacked directory or a tarball.
pub(super) struct Rootfs {
    pub(super) label: String,
    pub(super) list: Vec<String>,
    /// Tarball member name of each path; empty for a directory.
    members: HashMap<String, String>,
    src: PathBuf,
    cache: RefCell<HashMap<String, Option<String>>>,
}

impl Rootfs {
    pub(super) fn open(src: &Path) -> Result<Self, String> {
        let mut fs = Self {
            label: src.display().to_string(),
            list: Vec::new(),
            members: HashMap::new(),
            src: src.to_owned(),
            cache: RefCell::default(),
        };
        if src.is_dir() {
            fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
                let mut entries: Vec<_> = fs::read_dir(dir)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path())
                    .collect();
                entries.sort();
                for p in entries {
                    let rel = p.strip_prefix(root).unwrap_or(&p);
                    out.push(format!("/{}", rel.to_string_lossy().replace('\\', "/")));
                    if p.is_dir() && !p.is_symlink() {
                        walk(root, &p, out);
                    }
                }
            }
            walk(src, src, &mut fs.list);
            return Ok(fs);
        }
        fs.label = base(src);
        for raw in tar(src, &["-tf"])?.lines().filter(|l| !l.is_empty()) {
            let path = raw.trim_start_matches("./").trim_start_matches('/');
            let path = format!("/{}", path.trim_end_matches('/'));
            fs.list.push(path.clone());
            fs.members.insert(path, raw.to_owned());
        }
        Ok(fs)
    }

    pub(super) fn read(&self, path: &str) -> Option<String> {
        if self.members.is_empty() {
            return read(&self.src.join(path.trim_start_matches('/'))).ok();
        }
        let member = self.members.get(path)?;
        self.cache
            .borrow_mut()
            .entry(path.to_owned())
            .or_insert_with(|| tar(&self.src, &["-xOf", member]).ok())
            .clone()
    }
}

/// Runs the system `tar` on `archive` (it handles gz, bz2, xz and zst).
fn tar(archive: &Path, args: &[&str]) -> Result<String, String> {
    let (flag, rest) = args.split_first().expect("a tar flag");
    let out = Command::new("tar")
        .arg(flag)
        .arg(archive)
        .args(rest)
        .output()
        .map_err(|e| format!("tar: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tar {flag} {}: {}",
            archive.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

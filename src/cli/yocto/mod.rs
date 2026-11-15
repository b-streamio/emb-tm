// SPDX-License-Identifier: GPL-2.0-only
//! Yocto image + CycloneDX SBOMs → emb-tm project. Deterministic: the
//! rules are in `library/yocto-rules.json` (`library/README.md`).
//!
//! Inputs, all optional (the more the better):
//! - variables: `<image>.testdata.json` (written by every image build) or
//!   `bitbake -e <image>` output, which also records where each was set;
//! - packages: `<image>.manifest` and/or CycloneDX SBOMs (JSON);
//! - rootfs: the image's tarball (read with the system `tar`) or a directory;
//! - configs: kernel `.config`, bootloader (U-Boot, barebox) `.config`.
//!
//! Conditions are three-valued: true, false, or unknown when the input they
//! need was not given. Unknown never picks an answer: the answer falls
//! through and is flagged for review, naming the missing input.

mod deploy;
mod parse;
mod project;
mod rootfs;
mod rules;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use regex::Regex;
use serde_json::Value;

pub use deploy::from_deploy_dir;
pub use parse::{parse_bbenv, Sbom};

use crate::model::{Evidence, Library, Project};
use parse::{parse_config, parse_cyclonedx, parse_manifest, parse_testdata};
use rootfs::Rootfs;
use rules::Found;

/// What to read; `--deploy` fills it from a deploy directory.
#[derive(Debug, Default, PartialEq)]
pub struct Inputs {
    pub image: Option<String>,
    pub testdata: Option<PathBuf>,
    pub bbenv: Option<PathBuf>,
    pub manifest: Option<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub kernel_config: Option<PathBuf>,
    pub uboot_config: Option<PathBuf>,
    pub sboms: Vec<PathBuf>,
}

/// A build variable and the `file:line`s that set it (`bitbake -e` only).
#[derive(Debug)]
pub struct Var {
    pub value: String,
    pub file: String,
    pub origins: Vec<(String, u64)>,
}

/// What a scan found, for the command line summary.
#[derive(Debug, Default)]
pub struct Notes {
    pub used: Vec<String>,
    pub skipped: Vec<String>,
    pub sboms: Vec<Sbom>,
    pub packages: usize,
    pub variables: usize,
    pub cve_open: usize,
}

/// Reads the inputs and applies the rules: a version 1 project (one page).
pub fn scan(
    inputs: &Inputs,
    rules: &Value,
    lib: &Library,
    today: &str,
) -> Result<(Project, Notes), String> {
    let mut notes = Notes::default();
    let f = read_inputs(inputs, &mut notes)?;
    let (nodes, by_rule) = project::components(&f, rules, lib, &mut notes)?;
    let flows = project::flows(rules, &nodes, &by_rule);
    let p = project::project(&f, inputs, &mut notes, (nodes, flows), today);
    Ok((p, notes))
}

fn read_inputs(inputs: &Inputs, notes: &mut Notes) -> Result<Found, String> {
    let mut f = Found::default();
    let path = |p: &Path| p.display().to_string();
    if let Some(p) = &inputs.testdata {
        f.vars = Some(parse_testdata(&read(p)?, &path(p))?);
        notes.used.push(base(p));
    }
    if let Some(p) = &inputs.bbenv {
        // bitbake -e wins: it carries file:line origins.
        let vars = f.vars.get_or_insert_with(BTreeMap::new);
        vars.extend(parse_bbenv(&read(p)?, &path(p)));
        notes.used.push(base(p));
    }
    if let Some(p) = &inputs.manifest {
        parse_manifest(&read(p)?, &base(p), &mut f.pkgs);
        notes.used.push(base(p));
    }
    for p in &inputs.sboms {
        notes
            .sboms
            .push(parse_cyclonedx(&read(p)?, &base(p), &mut f.pkgs)?);
        notes.used.push(base(p));
    }
    if let Some(p) = &inputs.kernel_config {
        f.kconfig = Some(parse_config(&read(p)?, &path(p)));
        notes.used.push(base(p));
    }
    if let Some(p) = &inputs.uboot_config {
        f.uconfig = Some(parse_config(&read(p)?, &path(p)));
        notes.used.push(base(p));
    }
    if let Some(p) = &inputs.rootfs {
        let r = Rootfs::open(p)?;
        notes.used.push(r.label.clone());
        f.rootfs = Some(r);
    }
    Ok(f)
}

fn regex(re: &str) -> Result<Regex, String> {
    Regex::new(re).map_err(|e| format!("rule regex {re:?}: {e}"))
}

fn read(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn base(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into(),
    )
}

/// At most `n` characters, `…` when cut.
fn short(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n - 1).chain(['…']).collect()
    } else {
        s.to_owned()
    }
}

/// Removes repeats, keeping the first of each.
fn dedup(v: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|x| seen.insert(x.clone()));
}

fn evidence(file: &str, line: Option<u64>, text: &str) -> Evidence {
    Evidence {
        file: file.to_owned(),
        line,
        text: text.to_owned(),
    }
}

/// Truthiness of a rule value, as in the rules file's JavaScript origins.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::Null => false,
        _ => true,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/yocto/mod.rs"]
mod tests;

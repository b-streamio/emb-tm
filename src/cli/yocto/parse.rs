// SPDX-License-Identifier: GPL-2.0-only
//! Readers of the scanner inputs: build variables, package lists, CycloneDX
//! SBOMs and `.config` files.

use std::collections::{BTreeMap, HashMap};

use regex::Regex;
use serde_json::{Map, Value};

use super::{regex, Var};

#[derive(Debug, Default)]
pub(super) struct Pkg {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) sources: Vec<String>,
    /// `(id, open)`
    pub(super) cves: Vec<(String, bool)>,
}

/// Installed packages in first-seen order.
#[derive(Default)]
pub(super) struct Pkgs {
    pub(super) list: Vec<Pkg>,
    index: HashMap<String, usize>,
}

impl Pkgs {
    pub(super) fn entry(&mut self, name: &str) -> &mut Pkg {
        let i = *self.index.entry(name.to_owned()).or_insert_with(|| {
            self.list.push(Pkg {
                name: name.to_owned(),
                ..Default::default()
            });
            self.list.len() - 1
        });
        &mut self.list[i]
    }

    pub(super) fn matching(&self, pattern: &str) -> Result<Vec<&Pkg>, String> {
        let re = regex(&format!("^({pattern})$"))?;
        Ok(self.list.iter().filter(|p| re.is_match(&p.name)).collect())
    }
}

/// Counts of one SBOM, for the project description.
#[derive(Debug, Default)]
pub struct Sbom {
    pub file: String,
    pub components: usize,
    pub vulnerabilities: usize,
    pub open: usize,
    pub subject: String,
}

/// `.config`: `CONFIG_X` → `(value, line, text)`; "is not set" reads `n`.
pub(super) struct Config {
    pub(super) file: String,
    pub(super) map: HashMap<String, (String, u64, String)>,
}

/// `bitbake -e` output: variables with the `file:line` of each assignment.
pub fn parse_bbenv(text: &str, file: &str) -> BTreeMap<String, Var> {
    let origin = Regex::new(r"^#\s{2,}\S.*?\s(/\S+):(\d+)\s*$").expect("valid");
    let assign =
        Regex::new(r#"^(?:export )?([A-Za-z0-9_][A-Za-z0-9_\-:/.+~${}]*)="(.*)"$"#).expect("valid");
    let function = Regex::new(r"^\w+\s*\(\)").expect("valid");
    let mut vars = BTreeMap::new();
    let mut origins = Vec::new();
    for line in text.split('\n') {
        if let Some(c) = origin.captures(line) {
            origins.push((c[1].to_owned(), c[2].parse().unwrap_or(0)));
        } else if let Some(c) = assign.captures(line) {
            let value = c[2].replace("\\\"", "\"").replace("\\$", "$");
            let origins = std::mem::take(&mut origins);
            vars.insert(
                c[1].to_owned(),
                Var {
                    value,
                    file: file.to_owned(),
                    origins,
                },
            );
        } else if function.is_match(line) {
            origins.clear();
        }
    }
    vars
}

pub(super) fn parse_testdata(text: &str, file: &str) -> Result<BTreeMap<String, Var>, String> {
    let d: Map<String, Value> = serde_json::from_str(text).map_err(|e| format!("{file}: {e}"))?;
    Ok(d.into_iter()
        .filter_map(|(k, v)| {
            let value = match v {
                Value::String(s) => s,
                Value::Bool(_) | Value::Number(_) => v.to_string(),
                _ => return None,
            };
            Some((
                k,
                Var {
                    value,
                    file: file.to_owned(),
                    origins: Vec::new(),
                },
            ))
        })
        .collect())
}

pub(super) fn parse_manifest(text: &str, file: &str, pkgs: &mut Pkgs) {
    for line in text.lines() {
        let mut cols = line.split_whitespace();
        let (Some(name), version) = (cols.next(), cols.nth(1)) else {
            continue;
        };
        let p = pkgs.entry(name);
        if p.version.is_empty() {
            p.version = version.unwrap_or_default().to_owned();
        }
        p.sources.push(file.to_owned());
    }
}

/// VEX states that close a vulnerability.
const CLOSED_VEX: [&str; 4] = [
    "resolved",
    "resolved_with_pedigree",
    "not_affected",
    "false_positive",
];

pub(super) fn parse_cyclonedx(text: &str, file: &str, pkgs: &mut Pkgs) -> Result<Sbom, String> {
    let bom: Value = serde_json::from_str(text).map_err(|e| format!("{file}: {e}"))?;
    if bom["bomFormat"] != "CycloneDX" {
        return Err(format!(
            "{file}: not a CycloneDX BOM (bomFormat is {})",
            bom["bomFormat"]
        ));
    }
    let mut refs = HashMap::new();
    let components = walk_components(&bom["components"], file, pkgs, &mut refs);
    let vulns = bom["vulnerabilities"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let mut open = 0;
    for v in vulns {
        let id = v["id"].as_str().unwrap_or_default();
        let state = v["analysis"]["state"].as_str().unwrap_or_default();
        let is_open = !CLOSED_VEX.contains(&state);
        for a in v["affects"].as_array().into_iter().flatten() {
            let Some(name) = a["ref"].as_str().and_then(|r| refs.get(r)) else {
                continue;
            };
            let p = pkgs.entry(name);
            if !p.cves.iter().any(|(c, _)| c == id) {
                p.cves.push((id.to_owned(), is_open));
                open += usize::from(is_open);
            }
        }
    }
    let meta = &bom["metadata"]["component"];
    let subject = match (meta["name"].as_str(), meta["version"].as_str()) {
        (Some(n), Some(v)) if !v.is_empty() => format!("{n} {v}"),
        (Some(n), _) => n.to_owned(),
        _ => String::new(),
    };
    Ok(Sbom {
        file: file.to_owned(),
        components,
        vulnerabilities: vulns.len(),
        open,
        subject,
    })
}

/// Adds the components of a BOM, nested ones too, to `pkgs`; returns their count.
fn walk_components(
    list: &Value,
    file: &str,
    pkgs: &mut Pkgs,
    refs: &mut HashMap<String, String>,
) -> usize {
    let mut count = 0;
    for c in list.as_array().into_iter().flatten() {
        count += 1;
        if let Some(name) = c["name"].as_str() {
            let p = pkgs.entry(name);
            if p.version.is_empty() {
                p.version = c["version"].as_str().unwrap_or_default().to_owned();
            }
            p.sources.push(file.to_owned());
            if let Some(r) = c["bom-ref"].as_str() {
                refs.insert(r.to_owned(), name.to_owned());
            }
        }
        count += walk_components(&c["components"], file, pkgs, refs);
    }
    count
}

pub(super) fn parse_config(text: &str, file: &str) -> Config {
    let mut map = HashMap::new();
    for (i, l) in text.lines().enumerate() {
        let line = i as u64 + 1;
        if let Some((k, v)) = l.split_once('=').filter(|(k, _)| is_config(k)) {
            let v = v
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(v);
            map.insert(k.to_owned(), (v.to_owned(), line, l.to_owned()));
        } else if let Some(k) = l
            .strip_prefix("# ")
            .and_then(|r| r.split_once(" is not set"))
            .map(|x| x.0)
            .filter(|k| is_config(k))
        {
            map.insert(k.to_owned(), ("n".into(), line, l.to_owned()));
        }
    }
    Config {
        file: file.to_owned(),
        map,
    }
}

fn is_config(k: &str) -> bool {
    k.strip_prefix("CONFIG_")
        .is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/yocto/parse.rs"]
mod tests;

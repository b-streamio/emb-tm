// SPDX-License-Identifier: GPL-2.0-only
//! Rule conditions over what the scan read, three-valued: true, false, or
//! unknown (`None`) when the input they need was not given.

use std::{collections::BTreeMap, path::Path};

use regex::Regex;
use serde_json::Value;

use super::{
    base, evidence,
    parse::{Config, Pkgs},
    regex,
    rootfs::Rootfs,
    short, Var,
};
use crate::model::Evidence;

/// A condition's outcome: `v` is `None` when an input is missing (`miss`).
#[derive(Debug, Default)]
pub(super) struct Outcome {
    pub(super) v: Option<bool>,
    pub(super) ev: Vec<Evidence>,
    pub(super) miss: Vec<String>,
}

impl Outcome {
    fn known(v: bool, ev: Vec<Evidence>) -> Self {
        Self {
            v: Some(v),
            ev,
            miss: Vec::new(),
        }
    }

    fn missing(what: &str) -> Self {
        Self {
            v: None,
            ev: Vec::new(),
            miss: vec![what.to_owned()],
        }
    }
}

/// Everything the conditions look at.
#[derive(Default)]
pub(super) struct Found {
    pub(super) vars: Option<BTreeMap<String, Var>>,
    pub(super) pkgs: Pkgs,
    pub(super) kconfig: Option<Config>,
    pub(super) uconfig: Option<Config>,
    pub(super) rootfs: Option<Rootfs>,
}

/// `/etc/*.conf` → `^/etc/[^/]*\.conf$`.
fn glob(g: &str) -> Result<Regex, String> {
    let parts: Vec<String> = g.split('*').map(regex::escape).collect();
    regex(&format!("^{}$", parts.join("[^/]*")))
}

impl Found {
    pub(super) fn var(&self, name: &str) -> &str {
        self.vars
            .as_ref()
            .and_then(|v| v.get(name))
            .map_or("", |v| v.value.as_str())
    }

    /// `${A|B}` → the first of A, B that is set; whitespace collapsed.
    pub(super) fn fill(&self, tpl: &str) -> String {
        let re = Regex::new(r"\$\{([^}]+)\}").expect("valid");
        let s = re.replace_all(tpl, |c: &regex::Captures| {
            c[1].split('|')
                .map(|v| self.var(v))
                .find(|v| !v.is_empty())
                .unwrap_or_default()
                .to_owned()
        });
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    pub(super) fn eval(&self, c: &Value) -> Result<Outcome, String> {
        let s = |k: &str| c[k].as_str();
        if c["always"] == true {
            return Ok(Outcome::known(true, Vec::new()));
        }
        if let Some(list) = c["any"].as_array().or_else(|| c["all"].as_array()) {
            return self.eval_list(list, c["any"].is_array());
        }
        if c.get("not").is_some() {
            let r = self.eval(&c["not"])?;
            return Ok(Outcome {
                v: r.v.map(|v| !v),
                ev: Vec::new(),
                miss: r.miss,
            });
        }
        if let Some(name) = s("var") {
            return self.eval_var(c, name);
        }
        if let Some(pkg) = s("pkg") {
            return self.eval_pkg(pkg);
        }
        if let Some((name, cfg, what)) = s("kconfig")
            .map(|n| (n, &self.kconfig, "kernel .config"))
            .or_else(|| s("uboot").map(|n| (n, &self.uconfig, "bootloader .config")))
        {
            let Some(cfg) = cfg else {
                return Ok(Outcome::missing(what));
            };
            return eval_config(c, name, cfg);
        }
        if let Some(pattern) = s("file").or_else(|| s("exists")) {
            return self.eval_file(c, pattern);
        }
        Err(format!("Unknown rule condition: {c}"))
    }

    /// `any` (`any` true) or `all` of `list`.
    fn eval_list(&self, list: &[Value], any: bool) -> Result<Outcome, String> {
        let parts = list
            .iter()
            .map(|x| self.eval(x))
            .collect::<Result<Vec<_>, _>>()?;
        let has = |v: Option<bool>| parts.iter().any(|p| p.v == v);
        let evidence = |only: Option<bool>| {
            parts
                .iter()
                .filter(|p| only.is_none() || p.v == only)
                .flat_map(|p| p.ev.iter().cloned())
                .collect()
        };
        let unknown = Outcome {
            v: None,
            ev: Vec::new(),
            miss: parts.iter().flat_map(|p| p.miss.iter().cloned()).collect(),
        };
        Ok(match (any, has(Some(true)), has(Some(false)), has(None)) {
            (true, true, _, _) => Outcome::known(true, evidence(Some(true))),
            (true, false, _, true) | (false, _, false, true) => unknown,
            (true, false, _, false) | (false, _, true, _) => Outcome::known(false, Vec::new()),
            (false, _, false, false) => Outcome::known(true, evidence(None)),
        })
    }

    /// A build variable: `set`, a `word` of it, `eq` or `re`.
    fn eval_var(&self, c: &Value, name: &str) -> Result<Outcome, String> {
        let Some(vars) = &self.vars else {
            return Ok(Outcome::missing(
                "build variables (testdata.json or bitbake -e)",
            ));
        };
        let v = vars.get(name);
        let val = v.map_or("", |v| v.value.as_str());
        let ok = if let Some(set) = c["set"].as_bool() {
            val.trim().is_empty() != set
        } else if let Some(w) = c["word"].as_str() {
            val.split_whitespace().any(|x| x == w)
        } else if let Some(eq) = c["eq"].as_str() {
            val.trim() == eq
        } else if let Some(re) = c["re"].as_str() {
            regex(re)?.is_match(val)
        } else {
            false
        };
        let ev = v.filter(|_| ok).map(|v| {
            let text = short(&format!("{name} = \"{}\"", v.value), 160);
            match v.origins.last() {
                Some((f, l)) => evidence(f, Some(*l), &text),
                None => evidence(&base(Path::new(&v.file)), None, &text),
            }
        });
        Ok(Outcome::known(ok, ev.into_iter().collect()))
    }

    /// An installed package whose name matches `pkg`.
    fn eval_pkg(&self, pkg: &str) -> Result<Outcome, String> {
        if self.pkgs.list.is_empty() {
            return Ok(Outcome::missing("package list (manifest or SBOM)"));
        }
        let hits = self.pkgs.matching(pkg)?;
        let ev = hits
            .iter()
            .take(3)
            .map(|p| {
                let text = format!("{} {}", p.name, p.version);
                evidence(&p.sources[0], None, text.trim())
            })
            .collect();
        Ok(Outcome::known(!hits.is_empty(), ev))
    }

    /// A rootfs file matching `pattern` that `exists`, or whose text matches `re`.
    fn eval_file(&self, c: &Value, pattern: &str) -> Result<Outcome, String> {
        let Some(rootfs) = &self.rootfs else {
            return Ok(Outcome::missing("rootfs"));
        };
        let globs = pattern
            .split('|')
            .map(glob)
            .collect::<Result<Vec<_>, _>>()?;
        let mut files = rootfs
            .list
            .iter()
            .filter(|p| globs.iter().any(|g| g.is_match(p)));
        if c["exists"].is_string() {
            let found: Vec<Evidence> = files
                .take(2)
                .map(|f| evidence(&format!("rootfs:{f}"), None, "present"))
                .collect();
            return Ok(Outcome::known(!found.is_empty(), found));
        }
        let re = regex(&format!("(?m){}", c["re"].as_str().unwrap_or_default()))?;
        for f in files.by_ref() {
            let Some(txt) = rootfs.read(f) else { continue };
            if let Some(m) = re.find(&txt) {
                let line = txt[..m.start()].matches('\n').count();
                let text = short(txt.split('\n').nth(line).unwrap_or_default().trim(), 160);
                let ev = evidence(&format!("rootfs:{f}"), Some(line as u64 + 1), &text);
                return Ok(Outcome::known(true, vec![ev]));
            }
        }
        Ok(Outcome::known(false, Vec::new()))
    }
}

/// A `.config` option: `eq` a value or matching `re`; unset reads `n`.
fn eval_config(c: &Value, name: &str, cfg: &Config) -> Result<Outcome, String> {
    let e = cfg.map.get(name);
    let val = e.map_or("n", |e| e.0.as_str());
    let ok = match c["eq"].as_str() {
        Some(eq) => val == eq,
        None => regex(c["re"].as_str().unwrap_or_default())?.is_match(val),
    };
    let ev = e
        .filter(|_| ok)
        .map(|(_, line, text)| evidence(&base(Path::new(&cfg.file)), Some(*line), text));
    Ok(Outcome::known(ok, ev.into_iter().collect()))
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/yocto/rules.rs"]
mod tests;

// SPDX-License-Identifier: GPL-2.0-only
//! Yocto image + CycloneDX SBOMs → Workbench project. Deterministic: the
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

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::model::{Evidence, Flow, Library, Meta, Node, Project};

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

#[derive(Debug, Default)]
struct Pkg {
    name: String,
    version: String,
    sources: Vec<String>,
    /// `(id, open)`
    cves: Vec<(String, bool)>,
}

/// Installed packages in first-seen order.
#[derive(Default)]
struct Pkgs {
    list: Vec<Pkg>,
    index: HashMap<String, usize>,
}

impl Pkgs {
    fn entry(&mut self, name: &str) -> &mut Pkg {
        let i = *self.index.entry(name.to_owned()).or_insert_with(|| {
            self.list.push(Pkg {
                name: name.to_owned(),
                ..Default::default()
            });
            self.list.len() - 1
        });
        &mut self.list[i]
    }

    fn matching(&self, pattern: &str) -> Result<Vec<&Pkg>, String> {
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
struct Config {
    file: String,
    map: HashMap<String, (String, u64, String)>,
}

/// An image root file system: an unpacked directory or a tarball.
struct Rootfs {
    label: String,
    list: Vec<String>,
    /// Tarball member name of each path; empty for a directory.
    members: HashMap<String, String>,
    src: PathBuf,
    cache: RefCell<HashMap<String, Option<String>>>,
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

fn parse_testdata(text: &str, file: &str) -> Result<BTreeMap<String, Var>, String> {
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

fn parse_manifest(text: &str, file: &str, pkgs: &mut Pkgs) {
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

fn parse_cyclonedx(text: &str, file: &str, pkgs: &mut Pkgs) -> Result<Sbom, String> {
    let bom: Value = serde_json::from_str(text).map_err(|e| format!("{file}: {e}"))?;
    if bom["bomFormat"] != "CycloneDX" {
        return Err(format!(
            "{file}: not a CycloneDX BOM (bomFormat is {})",
            bom["bomFormat"]
        ));
    }
    fn walk(
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
            count += walk(&c["components"], file, pkgs, refs);
        }
        count
    }
    let mut refs = HashMap::new();
    let components = walk(&bom["components"], file, pkgs, &mut refs);
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

fn parse_config(text: &str, file: &str) -> Config {
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

impl Rootfs {
    fn open(src: &Path) -> Result<Self, String> {
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

    fn read(&self, path: &str) -> Option<String> {
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

/// `/etc/*.conf` → `^/etc/[^/]*\.conf$`.
fn glob(g: &str) -> Result<Regex, String> {
    let parts: Vec<String> = g.split('*').map(regex::escape).collect();
    regex(&format!("^{}$", parts.join("[^/]*")))
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

/// A condition's outcome: `v` is `None` when an input is missing (`miss`).
#[derive(Debug, Default)]
struct Outcome {
    v: Option<bool>,
    ev: Vec<Evidence>,
    miss: Vec<String>,
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

fn evidence(file: &str, line: Option<u64>, text: &str) -> Evidence {
    Evidence {
        file: file.to_owned(),
        line,
        text: text.to_owned(),
    }
}

/// Everything the conditions look at.
#[derive(Default)]
struct Found {
    vars: Option<BTreeMap<String, Var>>,
    pkgs: Pkgs,
    kconfig: Option<Config>,
    uconfig: Option<Config>,
    rootfs: Option<Rootfs>,
}

impl Found {
    fn var(&self, name: &str) -> &str {
        self.vars
            .as_ref()
            .and_then(|v| v.get(name))
            .map_or("", |v| v.value.as_str())
    }

    /// `${A|B}` → the first of A, B that is set; whitespace collapsed.
    fn fill(&self, tpl: &str) -> String {
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

    fn eval(&self, c: &Value) -> Result<Outcome, String> {
        let s = |k: &str| c[k].as_str();
        if c["always"] == true {
            return Ok(Outcome::known(true, Vec::new()));
        }
        if let Some(list) = c["any"].as_array().or_else(|| c["all"].as_array()) {
            let parts = list
                .iter()
                .map(|x| self.eval(x))
                .collect::<Result<Vec<_>, _>>()?;
            let any = c["any"].is_array();
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
            return Ok(match (any, has(Some(true)), has(Some(false)), has(None)) {
                (true, true, _, _) => Outcome::known(true, evidence(Some(true))),
                (true, false, _, true) | (false, _, false, true) => unknown,
                (true, false, _, false) | (false, _, true, _) => Outcome::known(false, Vec::new()),
                (false, _, false, false) => Outcome::known(true, evidence(None)),
            });
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
            let Some(vars) = &self.vars else {
                return Ok(Outcome::missing(
                    "build variables (testdata.json or bitbake -e)",
                ));
            };
            let v = vars.get(name);
            let val = v.map_or("", |v| v.value.as_str());
            let ok = if let Some(set) = c["set"].as_bool() {
                val.trim().is_empty() != set
            } else if let Some(w) = s("word") {
                val.split_whitespace().any(|x| x == w)
            } else if let Some(eq) = s("eq") {
                val.trim() == eq
            } else if let Some(re) = s("re") {
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
            return Ok(Outcome::known(ok, ev.into_iter().collect()));
        }
        if let Some(pkg) = s("pkg") {
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
            return Ok(Outcome::known(!hits.is_empty(), ev));
        }
        if let Some((name, cfg, what)) = s("kconfig")
            .map(|n| (n, &self.kconfig, "kernel .config"))
            .or_else(|| s("uboot").map(|n| (n, &self.uconfig, "bootloader .config")))
        {
            let Some(cfg) = cfg else {
                return Ok(Outcome::missing(what));
            };
            let e = cfg.map.get(name);
            let val = e.map_or("n", |e| e.0.as_str());
            let ok = match s("eq") {
                Some(eq) => val == eq,
                None => regex(s("re").unwrap_or_default())?.is_match(val),
            };
            let ev = e
                .filter(|_| ok)
                .map(|(_, line, text)| evidence(&base(Path::new(&cfg.file)), Some(*line), text));
            return Ok(Outcome::known(ok, ev.into_iter().collect()));
        }
        if let Some(pattern) = s("file").or_else(|| s("exists")) {
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
            if s("exists").is_some() {
                let found: Vec<Evidence> = files
                    .take(2)
                    .map(|f| evidence(&format!("rootfs:{f}"), None, "present"))
                    .collect();
                return Ok(Outcome::known(!found.is_empty(), found));
            }
            let re = regex(&format!("(?m){}", s("re").unwrap_or_default()))?;
            for f in files.by_ref() {
                let Some(txt) = rootfs.read(f) else { continue };
                if let Some(m) = re.find(&txt) {
                    let line = txt[..m.start()].matches('\n').count();
                    let text = short(txt.split('\n').nth(line).unwrap_or_default().trim(), 160);
                    let ev = evidence(&format!("rootfs:{f}"), Some(line as u64 + 1), &text);
                    return Ok(Outcome::known(true, vec![ev]));
                }
            }
            return Ok(Outcome::known(false, Vec::new()));
        }
        Err(format!("Unknown rule condition: {c}"))
    }
}

/// Reads the inputs and applies the rules: a version 1 project (one page).
pub fn scan(
    inputs: &Inputs,
    rules: &Value,
    lib: &Library,
    today: &str,
) -> Result<(Project, Notes), String> {
    let mut f = Found::default();
    let mut notes = Notes::default();
    if let Some(p) = &inputs.testdata {
        f.vars = Some(parse_testdata(&read(p)?, &p.display().to_string())?);
        notes.used.push(base(p));
    }
    if let Some(p) = &inputs.bbenv {
        // bitbake -e wins: it carries file:line origins.
        let vars = f.vars.get_or_insert_with(BTreeMap::new);
        vars.extend(parse_bbenv(&read(p)?, &p.display().to_string()));
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
        f.kconfig = Some(parse_config(&read(p)?, &p.display().to_string()));
        notes.used.push(base(p));
    }
    if let Some(p) = &inputs.uboot_config {
        f.uconfig = Some(parse_config(&read(p)?, &p.display().to_string()));
        notes.used.push(base(p));
    }
    if let Some(p) = &inputs.rootfs {
        let r = Rootfs::open(p)?;
        notes.used.push(r.label.clone());
        f.rootfs = Some(r);
    }

    let mut nodes: Vec<Node> = Vec::new();
    let mut by_rule: HashMap<&str, usize> = HashMap::new();
    let placeholder = Regex::new(r"\$\{[^}]+\}\s*").expect("valid");
    let recipe_rev = Regex::new(r"-r\d+$").expect("valid"); // 1.2-r0 → 1.2
    for rule in rules["components"].as_array().into_iter().flatten() {
        let (id, kind) = (
            rule["id"].as_str().unwrap_or_default(),
            rule["type"].as_str().unwrap_or_default(),
        );
        let Some(def) = lib.components.iter().find(|c| c.kind == kind) else {
            return Err(format!("rule {id}: unknown component type {kind}"));
        };
        let tpl = rule["name"].as_str().unwrap_or_default();
        let w = f.eval(&rule["when"])?;
        match w.v {
            Some(true) => {}
            Some(false) => continue,
            None => {
                let mut miss = w.miss.clone();
                dedup(&mut miss);
                let what = placeholder.replace_all(tpl, "");
                notes
                    .skipped
                    .push(format!("{what}: not checked, needs {}", miss.join(", ")));
                continue;
            }
        }
        let mut name = f.fill(tpl);
        if name.is_empty() {
            name.clone_from(&def.name);
        }
        let mut node = Node::new(nodes.len() as u64 + 1, kind, "", f64::NAN, f64::NAN);
        let mut comp: Vec<Evidence> = w.ev.into_iter().take(3).collect();
        if let Some(pattern) = rule["version"].as_str() {
            let hits = f.pkgs.matching(pattern)?;
            if let Some(p) = hits.iter().find(|p| !p.version.is_empty()) {
                name += &format!(" {}", recipe_rev.replace(&p.version, ""));
            }
            // SBOMs name recipes (openssh), manifests name packages
            // (openssh-sshd): gather CVEs from every match.
            for p in hits.iter().filter(|p| !p.cves.is_empty()) {
                let open: Vec<&str> = p
                    .cves
                    .iter()
                    .filter(|c| c.1)
                    .map(|c| c.0.as_str())
                    .collect();
                let list = match open.len() {
                    0 => String::new(),
                    n => format!(
                        " ({}{})",
                        open[..n.min(6)].join(", "),
                        if n > 6 { ", …" } else { "" }
                    ),
                };
                let file = p
                    .sources
                    .iter()
                    .find(|s| !s.ends_with("manifest"))
                    .unwrap_or(&p.sources[0]);
                let text = format!(
                    "{} {}: {} open of {} CVEs in SBOM{list}",
                    p.name,
                    p.version,
                    open.len(),
                    p.cves.len()
                );
                comp.push(evidence(file, None, &text));
            }
        }
        node.name = name;
        if !comp.is_empty() {
            node.evidence.insert("_component".into(), comp);
        }
        if let Some(r) = rule.get("review").filter(|r| truthy(r)) {
            node.review.insert("_component".into(), r.clone());
        }
        for q in &def.questions {
            let mut missing = Vec::new();
            let mut chosen = None;
            for r in rule["answers"][&q.id].as_array().into_iter().flatten() {
                if r.get("if").is_none() {
                    chosen = Some((r, Vec::new()));
                    break;
                }
                let res = f.eval(&r["if"])?;
                match res.v {
                    Some(true) => {
                        chosen = Some((r, res.ev));
                        break;
                    }
                    None => missing.extend(res.miss),
                    Some(false) => {}
                }
            }
            let Some((r, ev)) = chosen else {
                node.answers.insert(q.id.clone(), q.default.clone());
                node.review
                    .insert(q.id.clone(), "no scanner rule for this question".into());
                continue;
            };
            node.answers.insert(q.id.clone(), r["value"].clone());
            if !ev.is_empty() {
                node.evidence.insert(q.id.clone(), ev);
            }
            dedup(&mut missing);
            let mut why: Vec<String> = r["review"]
                .as_str()
                .map(str::to_owned)
                .into_iter()
                .collect();
            if !missing.is_empty() {
                why.push(format!("not checked, needs {}", missing.join(", ")));
            }
            if !why.is_empty() {
                node.review.insert(q.id.clone(), why.join("; ").into());
            }
        }
        by_rule.insert(id, nodes.len());
        nodes.push(node);
    }

    let mut flows = Vec::new();
    for fl in rules["flows"].as_array().into_iter().flatten() {
        let end = |k: &str| {
            fl[k]
                .as_str()
                .and_then(|r| by_rule.get(r))
                .map(|i| &nodes[*i])
        };
        let (Some(a), Some(b)) = (end("from"), end("to")) else {
            continue;
        };
        let encrypted = match &fl["encrypted"] {
            Value::String(s) => {
                let (rule, q) = s
                    .trim_start_matches("answer:")
                    .split_once('.')
                    .unwrap_or((s, ""));
                by_rule
                    .get(rule)
                    .is_some_and(|i| nodes[*i].answers.get(q).is_some_and(truthy))
            }
            v => truthy(v),
        };
        flows.push(Flow {
            id: 0,
            from: a.id,
            to: b.id,
            label: fl["label"].as_str().unwrap_or_default().to_owned(),
            encrypted,
            sensitive: truthy(&fl["sensitive"]),
        });
    }

    let first = |names: &[&str]| {
        names
            .iter()
            .map(|n| f.var(n))
            .find(|v| !v.is_empty())
            .map(str::to_owned)
    };
    let image = first(&["IMAGE_BASENAME", "PN"])
        .or_else(|| inputs.image.clone())
        .or_else(|| {
            notes
                .sboms
                .iter()
                .find(|s| !s.subject.is_empty())
                .map(|s| s.subject.clone())
        })
        .unwrap_or_else(|| "Yocto image".into());
    let machine = f.var("MACHINE");
    let distro = [f.var("DISTRO"), f.var("DISTRO_VERSION")]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    notes.cve_open = notes.sboms.iter().map(|s| s.open).sum();
    notes.packages = f.pkgs.list.len();
    notes.variables = f.vars.as_ref().map_or(0, BTreeMap::len);
    let used = if notes.used.is_empty() {
        "nothing".into()
    } else {
        notes.used.join(", ")
    };
    let mut desc = vec![
        format!(
            "{image}{}{}.",
            if machine.is_empty() {
                String::new()
            } else {
                format!(" for {machine}")
            },
            if distro.is_empty() {
                String::new()
            } else {
                format!(", {distro}")
            }
        ),
        format!("Generated by emb3d-wb scan from: {used}."),
    ];
    if !notes.sboms.is_empty() {
        let list: Vec<String> = notes
            .sboms
            .iter()
            .map(|s| {
                format!(
                    "{} ({} components, {} vulnerabilities, {} open)",
                    s.file, s.components, s.vulnerabilities, s.open
                )
            })
            .collect();
        desc.push(format!("SBOMs: {}.", list.join("; ")));
    }
    desc.push("Product applications and data flows beyond the defaults are not detected; add them in the Workbench.".into());
    let revision = first(&["BUILDNAME", "DATETIME"]).unwrap_or_default();
    let mut p = Project {
        name: if machine.is_empty() {
            image.clone()
        } else {
            format!("{image} ({machine})")
        },
        meta: Meta {
            description: desc.join(" "),
            ..Default::default()
        },
        nodes: Some(nodes),
        flows: Some(flows),
        ..Default::default()
    };
    p.extra.insert(
        "generator".into(),
        json!({"tool": "emb3d-wb scan", "source": image, "revision": revision, "date": today}),
    );
    Ok((p, notes))
}

/// Removes repeats, keeping the first of each.
fn dedup(v: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|x| seen.insert(x.clone()));
}

/// The inputs of one image in a Yocto deploy directory
/// (`tmp/deploy/images/<machine>`).
pub fn from_deploy_dir(dir: &Path, image: Option<&str>) -> Result<Inputs, String> {
    let mut files: Vec<String> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .filter(|e| e.path().is_file() || e.path().is_symlink())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    let re = |r: &str| Regex::new(r).expect("valid");
    let (stamp, suffix) = (re(r"-\d{14}"), re(r"(\.rootfs)?\.manifest$"));
    let mut images: Vec<String> = files
        .iter()
        .filter(|f| f.ends_with(".manifest") && !f.contains(".spdx") && !f.contains(".sdk"))
        .map(|f| {
            let name = suffix.replace(f, "");
            re(r"-\d{14}$").replace(&name, "").into_owned()
        })
        .collect();
    dedup(&mut images);
    let image = match image {
        Some(i) => Some(i.to_owned()),
        None if images.len() > 1 => {
            return Err(format!(
                "Several images in {}: {}. Pick one with --image.",
                dir.display(),
                images.join(", ")
            ))
        }
        None => images.into_iter().next(),
    };
    let ours = |f: &str| image.as_deref().is_none_or(|i| f.starts_with(i));
    // The stable symlink name (no timestamp) first.
    let pick = |pattern: &str| {
        let r = re(pattern);
        let mut c: Vec<&String> = files.iter().filter(|f| r.is_match(f) && ours(f)).collect();
        c.sort_by_key(|f| stamp.is_match(f));
        c.first().map(|f| dir.join(f))
    };
    let (sbom, rootfs_of_other) = (
        re(r"(?i)(\.cdx\.json|cyclonedx.*\.json|\.bom\.json)$"),
        re(r"^[\w.-]+-\w+\.rootfs"),
    );
    Ok(Inputs {
        manifest: pick(r"\.manifest$"),
        testdata: pick(r"\.testdata\.json$"),
        rootfs: pick(r"\.tar(\.(gz|bz2|xz|zst))?$"),
        sboms: files
            .iter()
            .filter(|f| sbom.is_match(f) && (ours(f) || !rootfs_of_other.is_match(f)))
            .map(|f| dir.join(f))
            .collect(),
        image,
        ..Default::default()
    })
}

#[cfg(test)]
#[path = "../../tests/unit/cli/yocto.rs"]
mod tests;

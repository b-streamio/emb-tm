//! Rules, roll-ups, validation, TM-BOM export and report markup.
//!
//! 1. A component's EMB3D properties = its type's `base` PIDs + the PIDs of
//!    its answers; a sub-property implies its parent.
//! 2. A device page without an update agent gives its OS (or SoC) PID-26.
//! 3. A threat applies to a component sharing at least one property with it;
//!    custom block types add their own threats.
//! 4. A threat handled with countermeasures is Mitigated when one is
//!    implemented, Not applicable when all are, Open otherwise; the threat
//!    can also be declared not applicable or accepted, with a justification.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

use serde_json::{json, Value};

use crate::{
    model::{num_cmp, Library, Node, Page, Project, Question, TypeDef, EXT_KEY},
    stix::{Emb3d, Mitigation, Threat},
};

pub const TMBOM_SCHEMA: &str = "https://github.com/OWASP/www-project-threat-model-library/blob/v1.0.2/threat-model.schema.json";

/// Countermeasure statuses: `(value, label)`.
pub const CM_STATUS: [(&str, &str); 5] = [
    ("recommended", "Recommended"),
    ("required", "Required"),
    ("implemented", "Implemented"),
    ("rejected", "Rejected"),
    ("na", "Not applicable"),
];

/// Statuses that need a justification.
pub const NEEDS_WHY: [&str; 2] = ["na", "rejected"];

pub fn cm_label(status: &str) -> &str {
    CM_STATUS
        .iter()
        .find(|(v, _)| *v == status)
        .map_or(status, |(_, l)| l)
}

/// EMB3D evidence level: `(rank, label)`; lower ranks have more evidence.
pub fn maturity(m: &str) -> (u8, &str) {
    match m {
        "observed adversarial behavior" => (0, "Observed in attacks"),
        "observed adversarial technique" => (1, "Observed technique"),
        "known exploitable weakness" => (2, "Known weakness"),
        "proof of concept" => (3, "Proof of concept"),
        "custom" => (4, "Custom threat"),
        other => (9, other),
    }
}

pub fn mit_rank(m: &str) -> u8 {
    match m {
        "foundational" => 0,
        "intermediate" => 1,
        "leading" => 2,
        "custom" => 3,
        _ => 9,
    }
}

/// HTML escaping for every value written into markup.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out += "&amp;",
            '<' => out += "&lt;",
            '>' => out += "&gt;",
            '"' => out += "&quot;",
            '\'' => out += "&#39;",
            c => out.push(c),
        }
    }
    out
}

/// `pre`, `s`, `post` joined, or `""` when `s` is empty.
pub fn around(pre: &str, s: &str, post: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        format!("{pre}{s}{post}")
    }
}

/// Lower-case, runs of anything but `[0-9a-z-]` become `-`, trimmed.
pub fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() || c == '-' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}

/// CSS class of a library group, e.g. `k-System`.
pub fn group_class(g: &str) -> String {
    format!("k-{}", g.split(' ').next().unwrap_or_default())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Open,
    Mitigated,
    Accepted,
    NotApplicable,
}

impl State {
    pub fn key(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Mitigated => "Mitigated",
            Self::Accepted => "Accepted",
            Self::NotApplicable => "NA",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::NotApplicable => "Not applicable",
            s => s.key(),
        }
    }
}

/// Why a component has a property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Base,
    Answer,
    Parent,
    /// PID-26: the device has no update agent.
    Rule,
}

pub struct Hit<'m> {
    pub tid: String,
    pub t: &'m Threat,
    /// Properties (or `custom`) that make it apply.
    pub via: Vec<String>,
}

pub struct Row<'m, 'p> {
    pub node: &'p Node,
    pub page: &'p Page,
    pub hit: Hit<'m>,
    pub state: State,
}

pub struct CmRow<'m, 'p> {
    pub node: &'p Node,
    pub page: &'p Page,
    pub mid: String,
    pub m: &'m Mitigation,
    pub tids: Vec<String>,
    pub status: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rollup {
    pub threats: usize,
    pub open: usize,
    pub review: usize,
}

/// Threat counts of every component and every page, computed once per
/// project change and read by the board, the page list and the report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Counts {
    pub nodes: BTreeMap<u64, Rollup>,
    /// A page includes the device pages inside it, each page once.
    pub pages: BTreeMap<String, Rollup>,
}

impl Counts {
    pub fn node(&self, id: u64) -> Rollup {
        self.nodes.get(&id).copied().unwrap_or_default()
    }

    pub fn page(&self, id: &str) -> Rollup {
        self.pages.get(id).copied().unwrap_or_default()
    }

    /// Open threats of the whole model.
    pub fn open(&self) -> usize {
        self.nodes.values().map(|r| r.open).sum()
    }

    fn rollup(&self, p: &Project, page: &str, seen: &mut BTreeSet<String>) -> Rollup {
        let mut out = Rollup::default();
        if !seen.insert(page.to_owned()) {
            return out;
        }
        for n in p.page(page).map_or(&[][..], |pg| &pg.nodes[..]) {
            let r = match &n.page {
                Some(inner) if n.is_device() => self.rollup(p, inner, seen),
                _ => self.node(n.id),
            };
            out.threats += r.threats;
            out.open += r.open;
            out.review += r.review;
        }
        out
    }
}

pub struct ReviewItem<'p> {
    pub node: &'p Node,
    pub question: String,
    pub reason: String,
}

#[derive(Debug, Default, PartialEq)]
pub struct Summary {
    pub pages: usize,
    pub devices: usize,
    pub components: usize,
    pub flows: usize,
    pub threats: usize,
    pub open: usize,
    pub mitigated: usize,
    pub not_applicable: usize,
    pub accepted: usize,
    /// Open threats per evidence rank 0..=4.
    pub open_by_evidence: [usize; 5],
    pub countermeasures: usize,
    pub implemented: usize,
    pub missing_justifications: usize,
    pub needs_review: usize,
}

/// Which parts of the report to include.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReportOpts {
    pub diagram: bool,
    pub mitigated: bool,
    pub closed: bool,
    pub empty: bool,
    pub props: bool,
    pub fulltext: bool,
}

impl Default for ReportOpts {
    fn default() -> Self {
        Self {
            diagram: true,
            mitigated: true,
            closed: true,
            empty: false,
            props: true,
            fulltext: false,
        }
    }
}

pub fn answer<'a>(node: &'a Node, q: &'a Question) -> &'a Value {
    node.answers.get(&q.id).unwrap_or(&q.default)
}

pub fn answer_label(node: &Node, q: &Question) -> String {
    let a = answer(node, q);
    if q.kind == "bool" {
        return if a.as_bool().unwrap_or(false) {
            "Yes"
        } else {
            "No"
        }
        .into();
    }
    let s = a.as_str().unwrap_or_default();
    q.options
        .iter()
        .find(|o| o.value == s)
        .map_or_else(|| s.to_owned(), |o| o.label.clone())
}

pub fn cm_status<'n>(node: &'n Node, mid: &str) -> &'n str {
    node.cm.get(mid).map_or("recommended", String::as_str)
}

pub fn why<'n>(node: &'n Node, key: &str) -> &'n str {
    node.why.get(key).map_or("", |s| s.trim())
}

pub fn missing_why(node: &Node, mid: &str) -> bool {
    NEEDS_WHY.contains(&cm_status(node, mid)) && why(node, mid).is_empty()
}

/// Threat-level decision: `""` (countermeasures), `"na"` or `"accept"`.
pub fn decision<'n>(node: &'n Node, tid: &str) -> &'n str {
    match node.accepted.get(tid) {
        Some(Value::Bool(true)) => "accept",
        Some(Value::String(s)) => s,
        _ => "",
    }
}

pub fn missing_accept_why(node: &Node, tid: &str) -> bool {
    !decision(node, tid).is_empty() && why(node, &format!("accept:{tid}")).is_empty()
}

/// The EMB3D catalogue and component library, bound to one project's custom
/// types. Cheap to build: library types are borrowed, not copied.
pub struct Model<'a> {
    pub e: &'a Emb3d,
    pub lib: &'a Library,
    pub types: BTreeMap<String, Cow<'a, TypeDef>>,
    threats: BTreeMap<String, Threat>,
    mits: BTreeMap<String, Mitigation>,
}

impl<'a> Model<'a> {
    pub fn new(e: &'a Emb3d, lib: &'a Library, p: &Project) -> Self {
        let mut types: BTreeMap<String, Cow<TypeDef>> = lib
            .components
            .iter()
            .map(|c| (c.kind.clone(), Cow::Borrowed(c)))
            .collect();
        let (mut threats, mut mits) = (BTreeMap::new(), BTreeMap::new());
        for c in &p.custom_types {
            let tag: String = if c.tag.is_empty() {
                "CUS".into()
            } else {
                c.tag.chars().take(4).collect()
            };
            types.insert(
                c.kind.clone(),
                Cow::Owned(TypeDef {
                    kind: c.kind.clone(),
                    name: c.name.clone(),
                    group: if c.group.is_empty() {
                        "Custom".into()
                    } else {
                        c.group.clone()
                    },
                    tag,
                    hint: if c.hint.is_empty() {
                        "Custom block".into()
                    } else {
                        c.hint.clone()
                    },
                    base: c.base.clone(),
                    questions: c.questions.clone(),
                    external: c.external,
                    custom: true,
                    threats: c.threats.clone(),
                    ..Default::default()
                }),
            );
            for t in &c.threats {
                threats.insert(
                    t.id.clone(),
                    Threat {
                        name: t.name.clone(),
                        cat: "custom".into(),
                        maturity: "custom".into(),
                        desc: t.desc.clone(),
                        text: vec![t.desc.clone()],
                        mids: t.cms.iter().map(|m| m.id.clone()).collect(),
                        custom: true,
                        ..Default::default()
                    },
                );
                for m in &t.cms {
                    mits.insert(
                        m.id.clone(),
                        Mitigation {
                            name: m.name.clone(),
                            maturity: "custom".into(),
                            desc: m.desc.clone(),
                            text: vec![m.desc.clone()],
                            custom: true,
                            ..Default::default()
                        },
                    );
                }
            }
        }
        Self {
            e,
            lib,
            types,
            threats,
            mits,
        }
    }

    pub fn threat(&self, tid: &str) -> Option<&Threat> {
        self.e.threats.get(tid).or_else(|| self.threats.get(tid))
    }

    pub fn mitigation(&self, mid: &str) -> Option<&Mitigation> {
        self.e.mitigations.get(mid).or_else(|| self.mits.get(mid))
    }

    pub fn type_of(&self, n: &Node) -> Option<&TypeDef> {
        self.types.get(&n.kind).map(|t| &**t)
    }

    pub fn is_external(&self, n: &Node) -> bool {
        self.type_of(n).is_some_and(|t| t.external)
    }

    pub fn has_threats(&self, n: &Node) -> bool {
        !self.is_external(n) && !n.is_device()
    }

    fn property_name(&self, pid: &str) -> &str {
        self.e.properties.get(pid).map_or("", |p| p.name.as_str())
    }

    /// EMB3D properties of a component and why it has each.
    pub fn node_pids(&self, p: &Project, node: &Node) -> BTreeMap<String, Source> {
        let mut out = BTreeMap::new();
        let Some(def) = self.type_of(node).filter(|_| !node.is_device()) else {
            return out;
        };
        for pid in &def.base {
            out.insert(pid.clone(), Source::Base);
        }
        for q in &def.questions {
            let a = answer(node, q);
            let pids = match q.kind.as_str() {
                "bool" if a.as_bool() == Some(true) => &q.pids[..],
                "choice" => q
                    .options
                    .iter()
                    .find(|o| a.as_str() == Some(&o.value))
                    .map_or(&[][..], |o| &o.pids[..]),
                _ => &[],
            };
            for pid in pids {
                out.entry(pid.clone()).or_insert(Source::Answer);
            }
        }
        let peers = p.page_of(node.id).map_or(&[][..], |pg| &pg.nodes[..]);
        if !peers.iter().any(|n| n.kind == "update") {
            let host = peers
                .iter()
                .find(|n| n.kind == "os")
                .or_else(|| peers.iter().find(|n| n.kind == "soc"));
            if host.is_some_and(|h| h.id == node.id) {
                out.insert("PID-26".into(), Source::Rule);
            }
        }
        out.retain(|pid, _| self.e.properties.contains_key(pid)); // not defined in this EMB3D version
        for pid in out.keys().cloned().collect::<Vec<_>>() {
            let mut parent = self.e.properties[&pid].parent.clone();
            while let Some(par) = parent {
                out.entry(par.clone()).or_insert(Source::Parent);
                parent = self.e.properties.get(&par).and_then(|p| p.parent.clone());
            }
        }
        out
    }

    pub fn node_threats(&self, p: &Project, node: &Node) -> Vec<Hit<'_>> {
        if !self.has_threats(node) {
            return Vec::new();
        }
        let pids = self.node_pids(p, node);
        let mut res: Vec<Hit> = self
            .e
            .threats
            .iter()
            .filter_map(|(tid, t)| {
                let via: Vec<String> = t
                    .pids
                    .iter()
                    .filter(|p| pids.contains_key(*p))
                    .cloned()
                    .collect();
                (!via.is_empty()).then(|| Hit {
                    tid: tid.clone(),
                    t,
                    via,
                })
            })
            .collect();
        for ct in self.type_of(node).map_or(&[][..], |d| &d.threats[..]) {
            if let Some(t) = self.threats.get(&ct.id) {
                res.push(Hit {
                    tid: ct.id.clone(),
                    t,
                    via: vec!["custom".into()],
                });
            }
        }
        res.sort_by(|a, b| {
            maturity(&a.t.maturity)
                .0
                .cmp(&maturity(&b.t.maturity).0)
                .then_with(|| num_cmp(&a.tid, &b.tid))
        });
        res
    }

    pub fn threat_state(&self, node: &Node, tid: &str) -> State {
        match decision(node, tid) {
            "accept" => return State::Accepted,
            "na" => return State::NotApplicable,
            _ => {}
        }
        let mids = self.threat(tid).map_or(&[][..], |t| &t.mids[..]);
        if mids.iter().any(|m| cm_status(node, m) == "implemented") {
            State::Mitigated
        } else if !mids.is_empty() && mids.iter().all(|m| cm_status(node, m) == "na") {
            State::NotApplicable
        } else {
            State::Open
        }
    }

    pub fn all_rows<'p>(&self, p: &'p Project) -> Vec<Row<'_, 'p>> {
        let mut rows = Vec::new();
        for page in &p.pages {
            for node in &page.nodes {
                for hit in self.node_threats(p, node) {
                    let state = self.threat_state(node, &hit.tid);
                    rows.push(Row {
                        node,
                        page,
                        hit,
                        state,
                    });
                }
            }
        }
        rows
    }

    pub fn cm_rows<'p>(&self, p: &'p Project) -> Vec<CmRow<'_, 'p>> {
        let mut rows = Vec::new();
        for page in &p.pages {
            for node in &page.nodes {
                let mut by_mid: BTreeMap<String, Vec<String>> = BTreeMap::new();
                for hit in self.node_threats(p, node) {
                    for m in &hit.t.mids {
                        by_mid.entry(m.clone()).or_default().push(hit.tid.clone());
                    }
                }
                for (mid, tids) in by_mid {
                    if let Some(m) = self.mitigation(&mid) {
                        let status = cm_status(node, &mid).to_owned();
                        rows.push(CmRow {
                            node,
                            page,
                            mid,
                            m,
                            tids,
                            status,
                        });
                    }
                }
            }
        }
        rows.sort_by(|a, b| {
            mit_rank(&a.m.maturity)
                .cmp(&mit_rank(&b.m.maturity))
                .then_with(|| num_cmp(&a.mid, &b.mid))
                .then(a.node.id.cmp(&b.node.id))
        });
        rows
    }

    /// Threat counts of every component and page.
    pub fn counts(&self, p: &Project) -> Counts {
        let mut c = Counts::default();
        for n in p.nodes().filter(|n| !n.is_device()) {
            let hits = self.node_threats(p, n);
            let open = hits
                .iter()
                .filter(|h| self.threat_state(n, &h.tid) == State::Open)
                .count();
            let review = n.reviews().count();
            c.nodes.insert(
                n.id,
                Rollup {
                    threats: hits.len(),
                    open,
                    review,
                },
            );
        }
        for pg in &p.pages {
            let r = c.rollup(p, &pg.id, &mut BTreeSet::new());
            c.pages.insert(pg.id.clone(), r);
        }
        c
    }

    /// Answers flagged for a human look (e.g. by the Yocto scanner).
    pub fn review_items<'p>(&self, p: &'p Project) -> Vec<ReviewItem<'p>> {
        let mut out = Vec::new();
        for node in p.nodes() {
            let Some(def) = self.type_of(node) else {
                continue;
            };
            // In questionnaire order, the component itself first.
            let mut reviews: Vec<_> = node.reviews().collect();
            reviews.sort_by_key(|(qid, _)| {
                match def.questions.iter().position(|q| &q.id == *qid) {
                    Some(i) => i + 1,
                    None if *qid == "_component" => 0,
                    None => usize::MAX,
                }
            });
            for (qid, reason) in reviews {
                let question = match def.questions.iter().find(|q| &q.id == qid) {
                    Some(q) => q.text.clone(),
                    None if qid == "_component" => "Component".into(),
                    None => qid.clone(),
                };
                out.push(ReviewItem {
                    node,
                    question,
                    reason,
                });
            }
        }
        out
    }

    pub fn summary(&self, p: &Project) -> Summary {
        let rows = self.all_rows(p);
        let cms = self.cm_rows(p);
        let count = |s: State| rows.iter().filter(|r| r.state == s).count();
        let mut open_by_evidence = [0; 5];
        for r in rows.iter().filter(|r| r.state == State::Open) {
            if let Some(n) = open_by_evidence.get_mut(usize::from(maturity(&r.hit.t.maturity).0)) {
                *n += 1;
            }
        }
        Summary {
            pages: p.pages.len(),
            devices: p.nodes().filter(|n| n.is_device()).count(),
            components: p.nodes().filter(|n| self.has_threats(n)).count(),
            flows: p.pages.iter().map(|pg| pg.flows.len()).sum(),
            threats: rows.len(),
            open: count(State::Open),
            mitigated: count(State::Mitigated),
            not_applicable: count(State::NotApplicable),
            accepted: count(State::Accepted),
            open_by_evidence,
            countermeasures: cms.len(),
            implemented: cms.iter().filter(|r| r.status == "implemented").count(),
            missing_justifications: cms.iter().filter(|r| missing_why(r.node, &r.mid)).count()
                + rows
                    .iter()
                    .filter(|r| missing_accept_why(r.node, &r.hit.tid))
                    .count(),
            needs_review: self.review_items(p).len(),
        }
    }

    /// Structural checks of a (migrated) project: `(errors, warnings)`.
    pub fn validate(&self, p: &Project) -> (Vec<String>, Vec<String>) {
        let (mut errors, mut warnings) = (Vec::new(), Vec::new());
        let mut page_ids = BTreeSet::new();
        for (i, pg) in p.pages.iter().enumerate() {
            if pg.id.is_empty() {
                errors.push(format!("pages[{i}]: missing id"));
            } else if !page_ids.insert(pg.id.as_str()) {
                errors.push(format!("pages[{i}]: duplicate page id {}", pg.id));
            }
        }
        for c in &p.custom_types {
            let mut ids = BTreeSet::new();
            for q in &c.questions {
                let at = format!("customTypes ({}): question \"{}\"", c.kind, q.id);
                if q.id.is_empty() || !ids.insert(q.id.as_str()) {
                    errors.push(format!("{at}: missing or repeated id"));
                }
                match q.kind.as_str() {
                    "bool" if !q.default.is_boolean() => {
                        errors.push(format!("{at}: default must be true or false"));
                    }
                    "choice"
                        if !q
                            .options
                            .iter()
                            .any(|o| q.default.as_str() == Some(&o.value)) =>
                    {
                        errors.push(format!("{at}: default must be one of its options"));
                    }
                    "bool" | "choice" => {}
                    _ => errors.push(format!("{at}: kind must be bool or choice")),
                }
            }
        }
        if !errors.is_empty() {
            return (errors, warnings);
        }
        let multi = p.pages.len() > 1;
        let mut ids = BTreeSet::new();
        for pg in &p.pages {
            let prefix = if multi {
                format!("{}: ", pg.name)
            } else {
                String::new()
            };
            for (i, n) in pg.nodes.iter().enumerate() {
                let label = if n.name.is_empty() { &n.kind } else { &n.name };
                let at = format!("{prefix}nodes[{i}] ({label})");
                if !ids.insert(n.id) {
                    errors.push(format!("{at}: duplicate id {}", n.id));
                }
                let Some(def) = self.type_of(n) else {
                    errors.push(format!(
                        "{at}: unknown type \"{}\". Run \"emb3d-wb library\" for the list.",
                        n.kind
                    ));
                    continue;
                };
                if n.is_device() {
                    if !n.page.as_deref().is_some_and(|id| page_ids.contains(id)) {
                        errors.push(format!(
                            "{at}: device page \"{}\" does not exist",
                            n.page.as_deref().unwrap_or_default()
                        ));
                    }
                    if n.qty == Some(0) {
                        errors.push(format!("{at}: qty must be a positive integer"));
                    }
                    continue;
                }
                for (qid, v) in &n.answers {
                    let Some(q) = def.questions.iter().find(|q| &q.id == qid) else {
                        errors.push(format!(
                            "{at}: unknown question \"{qid}\" for type {}",
                            n.kind
                        ));
                        continue;
                    };
                    if q.kind == "bool" && !v.is_boolean() {
                        errors.push(format!("{at}: \"{qid}\" must be true or false"));
                    }
                    if q.kind == "choice" && !q.options.iter().any(|o| v.as_str() == Some(&o.value))
                    {
                        let values: Vec<_> = q.options.iter().map(|o| o.value.as_str()).collect();
                        errors.push(format!(
                            "{at}: \"{qid}\" must be one of {}",
                            values.join(", ")
                        ));
                    }
                }
                for q in def
                    .questions
                    .iter()
                    .filter(|q| !n.answers.contains_key(&q.id))
                {
                    warnings.push(format!(
                        "{at}: \"{}\" not answered, default ({}) used",
                        q.id, q.default
                    ));
                }
                for qid in n.evidence.keys() {
                    if qid != "_component" && !def.questions.iter().any(|q| &q.id == qid) {
                        warnings.push(format!("{at}: evidence for unknown question \"{qid}\""));
                    }
                }
            }
            let here: BTreeSet<u64> = pg.nodes.iter().map(|n| n.id).collect();
            for (i, f) in pg.flows.iter().enumerate() {
                if !here.contains(&f.from) || !here.contains(&f.to) {
                    errors.push(format!(
                        "{prefix}flows[{i}]: from/to must reference nodes on the same page"
                    ));
                }
            }
        }
        // A device must not contain itself, directly or through nested devices.
        fn visit(p: &Project, id: &str, stack: &mut Vec<String>, errors: &mut Vec<String>) {
            if stack.iter().any(|s| s == id) {
                let names: Vec<String> = stack
                    .iter()
                    .chain([&id.to_owned()])
                    .map(|x| p.page(x).map_or(x.clone(), |pg| pg.name.clone()))
                    .collect();
                errors.push(format!("device pages form a loop: {}", names.join(" > ")));
                return;
            }
            let Some(pg) = p.page(id) else { return };
            stack.push(id.to_owned());
            for n in pg.nodes.iter().filter(|n| n.is_device()) {
                visit(p, n.page.as_deref().unwrap_or_default(), stack, errors);
            }
            stack.pop();
        }
        visit(p, &p.root, &mut Vec::new(), &mut errors);
        (errors, warnings)
    }

    /// Places nodes without a position: one column per library group.
    pub fn layout(&self, p: &mut Project) {
        for pg in &mut p.pages {
            let mut cols: Vec<(String, f64, f64)> = self
                .lib
                .groups
                .iter()
                .enumerate()
                .map(|(i, g)| (g.clone(), 60.0 + i as f64 * 240.0, 60.0))
                .collect();
            for n in pg.nodes.iter_mut().filter(|n| n.x.is_nan() || n.y.is_nan()) {
                let g = self
                    .types
                    .get(&n.kind)
                    .map_or_else(|| self.lib.groups[0].clone(), |t| t.group.clone());
                let i = cols.iter().position(|c| c.0 == g).unwrap_or_else(|| {
                    cols.push((g, 60.0 + cols.len() as f64 * 240.0, 60.0));
                    cols.len() - 1
                });
                n.x = cols[i].1;
                n.y = cols[i].2;
                cols[i].2 += if n.is_device() { 160.0 } else { 130.0 };
            }
        }
    }

    /// Migrates v1 files and fills in what an externally written project may omit.
    pub fn normalize(&self, p: &mut Project) {
        p.migrate();
        let mut fid = 1;
        for (i, pg) in p.pages.iter_mut().enumerate() {
            if pg.id.is_empty() {
                pg.id = format!("p{}", i + 1);
            }
            if pg.name.is_empty() {
                pg.name = format!("Page {}", i + 1);
            }
            for n in &mut pg.nodes {
                if n.name.is_empty() {
                    n.name = self
                        .types
                        .get(&n.kind)
                        .map_or_else(|| n.kind.clone(), |t| t.name.clone());
                }
                if n.is_device() && n.qty.is_none() {
                    n.qty = Some(1);
                }
            }
            for f in &mut pg.flows {
                if f.label.is_empty() {
                    f.label = "data flow".into();
                }
                fid = fid.max(f.id + 1);
            }
        }
        for f in p
            .pages
            .iter_mut()
            .flat_map(|pg| &mut pg.flows)
            .filter(|f| f.id == 0)
        {
            f.id = fid;
            fid += 1;
        }
        p.seq = p
            .nodes()
            .map(|n| n.id + 1)
            .chain([p.seq, 1])
            .max()
            .unwrap_or(1);
        p.flow_seq = p
            .pages
            .iter()
            .flat_map(|pg| &pg.flows)
            .map(|f| f.id + 1)
            .chain([p.flow_seq, 1])
            .max()
            .unwrap_or(1);
        self.layout(p);
    }

    /// OWASP Threat Model Library (TM-BOM) v1.0.2 document; embeds the project.
    pub fn to_tmbom(&self, p: &Project, today: &str) -> Value {
        const ZONES: [(&str, &str, &str); 7] = [
            ("System", "system", "System"),
            ("Hardware", "hardware", "Hardware"),
            ("System software", "system-software", "System software"),
            ("Application", "application", "Application"),
            ("Networking", "networking", "Networking"),
            ("External", "external", "External"),
            ("Custom", "custom", "Custom"),
        ];
        let zone = |n: &Node| {
            let g = self.type_of(n).map_or("Custom", |t| t.group.as_str());
            ZONES.iter().find(|z| z.0 == g).unwrap_or(&ZONES[6]).1
        };
        let sym = |n: &Node| format!("n{}-{}", n.id, slug(&n.kind));
        let nodes: Vec<&Node> = p.nodes().collect();
        let used: BTreeSet<&str> = nodes.iter().map(|n| zone(n)).collect();
        let mut trust_zones: Vec<Value> = ZONES
            .iter()
            .filter(|z| used.contains(z.1))
            .map(|&(_, z, t)| {
                let desc = match z {
                    "system" => "Devices of the solution".to_owned(),
                    "external" => format!("{t} parts of the devices (outside the devices)"),
                    _ => format!("{t} parts of the devices"),
                };
                json!({"symbolic_name": z, "title": t, "description": desc})
            })
            .collect();
        if trust_zones.is_empty() {
            trust_zones.push(
                json!({"symbolic_name": "device", "title": "Device", "description": "The device"}),
            );
        }
        let page_name = |id: &str| p.page(id).map_or(id.to_owned(), |pg| pg.name.clone());
        let actors: Vec<Value> = nodes
            .iter()
            .filter(|n| self.is_external(n))
            .map(|n| json!({
                "symbolic_name": sym(n), "title": n.name, "description": self.types[&n.kind].hint,
                "type": if n.kind == "person" { "user" } else { "third_party" }, "trust_zone": "external",
            }))
            .collect();
        let components: Vec<Value> = nodes
            .iter()
            .filter(|n| !self.is_external(n))
            .map(|n| {
                let (title, description) = if n.is_device() {
                    let units = if n.qty() > 1 { format!(", {} identical units", n.qty()) } else { String::new() };
                    let title = if n.qty() > 1 { format!("{} (x{})", n.name, n.qty()) } else { n.name.clone() };
                    (title, format!("Device{units}. Detailed design: page \"{}\".", page_name(n.page.as_deref().unwrap_or_default())))
                } else {
                    let t = self.type_of(n);
                    let mut pids: Vec<String> = self.node_pids(p, n).into_keys().collect();
                    pids.sort_by(|a, b| num_cmp(a, b));
                    let pids = if pids.is_empty() { "none".into() } else { pids.join(", ") };
                    let custom = if t.is_some_and(|t| t.custom) { " (custom block)" } else { "" };
                    (n.name.clone(), format!("{}{custom}. EMB3D properties: {pids}", t.map_or("", |t| t.name.as_str())))
                };
                let mut c = json!({"symbolic_name": sym(n), "title": title, "description": description, "trust_zone": zone(n)});
                let parent = p.page_of(n.id).and_then(|pg| p.parents_of(&pg.id).first().map(|d| sym(d)));
                if let Some(ps) = parent.filter(|ps| *ps != sym(n)) {
                    c["parent_component"] = ps.into();
                }
                c
            })
            .collect();
        let reference = |n: &Node| json!({"type": if self.is_external(n) { "actor" } else { "component" }, "object": sym(n)});
        let data_flows: Vec<Value> = p
            .pages
            .iter()
            .flat_map(|pg| &pg.flows)
            .filter_map(|f| {
                let (a, b) = (p.node(f.from)?, p.node(f.to)?);
                Some(json!({
                    "symbolic_name": format!("f{}", f.id), "title": if f.label.is_empty() { "data flow" } else { &f.label },
                    "description": format!("{} to {}", a.name, b.name), "source": reference(a), "destination": reference(b),
                    "has_sensitive_data": f.sensitive, "encrypted": f.encrypted,
                }))
            })
            .collect();
        let (mut threats, mut controls, mut assumptions) = (Vec::new(), Vec::new(), Vec::new());
        for n in nodes.iter().filter(|n| self.has_threats(n)) {
            // First-seen order, like the JavaScript engine.
            let mut by_mid: Vec<(String, Vec<String>)> = Vec::new();
            for Hit { tid, t, via } in self.node_threats(p, n) {
                let id = format!("{}-{}", slug(&tid), sym(n));
                let (description, event) = if t.custom {
                    let d = if t.desc.is_empty() { &t.name } else { &t.desc };
                    (
                        format!("{d}\n\nCustom threat defined in the project."),
                        format!(
                            "Custom threat of block type \"{}\"",
                            self.types[&n.kind].name
                        ),
                    )
                } else {
                    let via: Vec<String> = via
                        .iter()
                        .map(|pid| format!("{pid} {}", self.property_name(pid)))
                        .collect();
                    (
                        format!("{}\n\nEMB3D evidence: {}.", t.desc, t.maturity),
                        format!("Applies because the component has: {}", via.join("; ")),
                    )
                };
                let mut th = json!({
                    "symbolic_name": id, "title": format!("{tid}: {}", t.name), "description": description,
                    "components_affected": [sym(n)],
                    "threat_persona": if t.cat == "hardware" { "physical-adversary" } else { "remote-adversary" },
                    "event": event, "sources": ["adversary"],
                });
                if !t.cwes.is_empty() {
                    th["weaknesses"] = t
                        .cwes
                        .iter()
                        .map(|(i, title)| json!({"cwe_id": i, "cwe_title": title}))
                        .collect();
                }
                threats.push(th);
                let d = decision(n, &tid);
                if !d.is_empty() {
                    let head = if d == "na" {
                        format!("{tid} ({}) does not apply to {}.", t.name, n.name)
                    } else {
                        format!("Risk of {tid} ({}) accepted for {}.", t.name, n.name)
                    };
                    let w = why(n, &format!("accept:{tid}"));
                    let tail = if w.is_empty() {
                        " No justification given.".into()
                    } else {
                        format!(" Justification: {w}")
                    };
                    assumptions.push(json!({"description": head + &tail, "topics": [id], "validity": "confirmed"}));
                }
                for m in &t.mids {
                    match by_mid.iter_mut().find(|(k, _)| k == m) {
                        Some((_, tids)) => tids.push(id.clone()),
                        None => by_mid.push((m.clone(), vec![id.clone()])),
                    }
                }
            }
            for (mid, tids) in by_mid {
                let Some(m) = self.mitigation(&mid) else {
                    continue;
                };
                let st = cm_status(n, &mid);
                let mut d = format!(
                    "{}\n\n{}",
                    m.desc,
                    if m.custom {
                        "Custom countermeasure.".into()
                    } else {
                        format!("EMB3D level: {}.", m.maturity)
                    }
                );
                if !m.iec.is_empty() {
                    d += &format!("\nIEC 62443-4-2: {}", m.iec.join("; "));
                }
                d += &format!("\nWorkbench status: {}.", cm_label(st));
                if !why(n, &mid).is_empty() {
                    d += &format!("\nJustification: {}", why(n, &mid));
                }
                let status = match st {
                    "required" => "approved",
                    "implemented" => "active",
                    "rejected" | "na" => "wont_do",
                    _ => "suggested",
                };
                controls.push(json!({
                    "symbolic_name": format!("{}-{}", slug(&mid), sym(n)), "title": format!("{mid}: {}", m.name), "description": d,
                    "threats": tids, "status": status, "priority": if st == "required" { "high" } else { "none" },
                }));
            }
        }
        let description = if p.meta.description.is_empty() {
            format!(
                "Threat model of {}, built with EMB3D Workbench on MITRE EMB3D STIX {}.",
                p.name, self.e.version
            )
        } else {
            p.meta.description.clone()
        };
        let mut doc = json!({
            "$schema": TMBOM_SCHEMA,
            "version": "1.0",
            "scope": {
                "title": p.name, "description": description,
                "business_criticality": "moderate", "data_sensitivity": ["cred", "ip", "op"], "exposure": "external", "tier": "important",
            },
            "description": "Threats and countermeasures derived from MITRE EMB3D device properties (https://emb3d.mitre.org/).",
            "reviewed_at": today,
            "trust_zones": trust_zones, "trust_boundaries": [], "actors": actors, "components": components,
            "data_stores": [], "data_sets": [], "data_flows": data_flows,
            "threat_personas": [
                {"symbolic_name": "physical-adversary", "title": "Adversary with physical device access", "description": "Skilled attacker holding the device, able to probe buses, debug ports and side channels.", "is_person": true, "skill_level": "expert_engineer", "access_level": "anonymous", "malicious_intent": true, "applicability_to_org": "moderate"},
                {"symbolic_name": "remote-adversary", "title": "Remote or local software adversary", "description": "Attacker reaching the device over a network or through code running on it.", "is_person": true, "skill_level": "engineer", "access_level": "anonymous", "malicious_intent": true, "applicability_to_org": "high"},
            ],
            "threats": threats, "controls": controls,
            "extensions": { EXT_KEY: { "emb3d_version": self.e.version, "project": p } },
        });
        if !assumptions.is_empty() {
            doc["assumptions"] = assumptions.into();
        }
        doc
    }

    /// The diagram of a page as SVG (report and print).
    pub fn diagram_svg(&self, p: &Project, page: &Page) -> String {
        if page.nodes.is_empty() {
            return r#"<p class="muted">This page is empty.</p>"#.into();
        }
        let pad = 30.0;
        let min = |f: fn(&Node) -> f64| page.nodes.iter().map(f).fold(f64::INFINITY, f64::min);
        let max = |f: fn(&Node) -> f64| page.nodes.iter().map(f).fold(f64::NEG_INFINITY, f64::max);
        let (x0, y0) = (min(|n| n.x) - pad, min(|n| n.y) - pad);
        let (x1, y1) = (
            max(|n| n.x + n.size().0) + pad,
            max(|n| n.y + n.size().1) + pad,
        );
        let id = esc(&page.id);
        let mut out = format!(
            r#"<svg class="rdiagram" viewBox="{x0} {y0} {} {}" role="img" aria-label="{} diagram"><defs><marker id="rarr-{id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="rarrow"></path></marker></defs>"#,
            x1 - x0,
            y1 - y0,
            esc(&page.name)
        );
        for f in &page.flows {
            let (Some(a), Some(b)) = (
                page.nodes.iter().find(|n| n.id == f.from),
                page.nodes.iter().find(|n| n.id == f.to),
            ) else {
                continue;
            };
            let ((sx, sy), (qx, qy)) = (anchor(a, b), anchor(b, a));
            let plain = if f.encrypted { "" } else { " plain" };
            out += &format!(
                r#"<line class="redge{plain}" x1="{sx}" y1="{sy}" x2="{qx}" y2="{qy}" marker-end="url(#rarr-{id})"></line><text class="rlabel" x="{}" y="{}" text-anchor="middle">{}</text>"#,
                (sx + qx) / 2.0,
                (sy + qy) / 2.0 - 6.0,
                esc(&f.label)
            );
        }
        for n in &page.nodes {
            let (group, tag, external) = self.type_of(n).map_or(("Custom", "?", false), |t| {
                (t.group.as_str(), t.tag.as_str(), t.external)
            });
            let (w, h) = n.size();
            let lines = wrap(
                &format!("{}{}", n.name, n.units()),
                if n.is_device() { 28 } else { 22 },
            );
            let names: String = lines
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    format!(
                        r#"<text class="rname" x="{}" y="{}">{}</text>"#,
                        n.x + 10.0,
                        n.y + 36.0 + i as f64 * 16.0,
                        esc(l)
                    )
                })
                .collect();
            let see = if n.is_device() {
                let name = n
                    .page
                    .as_deref()
                    .and_then(|id| p.page(id))
                    .map_or("", |pg| pg.name.as_str());
                format!(
                    r#"<text class="rtag" x="{}" y="{}">see page: {}</text>"#,
                    n.x + 10.0,
                    n.y + h - 12.0,
                    esc(name)
                )
            } else {
                String::new()
            };
            out += &format!(
                r#"<g class="rnode {}{}{}"><rect x="{}" y="{}" width="{w}" height="{h}" rx="8"></rect><text class="rtag" x="{}" y="{}">{} · #{}</text>{names}{see}</g>"#,
                group_class(group),
                if external { " ext" } else { "" },
                if n.is_device() { " dev" } else { "" },
                n.x,
                n.y,
                n.x + 10.0,
                n.y + 17.0,
                esc(tag),
                n.id
            );
        }
        out + "</svg>"
    }

    /// The report body (`<article>`), laid out like OWASP Threat Dragon's report.
    pub fn report_html(&self, p: &Project, o: ReportOpts, today: &str) -> String {
        let s = self.summary(p);
        let mut stats: Vec<(&str, String)> = Vec::new();
        if s.pages > 1 {
            stats.extend([
                ("Devices", s.devices.to_string()),
                ("Pages", s.pages.to_string()),
            ]);
        }
        stats.extend([
            ("Total Threats", s.threats.to_string()),
            ("Total Mitigated", s.mitigated.to_string()),
            ("Total Open", s.open.to_string()),
        ]);
        if s.not_applicable > 0 {
            stats.push(("Total Not Applicable", s.not_applicable.to_string()));
        }
        if s.accepted > 0 {
            stats.push(("Total Accepted", s.accepted.to_string()));
        }
        let ev = s.open_by_evidence;
        stats.extend([
            ("Open / Observed in attacks", ev[0].to_string()),
            ("Open / Observed technique", ev[1].to_string()),
            ("Open / Known weakness", ev[2].to_string()),
            ("Open / Proof of concept", ev[3].to_string()),
        ]);
        if ev[4] > 0 {
            stats.push(("Open / Custom threats", ev[4].to_string()));
        }
        stats.push((
            "Countermeasures implemented",
            format!("{} of {}", s.implemented, s.countermeasures),
        ));
        if s.missing_justifications > 0 {
            stats.push((
                "Decisions missing a justification",
                s.missing_justifications.to_string(),
            ));
        }
        if s.needs_review > 0 {
            stats.push(("Answers needing review", s.needs_review.to_string()));
        }
        let (mut num, counts) = (0, self.counts(p));
        let multi = p.pages.len() > 1;
        let mut sections = String::new();
        for pg in p.page_order() {
            if o.diagram || multi {
                let users: Vec<String> = p
                    .parents_of(&pg.id)
                    .iter()
                    .map(|u| esc(&u.name) + &u.units())
                    .collect();
                let used = around(
                    r#"<p class="small muted">Used by: "#,
                    &users.join(", "),
                    "</p>",
                );
                let diagram = if o.diagram {
                    self.diagram_svg(p, pg)
                        + r#"<p class="small muted">Dashed lines are unencrypted data flows.</p>"#
                } else {
                    String::new()
                };
                sections += &format!(
                    r#"<section class="rpage"><h2>{}</h2>{used}{diagram}</section>"#,
                    esc(if multi { &pg.name } else { &p.name })
                );
            }
            for n in pg.nodes.iter().filter(|n| !self.is_external(n)) {
                sections += &self.report_entity(p, n, o, &counts, &mut num);
            }
        }
        if sections.is_empty() {
            sections = r#"<p class="muted">No components match the report options.</p>"#.into();
        }
        let m = &p.meta;
        let dash = |s: &str| {
            if s.is_empty() {
                "—".to_owned()
            } else {
                esc(s)
            }
        };
        let generator = p.generator().map_or(String::new(), |g| {
            format!(
                r#"<tr><th>Generated from</th><td colspan="3">{}</td></tr>"#,
                esc(&g)
            )
        });
        let rows: String = stats
            .iter()
            .map(|(k, v)| format!(r#"<tr><td>{k}</td><td class="num">{v}</td></tr>"#))
            .collect();
        format!(
            r#"<article class="report"><p class="rbrand">{today} | EMB3D Workbench</p><div class="rcard"><div class="rcard-h">Threat model report for {}</div><table class="rkv"><tbody><tr><th>Owner</th><td>{}</td><th>Reviewer</th><td>{}</td></tr><tr><th>Threat catalogue</th><td>MITRE EMB3D STIX {}</td><th>Date generated</th><td>{today}</td></tr>{generator}</tbody></table></div><div class="rcard"><div class="rcard-h">Executive Summary</div><h4>Description</h4><p class="rdesc">{}</p><h4>Summary</h4><table class="rtable rsum"><thead><tr><th>Metric</th><th>Total</th></tr></thead><tbody>{rows}</tbody></table></div>{sections}</article>"#,
            esc(&p.name),
            dash(&m.owner),
            dash(&m.reviewer),
            esc(&self.e.version),
            if m.description.is_empty() {
                "Not provided".into()
            } else {
                esc(&m.description)
            },
        )
    }

    fn report_entity(
        &self,
        p: &Project,
        n: &Node,
        o: ReportOpts,
        counts: &Counts,
        num: &mut usize,
    ) -> String {
        if n.is_device() {
            let page = n.page.as_deref().unwrap_or_default();
            let r = counts.page(page);
            let qty = n.units();
            let each = if n.qty() > 1 {
                format!("; applies to each of the {} units", n.qty())
            } else {
                String::new()
            };
            let name = p.page(page).map_or(page, |pg| pg.name.as_str());
            return format!(
                r#"<section class="rentity"><div class="rhead"><h3>{} (Device{qty})</h3><p class="rprops">Detailed on page "{}": {} threats, {} open{each}.</p></div></section>"#,
                esc(&n.name),
                esc(name),
                r.threats,
                r.open
            );
        }
        let Some(def) = self.type_of(n) else {
            return String::new();
        };
        let hits: Vec<(Hit, State)> = self
            .node_threats(p, n)
            .into_iter()
            .map(|h| {
                let st = self.threat_state(n, &h.tid);
                (h, st)
            })
            .filter(|(_, st)| {
                (o.mitigated || *st != State::Mitigated)
                    && (o.closed || !matches!(st, State::NotApplicable | State::Accepted))
            })
            .collect();
        if hits.is_empty() && !o.empty {
            return String::new();
        }
        let evidence = |qid: &str, sep: &str| {
            n.evidence.get(qid).map_or_else(String::new, |ev| {
                ev.iter()
                    .map(|e| esc(&e.label()))
                    .collect::<Vec<_>>()
                    .join(sep)
            })
        };
        let answers: String = def
            .questions
            .iter()
            .map(|q| {
                let flag = n.review_of(&q.id).map_or(String::new(), |r| {
                    format!(
                        r#" <span class="rflag">needs review{}</span>"#,
                        around(": ", &esc(&r), "")
                    )
                });
                let ev = around(r#"<div class="rwhy">"#, &evidence(&q.id, "<br>"), "</div>");
                format!(
                    r#"<li><span class="rq">{}:</span> <b>{}</b>{flag}{ev}</li>"#,
                    esc(&q.text),
                    esc(&answer_label(n, q))
                )
            })
            .collect();
        let mut body = String::new();
        for (h, st) in &hits {
            *num += 1;
            let d = decision(n, &h.tid);
            let cms: String =
                h.t.mids
                    .iter()
                    .filter_map(|mid| {
                        let m = self.mitigation(mid)?;
                        let w = around(r#"<div class="rwhy">"#, &esc(why(n, mid)), "</div>");
                        Some(format!(
                            r#"<div class="rcm"><b>{}</b> {} — <i>{}</i>{w}</div>"#,
                            esc(mid),
                            esc(&m.name),
                            esc(cm_label(cm_status(n, mid)))
                        ))
                    })
                    .collect();
            let decided = if d.is_empty() {
                String::new()
            } else {
                let w = esc(why(n, &format!("accept:{}", h.tid)));
                let w = if w.is_empty() {
                    "<i>no justification</i>".into()
                } else {
                    w
                };
                format!(
                    r#"<div class="rwhy">{}: {w}</div>"#,
                    if d == "na" {
                        "Not applicable"
                    } else {
                        "Risk accepted"
                    }
                )
            };
            let text = if o.fulltext {
                h.t.text.clone()
            } else {
                vec![h.t.desc.clone()]
            };
            let mut desc: String = text
                .iter()
                .map(|x| format!(r#"<p class="rp">{}</p>"#, esc(&x.replace('*', ""))))
                .collect();
            if !o.fulltext && !h.t.custom && h.t.text.len() > 1 {
                desc += &format!(
                    r#"<p class="rp rmore">Full text: emb3d.mitre.org/threats/{}.html</p>"#,
                    esc(&h.tid)
                );
            }
            body += &format!(
                r#"<tr><td class="num">{num}</td><td><b>{}</b> {}</td><td>{}</td><td>{}</td><td>{}{decided}</td><td>{desc}</td><td>{}</td></tr>"#,
                esc(&h.tid),
                esc(&h.t.name),
                esc(&h.t.cat),
                esc(maturity(&h.t.maturity).1),
                st.label(),
                if cms.is_empty() { "—".into() } else { cms },
            );
        }
        let comp_ev = around(
            r#"<p class="rprops">Identified from: "#,
            &evidence("_component", "; "),
            "</p>",
        );
        let comp_rv = n.review_of("_component").map_or(String::new(), |r| {
            format!(
                r#"<p class="rprops"><span class="rflag">needs review:</span> {}</p>"#,
                esc(&r)
            )
        });
        let props = if o.props {
            let mut pids: Vec<String> = self.node_pids(p, n).into_keys().collect();
            pids.sort_by(|a, b| num_cmp(a, b));
            let pids: Vec<String> = pids
                .iter()
                .map(|pid| format!("{pid} {}", esc(self.property_name(pid))))
                .collect();
            let pids = if pids.is_empty() {
                "none".into()
            } else {
                pids.join("; ")
            };
            let answers = around(r#"<ul class="ranswers">"#, &answers, "</ul>");
            format!(r#"<p class="rprops">EMB3D properties: {pids}</p>{answers}"#)
        } else {
            String::new()
        };
        let table = if hits.is_empty() {
            r#"<p class="muted">No threats to report for this component.</p>"#.to_owned()
        } else {
            format!(
                r#"<div class="rscroll"><table class="rtable rthreats"><colgroup><col style="width:3%"><col style="width:15%"><col style="width:8%"><col style="width:9%"><col style="width:10%"><col style="width:33%"><col style="width:22%"></colgroup><thead><tr><th>#</th><th>Threat</th><th>Type</th><th>Evidence</th><th>Status</th><th>Description</th><th>Countermeasures</th></tr></thead><tbody>{body}</tbody></table></div>"#
            )
        };
        format!(
            r#"<section class="rentity"><div class="rhead"><h3>{} ({})</h3>{comp_ev}{comp_rv}{props}</div>{table}</section>"#,
            esc(&n.name),
            esc(&def.name)
        )
    }
}

/// Point on node `a`'s border towards node `b`'s centre.
pub fn anchor(a: &Node, b: &Node) -> (f64, f64) {
    let ((aw, ah), (bw, bh)) = (a.size(), b.size());
    let (acx, acy) = (a.x + aw / 2.0, a.y + ah / 2.0);
    let (dx, dy) = (b.x + bw / 2.0 - acx, b.y + bh / 2.0 - acy);
    if dx == 0.0 && dy == 0.0 {
        return (acx, acy);
    }
    let sx = (aw / 2.0 + 6.0) / if dx == 0.0 { 1e-9 } else { dx.abs() };
    let sy = (ah / 2.0 + 8.0) / if dy == 0.0 { 1e-9 } else { dy.abs() };
    let s = sx.min(sy);
    (acx + dx * s, acy + dy * s)
}

/// At most two lines of about `w` characters.
fn wrap(t: &str, w: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in t.split_whitespace() {
        let last = lines.last_mut().expect("never empty");
        if !last.is_empty() && last.chars().count() + 1 + word.chars().count() > w {
            lines.push(word.to_owned());
        } else {
            if !last.is_empty() {
                last.push(' ');
            }
            last.push_str(word);
        }
    }
    lines.truncate(2);
    lines
}

#[cfg(test)]
#[path = "../tests/unit/engine.rs"]
pub mod tests;

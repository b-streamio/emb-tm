// SPDX-License-Identifier: GPL-2.0-only
//! A block's threats: why each applies, its countermeasures and decision,
//! and the justification boxes.

use leptos::{ev, prelude::*};
use serde_json::Value;

use crate::{
    engine::{
        cm_status, decision, maturity, missing_accept_why, missing_why, mit_rank, Hit, Model,
        CM_STATUS, NEEDS_WHY,
    },
    model::{Node, Project},
    ui::{dialogs::Dialog, web, Ctx},
};

/// Element id of the justification box of block `id` for `key`.
fn why_id(id: u64, key: &str) -> String {
    let key = key.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "_");
    format!("why-{id}-{key}")
}

/// Justification box; saved while typing, badges refresh when it is left.
pub fn why_box(ctx: Ctx, n: &Node, key: String, label: &'static str) -> impl IntoView {
    let value = n.why.get(&key).cloned().unwrap_or_default();
    let missing = RwSignal::new(value.trim().is_empty());
    let fid = why_id(n.id, &key);
    let id = n.id;
    view! {
        <div class="why" class:missing=move || missing.get()>
            <label for=fid.clone()>{label}</label>
            <textarea id=fid rows="2" placeholder="For example: this product variant has no network interface"
                on:input=move |e| {
                    let v = event_target_value(&e);
                    missing.set(v.trim().is_empty());
                    let k = key.clone();
                    ctx.typing(|p| if let Some(n) = p.node_mut(id) { n.why.insert(k, v); });
                }
                on:change=move |_| ctx.project.notify()>{value}</textarea>
        </div>
    }
}

pub fn cm_select(ctx: Ctx, n: &Node, mid: &str, extra_class: &'static str) -> impl IntoView {
    let (id, mid, current) = (n.id, mid.to_owned(), cm_status(n, mid).to_owned());
    let field = why_id(id, &mid);
    view! {
        <select class=format!("status{extra_class}") aria-label="Status" on:change=move |e| {
            let v = event_target_value(&e);
            let needs = NEEDS_WHY.contains(&v.as_str());
            let k = mid.clone();
            ctx.edit(|p, _| if let Some(n) = p.node_mut(id) { n.cm.insert(k, v); });
            if needs { web::focus(&field); }
        }>
            {CM_STATUS.iter().map(|(v, l)| view! { <option value=*v selected=current == *v>{*l}</option> }).collect_view()}
        </select>
    }
}

/// Short IEC 62443 references: `"EDR / HDR 3.14 – Boot"` → `"3.14"`.
fn iec_short(iec: &[String]) -> String {
    iec.iter()
        .map(|x| {
            let head = x.split('–').next().unwrap_or_default();
            head[head.find(|c: char| c.is_ascii_digit()).unwrap_or(0)..]
                .trim()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn threats(
    ctx: Ctx,
    p: &Project,
    m: &Model,
    n: &Node,
    type_name: &str,
) -> impl IntoView {
    let hits = m.node_threats(p, n);
    let open = ctx.open_threat.get_untracked();
    let list = hits
        .iter()
        .map(|h| threat(ctx, m, n, h, open.as_deref(), type_name))
        .collect_view();
    let count = hits.len();
    view! {
        <div class="sect"><p class="eyebrow">{format!("Threats · {count}")}</p>
            {if count == 0 { view! { <p class="muted small">"No threats for the current answers."</p> }.into_any() } else { list.into_any() }}
        </div>
    }
}

/// One threat, folded; `open` is the one left unfolded.
fn threat(
    ctx: Ctx,
    m: &Model,
    n: &Node,
    h: &Hit,
    open: Option<&str>,
    type_name: &str,
) -> impl IntoView {
    let st = m.threat_state(n, &h.tid);
    let (rank, mat) = maturity(&h.t.maturity);
    let missing = h.t.mids.iter().any(|x| missing_why(n, x)) || missing_accept_why(n, &h.tid);
    let tid = h.tid.clone();
    let (t1, t2) = (tid.clone(), tid.clone());
    let more = (!h.t.custom).then(|| view! {
        <div class="row"><button class="linkbtn small" on:click=move |_| ctx.show(Dialog::Detail(vec![t1.clone()]))>"Read more"</button>
        <a class="extlink" href=format!("https://emb3d.mitre.org/threats/{tid}.html") target="_blank" rel="noopener">{format!("{tid} on emb3d.mitre.org ↗")}</a></div>
    });
    let cwes = (!h.t.cwes.is_empty()).then(|| view! {
        <p class="small"><span class="lbl">"Weaknesses"</span>" "{h.t.cwes.iter().enumerate().map(|(i, (c, name))| view! { {(i > 0).then_some("; ")}<span class="tid">{format!("CWE-{c}")}</span>{format!(" {name}")} }).collect_view()}</p>
    });
    let d = decision(n, &h.tid).to_owned();
    let why = (!d.is_empty()).then(|| {
        why_box(
            ctx,
            n,
            format!("accept:{}", h.tid),
            if d == "na" {
                "Why does this threat not apply?"
            } else {
                "Why is the risk accepted?"
            },
        )
    });
    view! {
        <details class="threat" data-tid=h.tid.clone() open=open == Some(h.tid.as_str())
            on:toggle=move |e: ev::Event| {
                let opened = event_target::<web_sys::HtmlDetailsElement>(&e).open();
                if opened { ctx.open_threat.update_untracked(|x| *x = Some(t2.clone())); }
                else if ctx.open_threat.get_untracked().as_deref() == Some(t2.as_str()) { ctx.open_threat.update_untracked(|x| *x = None); }
            }>
            <summary><span class="tid">{h.tid.clone()}</span><span class="tname">{h.t.name.clone()}</span>
                <span class="chips"><span class=format!("pill st-{}", st.key())>{st.label()}</span>
                    {missing.then(|| view! { <span class="pill st-Open">"Justification missing"</span> })}
                    <span class=format!("mat m{rank}")>{mat.to_owned()}</span>
                    {(h.t.cves > 0).then(|| view! { <span class="mat">{format!("{} CVE", h.t.cves)}</span> })}</span></summary>
            <div class="tbody">
                <p>{h.t.desc.clone()}</p>
                {more}
                <p class="small"><span class="lbl">"Applies because of"</span>" "{because(m, h, type_name)}</p>
                {cwes}
                <div class="cms">{countermeasures(ctx, m, n, h)}</div>
                {decision_select(ctx, n, &h.tid)}
                {why}
            </div>
        </details>
    }
}

/// Countermeasures, not applicable or accepted; the latter two ask why.
fn decision_select(ctx: Ctx, n: &Node, tid: &str) -> impl IntoView {
    let (id, d, tid) = (n.id, decision(n, tid).to_owned(), tid.to_owned());
    let field = why_id(id, &format!("accept:{tid}"));
    view! {
        <div class="row small"><label class="lbl">"Decision for this threat"</label>
            <select class="status" on:change=move |e| {
                let v = event_target_value(&e);
                let (tid, set) = (tid.clone(), !v.is_empty());
                ctx.edit(|p, _| if let Some(n) = p.node_mut(id) { n.accepted.insert(tid, if set { Value::String(v) } else { Value::Bool(false) }); });
                if set { web::focus(&field); }
            }>
                {[("", "Handle with countermeasures"), ("na", "Not applicable"), ("accept", "Accept the risk")].map(|(v, l)| view! { <option value=v selected=d == v>{l}</option> }).collect_view()}
            </select></div>
    }
}

/// The properties that make the threat apply, or its custom block type.
fn because(m: &Model, h: &Hit, type_name: &str) -> AnyView {
    if h.t.custom {
        return view! { {format!("custom threat of the \"{type_name}\" block")} }.into_any();
    }
    h.via
        .iter()
        .enumerate()
        .map(|(i, pid)| {
            let name =
                m.e.properties
                    .get(pid)
                    .map(|x| x.name.clone())
                    .unwrap_or_default();
            view! { {(i > 0).then_some(", ")}<span class="tid" title=name>{pid.clone()}</span> }
        })
        .collect_view()
        .into_any()
}

/// The threat's countermeasures, foundational first, with status and justification.
fn countermeasures(ctx: Ctx, m: &Model, n: &Node, h: &Hit) -> AnyView {
    let mut mids: Vec<&String> =
        h.t.mids
            .iter()
            .filter(|x| m.mitigation(x).is_some())
            .collect();
    if mids.is_empty() {
        let none = if h.t.custom {
            "No countermeasure defined for this custom threat."
        } else {
            "EMB3D lists no mitigation for this threat."
        };
        return view! { <span class="muted small">{none}</span> }.into_any();
    }
    mids.sort_by_key(|x| mit_rank(&m.mitigation(x).expect("filtered").maturity));
    mids.iter().map(|mid| {
        let mm = m.mitigation(mid).expect("filtered");
        let status = cm_status(n, mid);
        let iec = (!mm.iec.is_empty()).then(|| format!(" · IEC 62443 {}", iec_short(&mm.iec)));
        let why = NEEDS_WHY.contains(&status).then(|| why_box(ctx, n, (*mid).clone(), if status == "na" { "Why is it not applicable?" } else { "Why is it rejected?" }));
        let mid2 = (*mid).clone();
        view! {
            <div class="cm">
                <span class="cmn"><span class="tid">{(*mid).clone()}</span>" "<button class="linkbtn" on:click=move |_| ctx.show(Dialog::Detail(vec![mid2.clone()]))>{mm.name.clone()}</button></span>
                {cm_select(ctx, n, mid, "")}
                <span class="cmm">{mm.maturity.clone()}{iec}</span>
                {why}
            </div>
        }
    }).collect_view().into_any()
}

#[cfg(test)]
#[path = "../../../tests/unit/ui/inspector/threats.rs"]
mod tests;

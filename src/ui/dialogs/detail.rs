// SPDX-License-Identifier: GPL-2.0-only
//! The EMB3D reader: a threat or mitigation, with links to the others.

use leptos::prelude::*;

use super::{frame, Dialog, MITRE};
use crate::{
    engine::{maturity, Model},
    stix::{Mitigation, Threat},
    ui::Ctx,
};

/// Part of reader text: plain, *emphasis*, or a link to another threat or mitigation.
#[derive(Debug, PartialEq)]
pub enum Seg {
    Text(String),
    Em(String),
    Link(String),
}

/// Splits `*emphasis*` and `TID-123` / `MID-123` references for which `known` holds.
pub fn rich(text: &str, known: impl Fn(&str) -> bool) -> Vec<Seg> {
    let mut out = Vec::new();
    let mut plain = String::new();
    let b = text.as_bytes();
    let mut i = 0;
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while i < b.len() {
        if b[i] == b'*' {
            if let Some(j) = text[i + 1..].find('*').filter(|j| *j > 0) {
                out.push(Seg::Text(std::mem::take(&mut plain)));
                out.push(Seg::Em(text[i + 1..i + 1 + j].to_owned()));
                i += j + 2;
                continue;
            }
        }
        let id = text.get(i..i + 7).filter(|s| {
            (s.starts_with("TID-") || s.starts_with("MID-"))
                && s[4..].bytes().all(|c| c.is_ascii_digit())
                && (i == 0 || !word(b[i - 1]))
                && b.get(i + 7).is_none_or(|c| !word(*c))
        });
        match id.filter(|s| known(s)) {
            Some(id) => {
                out.push(Seg::Text(std::mem::take(&mut plain)));
                out.push(Seg::Link(id.to_owned()));
                i += 7;
            }
            None => {
                let c = text[i..].chars().next().expect("in bounds");
                plain.push(c);
                i += c.len_utf8();
            }
        }
    }
    out.push(Seg::Text(plain));
    out.retain(|s| !matches!(s, Seg::Text(t) if t.is_empty()));
    out
}

fn open_detail(ctx: Ctx, id: String) {
    ctx.dialog.update(|d| match d {
        Some(Dialog::Detail(s)) => s.push(id),
        _ => *d = Some(Dialog::Detail(vec![id])),
    });
}

fn id_list(ctx: Ctx, items: Vec<(String, String)>) -> impl IntoView {
    view! {
        <div class="tlist">{items.into_iter().map(|(id, name)| {
            let id2 = id.clone();
            view! { <button on:click=move |_| open_detail(ctx, id2.clone())><span class="tid">{id}</span>{format!(" {name}")}</button> }
        }).collect_view()}</div>
    }
}

pub(super) fn detail(ctx: Ctx, stack: Vec<String>) -> AnyView {
    let back = stack.len() > 1;
    let Some(id) = stack.last().cloned() else {
        return ().into_any();
    };
    let content = ctx.with(|_, m| {
        let (t, mi) = (m.threat(&id), m.mitigation(&id));
        if t.is_some_and(|t| t.custom) || (t.is_none() && mi.is_some_and(|x| x.custom)) {
            custom_detail(ctx, m, &id, t, mi)
        } else if let (true, Some(x)) = (id.starts_with("MID"), mi) {
            mitigation_detail(ctx, m, &id, x)
        } else if let Some(t) = t {
            threat_detail(ctx, m, &id, t)
        } else {
            view! { <p>"Unknown id."</p> }.into_any()
        }
    });
    frame(content, None, back)
}

/// A paragraph of reader text, references as links.
fn para(ctx: Ctx, m: &Model, t: &str) -> impl IntoView {
    let known = |x: &str| m.e.threats.contains_key(x) || m.e.mitigations.contains_key(x);
    let segs = rich(t, known).into_iter().map(|s| match s {
        Seg::Text(t) => t.into_any(),
        Seg::Em(t) => view! { <em>{t}</em> }.into_any(),
        Seg::Link(x) => {
            let y = x.clone();
            view! { <button class="linkbtn" on:click=move |_| open_detail(ctx, y.clone())>{x}</button> }.into_any()
        }
    }).collect_view();
    view! { <p>{segs}</p> }
}

/// The page of `id` on emb3d.mitre.org.
fn site(id: &str) -> impl IntoView {
    let href = format!(
        "{MITRE}/{}/{id}.html",
        if id.starts_with("MID") {
            "mitigations"
        } else {
            "threats"
        }
    );
    view! { <a class="extlink" href=href target="_blank" rel="noopener">"Open on emb3d.mitre.org ↗"</a> }
}

fn custom_detail(
    ctx: Ctx,
    m: &Model,
    id: &str,
    t: Option<&Threat>,
    mi: Option<&Mitigation>,
) -> AnyView {
    let (name, desc) = t.map_or_else(
        || {
            mi.map(|x| (x.name.clone(), x.desc.clone()))
                .unwrap_or_default()
        },
        |t| (t.name.clone(), t.desc.clone()),
    );
    let linked: Vec<(String, String)> = t.map_or_else(Vec::new, |t| {
        t.mids
            .iter()
            .filter_map(|x| Some((x.clone(), m.mitigation(x)?.name.clone())))
            .collect()
    });
    let kind = if t.is_some() {
        "threat"
    } else {
        "countermeasure"
    };
    view! {
        <div class="dhead"><span class="eyebrow" style="margin:0">{format!("{id} · custom {kind}")}</span></div>
        <h3>{name}</h3><p>{if desc.is_empty() { "No description.".to_owned() } else { desc }}</p>
        {(!linked.is_empty()).then(|| view! { <div><p class="eyebrow">"Countermeasures"</p>{id_list(ctx, linked)}</div> })}
        <p class="small muted">"Defined in this project's custom blocks."</p>
    }.into_any()
}

fn mitigation_detail(ctx: Ctx, m: &Model, id: &str, x: &Mitigation) -> AnyView {
    let tids: Vec<(String, String)> =
        m.e.threats
            .iter()
            .filter(|(_, t)| t.mids.iter().any(|x| x == id))
            .map(|(k, t)| (k.clone(), t.name.clone()))
            .collect();
    let refs = x.refs.clone();
    view! {
        <div class="dhead"><span class="eyebrow" style="margin:0">{format!("{id} · {} mitigation", x.maturity)}</span>{site(id)}</div>
        <h3>{x.name.clone()}</h3>
        {x.text.iter().map(|t| para(ctx, m, t)).collect_view()}
        {(!x.iec.is_empty()).then(|| view! { <div><p class="eyebrow">"IEC 62443-4-2"</p><p class="small">{x.iec.iter().map(|i| view! { {i.clone()}<br /> }).collect_view()}</p></div> })}
        <div><p class="eyebrow">{format!("Mitigates {} threats", tids.len())}</p>{id_list(ctx, tids)}</div>
        {(!refs.is_empty()).then(|| view! { <div><p class="eyebrow">"References"</p><ol class="refs">{refs.into_iter().map(|r| {
            let link = (!r.u.is_empty()).then(|| view! { " " <a href=r.u.clone() target="_blank" rel="noopener">{r.u.clone()}</a> });
            view! { <li>{r.t}{link}</li> }
        }).collect_view()}</ol></div> })}
    }.into_any()
}

fn threat_detail(ctx: Ctx, m: &Model, id: &str, t: &Threat) -> AnyView {
    let (rank, mat) = maturity(&t.maturity);
    let mids: Vec<(String, String)> = t
        .mids
        .iter()
        .filter_map(|x| Some((x.clone(), m.mitigation(x)?.name.clone())))
        .collect();
    view! {
        <div class="dhead"><span class="eyebrow" style="margin:0">{format!("{id} · {} threat", t.cat)}</span><span class=format!("mat m{rank}")>{mat.to_owned()}</span>{site(id)}</div>
        <h3>{t.name.clone()}</h3>
        {t.text.iter().map(|x| para(ctx, m, x)).collect_view()}
        <div><p class="eyebrow">"Device properties"</p><p class="small">{t.pids.iter().map(|pid| view! {
            <span class="tid">{pid.clone()}</span>{format!(" {}", m.e.properties.get(pid).map(|x| x.name.as_str()).unwrap_or_default())}<br />
        }).collect_view()}</p></div>
        {(!t.cwes.is_empty()).then(|| view! { <div><p class="eyebrow">"Weaknesses"</p><p class="small">{t.cwes.iter().map(|(c, name)| view! {
            <a class="extlink" href=format!("https://cwe.mitre.org/data/definitions/{c}.html") target="_blank" rel="noopener">{format!("CWE-{c}")}</a>{format!(" {name}")}<br />
        }).collect_view()}</p></div> })}
        <div><p class="eyebrow">{format!("Mitigations · {}", mids.len())}</p>{id_list(ctx, mids)}</div>
    }.into_any()
}

#[cfg(test)]
#[path = "../../../tests/unit/ui/dialogs/detail.rs"]
mod tests;

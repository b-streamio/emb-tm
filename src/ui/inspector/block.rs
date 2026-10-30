// SPDX-License-Identifier: GPL-2.0-only
//! The inspector of a block: name, questions, EMB3D properties and threats.

use std::collections::BTreeMap;

use leptos::prelude::*;
use serde_json::Value;

use super::{move_controls, remove, threats::threats, ArmedDelete};
use crate::{
    engine::{answer, group_class, Model, Source},
    model::{Node, Project, TypeDef},
    ui::{dialogs::Dialog, Ctx},
};

pub(super) fn block(ctx: Ctx, p: &Project, m: &Model, n: &Node) -> impl IntoView {
    let page = ctx.page();
    let id = n.id;
    let Some(def) = m.type_of(n).cloned() else {
        return view! { <p class="muted">"Unknown block type."</p> }.into_any();
    };
    let pids = m.node_pids(p, n);
    let threats = (!def.external).then(|| threats(ctx, p, m, n, &def.name));
    let component = n.evidence.contains_key("_component") || n.review.contains_key("_component");
    let component = component.then(|| {
        let flagged = n.reviews().any(|(k, _)| k == "_component");
        view! { <div class="q" class:review=flagged>{n.evidence.contains_key("_component").then(|| view! { <span class="lbl">"Identified from"</span> })}{evidence_list(n, "_component")}{review_flag(ctx, n, "_component")}</div> }
    });
    let edit_type = def.custom.then(|| {
        let kind = def.kind.clone();
        view! { " " <button class="linkbtn small" on:click=move |_| ctx.show(Dialog::Custom { existing: Some(kind.clone()), copy_of: None })>"Edit block type"</button> }
    });
    let has_q = !def.questions.is_empty();
    view! {
        <p class="eyebrow"><span class=group_class(&def.group)>{def.group.clone()}</span>{format!(" · {}", def.name)}</p>
        <div class="field"><label for="node-name">"Name"</label>
            <input type="text" id="node-name" value=n.name.clone() on:input=move |e| { let v = event_target_value(&e); ctx.typing(|p| if let Some(n) = p.node_mut(id) { n.name = v }) } /></div>
        <p class="small muted">{def.hint.clone()}{edit_type}</p>
        {component}
        <div class="row">
            <button class="btn small" on:click=move |_| ctx.connect.set(Some(id))>"Draw data flow"</button>
            <ArmedDelete on_confirm=move |_| remove(ctx, id) />
        </div>
        {move_controls(ctx, p, n, &page)}
        {has_q.then(|| view! { <div class="sect"><p class="eyebrow">"Questions"</p>{questions(ctx, n, &def)}</div> })}
        {(!pids.is_empty()).then(|| view! { <div class="sect"><p class="eyebrow">"EMB3D properties"</p><div class="pids">{chips(m, &pids)}</div></div> })}
        {threats}
    }
    .into_any()
}

/// The questionnaire of the block's type, with evidence and review flags.
fn questions(ctx: Ctx, n: &Node, def: &TypeDef) -> impl IntoView {
    let id = n.id;
    let set_answer = move |qid: String, v: Value| {
        ctx.edit(|p, _| {
            if let Some(n) = p.node_mut(id) {
                n.answers.insert(qid.clone(), v);
                n.review.remove(&qid); // a human answered it
            }
        });
    };
    def.questions.iter().map(|q| {
        let a = answer(n, q).clone();
        let flagged = n.review_of(&q.id).is_some();
        let extra = view! { {review_flag(ctx, n, &q.id)}{evidence_list(n, &q.id)} };
        let qid = q.id.clone();
        let body = if q.kind == "bool" {
            view! { <label class="check"><input type="checkbox" prop:checked=a.as_bool().unwrap_or(false) on:change=move |e| set_answer(qid.clone(), Value::Bool(event_target_checked(&e))) /><span>{q.text.clone()}</span></label> }.into_any()
        } else {
            let name = format!("q-{id}-{}", q.id);
            let radios = q.options.iter().map(|o| {
                let (qid, v) = (qid.clone(), o.value.clone());
                view! { <label class="radio"><input type="radio" name=name.clone() value=o.value.clone() prop:checked=a.as_str() == Some(&o.value) on:change=move |_| set_answer(qid.clone(), Value::String(v.clone())) /><span>{o.label.clone()}</span></label> }
            }).collect_view();
            view! { <span class="qt">{q.text.clone()}</span><div class="radios">{radios}</div> }.into_any()
        };
        view! { <div class="q" class:review=flagged>{body}{extra}</div> }
    }).collect_view()
}

/// The block's EMB3D properties; those of the PID-26 rule are marked.
fn chips(m: &Model, pids: &BTreeMap<String, Source>) -> impl IntoView {
    pids.iter()
        .map(|(pid, src)| {
            let rule = *src == Source::Rule;
            let name =
                m.e.properties
                    .get(pid)
                    .map(|x| x.name.clone())
                    .unwrap_or_default();
            let title = if rule {
                format!("{name} (added because the model has no update agent)")
            } else {
                name
            };
            view! { <span class="pid" class:rule=rule title=title>{pid.clone()}</span> }
        })
        .collect_view()
}

fn evidence_list(n: &Node, qid: &str) -> Option<impl IntoView> {
    let ev = n.evidence.get(qid).filter(|e| !e.is_empty())?.clone();
    Some(view! {
        <ul class="qev">{ev.into_iter().map(|e| {
            let at = format!("{}{}", e.file, e.line.map(|l| format!(":{l}")).unwrap_or_default());
            view! { <li><span class="mono">{at}</span>{(!e.text.is_empty()).then(|| view! { " " <span class="evtext">{e.text}</span> })}</li> }
        }).collect_view()}</ul>
    })
}

fn review_flag(ctx: Ctx, n: &Node, qid: &str) -> Option<impl IntoView> {
    let reason = n.review_of(qid)?;
    let (id, qid) = (n.id, qid.to_owned());
    Some(view! {
        <div class="qreview"><span class="pill st-Open">"Needs review"</span>" "{reason}" "
            <button class="linkbtn small" on:click=move |_| { let q = qid.clone(); ctx.edit(|p, _| if let Some(n) = p.node_mut(id) { n.review.remove(&q); }); }>"Mark as reviewed"</button>
        </div>
    })
}

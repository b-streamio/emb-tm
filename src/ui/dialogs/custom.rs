// SPDX-License-Identifier: GPL-2.0-only
//! The custom block editor: name, EMB3D properties and custom threats.

use std::collections::BTreeSet;

use leptos::prelude::*;

use super::{frame, Dialog};
use crate::{
    model::{num_cmp, CustomCm, CustomThreat, CustomType, Question},
    ops,
    ui::{ctx, web},
};

#[derive(Clone, Default)]
struct ThreatRow {
    key: usize,
    id: String,
    cm_id: String,
    name: String,
    desc: String,
    cm_name: String,
    cm_desc: String,
}

const GROUPS: [&str; 5] = [
    "Hardware",
    "System software",
    "Application",
    "Networking",
    "Custom",
];
const CATEGORIES: [&str; 4] = [
    "Hardware",
    "System Software",
    "Application Software",
    "Networking",
];

/// The editor's fields.
#[derive(Clone, Copy)]
struct Form {
    name: RwSignal<String>,
    tag: RwSignal<String>,
    group: RwSignal<String>,
    hint: RwSignal<String>,
    base: RwSignal<BTreeSet<String>>,
    rows: RwSignal<Vec<ThreatRow>>,
}

impl Form {
    fn new(t: &CustomType) -> Self {
        let rows = t
            .threats
            .iter()
            .enumerate()
            .map(|(key, t)| {
                let cm = t.cms.first().cloned().unwrap_or_default();
                ThreatRow {
                    key,
                    id: t.id.clone(),
                    cm_id: cm.id,
                    name: t.name.clone(),
                    desc: t.desc.clone(),
                    cm_name: cm.name,
                    cm_desc: cm.desc,
                }
            })
            .collect();
        Self {
            name: RwSignal::new(t.name.clone()),
            tag: RwSignal::new(t.tag.clone()),
            group: RwSignal::new(t.group.clone()),
            hint: RwSignal::new(t.hint.clone()),
            base: RwSignal::new(t.base.iter().cloned().collect()),
            rows: RwSignal::new(rows),
        }
    }

    /// The block type, or why it cannot be saved.
    fn to_type(self, questions: &[Question], external: bool) -> Result<CustomType, &'static str> {
        let name = self.name.get_untracked().trim().to_owned();
        if name.is_empty() {
            return Err("Give the block a name.");
        }
        let threats: Vec<CustomThreat> = self
            .rows
            .get_untracked()
            .into_iter()
            .filter(|r| !r.name.trim().is_empty())
            .map(|r| CustomThreat {
                id: r.id,
                name: r.name.trim().into(),
                desc: r.desc.trim().into(),
                cms: if r.cm_name.trim().is_empty() {
                    Vec::new()
                } else {
                    vec![CustomCm {
                        id: r.cm_id,
                        name: r.cm_name.trim().into(),
                        desc: r.cm_desc.trim().into(),
                    }]
                },
            })
            .collect();
        let base: Vec<String> = self.base.get_untracked().into_iter().collect();
        if base.is_empty() && threats.is_empty() && questions.is_empty() {
            return Err("Tick at least one EMB3D property or add a custom threat, otherwise the block has no threats.");
        }
        let tag = self.tag.get_untracked().trim().to_owned();
        let tag = if tag.is_empty() {
            name.chars()
                .filter(char::is_ascii_alphanumeric)
                .take(3)
                .collect()
        } else {
            tag
        };
        let hint = self.hint.get_untracked().trim().to_owned();
        Ok(CustomType {
            kind: String::new(),
            name,
            group: self.group.get_untracked(),
            tag: tag.to_uppercase().chars().take(4).collect(),
            hint: if hint.is_empty() {
                "Custom block".into()
            } else {
                hint
            },
            base,
            threats,
            questions: questions.to_vec(),
            external,
        })
    }
}

/// What the editor starts from: the block type, a copy of one with fresh
/// ids, or a new hardware block.
fn start(found: Option<&CustomType>, copy_of: Option<CustomType>) -> CustomType {
    match (found, copy_of) {
        (Some(c), _) => c.clone(),
        (None, Some(c)) => CustomType {
            kind: String::new(),
            name: format!("{} (copy)", c.name),
            threats: c
                .threats
                .iter()
                .map(|t| CustomThreat {
                    id: String::new(),
                    cms: t
                        .cms
                        .iter()
                        .map(|m| CustomCm {
                            id: String::new(),
                            ..m.clone()
                        })
                        .collect(),
                    ..t.clone()
                })
                .collect(),
            ..c
        },
        (None, None) => CustomType {
            group: "Hardware".into(),
            ..Default::default()
        },
    }
}

#[component]
pub(super) fn CustomEditor(existing: Option<String>, copy_of: Option<CustomType>) -> impl IntoView {
    let ctx = ctx();
    let found = existing.as_ref().and_then(|k| {
        ctx.project
            .with_untracked(|p| p.custom_types.iter().find(|c| &c.kind == k).cloned())
    });
    let start = start(found.as_ref(), copy_of);
    let existing = found.as_ref().map(|c| c.kind.clone());
    let f = Form::new(&start);
    let error = RwSignal::new(None::<&'static str>);
    let (questions, external) = (start.questions.clone(), start.external);
    let asked = (!questions.is_empty()).then(|| view! { <p class="small muted">{format!("{} are kept as they are; answer them in the inspector.", ops::plural(questions.len(), "imported question"))}</p> });
    let save = {
        let existing = existing.clone();
        Callback::new(move |()| match f.to_type(&questions, external) {
            Err(e) => error.set(Some(e)),
            Ok(def) => {
                ctx.edit(|p, m| ops::save_custom(p, m, existing.as_deref(), def));
                ctx.dialog.set(None);
            }
        })
    };
    let manage = found.map(|c| view! { <Manage c=c /> });
    let title = if existing.is_some() {
        start.name.clone()
    } else {
        "Custom block".into()
    };
    web::focus("cb-name");
    let content = view! {
        <div class="dhead"><span class="eyebrow" style="margin:0">{if existing.is_some() { "Edit custom block" } else { "New custom block" }}</span></div>
        <h3>{title}</h3>
        <div class="cform">
            <div class="field"><label for="cb-name">"Name"</label><input type="text" id="cb-name" value=start.name.clone() placeholder="For example: Image sensor module" on:input=move |e| f.name.update_untracked(|x| *x = event_target_value(&e)) /></div>
            <div class="row2">
                <div class="field"><label for="cb-tag">"Tag (up to 4 letters)"</label><input type="text" id="cb-tag" maxlength="4" value=start.tag.clone() placeholder="CAM" on:input=move |e| f.tag.update_untracked(|x| *x = event_target_value(&e)) /></div>
                <div class="field"><label for="cb-group">"Group"</label><select id="cb-group" class="status" on:change=move |e| f.group.update_untracked(|x| *x = event_target_value(&e))>
                    {GROUPS.map(|g| view! { <option selected=start.group == g>{g}</option> }).collect_view()}</select></div>
            </div>
            <div class="field"><label for="cb-hint">"Description"</label><input type="text" id="cb-hint" value=start.hint.clone() on:input=move |e| f.hint.update_untracked(|x| *x = event_target_value(&e)) /></div>
            <div><p class="eyebrow">"EMB3D properties"</p><p class="small muted">"Every EMB3D threat linked to a ticked property applies to this block. Ticking a sub-property implies its parent."</p>
                <PidList base=f.base />{asked}</div>
            <ThreatRows rows=f.rows />
            {move || error.get().map(|e| view! { <p class="warn">{e}</p> })}
            {manage}
        </div>
    };
    let label = if existing.is_some() {
        "Save block"
    } else {
        "Create block"
    };
    frame(content, Some((label.into(), save)), false)
}

/// The EMB3D properties by category, as check boxes indented by depth.
#[component]
fn PidList(base: RwSignal<BTreeSet<String>>) -> impl IntoView {
    let e = ctx().emb3d.get_untracked();
    let depth = |pid: &str| {
        std::iter::successors(e.properties.get(pid).and_then(|p| p.parent.clone()), |p| {
            e.properties.get(p).and_then(|x| x.parent.clone())
        })
        .count()
    };
    let cats = CATEGORIES.map(|cat| {
        let mut ids: Vec<&String> = e.properties.iter().filter(|(_, p)| p.cat == cat).map(|(k, _)| k).collect();
        ids.sort_by(|a, b| num_cmp(a, b));
        let boxes = ids.into_iter().map(|pid| {
            let (p1, p2) = (pid.clone(), pid.clone());
            let pad = format!("{}px", depth(pid) * 14);
            view! { <label class="check small" style:padding-left=pad><input type="checkbox" prop:checked=move || base.with(|b| b.contains(&p1))
                on:change=move |ev| { let on = event_target_checked(&ev); let p = p2.clone(); base.update_untracked(|b| { if on { b.insert(p); } else { b.remove(&p); } }) } />
                <span><span class="tid">{pid.clone()}</span>{format!(" {}", e.properties[pid].name)}</span></label> }
        }).collect_view();
        view! { <div class="pidcat"><p class="lbl">{cat}</p>{boxes}</div> }
    });
    view! { <div class="pidlist">{cats}</div> }
}

/// The custom threats, each with an optional countermeasure.
#[component]
fn ThreatRows(rows: RwSignal<Vec<ThreatRow>>) -> impl IntoView {
    let field =
        move |key: usize, get: fn(&ThreatRow) -> String, set: fn(&mut ThreatRow, String)| {
            let value = rows
                .with_untracked(|r| r.iter().find(|x| x.key == key).map(get).unwrap_or_default());
            (value, move |ev: leptos::ev::Event| {
                let v = event_target_value(&ev);
                rows.update_untracked(|r| {
                    if let Some(x) = r.iter_mut().find(|x| x.key == key) {
                        set(x, v)
                    }
                });
            })
        };
    let list = move || {
        rows.with(|r| r.iter().map(|row| row.key).collect::<Vec<_>>()).into_iter().map(|key| {
            let (n, on_n) = field(key, |r| r.name.clone(), |r, v| r.name = v);
            let (d, on_d) = field(key, |r| r.desc.clone(), |r, v| r.desc = v);
            let (cn, on_cn) = field(key, |r| r.cm_name.clone(), |r, v| r.cm_name = v);
            let (cd, on_cd) = field(key, |r| r.cm_desc.clone(), |r, v| r.cm_desc = v);
            view! {
                <div class="cthreat">
                    <div class="field"><label>"Threat"</label><input type="text" id=format!("ct-{key}") value=n placeholder="For example: Optical blinding of the sensor" on:input=on_n /></div>
                    <div class="field"><label>"Description"</label><textarea rows="2" on:input=on_d>{d}</textarea></div>
                    <div class="field"><label>"Countermeasure (optional)"</label><input type="text" value=cn placeholder="For example: Detect blinding and alert" on:input=on_cn /></div>
                    <div class="field"><label>"Countermeasure description"</label><textarea rows="2" on:input=on_cd>{cd}</textarea></div>
                    <button class="linkbtn small" on:click=move |_| rows.update(|r| r.retain(|x| x.key != key))>"Remove this threat"</button>
                </div>
            }
        }).collect_view()
    };
    let next_key = StoredValue::new(rows.with_untracked(Vec::len));
    view! {
        <div><p class="eyebrow">"Custom threats"</p><p class="small muted">"Threats EMB3D does not cover. Each can have its own countermeasure."</p>
            <div>{list}</div>
            <button class="btn small" on:click=move |_| {
                let key = next_key.get_value();
                next_key.set_value(key + 1);
                rows.update(|r| r.push(ThreatRow { key, ..Default::default() }));
                web::focus(&format!("ct-{key}"));
            }>"Add a threat"</button></div>
    }
}

/// Duplicate or delete an existing block type (only when no block uses it).
#[component]
fn Manage(c: CustomType) -> impl IntoView {
    let ctx = ctx();
    let kind = c.kind.clone();
    let used = ctx
        .project
        .with_untracked(|p| p.nodes().filter(|n| n.kind == kind).count());
    let armed = RwSignal::new(false);
    let in_use = used > 0;
    view! {
        <div class="row">
            <button class="btn small" on:click=move |_| ctx.show(Dialog::Custom { existing: None, copy_of: Some(c.clone()) })>"Duplicate as a new type"</button>
            <button class="btn small danger" disabled=in_use title=in_use.then_some("Remove the blocks of this type first") on:click=move |_| {
                if !armed.get_untracked() { return armed.set(true); }
                let k = kind.clone();
                ctx.edit(|p, _| p.custom_types.retain(|c| c.kind != k));
                ctx.dialog.set(None);
            }>{move || if armed.get() { "Click again to delete" } else { "Delete block type" }}</button>
            {in_use.then(|| view! { <span class="small muted">{format!("Used by {}.", ops::plural(used, "block"))}</span> })}
        </div>
    }
}

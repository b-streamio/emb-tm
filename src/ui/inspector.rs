//! Right-hand panel: page summary, or the selected block, device box or data flow.

use std::time::Duration;

use leptos::{ev, prelude::*};
use serde_json::Value;

use super::{board, ctx, dialogs::Dialog, web, Ctx, Sel};
use crate::{
    engine::{
        answer, cm_status, decision, group_class, maturity, missing_accept_why, missing_why,
        mit_rank, Model, Source, CM_STATUS, NEEDS_WHY,
    },
    model::{Node, Project},
    ops,
};

#[component]
pub fn Inspector() -> impl IntoView {
    let ctx = ctx();
    move || {
        let (sel, page) = (ctx.sel.get(), ctx.page());
        ctx.with(|p, m| match sel {
            Some(Sel::Node(id)) if p.node(id).is_some() => {
                let n = p.node(id).expect("checked");
                if n.is_device() {
                    device(ctx, p, n).into_any()
                } else {
                    block(ctx, p, m, n).into_any()
                }
            }
            Some(Sel::Flow(id))
                if p.page(&page)
                    .is_some_and(|pg| pg.flows.iter().any(|f| f.id == id)) =>
            {
                flow(ctx, p, &page, id).into_any()
            }
            _ => summary(ctx, p, m, &page).into_any(),
        })
    }
}

fn summary(ctx: Ctx, p: &Project, m: &Model, page: &str) -> impl IntoView {
    let pg = p.page(page).expect("current page exists");
    let root = pg.id == p.root;
    let multi = p.pages.len() > 1;
    let r = ctx.counts.with(|c| c.page(page));
    let cms = m.cm_rows(p);
    let total = m.all_rows(p).len();
    let reviews = m.review_items(p).len();
    let page_id = pg.id.clone();
    let name_field = (!root).then(|| {
        let users = p.parents_of(page);
        let used = if users.is_empty() {
            "Not used by any device box.".to_owned()
        } else {
            format!(
                "Used by {}",
                users
                    .iter()
                    .map(|u| u.name.clone() + &u.units())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        view! {
            <div class="field" style="margin-top:12px"><label for="pgname">"Page name"</label>
                <input type="text" id="pgname" value=pg.name.clone() on:input=move |e| {
                    let v = event_target_value(&e);
                    let id = page_id.clone();
                    ctx.typing(|p| if let Some(pg) = p.page_mut(&id) { pg.name = v });
                } /></div>
            <p class="small muted">{used}</p>
        }
    });
    let eyebrow = if root {
        if multi {
            "System"
        } else {
            "Device"
        }
    } else {
        "Device page"
    };
    view! {
        <div class="empty">
            <p class="eyebrow">{eyebrow}</p>
            <h2>{if root { p.name.clone() } else { pg.name.clone() }}</h2>
            {name_field}
            <div class="stats">
                <div class="stat"><b>{pg.nodes.len()}</b><span>"blocks on this page"</span></div>
                <div class="stat"><b>{pg.flows.len()}</b><span>"data flows on this page"</span></div>
                <div class="stat open"><b>{r.open}</b><span>{format!("open threats{}", if root { "" } else { " in this device" })}</span></div>
                <div class="stat done"><b>{cms.iter().filter(|c| c.status == "implemented").count()}</b><span>{format!("countermeasures implemented of {} (whole model)", cms.len())}</span></div>
            </div>
            {(reviews > 0).then(|| view! { <p class="small"><span class="pill st-Open">{format!("{reviews} answers need review")}</span>" These were not determined from the source and use a default. Blocks with them are marked on the board."</p> })}
            {p.generator().map(|g| view! { <p class="small muted">{format!("Generated from {g}.")}</p> })}
            <p class="small">"Select a block to answer its questions and work through its threats. A " <b>"Device"</b> " box stands for a whole device: double-click it to design its inside on its own page. Use " <b>"Draw data flow"</b> " to connect blocks on the same page."</p>
            <p class="small">{format!("{total} threats in the whole model, from MITRE EMB3D STIX {} and your custom blocks. EMB3D rates evidence, not severity, so threats are ordered by how much real-world evidence exists for them.", m.e.version)}</p>
        </div>
    }
}

/// "Delete" that needs a second click within three seconds.
#[component]
pub fn ArmedDelete(#[prop(into)] on_confirm: Callback<()>) -> impl IntoView {
    let armed = RwSignal::new(false);
    view! {
        <button class="btn small danger" on:click=move |_| {
            if armed.get_untracked() {
                on_confirm.run(());
                return;
            }
            armed.set(true);
            set_timeout(move || { let _ = armed.try_set(false); }, Duration::from_secs(3));
        }>{move || if armed.get() { "Click again to delete" } else { "Delete" }}</button>
    }
}

fn remove(ctx: Ctx, id: u64) {
    let page = ctx.page();
    ctx.edit(|p, _| ops::remove_node(p, &page, id));
    ctx.select(None);
}

/// The keyboard shortcut of a button (`keyboard` in `ui/mod.rs`): `⌘V` on
/// Apple systems, `Ctrl+V` elsewhere.
fn key(letter: char) -> impl IntoView {
    let label = if web::apple() {
        format!("⌘{letter}")
    } else {
        format!("Ctrl+{letter}")
    };
    view! { <kbd>{label}</kbd> }
}

/// Duplicate / copy / cut / paste and "move into device".
fn move_controls(ctx: Ctx, p: &Project, n: &Node, page: &str) -> impl IntoView {
    let devs: Vec<(u64, String)> = p.page(page).map_or_else(Vec::new, |pg| {
        pg.nodes
            .iter()
            .filter(|d| d.is_device() && d.id != n.id)
            .map(|d| (d.id, d.name.clone()))
            .collect()
    });
    let id = n.id;
    let paste_label = if n.is_device() {
        "Paste inside"
    } else {
        "Paste"
    };
    let extra = ctx.multi.get_untracked().len();
    view! {
        <div class="row movebar">
            <button class="btn small" on:click=move |_| ctx.duplicate()>"Duplicate"{key('D')}</button>
            <button class="btn small" on:click=move |_| { ctx.copy(false); }>"Copy"{key('C')}</button>
            <button class="btn small" on:click=move |_| { ctx.copy(true); }>"Cut"{key('X')}</button>
            {move || ctx.clip.get().map(|c| view! { <button class="btn small" on:click=move |_| ctx.paste(&c, false, "", None)>{paste_label}{key('V')}</button> })}
            {(!devs.is_empty()).then(|| view! {
                <select class="status" aria-label="Move into a device" on:change=move |e| {
                    let Ok(dev) = event_target_value(&e).parse::<u64>() else { return };
                    let mut ids = ctx.selected_ids();
                    if ids.is_empty() { ids = vec![id]; }
                    board::move_into(ctx, &ids, dev);
                }>
                    <option value="">"Move into device…"</option>
                    {devs.into_iter().map(|(d, name)| view! { <option value=d.to_string()>{name}</option> }).collect_view()}
                </select>
            })}
            {(extra > 0).then(|| view! { <span class="small muted">{format!("{} blocks selected", extra + 1)}</span> })}
        </div>
    }
}

fn device(ctx: Ctx, p: &Project, n: &Node) -> impl IntoView {
    let page = ctx.page();
    let id = n.id;
    let design = n.page.clone().unwrap_or_default();
    let r = ctx.counts.with(|c| c.page(&design));
    // A device may not use a page that contains it.
    let ancestors: Vec<String> = board::page_path(p, &page)
        .into_iter()
        .map(|x| x.0)
        .collect();
    let choices: Vec<(String, String)> = p
        .pages
        .iter()
        .filter(|x| !ancestors.contains(&x.id))
        .map(|x| (x.id.clone(), x.name.clone()))
        .collect();
    let sharers: Vec<String> = p
        .parents_of(&design)
        .iter()
        .filter(|d| d.id != id)
        .map(|d| d.name.clone())
        .collect();
    let variant = (n.qty() > 1 || !sharers.is_empty()).then(|| {
        let mut text = String::new();
        if n.qty() > 1 {
            text += &format!("All {} units use one design. ", n.qty());
        }
        if !sharers.is_empty() {
            text += &format!("This design is also used by {}. ", sharers.join(", "));
        }
        text += "To change one of them, make it separate first.";
        let page2 = page.clone();
        let split = (n.qty() > 1).then(|| view! { <button class="btn small" on:click=move |_| {
            let page = page2.clone();
            if let Some(one) = ctx.edit(|p, _| ops::split_unit(p, &page, id)) {
                let msg = ctx.project.with_untracked(|p| match (p.node(id), p.node(one)) {
                    (Some(a), Some(b)) => format!("Split one unit out: {} ×{} and {} ×1, which has its own design to change.", a.name, a.qty(), b.name),
                    _ => String::new(),
                });
                ctx.select(Some(Sel::Node(one)));
                ctx.toast(msg);
            }
        }>"Split one unit out to modify"</button> });
        let detach = (!sharers.is_empty()).then(|| view! { <button class="btn small" on:click=move |_| {
            let name = ctx.edit(|p, _| {
                let n = p.node(id)?.clone();
                let page = ops::clone_design(p, n.page.as_deref()?, &n.name);
                p.node_mut(id)?.page = Some(page);
                Some(n.name)
            });
            if let Some(name) = name {
                ctx.toast(format!("{name} now has its own copy of the design. Changes to it no longer affect the other boxes."));
            }
        }>"Use a separate copy of the design"</button> });
        view! { <div class="variant"><p class="small">{text}</p><div class="row">{split}{detach}</div></div> }
    });
    let design2 = design.clone();
    let inside = p.page(&design).map_or(0, |x| x.nodes.len());
    view! {
        <p class="eyebrow"><span class="k-System">"System"</span>" · Device"</p>
        <div class="field"><label for="dev-name">"Name"</label>
            <input type="text" id="dev-name" value=n.name.clone() on:input=move |e| {
                let v = event_target_value(&e);
                ctx.typing(|p| {
                    let Some(n) = p.node(id).cloned() else { return };
                    let only = p.parents_of(n.page.as_deref().unwrap_or_default()).len() == 1;
                    if let Some(pg) = p.page_mut(n.page.as_deref().unwrap_or_default()).filter(|pg| only && pg.name == n.name) {
                        pg.name = v.clone(); // keep the page name in step while it matches
                    }
                    if let Some(n) = p.node_mut(id) { n.name = v; }
                });
            } /></div>
        <div class="field"><label for="dev-qty">"Quantity of identical units"</label>
            <input type="number" min="1" step="1" id="dev-qty" class="qtyin" value=n.qty().to_string() on:change=move |e| {
                let q = event_target_value(&e).parse::<u32>().unwrap_or(1).max(1);
                ctx.edit(|p, _| if let Some(n) = p.node_mut(id) { n.qty = Some(q) });
            } /></div>
        <div class="field"><label for="dev-page">"Design page"</label>
            <select id="dev-page" class="status" on:change=move |e| {
                let v = event_target_value(&e);
                ctx.edit(|p, _| {
                    let page = if v == "__new" {
                        let fresh = ops::new_page_id(p);
                        let name = p.node(id).map(|n| n.name.clone()).unwrap_or_default();
                        p.pages.push(crate::model::Page { id: fresh.clone(), name, ..Default::default() });
                        fresh
                    } else { v };
                    if let Some(n) = p.node_mut(id) { n.page = Some(page); }
                });
            }>
                {choices.into_iter().map(|(pid, name)| view! { <option value=pid.clone() selected=pid == design2>{name}</option> }).collect_view()}
                <option value="__new">"New empty page"</option>
            </select></div>
        <p class="small muted">"Boxes that share a design page share its threats and decisions: model a camera once and use it for every camera."</p>
        {variant}
        <div class="row">
            <button class="btn small primary" on:click=move |_| ctx.open_page(&design)>"Open design"</button>
            <button class="btn small" on:click=move |_| ctx.connect.set(Some(id))>"Draw data flow"</button>
            <ArmedDelete on_confirm=move |_| remove(ctx, id) />
        </div>
        {move_controls(ctx, p, n, &page)}
        <div class="stats" style="margin-top:14px">
            <div class="stat"><b>{inside}</b><span>"blocks inside"</span></div>
            <div class="stat open"><b>{r.open}</b><span>{format!("open threats of {}", r.threats)}</span></div>
        </div>
        {(r.review > 0).then(|| view! { <p class="small"><span class="pill st-Open">{format!("{} answers need review", r.review)}</span>" inside this device."</p> })}
    }
}

/// Element id of the justification box of block `id` for `key`.
fn why_id(id: u64, key: &str) -> String {
    let key = key.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "_");
    format!("why-{id}-{key}")
}

/// Justification box; saved while typing, badges refresh when it is left.
pub(super) fn why_box(ctx: Ctx, n: &Node, key: String, label: &'static str) -> impl IntoView {
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

pub(super) fn cm_select(ctx: Ctx, n: &Node, mid: &str, extra_class: &'static str) -> impl IntoView {
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

fn block(ctx: Ctx, p: &Project, m: &Model, n: &Node) -> impl IntoView {
    let page = ctx.page();
    let id = n.id;
    let Some(def) = m.type_of(n).cloned() else {
        return view! { <p class="muted">"Unknown block type."</p> }.into_any();
    };
    let set_answer = move |qid: String, v: Value| {
        ctx.edit(|p, _| {
            if let Some(n) = p.node_mut(id) {
                n.answers.insert(qid.clone(), v);
                n.review.remove(&qid); // a human answered it
            }
        });
    };
    let questions = def.questions.iter().map(|q| {
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
    }).collect_view();
    let pids = m.node_pids(p, n);
    let chips = pids
        .iter()
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
        .collect_view();
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
        {has_q.then(|| view! { <div class="sect"><p class="eyebrow">"Questions"</p>{questions}</div> })}
        {(!pids.is_empty()).then(|| view! { <div class="sect"><p class="eyebrow">"EMB3D properties"</p><div class="pids">{chips}</div></div> })}
        {threats}
    }
    .into_any()
}

fn threats(ctx: Ctx, p: &Project, m: &Model, n: &Node, type_name: &str) -> impl IntoView {
    let hits = m.node_threats(p, n);
    let open = ctx.open_threat.get_untracked();
    let id = n.id;
    let list = hits.iter().map(|h| {
        let st = m.threat_state(n, &h.tid);
        let (rank, mat) = maturity(&h.t.maturity);
        let mut mids: Vec<&String> = h.t.mids.iter().filter(|x| m.mitigation(x).is_some()).collect();
        mids.sort_by_key(|x| mit_rank(&m.mitigation(x).expect("filtered").maturity));
        let cms = mids.iter().map(|mid| {
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
        }).collect_view();
        let none = if h.t.custom { "No countermeasure defined for this custom threat." } else { "EMB3D lists no mitigation for this threat." };
        let cms = if mids.is_empty() { view! { <span class="muted small">{none}</span> }.into_any() } else { cms.into_any() };
        let missing = h.t.mids.iter().any(|x| missing_why(n, x)) || missing_accept_why(n, &h.tid);
        let tid = h.tid.clone();
        let (t1, t2, t3) = (tid.clone(), tid.clone(), tid.clone());
        let more = (!h.t.custom).then(|| view! {
            <div class="row"><button class="linkbtn small" on:click=move |_| ctx.show(Dialog::Detail(vec![t1.clone()]))>"Read more"</button>
            <a class="extlink" href=format!("https://emb3d.mitre.org/threats/{tid}.html") target="_blank" rel="noopener">{format!("{tid} on emb3d.mitre.org ↗")}</a></div>
        });
        let because = if h.t.custom {
            view! { {format!("custom threat of the \"{type_name}\" block")} }.into_any()
        } else {
            h.via.iter().enumerate().map(|(i, pid)| {
                let name = m.e.properties.get(pid).map(|x| x.name.clone()).unwrap_or_default();
                view! { {(i > 0).then_some(", ")}<span class="tid" title=name>{pid.clone()}</span> }
            }).collect_view().into_any()
        };
        let cwes = (!h.t.cwes.is_empty()).then(|| view! {
            <p class="small"><span class="lbl">"Weaknesses"</span>" "{h.t.cwes.iter().enumerate().map(|(i, (c, name))| view! { {(i > 0).then_some("; ")}<span class="tid">{format!("CWE-{c}")}</span>{format!(" {name}")} }).collect_view()}</p>
        });
        let d = decision(n, &h.tid).to_owned();
        let why = (!d.is_empty()).then(|| why_box(ctx, n, format!("accept:{}", h.tid), if d == "na" { "Why does this threat not apply?" } else { "Why is the risk accepted?" }));
        let field = why_id(id, &format!("accept:{}", h.tid));
        view! {
            <details class="threat" data-tid=h.tid.clone() open=open.as_deref() == Some(h.tid.as_str())
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
                    <p class="small"><span class="lbl">"Applies because of"</span>" "{because}</p>
                    {cwes}
                    <div class="cms">{cms}</div>
                    <div class="row small"><label class="lbl">"Decision for this threat"</label>
                        <select class="status" on:change=move |e| {
                            let v = event_target_value(&e);
                            let (tid, set) = (t3.clone(), !v.is_empty());
                            ctx.edit(|p, _| if let Some(n) = p.node_mut(id) { n.accepted.insert(tid, if set { Value::String(v) } else { Value::Bool(false) }); });
                            if set { web::focus(&field); }
                        }>
                            {[("", "Handle with countermeasures"), ("na", "Not applicable"), ("accept", "Accept the risk")].map(|(v, l)| view! { <option value=v selected=d == v>{l}</option> }).collect_view()}
                        </select></div>
                    {why}
                </div>
            </details>
        }
    }).collect_view();
    let count = hits.len();
    view! {
        <div class="sect"><p class="eyebrow">{format!("Threats · {count}")}</p>
            {if count == 0 { view! { <p class="muted small">"No threats for the current answers."</p> }.into_any() } else { list.into_any() }}
        </div>
    }
}

fn flow(ctx: Ctx, p: &Project, page: &str, id: u64) -> impl IntoView {
    let f = p
        .page(page)
        .and_then(|pg| pg.flows.iter().find(|f| f.id == id))
        .cloned()
        .expect("checked");
    let name = |n: u64| p.node(n).map(|x| x.name.clone()).unwrap_or_default();
    let (page1, page2) = (page.to_owned(), page.to_owned());
    let set = move |f: Box<dyn FnOnce(&mut crate::model::Flow)>| {
        let page = page1.clone();
        ctx.edit(move |p, _| {
            if let Some(fl) = p
                .page_mut(&page)
                .and_then(|pg| pg.flows.iter_mut().find(|x| x.id == id))
            {
                f(fl)
            }
        });
    };
    let (s1, s2, s3) = (set.clone(), set.clone(), set);
    view! {
        <p class="eyebrow">"Data flow"</p>
        <h2>{format!("{} → {}", name(f.from), name(f.to))}</h2>
        <div class="field" style="margin-top:14px"><label for="flow-label">"Label"</label>
            <input type="text" id="flow-label" value=f.label.clone() on:input=move |e| {
                let v = event_target_value(&e);
                let page = page2.clone();
                ctx.typing(|p| if let Some(fl) = p.page_mut(&page).and_then(|pg| pg.flows.iter_mut().find(|x| x.id == id)) { fl.label = v });
            } /></div>
        <div class="q"><label class="check"><input type="checkbox" prop:checked=f.encrypted on:change=move |e| { let c = event_target_checked(&e); s1(Box::new(move |f| f.encrypted = c)) } /><span>"Encrypted in transit"</span></label></div>
        <div class="q"><label class="check"><input type="checkbox" prop:checked=f.sensitive on:change=move |e| { let c = event_target_checked(&e); s2(Box::new(move |f| f.sensitive = c)) } /><span>"Carries sensitive data"</span></label></div>
        <p class="small muted">"Dashed lines are unencrypted. EMB3D threats come from component properties, so flows document the design and go into the TM-BOM export."</p>
        <div class="row">
            <button class="btn small" on:click=move |_| s3(Box::new(|f| std::mem::swap(&mut f.from, &mut f.to)))>"Reverse direction"</button>
            <ArmedDelete on_confirm=move |_| {
                let page = ctx.page();
                ctx.edit(|p, _| if let Some(pg) = p.page_mut(&page) { pg.flows.retain(|x| x.id != id) });
                ctx.select(None);
            } />
        </div>
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ui/inspector.rs"]
mod tests;

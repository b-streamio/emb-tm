// SPDX-License-Identifier: GPL-2.0-only
//! Diagram view: library rail and page list, breadcrumbs, the board with its
//! blocks and data flows, and the inspector beside it.

use std::collections::BTreeSet;

use leptos::{ev, html, prelude::*};
use wasm_bindgen::JsCast;

use super::{ctx, dialogs::Dialog, inspector::Inspector, parse, web, Ctx, Sel};
use crate::{
    engine::{anchor, esc, group_class, Counts, Model},
    model::{Flow, Page, Project, NODE_W},
    ops::{self, BOARD_H, BOARD_W},
};

/// A block drag in progress. The project changes once, on release; until
/// then only the dragged blocks and the data flows follow the pointer.
#[derive(Clone)]
struct Drag {
    node: u64,
    /// Dragged blocks and where they started.
    start: Vec<(u64, f64, f64)>,
    px: f64,
    py: f64,
    dx: f64,
    dy: f64,
    moved: bool,
    target: Option<u64>,
    modifier: bool,
}

impl Drag {
    /// Where block `id` of size `(w, h)` is drawn now, if it is being moved.
    fn place(&self, id: u64, (w, h): (f64, f64)) -> Option<(f64, f64)> {
        let (_, x, y) = self
            .start
            .iter()
            .find(|s| s.0 == id)
            .filter(|_| self.moved)?;
        Some((
            (x + self.dx).clamp(0.0, BOARD_W - w),
            (y + self.dy).clamp(0.0, BOARD_H - h),
        ))
    }
}

#[component]
pub fn Diagram() -> impl IntoView {
    let ctx = ctx();
    let board = NodeRef::<html::Div>::new();
    let drag = RwSignal::new(None::<Drag>);
    let drop_target = RwSignal::new(None::<u64>);
    let last_tap = StoredValue::new((0_u64, 0.0_f64));

    // Device box of this page under a screen point, ignoring `skip`.
    let device_at = move |cx: f64, cy: f64, skip: &[u64]| -> Option<u64> {
        let r = board.get_untracked()?.get_bounding_client_rect();
        let (x, y) = (cx - r.left(), cy - r.top());
        let page = ctx.page();
        ctx.project.with_untracked(|p| {
            p.page(&page)?
                .nodes
                .iter()
                .find(|n| {
                    n.is_device()
                        && !skip.contains(&n.id)
                        && x >= n.x
                        && y >= n.y
                        && x <= n.x + n.size().0
                        && y <= n.y + n.size().1
                })
                .map(|n| n.id)
        })
    };

    let move_handle = window_event_listener(ev::pointermove, move |e| {
        let Some(mut d) = drag.get_untracked() else {
            return;
        };
        let (dx, dy) = (
            f64::from(e.client_x()) - d.px,
            f64::from(e.client_y()) - d.py,
        );
        if !d.moved && dx.hypot(dy) < 4.0 {
            return;
        }
        (d.moved, d.dx, d.dy) = (true, dx, dy);
        let ids: Vec<u64> = d.start.iter().map(|s| s.0).collect();
        d.target = device_at(f64::from(e.client_x()), f64::from(e.client_y()), &ids);
        if drop_target.get_untracked() != d.target {
            drop_target.set(d.target);
        }
        drag.set(Some(d));
    });
    let up_handle = window_event_listener(ev::pointerup, move |e| {
        let Some(d) = drag.get_untracked() else {
            return;
        };
        drag.set(None);
        drop_target.set(None);
        if d.moved {
            let ids: Vec<u64> = d.start.iter().map(|s| s.0).collect();
            match d.target {
                Some(dev) => move_into(ctx, &ids, dev),
                None => ctx.edit(|p, _| {
                    for id in &ids {
                        if let Some(n) = p.node_mut(*id) {
                            if let Some((x, y)) = d.place(n.id, n.size()) {
                                (n.x, n.y) = (x, y);
                            }
                        }
                    }
                }),
            }
            return;
        }
        // The board re-renders on every click, so detect a double click by id.
        let now = js_sys::Date::now();
        let is_device = ctx.project.with_untracked(|p| {
            p.node(d.node)
                .filter(|n| n.is_device())
                .and_then(|n| n.page.clone())
        });
        let (last, t) = last_tap.get_value();
        if let (Some(page), true, None) = (
            is_device,
            last == d.node && now - t < 450.0,
            ctx.connect.get_untracked(),
        ) {
            last_tap.set_value((0, 0.0));
            ctx.open_page(&page);
            return;
        }
        last_tap.set_value((d.node, now));
        click_node(ctx, d.node, d.modifier || e.shift_key());
    });
    on_cleanup(move || {
        move_handle.remove();
        up_handle.remove();
    });

    let on_drop = move |e: ev::DragEvent| {
        drop_target.set(None);
        let kind = e
            .data_transfer()
            .and_then(|dt| dt.get_data("text/x-emb3d").ok())
            .unwrap_or_default();
        if kind.is_empty() {
            return;
        }
        e.prevent_default();
        let (cx, cy) = (f64::from(e.client_x()), f64::from(e.client_y()));
        match device_at(cx, cy, &[]) {
            Some(dev) => add_into(ctx, &kind, dev),
            None => {
                let Some(r) = board.get_untracked().map(|b| b.get_bounding_client_rect()) else {
                    return;
                };
                let half = if kind == "device" {
                    110.0
                } else {
                    NODE_W / 2.0
                };
                add_at(
                    ctx,
                    &kind,
                    (cx - r.left() - half).max(0.0),
                    (cy - r.top() - 30.0).max(0.0),
                );
            }
        }
    };

    // Typing changes only names: blocks follow it themselves (`live`).
    let nodes = move || {
        let page = ctx.page();
        let (sel, multi, connecting, target) = (
            ctx.sel.get(),
            ctx.multi.get(),
            ctx.connect.get().is_some(),
            drop_target.get(),
        );
        ctx.counts.with(|c| {
            ctx.with(|p, m| {
                let Some(pg) = p.page(&page) else {
                    return Vec::new();
                };
                pg.nodes
                    .iter()
                    .map(|n| block(ctx, p, m, c, n.id, sel, &multi, connecting, target, drag))
                    .collect::<Vec<_>>()
            })
        })
    };
    let edges = move || {
        ctx.soft.track();
        let (page, sel, d) = (ctx.page(), ctx.sel.get(), drag.get());
        ctx.project
            .with(|p| {
                let pg = p.page(&page)?;
                let Some(d) = d.filter(|d| d.moved) else {
                    return Some(edges_svg(pg, sel));
                };
                let mut pg = pg.clone();
                for n in &mut pg.nodes {
                    if let Some((x, y)) = d.place(n.id, n.size()) {
                        (n.x, n.y) = (x, y);
                    }
                }
                Some(edges_svg(&pg, sel))
            })
            .unwrap_or_default()
    };

    view! {
        <div class="diagram">
            <aside class="rail"><Rail /></aside>
            <section class="boardwrap" node_ref=ctx.wrap>
                <Crumbs />
                <div class="hint" hidden=move || ctx.connect.get().is_none()>
                    <span>"Tap the destination component"</span>
                    <button on:click=move |_| ctx.connect.set(None)>"Cancel"</button>
                </div>
                <div class="board" node_ref=board
                    on:pointerdown=move |e| {
                        let on_background = e.target().and_then(|t| t.dyn_into::<web_sys::Element>().ok())
                            .is_some_and(|el| el.class_list().contains("board") || el.id() == "edges");
                        if on_background && ctx.connect.get_untracked().is_none() && ctx.sel.get_untracked().is_some() {
                            ctx.select(None);
                            ctx.open_threat.set(None);
                        }
                    }
                    on:dragover=move |e: ev::DragEvent| {
                        e.prevent_default();
                        if let Some(dt) = e.data_transfer() { dt.set_drop_effect("copy"); }
                        drop_target.set(device_at(f64::from(e.client_x()), f64::from(e.client_y()), &[]));
                    }
                    on:dragleave=move |_| drop_target.set(None)
                    on:drop=on_drop>
                    <svg id="edges" inner_html=edges
                        on:click=move |e| {
                            let flow = e.target().and_then(|t| t.dyn_into::<web_sys::Element>().ok())
                                .and_then(|el| el.closest("g[data-flow]").ok().flatten())
                                .and_then(|g| g.get_attribute("data-flow")?.parse().ok());
                            if let Some(id) = flow { ctx.select(Some(Sel::Flow(id))); }
                        }></svg>
                    {nodes}
                </div>
            </section>
            <aside class="inspector"><Inspector /></aside>
        </div>
    }
}

/// Selects, extends the selection, or ends a data flow at block `id`.
fn click_node(ctx: Ctx, id: u64, modifier: bool) {
    let sel = ctx.sel.get_untracked();
    if ctx.connect.get_untracked().is_none() && modifier && matches!(sel, Some(Sel::Node(_))) {
        if sel != Some(Sel::Node(id)) {
            ctx.multi.update(|m| {
                if !m.remove(&id) {
                    m.insert(id);
                }
            });
        }
        return;
    }
    ctx.multi.update(BTreeSet::clear);
    if let Some(from) = ctx.connect.get_untracked() {
        ctx.connect.set(None);
        if from != id {
            let page = ctx.page();
            let fid = ctx.edit(|p, _| {
                let fid = p.flow_seq;
                p.flow_seq += 1;
                let f = Flow {
                    id: fid,
                    from,
                    to: id,
                    label: "data flow".into(),
                    encrypted: false,
                    sensitive: false,
                };
                if let Some(pg) = p.page_mut(&page) {
                    pg.flows.push(f);
                }
                fid
            });
            ctx.sel.set(Some(Sel::Flow(fid)));
        }
        return;
    }
    if sel != Some(Sel::Node(id)) {
        ctx.open_threat.set(None);
    }
    ctx.sel.set(Some(Sel::Node(id)));
}

#[allow(clippy::too_many_arguments)]
fn block(
    ctx: Ctx,
    p: &Project,
    m: &Model,
    c: &Counts,
    id: u64,
    sel: Option<Sel>,
    multi: &BTreeSet<u64>,
    connecting: bool,
    target: Option<u64>,
    drag: RwSignal<Option<Drag>>,
) -> impl IntoView {
    let n = p.node(id).expect("on page");
    let def = m.type_of(n);
    let (group, tag, external, custom) = def.map_or(("External", "?", false, false), |d| {
        (d.group.as_str(), d.tag.as_str(), d.external, d.custom)
    });
    let mut class = String::from("node");
    for (on, c) in [
        (external, " ext"),
        (n.is_device(), " device"),
        (custom, " custom"),
        (sel == Some(Sel::Node(id)), " sel"),
        (multi.contains(&id), " sel multi"),
        (connecting, " target"),
        (target == Some(id), " droptarget"),
    ] {
        if on {
            class += c;
        }
    }
    let counts = |open: usize, total: usize, review: usize| {
        let review = (review > 0).then(|| view! { <span class="rvcount" title=format!("{review} answers need review")>{format!("{review}?")}</span> });
        view! { <div class="meta"><span class="dot open">{format!("{open} open")}</span><span class="dot done">{format!("{} handled", total - open)}</span>{review}</div> }
    };
    let meta = if n.is_device() {
        let page = n.page.clone().unwrap_or_default();
        let r = c.page(&page);
        let name = live(ctx, move |p| p.page(&page).map(|pg| pg.name.clone()));
        view! { {counts(r.open, r.threats, r.review)}<div class="devhint">{name}" · double-click to open"</div> }.into_any()
    } else if !external {
        let r = c.node(id);
        counts(r.open, r.threats, r.review).into_any()
    } else {
        view! { <div class="meta">"external"</div> }.into_any()
    };
    let units = n.units();
    let qty = (!units.is_empty()).then(|| view! { <span class="qty">{units}</span> });
    let (x, y, size) = (n.x, n.y, n.size());
    let at = move || {
        drag.with(|d| d.as_ref().and_then(|d| d.place(id, size)))
            .unwrap_or((x, y))
    };
    view! {
        <div class=class tabindex="0" style:left=move || format!("{}px", at().0) style:top=move || format!("{}px", at().1)
            on:pointerdown=move |e| {
                if e.button() != 0 { return; }
                let mut ids = ctx.selected_ids();
                if !ids.contains(&id) { ids = vec![id]; }
                let start = ctx.project.with_untracked(|p| ids.iter().filter_map(|i| p.node(*i)).map(|n| (n.id, n.x, n.y)).collect());
                let modifier = e.ctrl_key() || e.meta_key();
                drag.set(Some(Drag { node: id, start, px: f64::from(e.client_x()), py: f64::from(e.client_y()), dx: 0.0, dy: 0.0, moved: false, target: None, modifier }));
            }
            on:keydown=move |e| if e.key() == "Enter" || e.key() == " " { e.prevent_default(); click_node(ctx, id, false); }>
            <div class="top"><span class=format!("tag {}", group_class(group))>{tag.to_owned()}</span><span class="mono muted">{format!("#{id}")}</span></div>
            <div class="nm">{live(ctx, move |p| p.node(id).map(|n| n.name.clone()))}{qty}</div>
            {meta}
        </div>
    }
}

/// Text that follows the project while the user types.
fn live(
    ctx: Ctx,
    get: impl Fn(&Project) -> Option<String> + Send + Sync + 'static,
) -> impl Fn() -> String {
    move || {
        ctx.soft.track();
        ctx.project.with(|p| get(p).unwrap_or_default())
    }
}

/// Data flows of a page as SVG markup (every value escaped).
fn edges_svg(pg: &Page, sel: Option<Sel>) -> String {
    let mut out = String::from(
        r#"<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrowhead" d="M0,0 L10,5 L0,10 z"></path></marker><marker id="arrSel" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" style="fill:var(--accent)"></path></marker></defs>"#,
    );
    for f in &pg.flows {
        let (Some(a), Some(b)) = (
            pg.nodes.iter().find(|n| n.id == f.from),
            pg.nodes.iter().find(|n| n.id == f.to),
        ) else {
            continue;
        };
        let ((x1, y1), (x2, y2)) = (anchor(a, b), anchor(b, a));
        let on = sel == Some(Sel::Flow(f.id));
        out += &format!(
            r#"<g data-flow="{}"><line class="edge {}{}" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" marker-end="url(#{})"></line><line class="edgehit" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"></line><text class="edgelabel" x="{}" y="{}" text-anchor="middle">{}</text></g>"#,
            f.id,
            if f.encrypted { "enc" } else { "plain" },
            if on { " sel" } else { "" },
            if on { "arrSel" } else { "arr" },
            (x1 + x2) / 2.0,
            (y1 + y2) / 2.0 - 6.0,
            esc(&f.label)
        );
    }
    out
}

/// New block of `kind` at `(x, y)` on the current page, selected.
fn add_at(ctx: Ctx, kind: &str, x: f64, y: f64) {
    let page = ctx.page();
    if let Some(id) = ctx.edit(|p, m| ops::add_node(p, m, kind, &page, x, y)) {
        ctx.select(Some(Sel::Node(id)));
        ctx.open_threat.set(None);
    }
}

/// New block of `kind` in the middle of the visible board.
fn add_visible(ctx: Ctx, kind: &str) {
    let page = ctx.page();
    let k = ctx
        .project
        .with_untracked(|p| p.page(&page).map_or(0, |pg| pg.nodes.len() % 6)) as f64;
    let (x, y) = ctx.wrap.get_untracked().map_or((60.0, 60.0), |w| {
        let (sl, st, cw, ch) = (
            f64::from(w.scroll_left()),
            f64::from(w.scroll_top()),
            f64::from(w.client_width()),
            f64::from(w.client_height()),
        );
        (
            sl + (cw / 2.0 - NODE_W / 2.0).max(20.0) + k * 18.0,
            st + (ch / 2.0 - 40.0).max(20.0) + k * 18.0,
        )
    });
    add_at(ctx, kind, x, y);
}

/// New block of `kind` inside device `dev`.
fn add_into(ctx: Ctx, kind: &str, dev: u64) {
    let Some((page, dev_name)) = ctx.project.with_untracked(|p| {
        p.node(dev)
            .and_then(|d| Some((d.page.clone()?, d.name.clone())))
    }) else {
        return;
    };
    let added = ctx.edit(|p, m| {
        let id = ops::add_node(p, m, kind, &page, 0.0, 0.0)?;
        ops::place_on_page(p.page_mut(&page)?, &[id]);
        Some(m.types.get(kind)?.name.clone())
    });
    if let Some(name) = added {
        ctx.select(Some(Sel::Node(dev)));
        ctx.open_threat.set(None);
        ctx.toast(format!("Added {name} to {dev_name}."));
    }
}

/// Moves blocks into device `dev` and says what happened.
pub fn move_into(ctx: Ctx, ids: &[u64], dev: u64) {
    let page = ctx.page();
    let name = ctx
        .project
        .with_untracked(|p| p.node(dev).map(|d| d.name.clone()).unwrap_or_default());
    match ctx.edit(|p, _| ops::move_into_device(p, &page, ids, dev)) {
        Ok((moved, cut)) => {
            ctx.select(Some(Sel::Node(dev)));
            ctx.open_threat.set(None);
            let cut = match cut {
                0 => String::new(),
                1 => format!(
                    " {} to blocks outside it was removed.",
                    ops::plural(1, "data flow")
                ),
                n => format!(
                    " {} to blocks outside it were removed.",
                    ops::plural(n, "data flow")
                ),
            };
            ctx.toast(format!(
                "Moved {} into {name}.{cut}",
                ops::plural(moved, "block")
            ));
        }
        Err(e) if !e.is_empty() => ctx.toast(e),
        Err(_) => {}
    }
}

/// "Add device from file…": another project or TM-BOM as a device box.
pub fn add_device_from(ctx: Ctx, text: &str) {
    let parsed = parse(text).and_then(Project::from_json);
    let other = match parsed {
        Ok(o) => o,
        Err(e) => return ctx.error("Could not add the device", e),
    };
    let page = ctx.page();
    let k = ctx
        .project
        .with_untracked(|p| p.page(&page).map_or(0, |pg| pg.nodes.len() % 5)) as f64;
    let (sl, st) = ctx.wrap.get_untracked().map_or((0.0, 0.0), |w| {
        (f64::from(w.scroll_left()), f64::from(w.scroll_top()))
    });
    match ctx.edit(|p, m| {
        ops::import_as_device(
            p,
            m,
            other,
            &page,
            sl + 60.0 + k * 30.0,
            st + 60.0 + k * 30.0,
        )
    }) {
        Ok(id) => ctx.select(Some(Sel::Node(id))),
        Err(e) => ctx.error("Could not add the device", e),
    }
}

/// "Import blocks…": the block types of a project, TM-BOM or component
/// library file.
pub fn import_types(ctx: Ctx, text: &str) {
    match parse(text).and_then(|v| ctx.edit(|p, m| ops::import_types(p, m, v))) {
        Ok((0, 0)) => ctx.toast("This file has no block types."),
        Ok((added, had)) => {
            let skipped = if had > 0 {
                format!(
                    " Skipped {} the project already has.",
                    ops::plural(had, "type")
                )
            } else {
                String::new()
            };
            ctx.toast(format!(
                "Imported {}.{skipped}",
                ops::plural(added, "block type")
            ));
        }
        Err(e) => ctx.error("Could not import the blocks", e),
    }
}

#[component]
fn Rail() -> impl IntoView {
    let ctx = ctx();
    let item = move |kind: String,
                     name: String,
                     group: String,
                     tag: String,
                     hint: String,
                     custom: bool| {
        let (k1, k2, k3) = (kind.clone(), kind.clone(), kind);
        let edit = custom.then(|| {
            let label = format!("Edit {name}");
            view! { <button class="iconbtn" title=label.clone() aria-label=label on:click=move |_| ctx.show(Dialog::Custom { existing: Some(k3.clone()), copy_of: None })>"✎"</button> }
        });
        view! {
            <div class="libitem-row">
                <button class="libitem" draggable="true" title=hint
                    on:click=move |_| add_visible(ctx, &k1)
                    on:dragstart=move |e: ev::DragEvent| if let Some(dt) = e.data_transfer() {
                        let _ = dt.set_data("text/x-emb3d", &k2);
                        dt.set_effect_allowed("copy");
                    }>
                    <span class=format!("tag {}", group_class(&group))>{tag}</span><span class="libname">{name.clone()}</span>
                </button>
                {edit}
            </div>
        }
    };
    let groups = move || {
        ctx.with(|_, m| {
            let lib = m.lib.groups.iter().map(|g| {
                let items = m.lib.components.iter().filter(|c| &c.group == g).map(|c| item(c.kind.clone(), c.name.clone(), c.group.clone(), c.tag.clone(), c.hint.clone(), false)).collect_view();
                view! { <div class="group"><p class="eyebrow">{g.clone()}</p><div class="lib">{items}</div></div> }
            }).collect_view();
            let customs = m.types.values().filter(|t| t.custom).map(|c| item(c.kind.clone(), c.name.clone(), c.group.clone(), c.tag.clone(), c.hint.clone(), true)).collect_view();
            view! {
                {lib}
                <div class="group"><p class="eyebrow">"Custom blocks"</p><div class="lib">{customs}
                    <button class="libitem addcustom" on:click=move |_| ctx.show(Dialog::Custom { existing: None, copy_of: None })>
                        <span class="tag k-Custom">"+"</span><span class="libname">"New custom block"</span>
                    </button>
                    <button class="libitem addcustom" title="Block types from a project, a TM-BOM or a component library file" on:click=move |_| web::click("typesFile")>
                        <span class="tag k-Custom">"↓"</span><span class="libname">"Import blocks…"</span>
                    </button>
                </div></div>
            }
        })
    };
    view! {
        <Pages />
        <div class="groups">{groups}</div>
        <p class="note">"Tap or drag a block onto the board, or drop it on a Device box to put it inside. Drag blocks onto a Device box to move them in; shift-click selects several; Ctrl/⌘ C, X, V copy, cut and paste (into the selected Device box). Custom blocks carry the EMB3D properties and threats you give them."</p>
    }
}

#[component]
fn Pages() -> impl IntoView {
    let ctx = ctx();
    let list = move || {
        ctx.soft.track();
        let cur = ctx.page();
        let c = ctx.counts.get();
        ctx.project.with(|p| {
            let order = p.page_order();
            let mut depth = std::collections::BTreeMap::from([(p.root.clone(), 0_usize)]);
            for pg in &order {
                let d = depth.get(&pg.id).copied().unwrap_or(0);
                for n in pg.nodes.iter().filter(|n| n.is_device()) {
                    depth.entry(n.page.clone().unwrap_or_default()).or_insert(d + 1);
                }
            }
            let multi = p.pages.len() > 1;
            order.iter().map(|pg| {
                let r = c.page(&pg.id);
                let unused = pg.id != p.root && p.parents_of(&pg.id).is_empty();
                let name = if pg.id == p.root && multi { "System".to_owned() } else { pg.name.clone() };
                let (id, id2) = (pg.id.clone(), pg.id.clone());
                let pad = format!("{}px", 8 + depth.get(&pg.id).copied().unwrap_or(0) * 14);
                let del = unused.then(|| {
                    let armed = RwSignal::new(false);
                    let label = format!("Delete page {}", pg.name);
                    view! {
                        <button class="iconbtn" class:armed=move || armed.get() title=label.clone() aria-label=label on:click=move |_| {
                            if !armed.get_untracked() {
                                armed.set(true);
                                set_timeout(move || armed.try_set(false).map_or((), |_| ()), std::time::Duration::from_secs(3));
                                return;
                            }
                            let id = id2.clone();
                            ctx.edit(|p, _| p.pages.retain(|x| x.id != id));
                        }>{move || if armed.get() { "Delete?" } else { "×" }}</button>
                    }
                });
                view! {
                    <li>
                        <button class="pagebtn" class:cur=pg.id == cur style:padding-left=pad on:click=move |_| ctx.open_page(&id)>
                            <span class="pn">{name}</span>{unused.then(|| view! { <span class="unused">"unused"</span> })}<span class="pc">{r.open}</span>
                        </button>
                        {del}
                    </li>
                }
            }).collect_view()
        })
    };
    view! {
        <div class="pagesbox">
            <p class="eyebrow">"Pages"</p>
            <ul class="pagelist">{list}</ul>
            <button class="btn small wide" on:click=move |_| web::click("devFile")>"Add device from file…"</button>
        </div>
    }
}

/// Root … current page, following the first device box that uses each page.
pub fn page_path(p: &Project, id: &str) -> Vec<(String, String)> {
    let mut path = Vec::new();
    let mut cur = p.page(id);
    for _ in 0..30 {
        let Some(pg) = cur else { break };
        path.insert(
            0,
            (
                pg.id.clone(),
                if pg.id == p.root {
                    "System".into()
                } else {
                    pg.name.clone()
                },
            ),
        );
        if pg.id == p.root {
            break;
        }
        cur = p.parents_of(&pg.id).first().and_then(|d| p.page_of(d.id));
    }
    if path.first().is_some_and(|(i, _)| *i != p.root) && p.page(&p.root).is_some() {
        path.insert(0, (p.root.clone(), "System".into()));
    }
    path
}

#[component]
fn Crumbs() -> impl IntoView {
    let ctx = ctx();
    move || {
        ctx.soft.track();
        let cur = ctx.page();
        ctx.project.with(|p| {
            (p.pages.len() > 1).then(|| {
                let path = page_path(p, &cur);
                let last = path.len() - 1;
                let items = path.into_iter().enumerate().map(|(i, (id, name))| {
                    if i < last {
                        view! { <button class="crumb" on:click=move |_| ctx.open_page(&id)>{name}</button><span class="sep">"›"</span> }.into_any()
                    } else {
                        view! { <span class="crumb here">{name}</span> }.into_any()
                    }
                }).collect_view();
                view! { <nav class="crumbs" aria-label="Page path">{items}</nav> }
            })
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ui/board.rs"]
mod tests;

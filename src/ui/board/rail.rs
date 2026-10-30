// SPDX-License-Identifier: GPL-2.0-only
//! The library rail: the page list and the blocks to add.

use leptos::{ev, prelude::*};

use super::{actions::add_visible, pages::Pages};
use crate::{
    engine::group_class,
    ui::{ctx, dialogs::Dialog, web},
};

#[component]
pub(super) fn Rail() -> impl IntoView {
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

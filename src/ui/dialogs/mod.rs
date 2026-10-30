// SPDX-License-Identifier: GPL-2.0-only
//! Dialogs: templates for New, the EMB3D reader, information panels,
//! switching EMB3D release, checking for a new release and the custom block
//! editor.

mod custom;
mod detail;
mod updates;

use std::sync::Arc;

use leptos::prelude::*;

use super::{ctx, example, examples, Ctx, Example};
use crate::{
    model::{CustomType, Project},
    stix::Emb3d,
};
use custom::CustomEditor;
use detail::detail;
pub use updates::{check_updates, propose_version, Updates};
use updates::{updates_panel, version_panel};

const MITRE: &str = "https://emb3d.mitre.org";

#[derive(Clone)]
pub enum Dialog {
    /// New: the examples to start from (an empty project is always offered).
    Templates(Vec<Example>),
    Info {
        title: String,
        text: String,
    },
    /// Reader history: threat and mitigation ids, last shown.
    Detail(Vec<String>),
    Custom {
        existing: Option<String>,
        copy_of: Option<CustomType>,
    },
    Version(Arc<Emb3d>),
    Updates(Updates),
}

#[component]
pub fn Host() -> impl IntoView {
    let ctx = ctx();
    let close = move || ctx.dialog.set(None);
    move || {
        ctx.dialog.get().map(|d| {
            let body = match d {
                Dialog::Templates(list) => templates_panel(ctx, list),
                Dialog::Info { title, text } => frame(view! { <h3>{title}</h3><p class="pre">{text}</p> }, None, false),
                Dialog::Detail(stack) => detail(ctx, stack),
                Dialog::Custom { existing, copy_of } => view! { <CustomEditor existing=existing copy_of=copy_of /> }.into_any(),
                Dialog::Version(next) => version_panel(ctx, next),
                Dialog::Updates(u) => updates_panel(ctx, u),
            };
            view! {
                <div class="overlay" on:click=move |e| if e.target() == e.current_target() { close() }>{body}</div>
            }
        })
    }
}

/// The reader's modal frame with an optional primary action.
fn frame(
    content: impl IntoView + 'static,
    action: Option<(String, Callback<()>)>,
    back: bool,
) -> AnyView {
    let ctx = ctx();
    let cancel = if action.is_some() { "Cancel" } else { "Close" };
    let close = move |_| {
        if matches!(ctx.dialog.get_untracked(), Some(Dialog::Version(_))) {
            ctx.emb3d.notify(); // puts the version selector back
        }
        ctx.dialog.set(None);
    };
    view! {
        <div class="modal" role="dialog" aria-modal="true" aria-label="EMB3D details">
            <div class="detail">{content}</div>
            <footer>
                {back.then(|| view! { <button class="btn" on:click=move |_| ctx.dialog.update(|d| if let Some(Dialog::Detail(s)) = d { s.pop(); })>"Back"</button> })}
                <button class="btn" on:click=close>{cancel}</button>
                {action.map(|(label, run)| view! { <button class="btn primary" on:click=move |_| run.run(())>{label}</button> })}
            </footer>
        </div>
    }
    .into_any()
}

/// New: an empty project or one of the examples of `examples/index.json`.
pub fn templates(ctx: Ctx) {
    leptos::task::spawn_local(async move {
        // Offline without a cached index, only the empty project is offered.
        ctx.show(Dialog::Templates(examples().await.unwrap_or_default()));
    });
}

fn templates_panel(ctx: Ctx, list: Vec<Example>) -> AnyView {
    // The example is fetched only when it is picked.
    let pick = move |x: Option<Example>| {
        leptos::task::spawn_local(async move {
            let p = match x {
                Some(x) => example(&x).await,
                None => {
                    let mut p = Project::empty();
                    p.emb3d = Some(ctx.emb3d.get_untracked().version.clone());
                    Ok(p)
                }
            };
            ctx.dialog.set(None);
            if let Err(e) = p.and_then(|p| ctx.open(p)) {
                ctx.error("Could not open the template", e);
            }
        })
    };
    let items = std::iter::once(None)
        .chain(list.into_iter().map(Some))
        .map(|x| {
            let (name, about) = x.as_ref().map_or_else(
                || ("Empty project".to_owned(), "A blank System page".to_owned()),
                |x| (x.name.clone(), x.description.clone()),
            );
            view! { <li><button class="linkbtn" title=about on:click=move |_| pick(x.clone())>{name}</button></li> }
        })
        .collect_view();
    let content = view! {
        <h3>"New project"</h3>
        <p class="small muted">"The current project is replaced. Save it first to keep a copy."</p>
        <ul class="tpl">{items}</ul>
    };
    let save = Callback::new(move |()| ctx.save_file());
    frame(content, Some(("Save current project".into(), save)), false)
}

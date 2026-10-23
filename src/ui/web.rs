// SPDX-License-Identifier: GPL-2.0-only
//! The few browser APIs the app uses, wrapped so that failures (private
//! mode, offline, blocked clipboard) degrade quietly.

use serde_json::Value;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;

fn window() -> Option<web_sys::Window> {
    web_sys::window()
}

pub fn store(key: &str, value: &str) {
    if let Some(s) = window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = s.set_item(key, value);
    }
}

pub fn load(key: &str) -> Option<String> {
    window()?.local_storage().ok()??.get_item(key).ok()?
}

#[wasm_bindgen]
extern "C" {
    /// The browser's gzip inflater (web-sys has it behind an unstable flag).
    type DecompressionStream;
    #[wasm_bindgen(constructor, catch)]
    fn new(format: &str) -> Result<DecompressionStream, JsValue>;
}

/// GET `url` and parse it as JSON.
pub async fn fetch_json(url: &str) -> Result<Value, String> {
    let text = fetch_text(url).await?;
    serde_json::from_str(&text).map_err(|e| format!("{url}: {e}"))
}

/// GET the gzip file `url` (`make build` compresses the EMB3D releases) and
/// parse the JSON inside.
pub async fn fetch_gzip_json(url: &str) -> Result<Value, String> {
    let body = get(url).await?.body().ok_or("no body")?;
    let gunzip = DecompressionStream::new("gzip")
        .map_err(|_| "this browser cannot read gzip files (DecompressionStream)")?;
    let inflated = body.pipe_through(gunzip.unchecked_ref());
    let res = web_sys::Response::new_with_opt_readable_stream(Some(&inflated))
        .map_err(|_| format!("{url}: unreadable"))?;
    let text = text(res).await.map_err(|e| format!("{url}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{url}: {e}"))
}

pub async fn fetch_text(url: &str) -> Result<String, String> {
    text(get(url).await?).await
}

async fn get(url: &str) -> Result<web_sys::Response, String> {
    let w = window().ok_or("no window")?;
    let res: web_sys::Response = JsFuture::from(w.fetch_with_str(url))
        .await
        .map_err(|_| format!("{url}: network error"))?
        .unchecked_into();
    if !res.ok() {
        return Err(format!("{url}: HTTP {}", res.status()));
    }
    Ok(res)
}

async fn text(res: web_sys::Response) -> Result<String, String> {
    let text = JsFuture::from(res.text().map_err(|_| "no body")?)
        .await
        .map_err(|_| "body read failed")?;
    text.as_string().ok_or_else(|| "body is not text".into())
}

/// Text of the file chosen in the `<input type=file>` behind `ev`; the input is reset.
pub async fn read_file(ev: &web_sys::Event) -> Option<String> {
    let input: web_sys::HtmlInputElement = ev.target()?.dyn_into().ok()?;
    let file = input.files()?.get(0)?;
    input.set_value("");
    JsFuture::from(file.text()).await.ok()?.as_string()
}

/// Saves `text` as the file `name` through the browser's downloads: works
/// offline and in the installed app.
pub fn download(name: &str, text: &str) {
    let Some(doc) = window().and_then(|w| w.document()) else {
        return;
    };
    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type("application/json");
    let parts = js_sys::Array::of1(&text.into());
    let Ok(url) = web_sys::Blob::new_with_str_sequence_and_options(&parts, &opts)
        .and_then(|b| web_sys::Url::create_object_url_with_blob(&b))
    else {
        return;
    };
    if let Ok(a) = doc.create_element("a") {
        let a: web_sys::HtmlAnchorElement = a.unchecked_into();
        a.set_href(&url);
        a.set_download(name);
        a.click();
    }
    // Some browsers read the URL after `click` returns.
    leptos::prelude::set_timeout(
        move || {
            let _ = web_sys::Url::revoke_object_url(&url);
        },
        std::time::Duration::from_secs(10),
    );
}

pub fn write_clipboard(text: &str) {
    if let Some(w) = window() {
        let _ = w.navigator().clipboard().write_text(text);
    }
}

/// macOS or iOS: shortcuts use ⌘ instead of Ctrl.
pub fn apple() -> bool {
    window()
        .and_then(|w| w.navigator().user_agent().ok())
        .is_some_and(|ua| ua.contains("Mac") || ua.contains("iPhone") || ua.contains("iPad"))
}

/// Focus is in a text field or a select.
pub fn typing_in_field() -> bool {
    let tag = window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element())
        .map(|e| e.tag_name().to_lowercase());
    matches!(tag.as_deref(), Some("input" | "textarea" | "select"))
}

pub fn has_text_selection() -> bool {
    window()
        .and_then(|w| w.get_selection().ok().flatten())
        .and_then(|s| s.to_string().as_string())
        .is_some_and(|s| !s.is_empty())
}

pub fn print(title: &str) {
    let Some(w) = window() else { return };
    let doc = w.document();
    let old = doc.as_ref().map(|d| d.title()).unwrap_or_default();
    if let Some(d) = &doc {
        d.set_title(title);
    }
    let _ = w.print();
    if let Some(d) = &doc {
        d.set_title(&old);
    }
}

/// Installs the offline cache (`sw.js`).
pub fn register_service_worker() {
    if let Some(w) = window() {
        let _ = w.navigator().service_worker().register("sw.js");
    }
}

fn element(id: &str) -> Option<web_sys::HtmlElement> {
    window()?.document()?.get_element_by_id(id)?.dyn_into().ok()
}

/// Focuses the element with this id, once it is in the page.
pub fn focus(id: &str) {
    let id = id.to_owned();
    leptos::prelude::request_animation_frame(move || {
        if let Some(e) = element(&id) {
            let _ = e.focus();
        }
    });
}

/// Clicks the element with this id (opens a hidden file input).
pub fn click(id: &str) {
    if let Some(e) = element(id) {
        e.click();
    }
}

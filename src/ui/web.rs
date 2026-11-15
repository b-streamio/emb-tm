// SPDX-License-Identifier: GPL-2.0-only
//! The few browser APIs the app uses, wrapped so that failures (private
//! mode, offline, blocked clipboard) degrade quietly.

use serde_json::Value;
use wasm_bindgen::JsCast;
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

/// GET `url` and parse it as JSON.
pub async fn fetch_json(url: &str) -> Result<Value, String> {
    let text = fetch_text(url).await?;
    serde_json::from_str(&text).map_err(|e| format!("{url}: {e}"))
}

pub async fn fetch_text(url: &str) -> Result<String, String> {
    text(get(url, &web_sys::RequestInit::new()).await?).await
}

/// The EMB3D releases downloaded from MITRE, apart from the service
/// worker's cache of the app itself.
const DATA_CACHE: &str = "emb-tm-emb3d";

async fn data_cache() -> Option<web_sys::Cache> {
    let caches = window()?.caches().ok()?;
    Some(
        JsFuture::from(caches.open(DATA_CACHE))
            .await
            .ok()?
            .unchecked_into(),
    )
}

/// `url` from the data cache, when it was downloaded before.
pub async fn cached(url: &str) -> Option<web_sys::Response> {
    let hit = JsFuture::from(data_cache().await?.match_with_str(url))
        .await
        .ok()?;
    hit.dyn_into().ok()
}

/// JSON at `url`: from the data cache, else downloaded, checked by the
/// browser against `sri` (`sha256-…`) and kept in the cache for offline use.
pub async fn data_json(url: &str, sri: &str) -> Result<Value, String> {
    let res = match cached(url).await {
        Some(res) => res,
        None => {
            let init = web_sys::RequestInit::new();
            init.set_integrity(sri);
            let res = get(url, &init).await?;
            if let (Some(c), Ok(copy)) = (data_cache().await, res.clone()) {
                let _ = JsFuture::from(c.put_with_str(url, &copy)).await;
            }
            res
        }
    };
    let text = text(res).await.map_err(|e| format!("{url}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{url}: {e}"))
}

async fn get(url: &str, init: &web_sys::RequestInit) -> Result<web_sys::Response, String> {
    let w = window().ok_or("no window")?;
    let res: web_sys::Response = JsFuture::from(w.fetch_with_str_and_init(url, init))
        .await
        .map_err(|_| format!("{url}: network error, or the file did not match its checksum"))?
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

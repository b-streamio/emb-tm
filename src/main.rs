// SPDX-License-Identifier: GPL-2.0-only
//! `emb-tm`: the browser app on wasm32, the command line
//! everywhere else.

#[cfg(target_arch = "wasm32")]
fn main() {
    emb_tm::ui::start();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    std::process::exit(emb_tm::cli::main(std::env::args().skip(1).collect()));
}

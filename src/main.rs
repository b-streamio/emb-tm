//! `emb3d-wb`: the browser app on wasm32, the command line
//! everywhere else.

#[cfg(target_arch = "wasm32")]
fn main() {
    emb3d_wb::ui::start();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    std::process::exit(emb3d_wb::cli::main(std::env::args().skip(1).collect()));
}

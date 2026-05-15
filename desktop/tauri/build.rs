// Drives tauri-build's compile-time setup: reads tauri.conf.json, wires
// up the invoke handler permissions, generates the context the Rust
// runtime expects. Kept separate from main.rs because tauri-build is a
// build-dependency only.

fn main() {
    tauri_build::build()
}

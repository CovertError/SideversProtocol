// Build script: regenerate `include/sidevers.h` from the FFI crate's source.
//
// The generated header is committed to the repo so consumers (mobile build
// pipelines, language-binding generators) don't need cbindgen installed.

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(v) => v,
        Err(_) => {
            // Build scripts always get CARGO_MANIFEST_DIR; if it's missing
            // we're being invoked in a strange way — bail without failing.
            println!("cargo:warning=CARGO_MANIFEST_DIR unset; skipping header generation");
            return;
        }
    };
    let out_dir = PathBuf::from(&crate_dir).join("include");
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        println!("cargo:warning=could not create include/ dir: {e}");
        return;
    }
    let out_path = out_dir.join("sidevers.h");

    // Tell cargo to re-run when our sources or config change.
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");

    // Skip header generation when running under rust-analyzer / docs.rs, or
    // when cross-compiling — cbindgen needs to be able to parse the local
    // source tree, which doesn't require the target compiler.
    let config =
        cbindgen::Config::from_file(format!("{crate_dir}/cbindgen.toml")).unwrap_or_default();

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&out_path);
        }
        Err(e) => {
            // Don't fail the build if header generation fails — the cdylib
            // still compiles. CI does a separate pass.
            println!("cargo:warning=cbindgen header generation failed: {e}");
        }
    }
}

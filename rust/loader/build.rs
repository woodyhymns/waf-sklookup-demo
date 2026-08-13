use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"));
    let repo_root = manifest_dir
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root");
    let src = repo_root.join("dispatch.bpf.c");
    let headers = repo_root.join("bpf/headers");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("dispatch.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH must be set");
    let gnu_inc = format!("/usr/include/{arch}-linux-gnu");

    SkeletonBuilder::new()
        .source(src.to_str().expect("dispatch.bpf.c path is valid UTF-8"))
        .clang_args([
            format!("-I{gnu_inc}"),
            format!("-I{}", headers.display()),
            "-I/usr/include".to_string(),
        ])
        .build_and_generate(&out)
        .unwrap_or_else(|e| {
            panic!(
                "failed to compile {} via libbpf-cargo (same clang object as Go bpf2go): {e}",
                src.display()
            )
        });

    println!("cargo:rerun-if-changed={}", src.display());
    println!(
        "cargo:rerun-if-changed={}",
        headers.join("bpf_helpers.h").display()
    );
}

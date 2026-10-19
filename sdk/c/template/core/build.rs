//! Reads FZ_ABI_VERSION out of ../libfiberzygote.h, so the crate checks
//! its own constant against the header at compile time (src/lib.rs). The
//! header stays hand-kept, nothing here writes it.

use std::{env, fs, path::Path};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let header = Path::new(&manifest).join("..").join("libfiberzygote.h");
    println!("cargo:rerun-if-changed={}", header.display());
    let text = fs::read_to_string(&header).unwrap_or_else(|e| panic!("{}: {e}", header.display()));
    let version = text
        .lines()
        .find_map(|l| l.strip_prefix("#define FZ_ABI_VERSION "))
        .map(str::trim)
        .expect("libfiberzygote.h defines FZ_ABI_VERSION");
    println!("cargo:rustc-env=FZ_HEADER_ABI_VERSION={version}");
}

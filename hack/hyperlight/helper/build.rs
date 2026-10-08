//! Hands main.rs the hyperlight-host version this helper is built with,
//! read from Cargo.lock so the fact fiberd records is the crate that
//! wrote the snapshots, never a string kept by hand.

use std::fs;
use std::path::Path;

fn main() {
    let lock = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    let text = fs::read_to_string(&lock).expect("read Cargo.lock");
    let version = hyperlight_host_version(&text).expect("hyperlight-host in Cargo.lock");
    println!("cargo:rustc-env=HYPERLIGHT_HOST_VERSION={version}");
}

/// The `version` line of the `[[package]]` named hyperlight-host.
fn hyperlight_host_version(lock: &str) -> Option<String> {
    let mut in_pkg = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_pkg = false;
        } else if line == "name = \"hyperlight-host\"" {
            in_pkg = true;
        } else if in_pkg {
            if let Some(v) = line.strip_prefix("version = ") {
                return Some(v.trim_matches('"').to_string());
            }
        }
    }
    None
}

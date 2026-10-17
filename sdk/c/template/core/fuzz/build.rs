//! Compiles the frozen C parser of main (csrc/record.c) for the
//! record_diff target. It reads the live header, so a header change
//! rebuilds it too.

fn main() {
    println!("cargo:rerun-if-changed=csrc/record.c");
    println!("cargo:rerun-if-changed=../../libfiberzygote.h");
    cc::Build::new()
        .file("csrc/record.c")
        .opt_level(2)
        .warnings(true)
        .compile("record_c");
}

//! Compiles the C reference in csrc/, record.c for record_diff and
//! line.c for line_diff. record.c reads the live header, so a header
//! change rebuilds it too.

fn main() {
    println!("cargo:rerun-if-changed=csrc/record.c");
    println!("cargo:rerun-if-changed=csrc/line.c");
    println!("cargo:rerun-if-changed=../../libfiberzygote.h");
    cc::Build::new()
        .file("csrc/record.c")
        .opt_level(2)
        .warnings(true)
        .compile("record_c");
    cc::Build::new()
        .file("csrc/line.c")
        .opt_level(2)
        .warnings(true)
        .compile("line_c");
}

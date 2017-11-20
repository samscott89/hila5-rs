// build.rs

extern crate cc;

fn main() {
    cc::Build::new()
        .file("hila5/KAT/src/rng.c")
        // .flag("-lcrypto")
        // .flag("-lssl")
        // .flag("-std=c99")
        // .include("/usr/include/")
        // .file("hila5/KAT/src/rng.h")
        .compile("kat");

    println!("cargo:rustc-link-lib=crypto");
}
extern crate cc;


fn main() {
    cc::Build::new()
        .file("hila5/KAT/src/rng.c")
        .compile("kat");

    cc::Build::new()
        .files(&[
            "hila5/Optimized_Implementation/kem.c",
            "hila5/Optimized_Implementation/ms_ntt.c",
            "hila5/Optimized_Implementation/ms_ntt_const.c",
            "hila5/Optimized_Implementation/hila5_sha3_opt.c",
        ])
        .compile("hila5_c");

    println!("cargo:rustc-link-lib=crypto");
}
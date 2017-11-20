extern crate cc;


fn main() {
    cc::Build::new()
        .file("hila5/KAT/src/rng.c")
        .warnings(false)
        .compile("kat");

    cc::Build::new()
        .opt_level_str("fast")
        .warnings(true)
        .warnings_into_errors(true)
        .files(&[
            "hila5/Optimized_Implementation/kem.c",
            "hila5/Optimized_Implementation/ms_ntt.c",
            "hila5/Optimized_Implementation/ms_ntt_const.c",
            "hila5/Optimized_Implementation/hila5_sha3_opt.c",
        ])
        .compile("hila5_c");

    println!("cargo:rustc-link-lib=crypto");
}
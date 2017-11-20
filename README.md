Rust HILA5 Implementation
========================

This is a pure-Rust implementation of the HILA5 PQC public key
encryption/encapsulation mechanism.

The original code this was based on is [here](https://github.com/mjosaarinen/hila5/)
and more details of the algorithm can be found [here](https://mjos.fi/hila5/).

## Usage

Requires Rust. On cloning the respository, make sure to initialise submodules
(we use the original codebase for benchmarks and test data).

Documentation can be generated with `cargo doc --no-deps --open`, run the
full KAT tests with `cargo test --features=kat`. Otherwise, this library can
be included in projects with `hila5 = { git = "https://github.com/samscott89/hila5-rs" }`.

There are currently no plans to publish this on crates.io.

## Warnings

This code has not been audited, nor thoroughly checked or tested and should only
be used for testing purposes. There are currently no plans to
maintain/support/package this library.

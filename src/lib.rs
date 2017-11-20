//! Rust implementation of [HILA5](https://mjos.fi/hila5/).
//!
//! This is a Rust port of the [HILA5 KEM](https://github.com/mjosaarinen/hila5). Reference document: [pdf](https://github.com/mjosaarinen/hila5/raw/master/Supporting_Documentation/hila5spec.pdf). Website: [https://mjos.fi/hila5/](https://mjos.fi/hila5/)
//!
//! ## Examples
//!
//! The main way of using this library is through the `PublicKey` and
//! `PrivateKey` structs, and the `enc`/`dec` methods.
//!
//! ```rust
//! extern crate hila5;
//!
//! use hila5::{kem, PublicKey, PrivateKey};
//!
//! fn main() {
//!     // Bob generates keypair, and published `pkB`.
//!     let (pk_bob, sk_bob) = hila5::crypto_kem_keypair().unwrap();
//!
//!     // Alice constructs ciphertext for Bob, and has shared secret `ssA`.
//!     let (ct, ss_alice) = pk_bob.enc().unwrap();
//!
//!     // sends `ct` to Bob ...
//!
//!     // Bob recovers `ssB`
//!     let ss_bob = sk_bob.dec(&ct).unwrap();
//!
//!     // Alice and Bob should have matching shared secrets
//!     assert_eq!(ss_alice.0, ss_bob.0)
//! }
//!
//! ```
//!
//! We also provide `crypto_kem_enc` and `crypto_kem_dec` methods to be closer
//! to the original methods.
//!
//! ## Features
//!
//! The default features are `["opt"]`.  The `opt` feature is used to
//! specify the optimised NTT methods based on
//! Microsoft's [LatticeCrypto](https://www.microsoft.com/en-us/research/project/lattice-cryptography-library/)
//!
//! The `kat` feature is used to run the KAT tests, and uses a seeded RNG for
//! predictable outputs. Do not use this feature other than for testing.

extern crate byteorder;
extern crate digest;
#[macro_use]
extern crate error_chain;
#[cfg(not(feature = "opt"))]
#[macro_use]
extern crate lazy_static;
extern crate sha3;
extern crate ring;

use sha3::{Digest, Sha3_256};

#[cfg(not(feature = "opt"))]
mod arith;
mod ecc;
mod encode;
/// Key encapsulation/decapsulation methods.
pub mod kem;
mod keygen;
#[cfg(feature = "opt")]
mod opt;
#[cfg(feature = "opt")]
use opt::arith;
mod rand;
mod recon;


/// Error handling and conversion
pub mod errors {
    use ring;
    use std::{fmt, io};
    error_chain! {
        foreign_links {
            Fmt(fmt::Error);
            Io(io::Error);
            Ring(ring::error::Unspecified) #[doc = "Errors originating from `ring`"];
        }
    }
}

use errors::*;

#[doc(inline)]
pub use keygen::{crypto_kem_keypair, PrivateKey, PublicKey};
#[doc(inline)]
pub use kem::SharedSecret;

/// Key encapsulation
pub fn crypto_kem_enc(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = PublicKey::from_bytes(pk);
    kem::enc(&pk).map(|(ct, ss)| (ct, ss.0))
}

/// Key decapsulation
pub fn crypto_kem_dec(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let sk = PrivateKey::from_bytes(sk);
    kem::dec(ct, &sk).map(|ss| ss.0)
}

/// Lattice Dimension
pub const HILA5_N: usize = 1024;
/// Lattice Modulus
pub const HILA5_Q: i32 = 12_289;

/// Length in bytes of `PublicKey` on calling `write_to`.
pub const PUBKEY_LEN: usize = rand::SEED_LEN + encode::PACKED14;
/// Length in bytes of `PrivateKey` on calling `write_to`.
pub const PRIVKEY_LEN: usize = encode::PACKED14 + 32;
/// Output ciphertext len from `kem::dec`
pub const CIPHERTEXT_LEN: usize = encode::PACKED14 + (HILA5_N / 8) + recon::PAYLOAD_LEN + recon::ECC_LEN;

pub type Scalar = i32;
/// Standard vector type
pub struct Vector([Scalar; HILA5_N]);
/// Vector mapped under the NTT transform.
pub struct NttVector([Scalar; HILA5_N]);

use std::fmt;
impl fmt::Debug for Vector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Vector([{}...])", self.0[0..5].iter().fold("".to_string(), |acc, &x| acc + &x.to_string() + ", "))
    }
}

impl fmt::Debug for NttVector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NttVector([{}...])", self.0[0..5].iter().fold("".to_string(), |acc, &x| acc +  &x.to_string() + ", "))
    }
}

/// Trait for methods agnostic over `Vector` or `NttVector` types.
pub trait Hila5Vector: From<[Scalar; HILA5_N]> {
    fn get_inner(&self) -> &[Scalar; HILA5_N];
    fn get_inner_mut(&mut self) -> &mut [Scalar; HILA5_N];

    #[cfg(feature = "opt")]
    fn norm(&mut self) {
        arith::correction(self);
    }

    #[cfg(not(feature = "opt"))]
    fn norm(&mut self) {
        for vi in self.get_inner_mut().iter_mut() {
            *vi = (*vi + 3 * HILA5_Q) % HILA5_Q;
        }
    }
}

impl Hila5Vector for Vector {
    fn get_inner(&self) -> &[Scalar; HILA5_N] {
        &self.0
    }

    fn get_inner_mut(&mut self) -> &mut [Scalar; HILA5_N] {
        &mut self.0
    }
}

impl Hila5Vector for NttVector {
    fn get_inner(&self) -> &[Scalar; HILA5_N] {
        &self.0
    }

    fn get_inner_mut(&mut self) -> &mut [Scalar; HILA5_N] {
        &mut self.0
    }
}

impl From<[Scalar; HILA5_N]> for Vector {
    fn from(other: [Scalar; HILA5_N]) -> Self {
        Vector(other)
    }
}

impl From<[Scalar; HILA5_N]> for NttVector {
    fn from(other: [Scalar; HILA5_N]) -> Self {
        NttVector(other)
    }
}

/// Convenience function for producing SHA3 hash
fn sha3(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::default();
    hasher.input(input);
    hasher.result().to_vec()
}

#[cfg(not(all(feature = "kat", test)))]
fn get_rng() -> ring::rand::SystemRandom {
    ring::rand::SystemRandom::new()
}

/// Used for reproducible KAT tests.
#[cfg(all(feature = "kat", test))]
fn get_rng() -> test::KatRandom {
    test::KatRandom
}


#[cfg(all(test, feature = "kat"))]
mod test {
    use ring::rand::SecureRandom;
    use ring::error::Unspecified;

    pub struct KatRandom;

    impl SecureRandom for KatRandom {
        fn fill(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
            unsafe {
                randombytes(dest.as_mut_ptr(), dest.len() as u64);
            }
            Ok(())
        }
    }

    extern "C" {
        fn randombytes(x: *mut u8, xlen: u64) -> i32;
        fn randombytes_init(entropy_input: *mut u8, personalization_string: *mut u8, security_strength: i32);
    }


    #[test]
    fn kat_test() {
        let mut entropy_input = [0u8; 48];
        for i in 0..48 {
            entropy_input[i] = i as u8;
        }
        unsafe {
            randombytes_init(entropy_input.as_mut_ptr(), [].as_mut_ptr(), 256);
        }

        let rng = KatRandom;
        let mut seeds = (0..100).map(|_| {
            // println!("count = {:?}", i);
            let mut seed = [0u8; 48];
            rng.fill(&mut seed).unwrap();
            // print!("seed = ");
            // print_bstr(&seed);
            seed
        }).collect::<Vec<[u8; 48]>>();
            
        for i in 0..100 {
            let seed: &mut [u8] = &mut seeds[i];
            print!("seed = ");
            print_bstr(seed);

            unsafe {
                randombytes_init(seed.as_mut_ptr(), [].as_mut_ptr(), 256);
            }
            let (pk, sk) = ::crypto_kem_keypair().unwrap();
            let mut pkb = vec![];
            pk.write_to(&mut pkb).unwrap();
            print!("pk = ");
            print_bstr(&pkb);
            let mut skb = vec![];
            sk.write_to(&mut skb).unwrap();
            print!("sk = ");
            print_bstr(&skb);

            let (ct, ss) = ::crypto_kem_enc(&pkb).unwrap();
            print!("ct = ");
            print_bstr(&ct);
            print!("ss = ");
            print_bstr(&ss);

            let ss1 = ::crypto_kem_dec(&skb, &ct).unwrap();
            assert_eq!(ss1, ss);
        }
    }

    fn print_bstr(b: &[u8]) {
        for bi in b {
            print!("{:02x}", bi);
        }
        println!();
    }
}

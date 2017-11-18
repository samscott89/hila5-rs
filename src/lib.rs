extern crate byteorder;
extern crate digest;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
extern crate sha3;
extern crate ring;

use sha3::{Digest, Sha3_256};

#[cfg(test)]
macro_rules! abbrev_eq {
    (V $x:ident, $len_l:expr, $len_r:expr, $($l:expr,)* ~ $($r:expr),*) => ( 
        assert_eq!(&$x.norm().0[..$len_l], &[$($l,)*]);
        assert_eq!(&$x.norm().0[HILA5_N - $len_r..], &[$($r,)*]);
    );
    ($x:ident, $len_l:expr, $len_r:expr, $($l:expr,)* ~ $($r:expr),*) => ( 
        assert_eq!(&$x[..$len_l], &[$($l,)*]);
        assert_eq!(&$x[$len_r..], &[$($r,)*]);
    )
}

mod arith;
mod ecc;
mod encode;
mod kem;
mod keygen;
mod rand;
mod recon;

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

pub use keygen::{crypto_kem_keypair, PrivateKey, PublicKey};
pub use kem::SharedSecret;

pub fn crypto_kem_enc(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = PublicKey::from_bytes(pk);
    kem::enc(&pk).map(|(ct, ss)| (ct, ss.0))
}

pub fn crypto_kem_dec(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let sk = PrivateKey::from_bytes(sk);
    kem::dec(&ct, &sk).map(|ss| ss.0)
}

// pub use keygen::{crypto_kem_keypair, PublicKey, PrivateKey};
// pub use kem::{crypto_kem_enc, crypto_kem_dec, Ciphertext, SharedSecret};

pub const HILA5_N: usize = 1024;
pub const HILA5_Q: i32 = 12289;

pub type Scalar = i32;
pub struct Vector([Scalar; HILA5_N]);
pub struct NttVector([Scalar; HILA5_N]);

pub trait Hila5Vector: From<[Scalar; HILA5_N]> {
    fn get_inner(&self) -> &[Scalar; HILA5_N];
    fn get_inner_mut(&mut self) -> &mut [Scalar; HILA5_N];

    fn norm(&self) -> Self {
        let mut new = self.get_inner().clone();
        for vi in new.iter_mut() {
            *vi = (*vi + HILA5_Q) % HILA5_Q;
        }
        Self::from(new)
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

fn sha3(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::default();
    hasher.input(input);
    hasher.result().to_vec()
}


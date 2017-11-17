extern crate byteorder;
extern crate digest;
#[macro_use]
extern crate lazy_static;
extern crate sha3;
extern crate ring;

use sha3::{Digest, Sha3_256};

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

fn u64_from_be_u8(input: &[u8; 8]) -> u64 {
    u64::from(input[0]) << 56 |
    u64::from(input[1]) << 48 |
    u64::from(input[2]) << 40 |
    u64::from(input[3]) << 32 |
    u64::from(input[4]) << 24 |
    u64::from(input[5]) << 16 |
    u64::from(input[6]) << 8 |
    u64::from(input[7])
}

fn sha3(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::default();
    hasher.input(input);
    hasher.result().to_vec()
}


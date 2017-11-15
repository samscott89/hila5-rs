extern crate digest;
#[macro_use]
extern crate lazy_static;
extern crate sha3;
extern crate ring;

mod arith;
mod encode;
mod rand;

pub const HILA5_N: usize = 1024;
pub const HILA5_Q: i32 = 12289;

pub type Scalar = i32;
pub struct Vector(pub [Scalar; HILA5_N]);
pub struct NttVector(pub [Scalar; HILA5_N]);
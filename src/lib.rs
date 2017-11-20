extern crate byteorder;
extern crate digest;
#[macro_use]
extern crate error_chain;
#[cfg(not(feature = "ntt"))]
#[macro_use]
extern crate lazy_static;
extern crate sha3;
extern crate ring;

use sha3::{Digest, Sha3_256};

#[cfg(not(feature = "ntt"))]
mod arith;
#[cfg(feature = "ntt")]
use ntt::arith;
mod ecc;
mod encode;
mod kem;
mod keygen;
#[cfg(feature = "ntt")]
mod ntt;
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
    kem::dec(ct, &sk).map(|ss| ss.0)
}

// pub use keygen::{crypto_kem_keypair, PublicKey, PrivateKey};
// pub use kem::{crypto_kem_enc, crypto_kem_dec, Ciphertext, SharedSecret};

pub const HILA5_N: usize = 1024;
pub const HILA5_Q: i32 = 12_289;

pub const PUBKEY_LEN: usize = rand::SEED_LEN + encode::PACKED14;
pub const PRIVKEY_LEN: usize = encode::PACKED14 + 32;
pub const CIPHERTEXT_LEN: usize = encode::PACKED14 + (HILA5_N / 8) + recon::PAYLOAD_LEN + recon::ECC_LEN;

pub type Scalar = i32;
pub struct Vector([Scalar; HILA5_N]);
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

pub trait Hila5Vector: From<[Scalar; HILA5_N]> {
    fn get_inner(&self) -> &[Scalar; HILA5_N];
    fn get_inner_mut(&mut self) -> &mut [Scalar; HILA5_N];

    #[cfg(feature = "ntt")]
    fn norm(&mut self) {
        // arith::two_reduce12289(self);
        arith::correction(self);
    }

    #[cfg(not(feature = "ntt"))]
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

fn sha3(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::default();
    hasher.input(input);
    hasher.result().to_vec()
}

#[cfg(not(test))]
fn get_rng() -> ring::rand::SystemRandom {
    ring::rand::SystemRandom::new()
}

#[cfg(test)]
fn get_rng() -> test::KatRandom {
    test::KatRandom
}


#[cfg(test)]
mod test {
    use ring::rand::SecureRandom;
    use ring::error::Unspecified;

    use super::print_bstr;

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

        // for (int i=0; i<100; i++) {
        //     fprintf(fp_req, "count = %d\n", i);
        //     randombytes(seed, 48);
        //     fprintBstr(fp_req, "seed = ", seed, 48);
        //     fprintf(fp_req, "pk =\n");
        //     fprintf(fp_req, "sk =\n");
        //     fprintf(fp_req, "ct =\n");
        //     fprintf(fp_req, "ss =\n\n");
        // }
        // fclose(fp_req);

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

}
pub fn print_bstr(b: &[u8]) {
    for bi in b {
        print!("{:02x}", bi);
    }
    println!();
}

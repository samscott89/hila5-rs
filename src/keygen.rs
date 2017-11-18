use ring::rand::{SecureRandom, SystemRandom};

use std::io::Write;

use super::*;
use encode::PACKED14;
use errors::*;

pub struct PublicKey {
    pub seed: [u8; rand::SEED_LEN],
    pub key:  NttVector,
}

pub struct PrivateKey {
    key: NttVector,
    pub pk_digest: Vec<u8>,
}

impl PublicKey {
    pub fn from_bytes(input: &[u8]) -> Self {
        let mut seed = [0u8; rand::SEED_LEN];
        seed.copy_from_slice(&input[..rand::SEED_LEN]);
        let key = encode::unpack14(&input[rand::SEED_LEN..]);
        Self { seed, key }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.seed)?;
        encode::pack14(&self.key, writer)
    }
}

impl PrivateKey {
    pub fn from_bytes(input: &[u8]) -> Self {
        let key = encode::unpack14(&input[..PACKED14]);
        let mut pk_digest = vec![];
        pk_digest.extend_from_slice(&input[PACKED14..]);
        Self { key, pk_digest }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        encode::pack14(&self.key, writer)?;
        writer.write_all(&self.pk_digest)?;
        Ok(())
    }

    pub fn get_shared_secret(&self, b: &NttVector) -> Vector {
        let a = &self.key;
        let a = a * &b;
        let b = arith::slow_intt(&a);
        &b * 1416
    }
}


/// Generate a keypair
pub fn crypto_kem_keypair() -> Result<(PublicKey, PrivateKey)> {
    let rng = SystemRandom::new();

    let t = rand::psi16();
    let a = arith::slow_ntt(&t, 27);

    let t = rand::psi16();
    let e = arith::slow_ntt(&t, 27);
    let mut seed = [0u8; rand::SEED_LEN];
    rng.fill(&mut seed)?;

    let mut t: NttVector = rand::from_seed(&seed);
    t = &t * &a;
    t = &t + &e;

    let mut pk_bytes = [0u8; rand::SEED_LEN + PACKED14];
    &pk_bytes[..rand::SEED_LEN].copy_from_slice(&seed[..]);
    encode::pack14(&t, &mut (&mut pk_bytes[rand::SEED_LEN..]))?;
    let pk_digest = sha3(&pk_bytes).to_vec();

    Ok((
        PublicKey {
            seed: seed,
            key: t,
        },
        PrivateKey {
            key: a,
            pk_digest: pk_digest,
        }
    ))
}

#[cfg(test)]
pub mod test {
    use super::*;

    lazy_static! {
        static ref test_a: NttVector = {
            // let rng = SystemRandom::new();

            // let t = rand::psi16();
            let t = {
                let mut tmp = [0; HILA5_N];
                for chunk in tmp.chunks_mut(5) {
                    let clen = chunk.len();
                    chunk.copy_from_slice(&[-1, 1, -2, -3, 5][..clen]);
                }
                Vector::from(tmp)
            };
            let a = arith::slow_ntt(&t, 27);
            abbrev_eq!(V a, 5, 5, 11172, 5208, 9207, 8751, 251, ~ 7603, 3490, 9191, 8666, 8302);
            a
        };

        pub static ref test_pk: PublicKey = {
            let a = &test_a;
            // let t = rand::psi16();
            let t = {
                let mut tmp = [0; HILA5_N];
                for chunk in tmp.chunks_mut(3) {
                    let clen = chunk.len();
                    chunk.copy_from_slice(&[2, 2, -4][..clen]);
                }
                Vector::from(tmp)
            };
            let e = arith::slow_ntt(&t, 27);
            abbrev_eq!(V e, 5, 5, 8226, 10812, 6666, 1749, 2228, ~ 10169, 10648, 5731, 1585, 4171);
            let seed = [0u8; rand::SEED_LEN];
            // rng.fill(&mut seed).unwrap();

            let mut t: NttVector = rand::from_seed(&seed);
            abbrev_eq!(V t, 5, 5, 2034, 8826, 9346, 872, 2929, ~ 2816, 441, 7160, 2952, 5275);
            t = &t * &a;
            t = &t + &e;

            abbrev_eq!(V t, 5, 5, 9713, 3471, 7710, 1152, 67, ~ 490, 1324, 5696, 10208, 11514);

            PublicKey {
                seed: seed,
                key: t,
            }
        };

        pub static ref test_sk: PrivateKey = {
            let a = NttVector(test_a.0.clone());
            let t = &test_pk.key;

            let seed = [0u8; rand::SEED_LEN];

            let mut pk_bytes = [0u8; rand::SEED_LEN + PACKED14];
            &pk_bytes[..rand::SEED_LEN].copy_from_slice(&seed[..]);
            encode::pack14(t, &mut (&mut pk_bytes[rand::SEED_LEN..])).unwrap();
            let pk_digest = sha3(&pk_bytes).to_vec();

            PrivateKey {
                key: a,
                pk_digest: pk_digest,
            }
        };
    }

    #[test]
    fn test_keygen() {
        let mut pk_bytes = vec![];
        test_pk.write_to(&mut pk_bytes).unwrap();
        assert_eq!(&pk_bytes[..2], &[0, 0]);
        assert_eq!(&pk_bytes[pk_bytes.len() - 5..], &[0x90, 0x05, 0x7E, 0xEA, 0xB3]);

        let mut sk_bytes = vec![];
        test_sk.write_to(&mut sk_bytes).unwrap();
        assert_eq!(&sk_bytes[..5], &[0xA4, 0x2B, 0x16, 0x75, 0x3F]);

        assert_eq!(&sk_bytes[sk_bytes.len() - 2..], &[0xE3, 0x3F]);
    }
}
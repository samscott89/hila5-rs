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
        let a = &self.key * b;
        let mut ss = if cfg!(feature = "ntt") {
            // scaling factors
            // 3651 = sqrt(-1) * 2^-10 * 3^-12
            // 4958 = 2^-10 * 3^-12
            // 1635 = 3^-12
            arith::intt(a, 1635)
        } else {
            // Need to clear 3^6 factor; 12171 = 3^-6
            arith::intt(a, 12171)
        };
        ss.norm();
        ss
    }
}


/// Generate a keypair
pub fn crypto_kem_keypair() -> Result<(PublicKey, PrivateKey)> {
    let rng = SystemRandom::new();

    let mut a = arith::ntt(rand::psi16());
    let e = arith::ntt(rand::psi16());
    let mut seed = [0u8; rand::SEED_LEN];
    rng.fill(&mut seed)?;

    let g: NttVector = rand::from_seed(&seed);
    // t = g * a + e
    let mut t = arith::mul_add(&g, &a, &e);

    #[cfg(feature = "ntt")]
    {
        arith::correction(&mut t);
    }

    let mut pk_bytes = [0u8; rand::SEED_LEN + PACKED14];
    &pk_bytes[..rand::SEED_LEN].copy_from_slice(&seed[..]);
    encode::pack14(&t, &mut (&mut pk_bytes[rand::SEED_LEN..]))?;
    let pk_digest = sha3(&pk_bytes).to_vec();

    // Normalise A before storing
    a.norm();

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
            let mut a = arith::ntt(t);
            a.norm();
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
            let mut e = arith::ntt(t);
            e.norm();
            abbrev_eq!(V e, 5, 5, 8226, 10812, 6666, 1749, 2228, ~ 10169, 10648, 5731, 1585, 4171);
            let seed = [0u8; rand::SEED_LEN];
            // rng.fill(&mut seed).unwrap();

            let mut g: NttVector = rand::from_seed(&seed);
            // g.norm();
            // abbrev_eq!(V g, 5, 5, 2034, 8826, 9346, 872, 2929, ~ 2816, 441, 7160, 2952, 5275);
            // t = g * a + e
            let mut t = arith::mul_add(&g, a, &e);
            #[cfg(feature = "ntt")]
            {
                t = &t * 2731;
            }

            // // force 0 <= ti < Q
            // t.norm();
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
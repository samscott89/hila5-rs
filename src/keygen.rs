use ring::rand::SecureRandom;

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
        let mut ss = if cfg!(feature = "opt") {
            // We get an extra 3^2 factor from these methods, so need to
            // clear9545 = 3^-8
            let mut a = arith::intt(a, 9545);
            #[cfg(feature = "opt")]
            arith::two_reduce12289(&mut a);
            a
        } else {
            // Need to clear 3^6 factor; 12171 = 3^-6
            arith::intt(a, 12_171)
        };
        ss.norm();
        ss
    }
}


/// Generate a keypair
pub fn crypto_kem_keypair() -> Result<(PublicKey, PrivateKey)> {
    let rng = get_rng();

    let mut a = arith::ntt(rand::psi16());
    let e = arith::ntt(rand::psi16());
    let mut seed = [0u8; rand::SEED_LEN];
    rng.fill(&mut seed)?;

    let g: NttVector = rand::from_seed(&seed);
    // t = g * a + e
    let mut t = arith::mul_add(&g, &a, &e);
    t.norm();

    let mut pk_bytes = [0u8; rand::SEED_LEN + PACKED14];
    pk_bytes[..rand::SEED_LEN].copy_from_slice(&seed[..]);
    encode::pack14(&t, &mut (&mut pk_bytes[rand::SEED_LEN..]))?;
    let pk_digest = sha3(&pk_bytes).to_vec();

    #[cfg(feature = "opt")]
    arith::two_reduce12289(&mut a);

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

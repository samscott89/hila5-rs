/// Key generation methods

// Rust port
// Original code due to:
// 2017-09-09  Markku-Juhani O. Saarinen <mjos@iki.fi>


use ring::rand::SecureRandom;

use std::io::Write;

use super::*;
use encode::PACKED14;
use errors::*;


/// Hila5 public key type.
///
/// Contains the seed to generate the generator, the generator itself (`g`), and the 
/// public key (`A`).
pub struct PublicKey {
    seed: [u8; rand::SEED_LEN],
    pub gen: NttVector,
    pub key:  NttVector,
}

/// Hila5 private key type.
///
/// Contains the `NttVector` key, and the hash of the
/// public key (needed for API compatability, `crypto_kem_dec` does not take PK
/// as input).
pub struct PrivateKey {
    key: NttVector,
    pub pk_digest: Vec<u8>,
}

impl PublicKey {
    /// Unpacks a public key from the generator seed, and the packed public
    /// key value.
    pub fn from_bytes(input: &[u8]) -> Self {
        let mut seed = [0u8; rand::SEED_LEN];
        seed.copy_from_slice(&input[..rand::SEED_LEN]);
        let gen = rand::from_seed(&seed[..]);
        let key = encode::unpack14(&input[rand::SEED_LEN..]);
        Self { seed, gen, key }
    }

    /// Write the serialised public key to the `writer`.
    pub(crate) fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.seed)?;
        encode::pack14(&self.key, writer)
    }

    pub fn enc(&self) -> Result<(Vec<u8>, SharedSecret)> {
        kem::enc(&self)
    }
}

impl PrivateKey {
    /// Unpacks a private key from the packed private key vector and the
    /// public key digest.
    pub fn from_bytes(input: &[u8]) -> Self {
        let key = encode::unpack14(&input[..PACKED14]);
        let mut pk_digest = vec![];
        pk_digest.extend_from_slice(&input[PACKED14..]);
        Self { key, pk_digest }
    }

    /// Write the serialised private key to the `writer`.
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

    pub fn dec(&self, ct: &[u8]) -> Result<SharedSecret> {
        kem::dec(&ct, self)
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
            gen: g,
            key: t,
        },
        PrivateKey {
            key: a,
            pk_digest: pk_digest,
        }
    ))
}

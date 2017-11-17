use ring::rand::{SecureRandom, SystemRandom};

use super::*;
use encode::HILA5_PACKED14;

pub const HILA5_PUBKEY_LEN: usize  = rand::HILA5_SEED_LEN + HILA5_PACKED14;
pub const HILA5_PRIVKEY_LEN: usize = HILA5_PACKED14 + 32; 

pub struct PublicKey(pub [u8; HILA5_PUBKEY_LEN]);
pub struct PrivateKey(pub [u8; HILA5_PRIVKEY_LEN]);

impl PublicKey {
    pub fn get_seed(&self) -> &[u8] {
        &self.0[..rand::HILA5_SEED_LEN]
    }

    pub fn get_key(&self) -> &[u8] {
        &self.0[rand::HILA5_SEED_LEN..]
    }
}

/// Generate a keypair
fn crypto_kem_keypair() -> Result<(PublicKey, PrivateKey), ()> {
    let rng = SystemRandom::new();

    let mut pk = [0; HILA5_PUBKEY_LEN];
    let mut sk = [0; HILA5_PRIVKEY_LEN];

    let t = rand::hila5_psi16();
    let a = arith::slow_ntt(&t, 27);

    let t = rand::hila5_psi16();
    let e = arith::slow_ntt(&t, 27);
    rng.fill(&mut pk[..rand::HILA5_SEED_LEN]).map_err(|_| ())?;

    let mut t: NttVector = rand::hila5_parse(&pk[..rand::HILA5_SEED_LEN]);
    t = &t * &a;
    t = &t + &e;

    encode::hila5_pack14(&t, &mut pk[rand::HILA5_SEED_LEN..]);
    encode::hila5_pack14(&a, &mut sk[..HILA5_PACKED14]);

    let digest = sha3(&pk);
    &sk[HILA5_PACKED14..].copy_from_slice(&digest);

    Ok((PublicKey(pk), PrivateKey(sk)))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_keygen() {
        // let rng = SystemRandom::new();

        let mut pk = [0; HILA5_PUBKEY_LEN];
        let mut sk = [0; HILA5_PRIVKEY_LEN];

        // let t = rand::hila5_psi16();
        let t = {
            let mut tmp = [0; HILA5_N];
            for chunk in tmp.chunks_mut(5) {
                let clen = chunk.len();
                chunk.copy_from_slice(&[-1, 1, -2, -3, 5][..clen]);
            }
            Vector::from(tmp)
        };

        let mut a = arith::slow_ntt(&t, 27);
        abbrev_eq!(V a, 5, 5, 11172, 5208, 9207, 8751, 251, ~ 7603, 3490, 9191, 8666, 8302);

        // let t = rand::hila5_psi16();
        let t = {
            let mut tmp = [0; HILA5_N];
            for chunk in tmp.chunks_mut(3) {
                let clen = chunk.len();
                chunk.copy_from_slice(&[2, 2, -4][..clen]);
            }
            Vector::from(tmp)
        };
        let mut e = arith::slow_ntt(&t, 27);
        abbrev_eq!(V e, 5, 5, 8226, 10812, 6666, 1749, 2228, ~ 10169, 10648, 5731, 1585, 4171);

        // rng.fill(&mut pk[..rand::HILA5_SEED_LEN]).map_err(|_| ())?;
        let mut t: NttVector = rand::hila5_parse(&pk[..rand::HILA5_SEED_LEN]);
        abbrev_eq!(V t, 5, 5, 2034, 8826, 9346, 872, 2929, ~ 2816, 441, 7160, 2952, 5275);

        t = &t * &a;
        t = &t + &e;

        abbrev_eq!(V t, 5, 5, 9713, 3471, 7710, 1152, 67, ~ 490, 1324, 5696, 10208, 11514);
        // assert_eq!(&t.0[..5], &[9713, 3471, 7710, 1152, 67]);

        encode::hila5_pack14(&t.norm(), &mut pk[rand::HILA5_SEED_LEN..]);
        encode::hila5_pack14(&a.norm(), &mut sk[..HILA5_PACKED14]);

        let digest = sha3(&pk);
        &sk[HILA5_PACKED14..].copy_from_slice(&digest);

        assert_eq!(&pk[..2], &[0, 0]);
        assert_eq!(&pk[HILA5_PUBKEY_LEN - 5..], &[0x90, 0x05, 0x7E, 0xEA, 0xB3]);
    
        assert_eq!(&sk[..5], &[0xA4, 0x2B, 0x16, 0x75, 0x3F]);
        assert_eq!(&sk[HILA5_PUBKEY_LEN - 2..], &[0xE3, 0x3F]);

        // Ok((PublicKey(pk), PrivateKey(sk)))
    }
}
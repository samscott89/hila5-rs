use super::*;

use digest::{Input, ExtendableOutput ,XofReader};
use ring::rand::{SecureRandom, SystemRandom};
use sha3::Shake256;

pub const SEED_LEN: usize = 32;

/// generate uniform vector from the seed
/// aka `hila5_parse`
pub fn from_seed<V: Hila5Vector>(seed: &[u8]) -> V {
    debug_assert!(seed.len() >= 32 );
    let mut hasher = Shake256::default();
    hasher.process(&seed[..32]);
    let mut xof = hasher.xof_result();

    let mut v = [0; HILA5_N];
    let mut buf = [0; 2];

    for vi in v.iter_mut() {
        *vi = loop {
            xof.read(&mut buf);
            let x = (buf[0] as Scalar) | ( buf[1] as Scalar) << 8;
            if x < 5 * HILA5_Q {
                break x;
            }
        };
    }
    V::from(v)
}

/// sample a vector of values from the psi16 distribution
/// aka `hila5_psi16`
pub fn psi16<V: Hila5Vector>() -> V {
    let rng = SystemRandom::new();
    let mut v = [0; HILA5_N];
    for vi in v.iter_mut() {
        let mut rand_bytes = [0u8; 4];
        rng.fill(&mut rand_bytes).unwrap();
        *vi = (rand_bytes.iter().map(|x| x.count_ones() as i32).sum::<i32>() +  HILA5_Q - 16) % HILA5_Q;
    }
    V::from(v)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_test() {
        let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
        let v: Vector =  from_seed(&seed[..]);
        assert_eq!(&v.0[..5], &[34940, 52800, 640, 45901, 14601]);
        assert_eq!(&v.0[HILA5_N-5..], &[46031, 8999, 56069, 2120, 49166]);
    }
}
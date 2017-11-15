use super::*;

use digest::{Input, ExtendableOutput ,XofReader};
use ring::rand::{SecureRandom, SystemRandom};
use sha3::Shake256;

pub const HILA5_SEED_LEN: usize = 32;

/// generate n uniform samples from the seed
pub fn hila5_parse(seed: &[u8]) -> Vector {
    assert!(seed.len() >= 32 );
    let mut hasher = Shake256::default();
    hasher.process(&seed[..32]);
    let mut xof = hasher.xof_result();

    let mut v = [0; HILA5_N];

    // due to bug(?) in sha3, need to fake this as extensible
    // 2N trials should be enough to get value with rejection prob of 6.25%  
    let mut buf = [0; HILA5_N * 4];
    xof.read(&mut buf);
    let mut buf_iter = buf.chunks(2);

    for vi in v.iter_mut() {
        *vi = loop {
            let buf = buf_iter.next().unwrap();
            // xof.read(&mut buf);
            let x = (buf[0] as Scalar) | ( buf[1] as Scalar) << 8;
            if x < 5 * HILA5_Q {
                break x;
            }
        };
    }
    Vector(v)
}


/// sample a vector of values from the psi16 distribution
pub fn hila5_psi16() -> Vector {
    let rng = SystemRandom::new();
    let mut v = [0; HILA5_N];
    for vi in v.iter_mut() {
        let mut rand_bytes = [0; 4];
        rng.fill(&mut rand_bytes).unwrap();
        *vi = (rand_bytes.iter().sum(|x| x.count_ones()) +  HILA5_Q - 16) % HILA5_Q;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_test() {
        let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
        let v =  hila5_parse(&seed[..]);
        assert_eq!(&v.0[..5], &[34940, 52800, 640, 45901, 14601]);
        assert_eq!(&v.0[HILA5_N-5..], &[46031, 8999, 56069, 2120, 49166]);
    }
}
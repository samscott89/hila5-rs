use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use sha3::{Digest, Sha3_256};

use std::io::Cursor;

use super::*;
use encode::PACKED14;
use errors::*;

const MAX_ITER: usize = 1000;

pub struct SharedSecret(pub Vec<u8>);

/// Type-friendly version of `crypto_kem_enc`
pub fn enc(pk: &keygen::PublicKey) -> Result<(Vec<u8>, SharedSecret)> {
    let mut ct = vec![0u8; PACKED14];

    let a = &pk.key;
    #[allow(unused_assignments)]
    let mut b = NttVector([0; HILA5_N]);

    let mut ctr = 0;
    let (payload, info) = loop {
        b = arith::ntt(rand::psi16());
        let e = a * &b;
        let mut t = if cfg!(feature = "ntt") {
            // 8281 = sqrt(-1) * 2^-10 * 3^-10, 7755 = 2^-10 * 3^-10
            // 2426 = 3^-10
            arith::intt(e, 2426)
        } else {
            // Need to clear 3^6 factor; 12171 = 3^-6
            arith::intt(e, 12171)
        };

        t.norm();

        if let Ok(x) = recon::safebits(&t) {
            break x;
        }

        ctr += 1;
        if ctr >= MAX_ITER {
            return Err("ran out of iterations to find a payload".into());
        }
    };

    info.write_to(&mut ct)?;


    // split the payload into data z and OTP data r
    let (z, mut r) = payload.parse()?;
    // r now contains redundancy for z XOR the one-time pad data
    ecc::xe5_cod(&z, &mut r);

    for zi in r.iter() {
        ct.write_u64::<LittleEndian>(*zi)?;
    }

    // last two bytes are redundant due to encoding scheme
    let _ = ct.pop();
    let _ = ct.pop();

    // recover the seed/generator
    let g: NttVector = rand::from_seed(&pk.seed);
    // generate some random noise
    let t: Vector = rand::psi16();
    let e = arith::ntt(t);
    // secret key is a = g*b + e
    let mut a = arith::mul_add(&g, &b, &e);
    a.norm();

    encode::pack14(&a, &mut &mut ct[..PACKED14])?;

    let mut pk_bytes = vec![];
    pk.write_to(&mut pk_bytes)?;

    let mut hasher = Sha3_256::default();
    hasher.input(b"HILA5v10");
    hasher.input(&sha3(&pk_bytes));
    hasher.input(&sha3(&ct));
    hasher.input(&payload.0[..32]);
    let ss = hasher.result().to_vec();

    Ok((ct, SharedSecret(ss)))
}

pub fn dec(ct: &[u8], sk: &keygen::PrivateKey) -> Result<SharedSecret> {
    let b = encode::unpack14(&ct[..encode::PACKED14]);
    let x = sk.get_shared_secret(&b);

    // recover the reconciliation info from the ciphertext
    let info = recon::Info::from_bytes(&ct[encode::PACKED14..]);
    // recovers the payload from b ~= v
    let payload = recon::select(&info, &x)?;
    // split the payload into data z and one-time pad encrypted redundancy r
    let (ref mut z, mut r) = payload.parse()?;

    // So we dont treat the 30 bytes as 4-ish 64 bit values.
    let mut tmp = [0u8; 32];
    let mut otp = [0u64; 4];
    tmp[..30].copy_from_slice(&ct[ct.len() - 30..]);
    let mut rdr = Cursor::new(tmp);
    rdr.read_u64_into::<LittleEndian>(&mut otp)?;
    r[0] ^= otp[0];
    r[1] ^= otp[1];
    r[2] ^= otp[2];
    r[3] ^= otp[3];
    ecc::xe5_cod(z, &mut r);
    ecc::xe5_fix(z, &r);

    let mut z_bytes = vec![];
    for zi in z.iter() {
        z_bytes.write_u64::<LittleEndian>(*zi)?;
    }

    let mut hasher = Sha3_256::default();
    hasher.input(b"HILA5v10");
    hasher.input(&sk.pk_digest);
    hasher.input(&sha3(&ct));
    hasher.input(&z_bytes);
    let ss = hasher.result().to_vec();

    Ok(SharedSecret(ss))
} 


#[cfg(test)]
mod test {
    use super::*;

    lazy_static! {
        static ref test_ct: Vec<u8> = {
            let mut ct = vec![0u8; PACKED14];
            let a: &NttVector = &keygen::test::test_pk.key;
            let b = {
                let mut tmp = [0; HILA5_N];
                for chunk in tmp.chunks_mut(7) {
                    let clen = chunk.len();
                    chunk.copy_from_slice(&[0, 1, 1, 2, -3, 4, -5][..clen]);
                }
                Vector::from(tmp)
            };
            let mut b = arith::ntt(b);
            b.norm();
            abbrev_eq!(V b, 5, 5, 5361, 11011, 5111, 10968, 6240, ~ 1901, 10941, 7723, 10979, 9431);
            let mut ctr = 0;
            let (payload, info) = loop {
                // b = arith::ntt(rand::psi16());
                let e = a * &b;

                let mut t = if cfg!(feature = "ntt") {
                    // 8281 = sqrt(-1) * 2^-10 * 3^-10, 7755 = 2^-10 * 3^-10
                    // 2426 = 3^-10
                    arith::intt(e, 9545)
                } else {
                    // Need to clear 3^6 factor; 12171 = 3^-6
                    arith::intt(e, 12171)
                };

                t.norm();
                abbrev_eq!(V t, 5, 5, 11982, 1189, 1239, 8956, 11579, ~ 8947, 10863, 2725, 6368, 1295);

                if let Ok(x) = recon::safebits(&t) {
                    break x;
                }
                ctr += 1;
                if ctr >= 1 {
                    assert!(false);
                }
            };

            info.write_to(&mut ct).unwrap();

            // split the payload into data z and OTP data r
            let (z, mut r) = payload.parse().unwrap();
            // r now contains redundancy for z XOR the one-time pad data
            ecc::xe5_cod(&z, &mut r);

            for zi in r.iter() {
                ct.write_u64::<LittleEndian>(*zi).unwrap();
            }

            // last two bytes are redundant due to encoding scheme
            let _ = ct.pop();
            let _ = ct.pop();

            // recover the seed/generator
            let g: NttVector = rand::from_seed(&keygen::test::test_pk.seed);
            // generate some random noise
            // let t: Vector = rand::psi16();
            let t = {
                let mut tmp = [0; HILA5_N];
                for chunk in tmp.chunks_mut(4) {
                    let clen = chunk.len();
                    chunk.copy_from_slice(&[0, 4, 0, -4][..clen]);
                }
                Vector::from(tmp)
            };

            let e = arith::ntt(t);
            // secret key is a = g*b + e
            let mut a = arith::mul_add(&g, &b, &e);
            a.norm();
            abbrev_eq!(V a, 5, 5, 9437, 8457, 4675, 10931, 3829, ~ 8113, 3081, 792, 10698, 8159);

            encode::pack14(&a, &mut &mut ct[..PACKED14]).unwrap();

            let mut pk_bytes = vec![];
            keygen::test::test_pk.write_to(&mut pk_bytes).unwrap();

            let mut hasher = Sha3_256::default();
            hasher.input(b"HILA5v10");
            hasher.input(&sha3(&pk_bytes));
            hasher.input(&sha3(&ct));
            hasher.input(&payload.0[..32]);
            let ss = hasher.result().to_vec();

            assert_eq!(&ct[..5], &[0xDD, 0x64, 0x42, 0x38, 0x24]);

            assert_eq!(ss, &[ 0xc2, 0x95, 0xa5, 0x2d, 0xbf, 0xb, 0x86, 0x3, 0xac,
            0x49, 0xb4, 0x1a, 0x5b, 0xe1, 0xee, 0xbd, 0x64, 0xe, 0x34, 0x7d, 0x16,
            0xc1, 0x58, 0xe1, 0xbd, 0xa0, 0x75, 0x96, 0x14, 0xb1, 0x72, 0x60]);
            ct
        };
    }

    #[test]
    fn test_shared_secret() {
        let b = encode::unpack14(&test_ct[..encode::PACKED14]);
        let ss = keygen::test::test_sk.get_shared_secret(&b);
        abbrev_eq!(V ss, 5, 5, 11982, 1157, 1261, 8932, 11561, ~ 8967, 10861, 2727, 6374, 1259);
    }


    #[test]
    fn test_dec() {
        let ss = dec(&test_ct, &keygen::test::test_sk).unwrap();

        assert_eq!(ss.0, &[ 0xc2, 0x95, 0xa5, 0x2d, 0xbf, 0xb, 0x86, 0x3, 0xac,
        0x49, 0xb4, 0x1a, 0x5b, 0xe1, 0xee, 0xbd, 0x64, 0xe, 0x34, 0x7d, 0x16,
        0xc1, 0x58, 0xe1, 0xbd, 0xa0, 0x75, 0x96, 0x14, 0xb1, 0x72, 0x60]);

    }
}

use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use sha3::{Digest, Sha3_256};

use std::io::Cursor;
use std::mem;

use super::*;
use encode::HILA5_PACKED14;

const HILA5_B: Scalar = 799;
const HILA5_PACKED1: usize = (HILA5_N / 8);
const HILA5_KEY_LEN: usize = 32;
const HILA5_ECC_LEN: usize = 30;
const HILA5_PAYLOAD_LEN: usize = (HILA5_KEY_LEN + HILA5_ECC_LEN);
const HILA5_MAX_ITER: usize = 1000;

struct Selector(pub [u8; HILA5_PACKED1]);
struct Reconciliation(pub [u8; HILA5_PAYLOAD_LEN]);
struct Payload(pub [u8; HILA5_PAYLOAD_LEN + 2]);

fn hila5_safebits(v: &Vector) -> Result<(Selector, Reconciliation, Payload), ()> {
    let mut sel = [0; HILA5_PACKED1];
    let mut rec = [0; HILA5_PAYLOAD_LEN];
    let mut pld = [0; HILA5_PAYLOAD_LEN + 2];

    let mut j = 0;
    for (i, vi) in v.get_inner().iter().enumerate() {
        let mut x = *vi % (HILA5_Q / 4);
        if (x >= (HILA5_Q  / 8) - HILA5_B) && (x <= (HILA5_Q  / 8) + HILA5_B) {
            sel[i >> 3] |= (1 << (i & 7)) as u8;
            x = (4 * vi) / HILA5_Q;
            rec[j >> 3] ^= ((x & 1) << (j & 7)) as u8;
            x >>= 1;
            pld[j >> 3] ^= ((x & 1) << (j & 7)) as u8;
            j += 1;
            if j >= 8 * HILA5_PAYLOAD_LEN {
                return Ok((Selector(sel), Reconciliation(rec), Payload(pld)));   
            }
        }
    }
    Err(())
}

struct Ciphertext(Vec<u8>);
struct SharedSecret(Vec<u8>);

fn crypto_kem_enc(pk: &keygen::PublicKey) -> Result<(Ciphertext, SharedSecret), ()> {
    let mut ct = vec![0u8; HILA5_PACKED14];

    let a: NttVector = encode::hila5_unpack14(pk.get_key());
    let mut b = NttVector([0; HILA5_N]);

    let mut ctr = 0;
    let (sel, rec, pld) = loop {
        let t = rand::hila5_psi16();
        b = arith::slow_ntt(&t, 27);
        let e = &a * &b;
        let mut t = arith::slow_intt(&e);
        t = &t * 1416;

        if let Ok(x) = hila5_safebits(&t) {
            break x;
        }

        ctr += 1;
        if ctr >= HILA5_MAX_ITER {
            return Err(());
        }
    };

    ct.extend_from_slice(&sel.0);
    ct.extend_from_slice(&rec.0);

    let (z, z_ecc) = pld.0.split_at(4 * 8);
    let mut z8     = vec![0u64; 4];
    let mut z8_ecc = vec![0u64; 4];
    let mut rdr = Cursor::new(z);
    rdr.read_u64_into::<LittleEndian>(&mut z8).map_err(|_| ())?;
    let mut rdr = Cursor::new(z_ecc);
    rdr.read_u64_into::<LittleEndian>(&mut z8_ecc).map_err(|_| ())?;
    ecc::xe5_cod(&z8, &mut z8_ecc);

    for zi in z8_ecc {
        ct.write_u64::<LittleEndian>(zi).map_err(|_| ())?;
    }

    // last two bytes are redundant
    let _ = ct.pop();
    let _ = ct.pop();

    let g: NttVector = rand::hila5_parse(pk.get_seed());
    let t: Vector = rand::hila5_psi16();
    let e = arith::slow_ntt(&t, 27);
    let mut t = &g * &b;
    t = &t + &e;

    encode::hila5_pack14(&t, &mut ct[..HILA5_PACKED14]);

    let mut hasher = Sha3_256::default();
    hasher.input(b"HILA5v10");
    hasher.input(&sha3(&pk.0));
    hasher.input(&sha3(&ct));
    hasher.input(&z);
    let ss = hasher.result().to_vec();

    Ok((Ciphertext(ct), SharedSecret(ss)))
}

// == Decapsulation ==========================================================

// Decode selected key bits. Return nonzero on failure.

fn hila5_select<V: Hila5Vector>(sel: &[u8], rec: &[u8], v: &V) -> Result<Payload, ()> {
    let mut pld = [0; HILA5_PAYLOAD_LEN + 2];
    assert_eq!(sel.len(), HILA5_PACKED1);
    assert_eq!(rec.len(), HILA5_PAYLOAD_LEN);

    let mut j = 0;
    for (i, vi) in v.get_inner().iter().enumerate() {
        if (sel[i >> 3] >> (i & 7)) & 1 == 1 {
            let mut x = *vi + HILA5_Q / 8;
            x -=  -((rec[j >> 3] as i32 >> (j & 7)) & 1) & (HILA5_Q / 4);
            x = ((2 * ((x + HILA5_Q) % HILA5_Q)) / HILA5_Q);
            pld[j >> 3] ^= ((x & 1) as u8) << (j & 7);
            j += 1;
            if j >= 8 * HILA5_PAYLOAD_LEN {
                return Ok(Payload(pld));
            }
        }
    }

    Err(())
}



fn crypto_kem_dec(ct: &Ciphertext, sk: &keygen::PrivateKey) -> Result<SharedSecret, ()> {
    let a: NttVector = encode::hila5_unpack14(&sk.0[..HILA5_PACKED14]);
    let b: NttVector = encode::hila5_unpack14(&ct.0[..HILA5_PACKED14]);

    let a = &a * &b;
    let mut b = arith::slow_intt(&a);
    b = &b * 1416;

    let mut z = hila5_select(
        &ct.0[HILA5_PACKED14..][..HILA5_PACKED1],
        &ct.0[HILA5_PACKED14 + HILA5_PACKED1..][..HILA5_PAYLOAD_LEN], 
        &b
    )?;
    let (z, z_ecc) = z.0.split_at(4 * 8);
    let mut z8     = vec![0u64; 4];
    let mut z8_ecc = vec![0u64; 4];
    let mut rdr = Cursor::new(z);
    rdr.read_u64_into::<LittleEndian>(&mut z8).map_err(|_| ())?;
    let mut rdr = Cursor::new(z_ecc);
    rdr.read_u64_into::<LittleEndian>(&mut z8_ecc).map_err(|_| ())?;

    let mut otp = vec![0; 4];
    let mut z_ecc = [0; 32];
    z_ecc[..30].copy_from_slice(&ct.0[HILA5_PACKED14 + HILA5_PACKED1 + HILA5_PAYLOAD_LEN..]);
    let mut rdr = Cursor::new(z_ecc);
    rdr.read_u64_into::<LittleEndian>(&mut otp).map_err(|_| ())?;
    z8_ecc[0] ^= otp[0];
    z8_ecc[1] ^= otp[1];
    z8_ecc[2] ^= otp[2];
    z8_ecc[3] ^= otp[3];
    ecc::xe5_cod(&z8, &mut z8_ecc);
    ecc::xe5_fix(&mut z8, &z8_ecc);

    let mut z = vec![];
    for zi in z8 {
        z.write_u64::<LittleEndian>(zi).map_err(|_| ())?;
    }

    let mut hasher = Sha3_256::default();
    hasher.input(b"HILA5v10");
    hasher.input(&sk.0[HILA5_PACKED14..]);
    hasher.input(&sha3(&ct.0));
    hasher.input(&z);
    let ss = hasher.result().to_vec();

    Ok(SharedSecret(ss))
} 


#[cfg(test)]
mod test {
    use super::*;

    lazy_static! {
        static ref test_a: NttVector = {
            let t = {
                let mut tmp = [0; HILA5_N];
                for chunk in tmp.chunks_mut(5) {
                    let clen = chunk.len();
                    chunk.copy_from_slice(&[-1, 1, -2, -3, 5][..clen]);
                }
                Vector::from(tmp)
            };

            let a = arith::slow_ntt(&t, 27);
            let t = {
                let mut tmp = [0; HILA5_N];
                for chunk in tmp.chunks_mut(3) {
                    let clen = chunk.len();
                    chunk.copy_from_slice(&[2, 2, -4][..clen]);
                }
                Vector::from(tmp)
            };
            let e = arith::slow_ntt(&t, 27);
            let mut t: NttVector = rand::hila5_parse(&[0; rand::HILA5_SEED_LEN]);
            t = &t * &a;
            t = &t + &e;
            t
        };

        static ref test_pk: [u8; keygen::HILA5_PUBKEY_LEN] = {
            let mut pk = [0; keygen::HILA5_PUBKEY_LEN];
            encode::hila5_pack14::<NttVector>(&test_a, &mut pk[rand::HILA5_SEED_LEN..]);
            pk
        };

        static ref test_sk: [u8; keygen::HILA5_PRIVKEY_LEN] = {
            // let rng = SystemRandom::new();

            let mut pk = [0; keygen::HILA5_PUBKEY_LEN];
            let mut sk = [0; keygen::HILA5_PRIVKEY_LEN];

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
            let t = {
                let mut tmp = [0; HILA5_N];
                for chunk in tmp.chunks_mut(3) {
                    let clen = chunk.len();
                    chunk.copy_from_slice(&[2, 2, -4][..clen]);
                }
                Vector::from(tmp)
            };
            let mut e = arith::slow_ntt(&t, 27);
            let mut t: NttVector = rand::hila5_parse(&pk[..rand::HILA5_SEED_LEN]);
            t = &t * &a;
            t = &t + &e;
            encode::hila5_pack14(&t.norm(), &mut pk[rand::HILA5_SEED_LEN..]);
            encode::hila5_pack14(&a.norm(), &mut sk[..HILA5_PACKED14]);
            let digest = sha3(&pk);
            &sk[HILA5_PACKED14..].copy_from_slice(&digest);
            sk
        };

        static ref test_ct: Vec<u8> = {
            let mut ct = vec![0u8; HILA5_PACKED14];
            let a: &NttVector = &test_a;
            let b = {
                let mut tmp = [0; HILA5_N];
                for chunk in tmp.chunks_mut(7) {
                    let clen = chunk.len();
                    chunk.copy_from_slice(&[0, 1, 1, 2, -3, 4, -5][..clen]);
                }
                Vector::from(tmp)
            };
            let b = arith::slow_ntt(&b, 27);
            let mut ctr = 0;
            let (sel, rec, mut pld) = loop {
                let e = a * &b;
                let mut t = arith::slow_intt(&e);
                t = &t * 1416;
                if let Ok(x) = hila5_safebits(&t) {
                    break x;
                }
                ctr += 1;
                if ctr >= 1 {
                    assert!(false);
                }
            };
            ct.extend_from_slice(&sel.0);
            ct.extend_from_slice(&rec.0);
            let (z, z_ecc) = pld.0.split_at(4 * 8);
            let mut z8     = vec![0u64; 4];
            let mut z8_ecc = vec![0u64; 4];
            let mut rdr = Cursor::new(z);
            rdr.read_u64_into::<LittleEndian>(&mut z8).unwrap();
            let mut rdr = Cursor::new(z_ecc);
            rdr.read_u64_into::<LittleEndian>(&mut z8_ecc).unwrap();
            println!("z8: {:?}",z8 );
            println!("z8_ecc: {:?}", z8_ecc);
            ecc::xe5_cod(&z8, &mut z8_ecc);
            println!("z8_ecc post-cod: {:?}", z8_ecc);
            for zi in z8_ecc {
                ct.write_u64::<LittleEndian>(zi).map_err(|_| ()).unwrap();
            }
            let _ = ct.pop();
            let _ = ct.pop();
            let g: NttVector = rand::hila5_parse(&[0; rand::HILA5_SEED_LEN]);
            let t = {
                let mut tmp = [0; HILA5_N];
                for chunk in tmp.chunks_mut(4) {
                    let clen = chunk.len();
                    chunk.copy_from_slice(&[0, 4, 0, -4][..clen]);
                }
                Vector::from(tmp)
            };
            let e = arith::slow_ntt(&t, 27);
            let mut t = &g * &b;
            t = &t + &e;
            encode::hila5_pack14(&t, &mut ct[..HILA5_PACKED14]);
            let mut hasher = Sha3_256::default();
            hasher.input(b"HILA5v10");
            hasher.input(&sha3(&test_pk[..]));
            hasher.input(&sha3(&ct));
            hasher.input(&z);
            let ss = hasher.result().to_vec();
            ct
        };
    }

    #[test]
    fn select_vs_safebits() {
        let v: Vector = rand::hila5_parse(&[0xf0; 32]);
        let mut err = [0; HILA5_N];
        err[0] = 0x01;
        err[10] = 0x10;
        err[15] = 0xf0;
        err[53] = 0x11;
        let err = Vector(err);

        let (sel, rec, pld) = hila5_safebits(&v).unwrap();
        let pld2 = hila5_select(&sel.0, &rec.0, &(&v + &err)).unwrap();
        assert_eq!(&pld.0[..], &pld2.0[..]);
    }

    #[test]
    fn test_dec() {
        let ss = crypto_kem_dec(&Ciphertext(test_ct.clone()), &keygen::PrivateKey(*test_sk)).unwrap();

        assert_eq!(ss.0, &[ 0xc2, 0x95, 0xa5, 0x2d, 0xbf, 0xb, 0x86, 0x3, 0xac,
        0x49, 0xb4, 0x1a, 0x5b, 0xe1, 0xee, 0xbd, 0x64, 0xe, 0x34, 0x7d, 0x16,
        0xc1, 0x58, 0xe1, 0xbd, 0xa0, 0x75, 0x96, 0x14, 0xb1, 0x72, 0x60]);

    }
}

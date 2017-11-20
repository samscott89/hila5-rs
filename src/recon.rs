use byteorder::{ReadBytesExt, LittleEndian};

use std::io::{Cursor, Write};

use errors::*;
use super::*;

const HILA5_B: Scalar = 799;
const KEY_LEN: usize = 32;
pub const ECC_LEN: usize = 30;
pub const PAYLOAD_LEN: usize = (KEY_LEN + ECC_LEN);


/// Reconciliation information
pub struct  Info {
    sel: [u8; (HILA5_N / 8)],
    rec: [u8; PAYLOAD_LEN],
}

impl Info {
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.sel[..])?;
        writer.write_all(&self.rec[..])?;
        Ok(())
    }

    pub fn from_bytes(input: &[u8]) -> Self {
        debug_assert!(input.len() >= (HILA5_N / 8) + PAYLOAD_LEN);
        let mut sel = [0u8; (HILA5_N / 8)];
        let mut rec = [0u8; PAYLOAD_LEN];
        sel.copy_from_slice(&input[..(HILA5_N / 8)]);
        rec.copy_from_slice(&input[(HILA5_N / 8)..][..PAYLOAD_LEN]);
         Info { sel, rec }
    }
}

pub struct Payload(pub [u8; PAYLOAD_LEN + 2]);

impl Payload {
    pub fn parse(&self) -> Result<([u64; 4], [u64; 4])> {
        let (z, z_ecc) = self.0.split_at(4 * 8);
        let mut z8     = [0u64; 4];
        let mut z8_ecc = [0u64; 4];
        let mut rdr = Cursor::new(z);
        rdr.read_u64_into::<LittleEndian>(&mut z8)?;
        let mut rdr = Cursor::new(z_ecc);
        rdr.read_u64_into::<LittleEndian>(&mut z8_ecc)?;
        Ok((z8, z8_ecc))
    } 
}

/// compute the selector, reconciliation, and payload for a given vector `v`.
/// aka `hila5_safebits`
pub fn safebits(v: &Vector) -> Result<(Payload,  Info)> {
    let mut sel = [0; (HILA5_N / 8)];
    let mut rec = [0; PAYLOAD_LEN];
    let mut pld = [0; PAYLOAD_LEN + 2];

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
            if j >= 8 * PAYLOAD_LEN {
                return Ok((Payload(pld),  Info { sel, rec }));
            }
        }
    }
    Err("not enough bits".into())
}


/// Decode payload from selector and reconciliation vector, and approximate
/// vector `v`.
/// aka `hila5_select`
pub fn select<V: Hila5Vector>(info: & Info, v: &V) -> Result<Payload> {
    let mut pld = [0; PAYLOAD_LEN + 2];
    debug_assert_eq!(info.sel.len(), (HILA5_N / 8));
    debug_assert_eq!(info.rec.len(), PAYLOAD_LEN);

    let mut j = 0;
    for (i, vi) in v.get_inner().iter().enumerate() {
        if (info.sel[i >> 3] >> (i & 7)) & 1 == 1 {
            let mut x = *vi + HILA5_Q / 8;
            x -=  -((info.rec[j >> 3] as i32 >> (j & 7)) & 1) & (HILA5_Q / 4);
            x = (2 * ((x + HILA5_Q) % HILA5_Q)) / HILA5_Q;
            pld[j >> 3] ^= ((x & 1) as u8) << (j & 7);
            j += 1;
            if j >= 8 * PAYLOAD_LEN {
                return Ok(Payload(pld));
            }
        }
    }

    Err("not enough bits".into())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn select_vs_safebits() {
        let v: Vector = rand::from_seed(&[0xf0; 32]);
        let mut err = [0; HILA5_N];
        err[0] = 0x01;
        err[10] = 0x10;
        err[15] = 0xf0;
        err[53] = 0x11;
        let err = Vector(err);

        let (pld, info) = safebits(&v).unwrap();
        let pld2 = select(&info, &(&v + &err)).unwrap();
        assert_eq!(&pld.0[..], &pld2.0[..]);
    }

}
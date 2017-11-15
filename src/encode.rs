use super::*;

pub const HILA5_PACKED14: usize = (14 * HILA5_N) / 8;

/// 14-bit packing; mod q integer vector v[1024] to byte sequence d[1792]
pub fn hila5_pack14(v: &Vector) -> [u8; HILA5_PACKED14] {
    let mut d = [0; HILA5_PACKED14];
    for (i, chunk) in v.0.chunks(4).enumerate() {
        //             bits 8 to 0 of x0
        d[7*i]     = (chunk[0] & 0xff) as u8;

        //              bits 1,0 of x1  || bits 14 to 8 of x1
        d[7*i + 1] = ((chunk[1] & 0x03) as u8) << 6 | (chunk[0] >> 8) as u8;

        //              bits 10 to 2 of x1
        d[7*i + 2] = ((chunk[1] >> 2) & 0xff) as u8;
        
        //             bits 4 to 0 of x2  || bits 14 to 10 of x1
        d[7*i + 3] = ((chunk[2] & 0x0f) as u8) << 4 | (chunk[1] >> 10) as u8;
        
        //             bits 12 to 4 of x2
        d[7*i + 4] = ((chunk[2] >> 4) & 0xff) as u8;
        
        //             bits 6 to 0 of x3  || bits 14 to 12 of x2
        d[7*i + 5] = ((chunk[3] & 0x3f) as u8) << 2 | (chunk[2] >> 12) as u8;
        
        //             bits 14 to 6 of x3
        d[7*i + 6] = (chunk[3] >> 6) as u8;
    }
    d
}

/// 14-bit unpacking; bytes in d[1792] to integer vector v[1024]
pub fn hila5_unpack14(d: &[u8]) -> Vector {
    assert_eq!(d.len(), HILA5_PACKED14);
    let mut v = [0; HILA5_N];
    for (i, chunk) in d.chunks(7).enumerate() {
        //       bottom 6 bits of d1 || 8 bits of d0
        v[4*i]     = ((chunk[1] & 0x3f) as Scalar) << 8 | chunk[0] as Scalar;

        //       bottom 4 bits of d3 || 8 bits of d2 || top 2 bits of d1
        v[4*i + 1] = ((chunk[3] & 0x0f) as Scalar) << 10 | (chunk[2]as Scalar) << 2 | (chunk[1] >> 6) as Scalar;

        //       bottom 2 bits of d5 || 8 bits of d4 || top 4 bits of d3
        v[4*i + 2] = ((chunk[5] & 0x03) as Scalar) << 12 | (chunk[4]as Scalar) << 4 | (chunk[3] >> 4) as Scalar;

        //             8 bits of d6 || top 6 bits of d5
        v[4*i + 3] = (chunk[6] as Scalar) << 6 | (chunk[5] >> 2) as Scalar;
    }
    Vector(v)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_packing() {
        let mut x = [0; HILA5_N];
        x[..4].copy_from_slice(&[10951, 5645, 3732, 4089]);
        let x = Vector(x);
        let y = hila5_pack14(&x);
        assert_eq!(&y[..7], &[0xC7, 0x6A, 0x83, 0x45, 0xE9, 0xE4, 0x3F]);
        assert_eq!(&x.0[..], &hila5_unpack14(&y).0[..]);

    }
}
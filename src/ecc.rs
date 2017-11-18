#[cfg(target_endian = "big")]
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian, BigEndian};
#[cfg(target_endian = "big")]
use std::io::Cursor;


const XE5_LENGTHS: [u8; 10] = [16 , 16 , 17 , 31 , 19 , 29 , 23 , 25 , 27 , 37];

/// Compute redundancy r[] ( XOR over original ) from data d[]
pub fn xe5_cod(d: &[u64; 4], r: &mut [u64; 4]) {
    let d = &switch_endianness(d);
    switch_endianness_in_place(r);

    let mut ri = [0u64; 10];

    for (i, di) in d.iter().enumerate().rev() {
        let mut x = *di;
        for (j, rj) in ri.iter_mut().enumerate().skip(1) {
            let l = XE5_LENGTHS[j];
            let mut t = *rj << (64 % l);
            t ^= x;
            if l < 32 {
                t ^= t >> (2 * l);
            }
            t ^= t >> l;
            *rj = t & ((1u64 << l) - 1);
        }
        x ^= x >> 8;
        x ^= x >> 4;
        x ^= x >> 2;
        x ^= x >> 1;
        x &= 0x0001000100010001;
        x ^= (x >> (16 - 1)) ^ (x >> (32 - 2)) ^ (x >> (48 - 3));
        ri[0] |= (x & 0x0F) << (4 * i);
    }

    r[0] ^= ri[0] ^ (ri[1] << 16) ^ (ri[2] << 32) ^ (ri[3] << 49);
    r[1] ^= (ri[3] >> 15) ^ (ri[4] << 16) ^ (ri[5] << 35);
    r[2] ^= ri[6] ^ (ri[7] << 23) ^ (ri[8] << 48);
    r[3] ^= (ri[8] >> 16) ^ (ri[9] << 11);
}

/// Fix errors in data d[] using redundancy in r[]
pub fn xe5_fix(d: &mut [u64; 4], r: &[u64; 4]) {
    let mut ri = [
        r[0],
        r[0] >> 16,
        r[0] >> 32,
        (r[0] >> 49) ^ (r[1] << 15),
        r[1] >> 16,
        r[1] >> 35,
        r[2],
        r[2] >> 23,
        (r[2] >> 48) ^ (r[3] << 16),
        r[3] >> 11,
    ];

    for (i, di) in d.iter_mut().enumerate() {
        for (j, rj) in ri.iter_mut().enumerate().skip(1) {
            let l = XE5_LENGTHS[j];
            let mut x = *rj & ((1 << l) - 1);
            x |= x << l;
            if l < 32 {
                x |= x << (2 * l);
            }
            *rj = x;
        }
        let mut x = ri[0] >> (4 * i) & 0xF;
        x ^= (x << (16 - 1)) ^ (x << (32 - 2)) ^ (x << (48 - 3));
        x  = 0x0100010001000100 - (x & 0x0001000100010001);
        x &= 0x00FF00FF00FF00FF;
        x |= x << 8;

        for j in 0..4 {
            let mut t = (x >> j) & 0x1111111111111111;
            for rk in ri.iter().skip(1) {
                t += (*rk >> j) & 0x1111111111111111;
            }
            t = ((t + 0x2222222222222222) >> 3) & 0x1111111111111111;
            *di ^= t << j;
        }
        if i < 3 {
            for (j, rj) in ri.iter_mut().enumerate().skip(1) {
                *rj >>= 64 % XE5_LENGTHS[j];
            }
        }

    }
}

#[cfg(target_endian = "big")]
fn switch_endianness(input: &[u64]) -> Vec<u64> {
    let mut output = input.to_vec();
    switch_endianness_in_place(&mut output);
    output
}

#[cfg(target_endian = "big")]
fn switch_endianness_in_place(input: &mut [u64]) {
    let mut tmp = vec![];
    for x in input {
        tmp.write_u64::<BigEndian>(*x).unwrap();
    }
    let mut rdr = Cursor::new(tmp);
    rdr.read_u64_into::<LittleEndian>(&mut input).unwrap();
    output
}

#[cfg(target_endian = "little")]
fn switch_endianness(input: &[u64]) -> &[u64] { input }

#[cfg(target_endian = "little")]
fn switch_endianness_in_place(_input: &mut [u64]) { }

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_cod() {
        let d = vec![0x0, 0x1, 0x1, 0x2, 0x3, 0x5, 0x8, 0xd, 0x15, 0x22, 0x37, 0x59,
        0x90, 0xe9, 0x79, 0x62, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
        0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd];

        let d4 = [0x0D08050302010100, 0x6279E99059372215, 0xF12FC26D55183DDB, 0xDD28B57342311120];
        let mut r = [0; 4];
        xe5_cod(&d4, &mut r);
        assert_eq!(&r, &[0x5D193C3A9B0A3171, 0xE439D357352B06CF, 0xDF517AD4F8F2DE07, 0x492E2AC7B92B]);
    }

    #[test]
    fn test_fix() {
        let d_orig     = [0x0D08050302010100, 0x6279E99059372215, 0xF12FC26D55183DDB, 0xDD28B57342311120];
        // let d_err = [0x0000000000002000, 0x0800000000000000, 0x0000000000000000, 0x0000040000000000];
        // let r     = [0x5D193C3A9B0A3171, 0xE439D357372B06CF, 0xDF517AD4F8F2DE07, 0x492E2AC7B82B];
        // let r_err = [0x0000000000000000, 0x0000000002000000, 0x0000000000000000, 0x0000000000000100];

        // let d2 = [d[0] ^ d_err[0], d[1] ^ d_err[1], d[2] ^ d_err[2], d[3] ^ d_err[3]];
        // let r2 = [r[0] ^ r_err[0], r[1] ^ r_err[1], r[2] ^ r_err[2], r[3] ^ r_err[3]];
        let mut d = [0x0D08050302012100, 0x6A79E99059372215, 0xF12FC26D55183DDB, 0xDD28B17342311120];
        let r     = [0x5D193C3A9B0A3171, 0xE439D357372B06CF, 0xDF517AD4F8F2DE07,     0x492E2AC7B82B];

        let mut r3 = r.clone();
        xe5_cod(&d, &mut r3);
        assert_eq!(r3, [0x400000102C004081, 0x0001042020408004, 0xA000401100002110, 0x0000000001000104]);

        xe5_fix(&mut d, &r3);
        assert_eq!(d, d_orig);
    }
}
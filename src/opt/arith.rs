// Modified from code released by Microsoft under MIT License and 
// 2017-05-11  Markku-Juhani O. Saarinen <mjos@iki.fi> (as ms_ntt.c)    
// 2017-11-20  Sam Scott <me@samjs.co.uk>

/*****************************************************************************
* LatticeCrypto: an efficient post-quantum Ring-Learning With Errors
*   cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: NTT functions and other polynomial operations
*
*****************************************************************************/

use std::ops::{Add, Mul, MulAssign};

use super::super::*;

use opt::consts::MSLC_PSI_REV_NTT1024 as PSI_REV;
use opt::consts::MSLC_INV_REV_NTT1024 as OMEGAINV_REV;

/// Vector addition : d = a + b .
impl<'a, 'b> Add<&'a Vector> for &'b Vector {
    type Output = Vector;

    fn add(self, rhs: &Vector) -> Self::Output {
        let mut d = [0; HILA5_N];
        for (i, (ai, bi)) in self.0.iter().zip(rhs.0.iter()).enumerate() {
            d[i] = (ai + bi) % HILA5_Q;
        }

        Vector(d)
    }
}

/// Vector addition : d = a + b .
impl<'a, 'b> Add<&'a NttVector> for &'b NttVector {
    type Output = NttVector;

    fn add(self, rhs: &NttVector) -> Self::Output {
        let mut d = [0; HILA5_N];
        for (i, (ai, bi)) in self.0.iter().zip(rhs.0.iter()).enumerate() {
            d[i] = reduce_12289((ai + bi) as i64);
        }

        NttVector(d)
    }
}

/// Vector multiplication : v = c * u .
impl<'a> Mul<Scalar> for &'a Vector {
    type Output = Vector;

    fn mul(self, c: Scalar) -> Self::Output {
        let mut v = [0; HILA5_N];
        for (i, ui) in self.0.iter().enumerate() {
            v[i] = (ui * c) % HILA5_Q;
        }

        Vector(v)
    }
}

/// Vector multiplication : v = c * u .
impl<'a> Mul<Scalar> for &'a NttVector {
    type Output = NttVector;

    fn mul(self, c: Scalar) -> Self::Output {
        let mut v = [0; HILA5_N];
        for (i, ui) in self.0.iter().enumerate() {
            v[i] = ((*ui as i64 * c as i64) % HILA5_Q as i64) as Scalar;
        }

        NttVector(v)
    }
}

// Vector multiplication : v = c * v .
impl MulAssign<Scalar> for Vector {
    fn mul_assign(&mut self, c: Scalar) {
        for vi in self.0.iter_mut() {
            *vi *= c % HILA5_Q;
        }
    }
}

/// Slow polynomial ring multiplication : d = a * b
impl<'a, 'b> Mul<&'a Vector> for &'b Vector {
    type Output = Vector;

    fn mul(self, b: &Vector) -> Self::Output {
        let a = self;
        let mut d = [0; HILA5_N];

        for (i, di) in d.iter_mut().enumerate() {
            let mut x = 0;
            for (aj, bij) in a.0.iter().zip(b.0[..(i+1)].iter().rev()) {
                x = (x + aj * bij) % HILA5_Q;
            }
            for (aj, bij) in a.0.iter().skip(i + 1).zip(b.0.iter().rev()) {
                x +=  HILA5_Q - ((aj * bij) % HILA5_Q);
            }
            *di = x % HILA5_Q;
        }
        Vector(d)
    }
}


/// Fast number theoretic transform and scaling : d = c * NTT ( v ) .
/// c is effectively hardcoded however to be c = 27
pub fn ntt(v: Vector) -> NttVector {
    // maybe rewrite so this can be in place?
    let mut d = v.0;

    let mut k = HILA5_N;
    for m in (0..7).map(|i| 1 << i) {
        k = k >> 1;
        for i in 0..m {
            let j1 = 2 * i * k;
            let j2 = j1 + k - 1;
            let s = PSI_REV[m + i];
            for j in j1..(j2 + 1) {
                let u = d[j];
                let v = reduce_12289(d[j + k] as i64 * s as i64);
                d[j] = u + v;
                d[j + k] = u - v;
            }
        }

    }

    k = 4;

    for i in 0..128 {
        let j1 = 8 * i;
        let j2 = j1 + 3;
        let s = PSI_REV[i + 128];
        for j in j1..(j2 + 1) {
            let u = reduce_12289(d[j] as i64);
            let v = reduce12289_2x(d[j + 4] as i64 * s as i64);
            d[j] = u + v;
            d[j + 4] = u - v;
        }
    }

    for m in (8..10).map(|i| 1 << i) {
        k = k >> 1;
        for i in 0..m {
            let j1 = 2 * i * k;
            let j2 = j1 + k - 1;
            let s = PSI_REV[m + i];
            for j in j1..(j2 + 1) {
                let u = d[j];
                let v = reduce_12289(d[j + k] as i64 * s as i64);
                d[j] = u + v;
                d[j + k] = u - v;
            }
        }
    }
    NttVector::from(d)
}


/// Fast inverse number theoretic transform : d = c * NTT ^ -1( v ) .
/// Result already has the usual n=1024 factor cleared
pub fn intt(v: NttVector, c: Scalar) -> Vector {
    // 12277 = 2^-10
    // 2950 = 2^-10 * 11227 = 2^-10 * 3^-4 (why 3^-4 here?)
    // let o_inv = 12277 * c % HILA5_Q;
    let o_inv = 2950 * c % HILA5_Q;
    // n_inv is o_inv * sqrt(-1) ((sqrt(-1) = 1479))
    let n_inv = 455 * c % HILA5_Q;
    let mut d =  v.0;

    let mut k = 1;

    for m in (2..11).rev().map(|i| 1 << i) {
        let mut j1 = 0;
        let h = m >> 1;
        for i in 0..h {
            let j2 = j1 + k - 1;
            let s = OMEGAINV_REV[h + i];
            for j in j1..(j2 + 1) {
                let u = d[j];
                let v = d[j + k];
                d[j] = u + v;
                let tmp = (u - v) as i64 * s as i64;
                if m == 32 {
                    d[j] = reduce_12289(d[j] as i64);
                    d[j + k] = reduce12289_2x(tmp);
                } else {
                    d[j + k] = reduce_12289(tmp);
                }
            }
            j1 += 2 * k;
        }
        k *= 2;
    }

    for j in 0..k {
        let u = d[j];
        let v = d[j + k];
        d[j] = reduce_12289((u + v) as i64 * n_inv as i64);
        d[j + k] = reduce_12289((u - v) as i64 * o_inv as i64);
    }

    Vector::from(d)
}

/// return a * b + c
pub fn mul_add<V: Hila5Vector>(a: &V, b: &V, c: &V) -> V {
    let mut d = [0; HILA5_N];
    let a = a.get_inner();
    let b = b.get_inner();
    let c = c.get_inner();

    for (di, (&ci, (&bi, &ai))) in d.iter_mut().zip(c.iter().zip(b.iter().zip(a.iter()))) {
        *di = reduce_12289(reduce_12289((ai as i64 * bi as i64) + ci as i64) as i64);
    }
    V::from(d)
}



/// Pointwise multiplication : d = a (*) b .
impl<'a, 'b> Mul<&'a NttVector> for &'b NttVector {
    type Output = NttVector;

    fn mul(self, b: &NttVector) -> Self::Output {
        let a = self;
        let mut d = [0; HILA5_N];
        for (di, (ai, bi)) in d.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
            *di = reduce_12289(reduce_12289((*ai as i64 * *bi as i64)) as i64);
        }
        NttVector(d)
    }
}

// Additional mslc_ntt functions:

/// Reduction modulo q
fn reduce_12289(a: i64) -> i32 {
    let c0 = (a & 0xfff) as i32;
    let c1 = (a >> 12) as i32;
    3 * c0 - c1
}

/// Two merged reductions modulo q
fn reduce12289_2x(a: i64) -> i32 {
    let c0 = (a & 0xFFF) as i32;
    let c1 = ((a >> 12) & 0xFFF) as i32;
    let c2 = (a >> 24) as i32;

    9 * c0 - 3 * c1 + c2
}

/// Two consecutive reductions modulo q
pub fn two_reduce12289<V: Hila5Vector>(v: &mut V) {
    for vi in v.get_inner_mut().iter_mut() {
        *vi = reduce_12289(reduce_12289(*vi as i64) as i64);
    }
}

/// `mslc_correction` with hardcoded `p = HILA5_Q` and `n = HILA5_N`
pub fn correction<V: Hila5Vector>(v: &mut V) {
    for vi in v.get_inner_mut().iter_mut() {
        // assume sizeof(i32) == 4
        let mask = *vi >> 15;
        *vi += (HILA5_Q & mask) - HILA5_Q;
        let mask = *vi >> 15;
        *vi += HILA5_Q & mask;
    }
}


#[cfg(test)]
mod test {
    use ring::rand::{SecureRandom, SystemRandom};

    use super::*;
    #[test]
    fn test_vector() {
        let mut fibv = [0; HILA5_N];
        fibv[1] = 1;
        for i in 2..HILA5_N {
            fibv[i] = (fibv[i-1] + fibv[i-2]) % HILA5_Q;
        }
        let fibv = Vector(fibv);
        let fibv_clone = Vector(fibv.0.clone());
        let mut fib_ntt = ntt(fibv);
        two_reduce12289(&mut fib_ntt);
        fib_ntt.norm();
         // ntt multiplies by 27 inherently. this cancels that out so we have
         // fib_ntt = NTT(fibv)
        let fib_ntt = &fib_ntt * 9103;
        assert_eq!(&fib_ntt.0[..5], &[10951, 5645, 3732, 4089, 442]);
        assert_eq!(&fib_ntt.0[HILA5_N - 5..], &[10237, 754, 6341, 4211, 7921]);
        let mut rec = intt(fib_ntt, 1024);
        two_reduce12289(&mut rec);
        rec.norm();
        assert_eq!(&rec.0[..5], &[0, 1024, 1024, 2048, 3072]);
        assert_eq!(&rec.0[HILA5_N - 5..], &[11912, 333, 12245, 289, 245]);
        let rec2 = &rec * 12277;
        assert_eq!(&rec2.0[..], &fibv_clone.0[..]);
    }


    #[test]
    fn random_test() {
        let rng = SystemRandom::new();
        let mut rand_bytes = [0u8; 64];
        rand_bytes[0] = 0xff;

        for _ in 0..10 {
            rng.fill(&mut rand_bytes).unwrap();

            let mut a: Vector = rand::from_seed(&rand_bytes[..32]);
            two_reduce12289(&mut a);
            a.norm();

            let mut b: Vector = rand::from_seed(&rand_bytes[32..]);
            two_reduce12289(&mut b);
            b.norm();

            let x: Vector = &a * &b; // x is a * b
            let mut t = ntt(a); // t is NTT(a)
            two_reduce12289(&mut t);
            t.norm();
            let mut y = ntt(b); // y is NTT(n)
            two_reduce12289(&mut y);
            y.norm();
            let mut t: NttVector = &t * &y; // t is NTT(a) * NTT(b)
             // result is actually 9 * NTT(a) * NTT(b), clear it?
            t = &t * 2731;

            // Need to clear factor of 3^6.
            let mut y = arith::intt(t, 12171);
            two_reduce12289(&mut y);
            y.norm();
            // let y = &y * 7755;
            assert_eq!( &y.0[..5], &x.0[..5]);
        }
    }

    #[test]
    fn round_trip() {
        let rng = SystemRandom::new();
        let mut rand_bytes = [0u8; 64];
        rand_bytes[0] = 0xff;

        for _ in 0..10 {
            rng.fill(&mut rand_bytes).unwrap();

            let mut a: Vector = rand::from_seed(&rand_bytes[..32]);
            two_reduce12289(&mut a);
            a.norm();

            let mut a2: Vector = rand::from_seed(&rand_bytes[..32]);
            two_reduce12289(&mut a2);
            a2.norm();

            let a = arith::ntt(a);
            // We get an extra factor of 3 somehow
            let mut a = arith::intt(a, 8193);
            two_reduce12289(&mut a);
            a.norm();

            // should have factors cleared automatically
            assert_eq!(&a.0[..5], &a2.0[..5]); 
        }
    }
}
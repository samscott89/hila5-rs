use std::ops::{Add, Mul, MulAssign};

use super::*;


lazy_static! {
    /// powers of g =1945 mod q
    static ref pow1945: [Scalar; 2048] = {
        let mut tmp = [0; 2048];
        let mut x = 1;
        for p in tmp.iter_mut() {
            *p = x;
            x = (1945 * x) % HILA5_Q;
        }
        tmp
    };
}

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
            d[i] = (ai + bi) % HILA5_Q;
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

// Vector multiplication : v = c * v .
impl MulAssign<Scalar> for Vector {
    fn mul_assign(&mut self, c: Scalar) {
        for vi in self.0.iter_mut() {
            *vi *= c % HILA5_Q;
        }
    }
}

/// Slow polynomial ring multiplication : d = a * b (== `slow_rmul`)
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

/// reverse order of ten bits i . e . 0 x200 -> 0 x001 and vice versa
pub fn bitrev10(x: usize) -> usize {
    let mut x = x & 0x3ff;
    x = (x << 5) | (x >> 5);
    let mut t = (x ^ (x >> 4)) & 0x021;
    x ^= t ^ (t << 4);
    t = (x ^ (x >> 2)) & 0x042;
    x ^= t ^ (t << 2);
    return x & 0x3ff;
}

/// Slow number theoretic transform and scaling : d = c * NTT ( v ) .
pub fn slow_ntt(v: &Vector, c: Scalar) -> NttVector {
    let mut d = [0; HILA5_N];
    for (i, di) in d.iter_mut().enumerate() {
        let r = (2 * bitrev10(i) + 1) as Scalar;
        let mut x = 0;
        let mut k: Scalar = 0;
        for vj in v.0.iter() {
            x = (x + vj * pow1945[k as usize]) % HILA5_Q;
            k = (k + r) & 0x7ff;
        }
        *di = (c * x) % HILA5_Q;
    }
    NttVector(d)
}

/// Slow inverse number theoretic transform : d = NTT ^ -1( v ) .
pub fn slow_intt(v: &NttVector) -> Vector {
    let mut d = [0; HILA5_N];
    for (i, vi) in v.0.iter().enumerate() {
        let r = (2 * bitrev10(i) + 1) as Scalar;
        let mut k: Scalar = 0;
        for dj in d.iter_mut() {
            *dj = (*dj + vi * pow1945[k as usize]) % HILA5_Q;
            k = (k - r) & 0x7ff;
        }
    }
    Vector(d)
}

/// Pointwise multiplication : d = a (*) b . (== `slow_vmul`)
impl<'a, 'b> Mul<&'a NttVector> for &'b NttVector {
    type Output = NttVector;

    fn mul(self, b: &NttVector) -> Self::Output {
        let a = self;
        let mut d = [0; HILA5_N];
        for (di, (ai, bi)) in d.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
            *di = (ai * bi) % HILA5_Q;
        }
        NttVector(d)
    }
}




#[cfg(test)]
mod test {
    use ring::rand::{SecureRandom, SystemRandom};

    use super::*;

    #[test]
    fn test_bitflip() {
        assert_eq!(bitrev10(0x200), 0x001);
    }

    #[test]
    fn test_vector() {
        let mut fibv = [0; HILA5_N];
        fibv[1] = 1;
        for i in 2..HILA5_N {
            fibv[i] = (fibv[i-1] + fibv[i-2]) % HILA5_Q;
        }
        let fibv = Vector(fibv);
        let fib_ntt = slow_ntt(&fibv, 1);
        assert_eq!(&fib_ntt.0[..5], &[10951, 5645, 3732, 4089, 442]);
        assert_eq!(&fib_ntt.0[HILA5_N - 5..], &[10237, 754, 6341, 4211, 7921]);
        let rec = slow_intt(&fib_ntt);
        assert_eq!(&rec.0[..5], &[0, 1024, 1024, 2048, 3072]);
        assert_eq!(&rec.0[HILA5_N - 5..], &[11912, 333, 12245, 289, 245]);
    }

    #[test]
    fn random_test() {
        let rng = SystemRandom::new();
        let mut rand_bytes = [0u8; 4 * HILA5_N];

        for _ in 0..10 {
            rng.fill(&mut rand_bytes).unwrap();
            let mut a = [0; HILA5_N];
            let mut b = [0; HILA5_N];
            
            for i in 0..HILA5_N {
                let ai = ((rand_bytes[2*i] as Scalar) << 8  | (rand_bytes[2*i + 1]) as Scalar) % HILA5_Q;
                let bi = ((rand_bytes[HILA5_N + 2*i] as Scalar) << 8 | (rand_bytes[HILA5_N + 2*i + 1]) as Scalar) % HILA5_Q;
                a[i] = ai as Scalar;
                b[i] = bi as Scalar;
            }
            let a = Vector(a);
            let b = Vector(b);

            let x: Vector = &a * &b; // x is a * b
            let t = slow_ntt(&a, 1); // t is NTT(a)
            let y = slow_ntt(&b, 12277); // y is NTT(n) / 1024
            let t: NttVector = &t * &y; // t is NTT(a) * NTT(b) / 1024
            let y = slow_intt(&t); // y is a * b

            assert_eq!( &x.0[..], &y.0[..] );
        }
    }
}
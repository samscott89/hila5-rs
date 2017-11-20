#![feature(test)]

extern crate hila5;

extern crate test;
use test::Bencher;

#[bench]
fn keygen_rs(b: &mut Bencher) {
    b.iter(|| hila5::crypto_kem_keypair().unwrap())
}
#[bench]
fn keygen_c(b: &mut Bencher) {
    b.iter(|| {
        let mut pk = [0u8; hila5::PUBKEY_LEN];
        let mut sk = [0u8; hila5::PRIVKEY_LEN];
        unsafe {
           assert!(0 == ffi::crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()));;
        }
    })
}

#[bench]
fn enc_rs(b: &mut Bencher) {
    let (pk, sk) = hila5::crypto_kem_keypair().unwrap();

    b.iter(|| hila5::kem::enc(&pk).unwrap())
}

#[bench]
fn enc_c(b: &mut Bencher) {
    let mut pk = [0u8; hila5::PUBKEY_LEN];
    let mut sk = [0u8; hila5::PRIVKEY_LEN];
    unsafe {
        ffi::crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }

    b.iter(|| {
        let mut ss = [0u8; 32];
        let mut ct = [0u8; hila5::CIPHERTEXT_LEN];
        unsafe {
            assert!(0 == ffi::crypto_kem_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()));
        }
    })
}

#[bench]
fn dec_rs(b: &mut Bencher) {
    let (pk, sk) = hila5::crypto_kem_keypair().unwrap();
    let (ct, ss) = hila5::kem::enc(&pk).unwrap();

    b.iter(|| {
        let ss2 = hila5::kem::dec(&ct, &sk).unwrap();
        assert_eq!(&ss.0[..], &ss2.0[..]);
    })
}

#[bench]
fn dec_c(b: &mut Bencher) {
    let mut pk = [0u8; hila5::PUBKEY_LEN];
    let mut sk = [0u8; hila5::PRIVKEY_LEN];
    let mut ss = [0u8; 32];
    let mut ct = [0u8; hila5::CIPHERTEXT_LEN];
    unsafe {
        ffi::crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        ffi::crypto_kem_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr());
    }

    b.iter(|| {
        let mut ss2 = [0u8; 32];
        unsafe {
            assert!(0 == ffi::crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()));
            assert_eq!(ss, ss2);
        }

    })
}



mod ffi {
    extern "C" {
        pub fn crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> i32;
        pub fn crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
        pub fn crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
    }
}

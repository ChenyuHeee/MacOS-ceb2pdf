//! Unwrapping the 3DES key: a 512-bit textbook RSA operation with no padding.
//!
//! The key blob in section 5 is 64 bytes of raw ciphertext.  Applying the
//! hardcoded public exponent to it yields, little-endian:
//!
//! ```text
//! u32 length  ||  `length` key bytes  ||  zero padding
//! ```
//!
//! The two 512-bit constants come from the upstream C++ implementation, where
//! the bytes were memcpy'd straight into an OpenSSL `BIGNUM` limb array --
//! which means they must be read **little-endian**, not big-endian as an RSA
//! modulus normally would be.  Same for the ciphertext and the result.
//!
//! ## Why a hand-rolled bignum
//!
//! This runs exactly once per file, on 512 bits.  `num-bigint` would add more
//! to the binary than this whole file.  So: fixed 8x u64 limbs, and modular
//! multiplication by double-and-add rather than Montgomery.  That is ~512
//! modular doublings per multiply, which is asymptotically silly and
//! measurably irrelevant (a few ms per file), and it is short enough to audit
//! by eye.

use crate::error::{Error, Result};

pub const LIMBS: usize = 8;
pub const BYTES: usize = LIMBS * 8;
pub const BITS: usize = BYTES * 8;

/// Fixed-width 512-bit unsigned integer, limb 0 least significant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U512(pub [u64; LIMBS]);

/// `91437cd8...522497db`, read little-endian.
pub const MODULUS: U512 = U512([
    0xce22073dd87c4391,
    0x34ff0ca86cd90b41,
    0xc38b12255e315a89,
    0x9750e414f6d52925,
    0xadf1da680c452ee1,
    0x4f5608b70a748e8d,
    0x5648c412807b314f,
    0xdb972452587d56de,
]);

/// `f384ff17...59db00c5`, read little-endian.
pub const EXPONENT: U512 = U512([
    0x0e5a16a817ff84f3,
    0xa91244f526a5b0ce,
    0x4fe1b56869ec889a,
    0xe3fd2fe9be087aaf,
    0xcc6ed89746c5185b,
    0x7591bc42e6009763,
    0xcc954cefc52d527e,
    0xc500db59d2d246d7,
]);

impl U512 {
    pub const ZERO: U512 = U512([0; LIMBS]);

    pub fn one() -> Self {
        let mut v = U512::ZERO;
        v.0[0] = 1;
        v
    }

    pub fn from_le_bytes(b: &[u8; BYTES]) -> Self {
        let mut v = U512::ZERO;
        for (i, limb) in v.0.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i * 8..i * 8 + 8]);
            *limb = u64::from_le_bytes(w);
        }
        v
    }

    pub fn to_le_bytes(self) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    pub fn bit(&self, i: usize) -> bool {
        self.0[i / 64] >> (i % 64) & 1 == 1
    }

    /// Index of the highest set bit plus one; 0 for zero.
    pub fn bit_len(&self) -> usize {
        for i in (0..LIMBS).rev() {
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    fn ge(&self, other: &U512) -> bool {
        for i in (0..LIMBS).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Greater => return true,
                std::cmp::Ordering::Less => return false,
                std::cmp::Ordering::Equal => {}
            }
        }
        true
    }

    /// `self + rhs`, returning the 513th bit as the carry.
    fn add(&self, rhs: &U512) -> (U512, bool) {
        let mut out = U512::ZERO;
        let mut carry = 0u64;
        for i in 0..LIMBS {
            let (s, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (s, c2) = s.overflowing_add(carry);
            out.0[i] = s;
            carry = u64::from(c1) + u64::from(c2);
        }
        (out, carry != 0)
    }

    /// `self - rhs` wrapping, plus the borrow out.
    fn sub(&self, rhs: &U512) -> (U512, bool) {
        let mut out = U512::ZERO;
        let mut borrow = 0u64;
        for i in 0..LIMBS {
            let (d, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            out.0[i] = d;
            borrow = u64::from(b1) + u64::from(b2);
        }
        (out, borrow != 0)
    }
}

/// Arithmetic modulo an odd 512-bit modulus whose top bit is set.
///
/// That precondition is what makes the single conditional subtraction in
/// [`ModRing::reduce`] sufficient: any 512-bit value is below `2 * n`.
pub struct ModRing {
    n: U512,
}

impl ModRing {
    pub fn new(n: U512) -> Option<Self> {
        if n.bit_len() != BITS {
            return None;
        }
        Some(ModRing { n })
    }

    /// Reduce a value known to be < 2^512 (hence < 2n).
    fn reduce(&self, a: U512) -> U512 {
        if a.ge(&self.n) {
            a.sub(&self.n).0
        } else {
            a
        }
    }

    fn add_mod(&self, a: U512, b: U512) -> U512 {
        let (s, carry) = a.add(&b);
        // With a, b < n < 2^512 the sum is < 2^513, so one subtraction is
        // enough -- but it is needed either when the sum overflowed 512 bits
        // or when it merely reached n.
        if carry || s.ge(&self.n) {
            s.sub(&self.n).0
        } else {
            s
        }
    }

    /// Double-and-add: `a * b mod n` in `BITS` modular doublings.
    fn mul_mod(&self, a: U512, b: U512) -> U512 {
        let mut acc = U512::ZERO;
        let top = b.bit_len();
        for i in (0..top).rev() {
            acc = self.add_mod(acc, acc);
            if b.bit(i) {
                acc = self.add_mod(acc, a);
            }
        }
        acc
    }

    /// `base^exp mod n`, square-and-multiply, most significant bit first.
    pub fn pow_mod(&self, base: U512, exp: U512) -> U512 {
        let base = self.reduce(base);
        let top = exp.bit_len();
        if top == 0 {
            return self.reduce(U512::one());
        }
        let mut acc = self.reduce(U512::one());
        for i in (0..top).rev() {
            acc = self.mul_mod(acc, acc);
            if exp.bit(i) {
                acc = self.mul_mod(acc, base);
            }
        }
        acc
    }
}

/// Longest key we will accept out of the RSA envelope.  3DES is 24 bytes; the
/// slack is there in case another algorithm id turns up.
pub const MAX_KEY_LEN: usize = 32;

/// Apply the built-in public exponent to a 64-byte wrapped key blob and pull
/// the key out of the result.
pub fn unwrap_key(blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() != BYTES {
        return Err(Error::BadKeyLength {
            ty: crate::container::section::KEY_BLOB,
            what: "RSA-wrapped 3DES key",
            len: blob.len(),
            expected: "64 bytes",
        });
    }
    let ring = ModRing::new(MODULUS).ok_or_else(|| Error::RsaUnwrapFailed {
        reason: "built-in modulus is not a full 512 bits (this is a bug)".into(),
    })?;

    let mut c = [0u8; BYTES];
    c.copy_from_slice(blob);
    let plain = ring
        .pow_mod(U512::from_le_bytes(&c), EXPONENT)
        .to_le_bytes();

    let len = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    if len == 0 || len > MAX_KEY_LEN {
        return Err(Error::RsaUnwrapFailed {
            reason: format!(
                "length field says {len} bytes, which is not a plausible key length \
                 (expected 1..={MAX_KEY_LEN}). The file may use a different RSA key pair \
                 than the one built in."
            ),
        });
    }
    Ok(plain[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::{decode, encode};

    fn u512(hex: &str) -> U512 {
        let v = decode(hex).unwrap();
        let mut b = [0u8; BYTES];
        b[..v.len()].copy_from_slice(&v);
        U512::from_le_bytes(&b)
    }

    #[test]
    fn modulus_is_512_bit_and_odd() {
        assert_eq!(MODULUS.bit_len(), 512);
        assert_eq!(EXPONENT.bit_len(), 512);
        assert!(MODULUS.0[0] & 1 == 1);
        assert!(ModRing::new(MODULUS).is_some());
    }

    #[test]
    fn constants_round_trip_to_the_published_hex() {
        assert_eq!(
            encode(&MODULUS.to_le_bytes()),
            "91437cd83d0722ce410bd96ca80cff34895a315e25128bc32529d5f614e45097\
             e12e450c68daf1ad8d8e740ab708564f4f317b8012c44856de567d58522497db"
        );
        assert_eq!(
            encode(&EXPONENT.to_le_bytes()),
            "f384ff17a8165a0eceb0a526f54412a99a88ec6968b5e14faf7a08bee92ffde3\
             5b18c54697d86ecc639700e642bc91757e522dc5ef4c95ccd746d2d259db00c5"
        );
    }

    #[test]
    fn add_sub_are_consistent() {
        let a = u512("0102030405060708090a0b0c0d0e0f10");
        let b = u512("f0e0d0c0b0a090807060504030201000");
        let (s, c) = a.add(&b);
        assert!(!c);
        assert_eq!(s.sub(&b).0, a);
    }

    #[test]
    fn bit_len_edges() {
        assert_eq!(U512::ZERO.bit_len(), 0);
        assert_eq!(U512::one().bit_len(), 1);
        assert_eq!(u512("03").bit_len(), 2);
    }

    /// `pow(2, e, n)` and friends, computed by Python in tools/ceb_poc.py's
    /// constants.  These pin the bignum down independently of any sample file.
    #[test]
    fn pow_mod_matches_python() {
        let ring = ModRing::new(MODULUS).unwrap();
        let cases = [
            (
                "02",
                "427fd61435709f268cae529c8d05c29c03120fa258448cfa362d8a3846a3bc78\
                 e38beeab8c9ba39b55e513462ec5f79811454b90e714a5698e9ed1ac44312ca4",
            ),
            (
                "03",
                "1bfe3ff0dce7278fd27aa954976a8bcced1184caee6c3f26889eec76178f8f39\
                 74f369ee607341a5f072c1acb67ee2cb9bdf66558d491f928972101efa973214",
            ),
        ];
        for (base, want) in cases {
            let got = ring.pow_mod(u512(base), EXPONENT).to_le_bytes();
            assert_eq!(encode(&got), want.replace(' ', ""), "base {base}");
        }
    }

    #[test]
    fn pow_mod_of_n_minus_one() {
        let ring = ModRing::new(MODULUS).unwrap();
        let nm1 = MODULUS.sub(&U512::one()).0;
        assert_eq!(
            encode(&ring.pow_mod(nm1, EXPONENT).to_le_bytes()),
            "90437cd83d0722ce410bd96ca80cff34895a315e25128bc32529d5f614e45097\
             e12e450c68daf1ad8d8e740ab708564f4f317b8012c44856de567d58522497db"
                .replace(' ', "")
        );
    }

    /// The real thing: the sample's section 5, and the key FINDINGS.md says it
    /// must yield.
    #[test]
    fn unwraps_the_sample_key() {
        let blob = decode(
            "a2c8c0244570858b23ccaf50cd41862fd3b0a159f4101be7d1208abcfe5e2df4\
             237032acf107c5130792876aff1cda946b5ecb70e0332ade601950ef1aa8fac4",
        )
        .unwrap();
        let key = unwrap_key(&blob).unwrap();
        assert_eq!(key.len(), 24);
        assert_eq!(
            encode(&key),
            "a1e7f815671f82812870e2315352f1569a4cb39584f08b03"
        );
        // FINDINGS.md's cross-check: the first 16 bytes are the RC4 key.
        assert_eq!(&encode(&key)[..32], "a1e7f815671f82812870e2315352f156");
    }

    #[test]
    fn rejects_wrong_blob_length() {
        match unwrap_key(&[0u8; 32]) {
            Err(Error::BadKeyLength { len: 32, .. }) => {}
            other => panic!("expected BadKeyLength, got {other:?}"),
        }
    }

    #[test]
    fn rejects_implausible_length_field() {
        // Random garbage will essentially never decrypt to a 1..=32 length.
        let blob: Vec<u8> = (0..64)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect();
        match unwrap_key(&blob) {
            Err(Error::RsaUnwrapFailed { .. }) => {}
            other => panic!("expected RsaUnwrapFailed, got {other:?}"),
        }
    }
}

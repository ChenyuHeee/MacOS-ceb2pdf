//! The second layer: 3DES over each PDF stream's payload.
//!
//! Parameters, all measured on real files:
//!
//! * **Mode: CFB with 64-bit (full-block) segments.**  Not OFB -- see below.
//! * IV = the first 8 bytes of the key itself.
//! * The cipher is **re-initialised every 256 bytes** rather than chained
//!   across the whole stream, so every 256-byte window restarts from the IV.
//!
//! Both modes are length-preserving, which is the whole reason the conversion
//! can happen in place and leave every `xref` offset in the PDF valid.
//!
//! ## Why OFB is here too, and why CFB64 is the default
//!
//! This layer was first recorded as OFB, and that was wrong.  The two modes are
//! *provably indistinguishable* on the evidence that was being used:
//!
//! ```text
//! CFB64 decrypt:  P1 = C1 ^ E(IV),  Pi = Ci ^ E(C{i-1})
//! OFB   decrypt:  P1 = C1 ^ E(IV),  Pi = Ci ^ Oi, Oi = E(O{i-1}), O0 = IV
//! ```
//!
//! The expressions for `P1` are literally identical, so the **first 8 bytes of
//! every 256-byte window come out the same either way** -- including the two
//! bytes of a zlib header.  And if the plaintext is all zeros the two feedback
//! chains coincide, so all-blank image bitmaps match as well.  "We get `78 9c`"
//! and "the blank bitmap decodes to zeros" were therefore not evidence at all.
//!
//! What settles it: under CFB64 all 20 `/FlateDecode` streams in the v3 sample
//! inflate and all 18 pages render; under OFB, none do.  The container had been
//! saying so all along -- algorithm id low bits 2 is `TYPE_3DES_CFB` in the
//! upstream enum.
//!
//! OFB stays implemented because algorithm id 1 is `TYPE_3DES_OFB` upstream.  No
//! sample has ever had that id, so the default dispatch refuses it rather than
//! guessing; `--force-mode ofb` will try it.

use des::cipher::{Array, BlockCipherEncrypt, KeyInit};
use des::TdesEde3;

use crate::error::{Error, Result};

pub const BLOCK: usize = 8;
/// The cipher restarts from the IV at every multiple of this many bytes.
pub const RESET: usize = 256;

/// The chaining modes we know how to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Cipher feedback, 64-bit segments.  Verified.
    Cfb64,
    /// Output feedback.  Implemented for algorithm id 1; never verified.
    Ofb,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Cfb64 => "3DES-CFB64",
            Mode::Ofb => "3DES-OFB",
        }
    }
}

pub struct Tdes {
    cipher: TdesEde3,
    iv: [u8; BLOCK],
    reset: usize,
}

impl Tdes {
    /// `key` may be 24 bytes (K1|K2|K3) or 16 bytes, which is expanded to the
    /// usual two-key form K1|K2|K1.
    pub fn new(key: &[u8], reset: usize) -> Result<Self> {
        let full: [u8; 24] = match key.len() {
            24 => {
                let mut k = [0u8; 24];
                k.copy_from_slice(key);
                k
            }
            16 => {
                let mut k = [0u8; 24];
                k[..16].copy_from_slice(key);
                k[16..].copy_from_slice(&key[..8]);
                k
            }
            other => {
                return Err(Error::BadKeyLength {
                    ty: crate::container::section::KEY_BLOB,
                    what: "3DES key",
                    len: other,
                    expected: "16 or 24 bytes",
                })
            }
        };
        assert!(
            reset > 0 && reset % BLOCK == 0,
            "the reset interval must be a positive multiple of 8"
        );
        let mut iv = [0u8; BLOCK];
        iv.copy_from_slice(&full[..BLOCK]);
        Ok(Tdes {
            cipher: TdesEde3::new(&Array::from(full)),
            iv,
            reset,
        })
    }

    fn e(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut b = Array::from(*block);
        self.cipher.encrypt_block(&mut b);
        b.into()
    }

    /// One OFB run from the IV.  Self-inverse.
    fn ofb_window(&self, buf: &mut [u8]) {
        let mut feedback = self.iv;
        for chunk in buf.chunks_mut(BLOCK) {
            feedback = self.e(&feedback);
            for (b, k) in chunk.iter_mut().zip(feedback.iter()) {
                *b ^= k;
            }
        }
    }

    /// One CFB64 decryption run from the IV: feedback is the *ciphertext*, so
    /// it has to be saved before the XOR overwrites it.
    fn cfb_decrypt_window(&self, buf: &mut [u8]) {
        let mut feedback = self.iv;
        for chunk in buf.chunks_mut(BLOCK) {
            let keystream = self.e(&feedback);
            let mut next = [0u8; BLOCK];
            next[..chunk.len()].copy_from_slice(chunk);
            for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
                *b ^= k;
            }
            feedback = next;
        }
    }

    /// One CFB64 encryption run from the IV: feedback is the ciphertext we just
    /// produced.  Only needed to build test fixtures.
    fn cfb_encrypt_window(&self, buf: &mut [u8]) {
        let mut feedback = self.iv;
        for chunk in buf.chunks_mut(BLOCK) {
            let keystream = self.e(&feedback);
            for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
                *b ^= k;
            }
            let mut next = [0u8; BLOCK];
            next[..chunk.len()].copy_from_slice(chunk);
            feedback = next;
        }
    }

    /// Decrypt in place, restarting the cipher every [`Tdes::reset`] bytes.
    pub fn decrypt(&self, mode: Mode, buf: &mut [u8]) {
        for window in buf.chunks_mut(self.reset) {
            match mode {
                Mode::Ofb => self.ofb_window(window),
                Mode::Cfb64 => self.cfb_decrypt_window(window),
            }
        }
    }

    /// Encrypt in place.  Exists so tests can build a ciphertext to decrypt.
    pub fn encrypt(&self, mode: Mode, buf: &mut [u8]) {
        for window in buf.chunks_mut(self.reset) {
            match mode {
                Mode::Ofb => self.ofb_window(window),
                Mode::Cfb64 => self.cfb_encrypt_window(window),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::{decode, encode};

    const SAMPLE_KEY: &str = "a1e7f815671f82812870e2315352f1569a4cb39584f08b03";

    fn key() -> Vec<u8> {
        decode(SAMPLE_KEY).unwrap()
    }

    fn tdes() -> Tdes {
        Tdes::new(&key(), RESET).unwrap()
    }

    /// Standard 3DES-EDE known-answer test, so we know the block cipher
    /// underneath really is 3DES and not something with a transposed schedule.
    #[test]
    fn block_cipher_is_3des() {
        let k: [u8; 24] = decode("0123456789abcdef23456789abcdef01456789abcdef0123")
            .unwrap()
            .try_into()
            .unwrap();
        let pt: [u8; 8] = decode("5468652071756663").unwrap().try_into().unwrap();
        let c = TdesEde3::new(&Array::from(k));
        let mut b = Array::from(pt);
        c.encrypt_block(&mut b);
        assert_eq!(encode(b.as_slice()), "a826fd8ce53b855f");
    }

    /// pycryptodome, same key: E(IV) is the first keystream block in both modes.
    #[test]
    fn first_keystream_block_is_e_of_iv() {
        for mode in [Mode::Cfb64, Mode::Ofb] {
            let mut buf = [0u8; 8];
            tdes().decrypt(mode, &mut buf);
            assert_eq!(encode(&buf), "8ebbb5121ed7ec0e", "{mode:?}");
        }
    }

    /// 600 zero bytes through CFB64, from tools/ceb_poc.py via pycryptodome.
    /// With an all-zero input the ciphertext feedback is E(IV) forever after the
    /// first block, so the output is E(IV) then E(0) repeated -- which is also a
    /// neat demonstration that CFB64 is *not* OFB.
    #[test]
    fn cfb64_zeros_match_python() {
        let mut buf = vec![0u8; 600];
        tdes().decrypt(Mode::Cfb64, &mut buf);
        assert_eq!(
            encode(&buf[..64]),
            "8ebbb5121ed7ec0e8203f6bb705c64448203f6bb705c64448203f6bb705c6444\
             8203f6bb705c64448203f6bb705c64448203f6bb705c64448203f6bb705c6444"
        );
    }

    #[test]
    fn ofb_zeros_match_python() {
        let mut buf = vec![0u8; 600];
        tdes().decrypt(Mode::Ofb, &mut buf);
        assert_eq!(
            encode(&buf[..64]),
            "8ebbb5121ed7ec0e4ed688541b569e67dc86a936fd628de2ece0db40eeacbeca\
             5fe0416037dada71ca29bc8a0b29f886390ac2d2e8e10a9454b1a2cad541b21e"
        );
    }

    #[test]
    fn cfb64_decrypt_matches_python_over_real_bytes() {
        let mut buf: Vec<u8> = (0..768).map(|i| (i % 256) as u8).collect();
        tdes().decrypt(Mode::Cfb64, &mut buf);
        assert_eq!(
            encode(&buf[..64]),
            "8ebab7111ad2ea092b77c40946f63a6bc1518b14a0efa0f77e1f1fb30da79053\
             5ba079fbcb7b20f94932d29c65aa0a672315e61d98d25ee5a650159605d58ae2"
        );
    }

    #[test]
    fn cfb64_encrypt_matches_python_over_real_bytes() {
        let mut buf: Vec<u8> = (0..768).map(|i| (i % 256) as u8).collect();
        tdes().encrypt(Mode::Cfb64, &mut buf);
        assert_eq!(
            encode(&buf[..64]),
            "8ebab7111ad2ea092bd71bd68d9951f18d75da78f244ad1e110c998889b4aff9\
             fa82a3b28dabf4f2eb3408244a78756210530e34a63594fb3e089852c1c97936"
        );
    }

    /// Partial trailing block: the keystream is simply truncated.
    #[test]
    fn cfb64_handles_a_partial_final_block() {
        let plain: Vec<u8> = (0..13).collect();
        let mut dec = plain.clone();
        tdes().decrypt(Mode::Cfb64, &mut dec);
        assert_eq!(encode(&dec), "8ebab7111ad2ea092b77c40946");
        let mut enc = plain.clone();
        tdes().encrypt(Mode::Cfb64, &mut enc);
        assert_eq!(encode(&enc), "8ebab7111ad2ea092bd71bd68d");
    }

    /// The identity that caused the original misdiagnosis: the first 8 bytes of
    /// every 256-byte window agree between the modes, and nothing after that.
    #[test]
    fn ofb_and_cfb64_agree_on_exactly_the_first_block_of_each_window() {
        let plain: Vec<u8> = (0..768).map(|i| (i % 256) as u8).collect();
        let (mut a, mut b) = (plain.clone(), plain.clone());
        tdes().decrypt(Mode::Cfb64, &mut a);
        tdes().decrypt(Mode::Ofb, &mut b);
        for w in 0..3 {
            let base = w * RESET;
            assert_eq!(a[base..base + 8], b[base..base + 8], "window {w}");
            assert_ne!(a[base + 8], b[base + 8], "window {w}");
        }
    }

    /// ... and they agree everywhere when the plaintext is all zeros, which is
    /// why blank image bitmaps could not tell them apart either.
    #[test]
    fn ofb_and_cfb64_agree_completely_on_all_zero_ciphertext() {
        // "All-zero plaintext" for the decrypt direction means the ciphertext
        // itself is the two chains' keystream; use the encrypt direction to
        // build it.
        let mut ct = vec![0u8; 256];
        tdes().encrypt(Mode::Cfb64, &mut ct);
        let (mut a, mut b) = (ct.clone(), ct.clone());
        tdes().decrypt(Mode::Cfb64, &mut a);
        tdes().decrypt(Mode::Ofb, &mut b);
        assert!(a.iter().all(|&x| x == 0));
        assert_eq!(a, b);
    }

    #[test]
    fn every_window_restarts_from_the_iv() {
        let mut buf = vec![0u8; 600];
        tdes().decrypt(Mode::Cfb64, &mut buf);
        assert_eq!(buf[..256], buf[256..512]);
        assert_eq!(buf[..88], buf[512..600]);
    }

    #[test]
    fn encrypt_then_decrypt_is_the_identity() {
        let plain: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        for mode in [Mode::Cfb64, Mode::Ofb] {
            let mut buf = plain.clone();
            tdes().encrypt(mode, &mut buf);
            assert_ne!(buf, plain, "{mode:?}");
            tdes().decrypt(mode, &mut buf);
            assert_eq!(buf, plain, "{mode:?}");
        }
    }

    #[test]
    fn expands_16_byte_key_to_k1k2k1() {
        let k16 = decode("a1e7f815671f82812870e2315352f156").unwrap();
        let mut k24 = k16.clone();
        k24.extend_from_slice(&k16[..8]);
        let (mut a, mut b) = (vec![0u8; 32], vec![0u8; 32]);
        Tdes::new(&k16, RESET).unwrap().decrypt(Mode::Cfb64, &mut a);
        Tdes::new(&k24, RESET).unwrap().decrypt(Mode::Cfb64, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_bad_key_length() {
        match Tdes::new(&[0u8; 20], RESET) {
            Err(Error::BadKeyLength { len: 20, .. }) => {}
            other => panic!("expected BadKeyLength, got {:?}", other.err()),
        }
    }
}

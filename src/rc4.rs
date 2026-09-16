//! Founder's RC4 variant -- the first encryption layer, applied to the whole
//! PDF body with the state reset to its post-KSA value every 64 KiB.
//!
//! Two things make it *not* RC4:
//!
//! 1. The KSA ORs every key byte with `0xAA` before mixing, and walks the key
//!    with its own modulo counter.
//! 2. The PRGA has a bug in the swap.  Upstream writes
//!
//!    ```c
//!    byT = pbyState[byX];
//!    pbyState[byX] = pbyState[byY];
//!    pbyState[byY] = pbyState[byT];   /* should be `= byT` */
//!    ```
//!
//!    -- using the *value* it just read as an *index* instead of writing it
//!    back.  That destroys the bijectivity of the permutation and the state
//!    collapses: over a full 64 KiB block 97.3% of keystream bytes come out
//!    `0x45`.
//!
//! **The bug is reproduced on purpose.**  Fixing it would produce a different
//! keystream and nothing would decrypt.  Do not "clean this up".
//!
//! The collapse is also why you cannot approximate this with `XOR 0x45`: the
//! first ~1.8 KB of each block, before the state has degenerated, is genuinely
//! pseudorandom.

/// State is reset to its post-KSA value at every multiple of this many bytes.
pub const BLOCK: usize = 64 * 1024;

#[derive(Clone)]
pub struct FounderRc4 {
    state: [u8; 256],
    x: u8,
    y: u8,
}

impl FounderRc4 {
    /// Panics on an empty key; callers validate key length first and report a
    /// proper [`crate::error::Error`].
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "FounderRc4 needs a non-empty key");

        let mut state = [0u8; 256];
        for (i, s) in state.iter_mut().enumerate() {
            *s = i as u8;
        }

        // Upstream seeds a 256-byte array but only fills the first `keylen`
        // entries, then indexes it modulo the key length -- equivalent to
        // walking the key cyclically.  The `| 0xAA` is theirs too.
        let mut j = 0u8;
        for i in 0..256usize {
            let k = key[i % key.len()] | 0xAA;
            j = k.wrapping_add(state[i]).wrapping_add(j);
            state.swap(i, j as usize);
        }

        FounderRc4 { state, x: 0, y: 0 }
    }

    /// XOR `buf` with the keystream, in place.  The cipher is its own inverse.
    pub fn apply(&mut self, buf: &mut [u8]) {
        let (s, mut x, mut y) = (&mut self.state, self.x, self.y);
        for b in buf.iter_mut() {
            x = x.wrapping_add(1);
            y = s[x as usize].wrapping_add(y);
            let t = s[x as usize];
            s[x as usize] = s[y as usize];
            // The upstream bug, verbatim: the value `t` is used as an index
            // rather than being written back.  See the module docs.
            s[y as usize] = s[t as usize];
            *b ^= s[(s[x as usize].wrapping_add(s[y as usize])) as usize];
        }
        self.x = x;
        self.y = y;
    }
}

/// Decrypt (or encrypt -- it is symmetric) a whole PDF body: a fresh cipher
/// every [`BLOCK`] bytes.
pub fn apply_body(key: &[u8], body: &mut [u8]) {
    for chunk in body.chunks_mut(BLOCK) {
        FounderRc4::new(key).apply(chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keystream(key: &[u8], n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        FounderRc4::new(key).apply(&mut buf);
        buf
    }

    use crate::hex::{decode, encode};

    /// Vectors produced by `tools/ceb_poc.py` (see tests/vectors.rs for the
    /// rest); duplicated here so the unit test is self-contained.
    #[test]
    fn keystream_matches_python_poc() {
        let key = decode("a1e7f815671f82812870e2315352f156").unwrap();
        assert_eq!(
            encode(&keystream(&key, 64)),
            "52be918b84e8454a21be38e8c272b1be6b9ebb406efbd2a64f46199e80b72a98\
             7611eb0b46c88a611e62810d8218f5dd4f97ac88163f12c56be07b2f2063285c"
        );
    }

    #[test]
    fn ksa_state_matches_python_poc() {
        let key = decode("a1e7f815671f82812870e2315352f156").unwrap();
        let c = FounderRc4::new(&key);
        assert_eq!(
            encode(&c.state[..32]),
            "a48735d8921d5bdc24271b7a94eff1105c055393866ab0ece9544e164776d1ee"
        );
    }

    #[test]
    fn short_key_works() {
        assert_eq!(
            encode(&keystream(b"key", 32)),
            "213a9a0e08743cf6536c9b40a485d84b40d04ead032ac26875c7d2bdbe3be683"
        );
    }

    #[test]
    fn is_involutive() {
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
        let plain: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        let mut buf = plain.clone();
        FounderRc4::new(key).apply(&mut buf);
        assert_ne!(buf, plain);
        FounderRc4::new(key).apply(&mut buf);
        assert_eq!(buf, plain);
    }

    /// The whole point of the bug: the state collapses.  If someone "fixes"
    /// the swap this assertion fails loudly.
    #[test]
    fn keystream_collapses_to_0x45() {
        let key = decode("a1e7f815671f82812870e2315352f156").unwrap();
        let ks = keystream(&key, BLOCK);
        let n45 = ks.iter().filter(|&&b| b == 0x45).count();
        let pct = 100.0 * n45 as f64 / ks.len() as f64;
        assert!(
            (pct - 97.33).abs() < 0.01,
            "0x45 share was {pct:.2}%, expected 97.33% -- did someone repair \
             the deliberate PRGA bug?"
        );
        // ... but the head of the block is not degenerate, which is why a
        // plain `XOR 0x45` does not work.
        assert!(ks[..1024].iter().filter(|&&b| b == 0x45).count() < 100);
    }

    #[test]
    fn body_resets_every_64k() {
        let key = decode("a1e7f815671f82812870e2315352f156").unwrap();
        let mut body = vec![0u8; BLOCK + 64];
        apply_body(&key, &mut body);
        assert_eq!(&body[..64], &keystream(&key, 64)[..]);
        assert_eq!(&body[BLOCK..], &keystream(&key, 64)[..]);
    }
}

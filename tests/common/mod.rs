//! Shared scaffolding for the integration tests.
//!
//! The CEB *writer* here is deliberately a second, independent implementation
//! of the container layout rather than a reuse of anything in `src/` -- if both
//! sides shared a bug the round-trip tests would happily agree with themselves.

#![allow(dead_code)]

use ceb2pdf::tdes::{Mode, Tdes, RESET};
use ceb2pdf::{pdf, rc4};

pub const HEADER_LEN: usize = 0x1F;
pub const ENTRY_LEN: usize = 17;

/// zlib stream for "hello, ceb", produced by Python's `zlib.compress`.
pub const ZLIB_HELLO: &[u8] = &[
    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x48, 0x4e, 0x4d, 0x02, 0x00, 0x14, 0x46,
    0x03, 0x8b,
];

/// A small but structurally real PDF with one `/FlateDecode` stream.
pub fn tiny_pdf() -> Vec<u8> {
    let mut d = format!(
        "%PDF-1.5\r1 0 obj\r<</Filter/FlateDecode /Length {}>>\rstream\r\n",
        ZLIB_HELLO.len()
    )
    .into_bytes();
    d.extend_from_slice(ZLIB_HELLO);
    d.extend_from_slice(b"\rendstream\rendobj\r");
    d.extend_from_slice(b"trailer\r<</Size 2 /Root 1 0 R /Encrypt 9 0 R>>\rstartxref\r0\r%%EOF");
    d
}

/// Write a container.  `version_field` goes at 0x0C; pass `[0,0,3,0]` for the
/// numeric v3 header or ASCII bytes (plus a NUL) for the legacy one.
pub fn container(version_field: &[u8], legacy: bool, sections: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let table_end = HEADER_LEN + sections.len() * ENTRY_LEN;
    let mut out = vec![0u8; table_end];
    out[..11].copy_from_slice(b"Founder CEB");
    out[11] = if legacy { b' ' } else { 0 };
    out[0x0C..0x0C + version_field.len()].copy_from_slice(version_field);
    if version_field.len() <= 4 {
        out[0x10..0x14].copy_from_slice(&((sections.len() * ENTRY_LEN) as u32).to_le_bytes());
    }
    out[0x14..0x16].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    out[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());

    let mut cursor = table_end as u32;
    for (i, (ty, body)) in sections.iter().enumerate() {
        let p = HEADER_LEN + i * ENTRY_LEN;
        out[p..p + 4].copy_from_slice(&cursor.to_le_bytes());
        out[p + 4..p + 8].copy_from_slice(&(body.len() as u32).to_le_bytes());
        out[p + 8] = *ty;
        cursor += body.len() as u32;
    }
    for (_, body) in sections {
        out.extend_from_slice(body);
    }
    out
}

/// Encrypt a plaintext PDF the way a CEB producer would, and wrap it up.
pub fn synth_ceb(plain: &[u8], key: &[u8], algorithm_id: u32, mode: Option<Mode>) -> Vec<u8> {
    let mut body = plain.to_vec();
    if let Some(m) = mode {
        let c = Tdes::new(key, RESET).unwrap();
        for s in pdf::scan_streams(&body) {
            c.encrypt(m, &mut body[s.data.clone()]);
        }
    }
    rc4::apply_body(&key[..16], &mut body);
    container(
        &[0, 0, 3, 0],
        false,
        &[
            (3, body),
            (4, key[..16].to_vec()),
            (5, key.to_vec()),
            (16, algorithm_id.to_le_bytes().to_vec()),
        ],
    )
}

/// Where the (gitignored) sample corpus lives, if it is present.
///
/// Set `CEB2PDF_SAMPLES` to point somewhere else -- that is how these tests run
/// from a git worktree, where `samples/` stays in the main checkout.
pub fn samples_dir() -> Option<std::path::PathBuf> {
    let dir = match std::env::var_os("CEB2PDF_SAMPLES") {
        Some(p) => std::path::PathBuf::from(p),
        None => std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples")
            .join("ceb"),
    };
    dir.is_dir().then_some(dir)
}

/// Every `.ceb` in the corpus, sorted, or an empty list when there is none.
pub fn sample_files() -> Vec<std::path::PathBuf> {
    let Some(dir) = samples_dir() else {
        return Vec::new();
    };
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("ceb")))
        .collect();
    out.sort();
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    ceb2pdf::hex::encode(&sha256(bytes))
}

/// A compact SHA-256, so the tests can pin exact outputs without a dependency.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());

    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

#[test]
fn sha256_self_test() {
    // NIST vectors.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(&vec![b'a'; 1_000_000]),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

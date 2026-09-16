//! Turn a Founder Apabi `.ceb` file back into the PDF it wraps.
//!
//! CEB is not a page-description format of its own.  It is a small container
//! holding a **standard PDF** behind one or two layers of weak encryption, so
//! the conversion is lossless and needs no PDF library, no renderer, no font
//! handling and no OCR:
//!
//! ```text
//! Founder CEB container
//! `-- PDF body --> Founder-RC4 over the whole thing, state reset every 64 KiB
//!                  `-- standard PDF
//!                      `-- each stream --> 3DES, IV reset every 256 B
//!                                          (or nothing at all -- see below)
//! ```
//!
//! Both ciphers are stream ciphers, so decryption is length-preserving and
//! happens **in place**: every `xref` offset in the PDF stays valid and the file
//! structure is never rewritten.  Even removing the `/Encrypt` entry from the
//! trailer is done by overwriting it with the same number of spaces.
//!
//! The per-stream layer is **never hardcoded** -- it is dispatched on the low
//! bits of the container's algorithm id, and all three values that occur in the
//! wild have been checked against real files:
//!
//! | low bits | cipher | evidence |
//! |---|---|---|
//! | 0 | none; the streams are plaintext | streams inflate as-is |
//! | 1 | 3DES-OFB | 100% of `/FlateDecode` streams inflate, 0% under CFB64 |
//! | 2 | 3DES-CFB64 | 100% of `/FlateDecode` streams inflate, 0% under OFB |
//!
//! Getting that dispatch wrong is silent -- OFB and CFB64 agree on the first 8
//! bytes of every 256-byte window, so a zlib header decodes correctly either
//! way and only the *body* of the deflate stream is garbage.  That is why
//! [`Options::verify`] inflates every stream after conversion and why the CLI
//! exits non-zero when any of them fails.
//!
//! ```no_run
//! let raw = std::fs::read("book.ceb")?;
//! let out = ceb2pdf::convert(&raw)?;
//! for c in out.report.complaints() {
//!     eprintln!("warning: {c}");   // empty when everything checked out
//! }
//! std::fs::write("book.pdf", &out.pdf)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Scope
//!
//! Only files whose keys are stored in the file itself -- no licence server, no
//! user credential, no per-device binding.  That is format-level obfuscation,
//! and undoing it is an interoperability measure.  Files that are actually
//! bound to a licence (library loans) are out of scope, and the container
//! parser fails on them rather than trying.

pub mod container;
pub mod error;
pub mod hex;
pub mod pdf;
pub mod rc4;
pub mod rsa;
pub mod stream;
pub mod tdes;
pub mod verify;

use container::{Container, Layout, Version};
use error::{Error, KeySource, Result};
use pdf::EncryptRemoval;
use stream::{Identity, StreamDecryptor, Tdes3};
use tdes::Mode;
use verify::Verification;

/// Set in the algorithm id when the key blob is RSA-wrapped.
pub const WRAPPED_KEY_FLAG: u32 = 0x8000_0000;

/// Algorithm id 0: the streams are not encrypted.  The upstream implementation
/// guards the whole per-stream pass with `if (algorithmID)`, and the 2.99D
/// sample takes that branch.
pub const ALGO_NONE: u32 = 0;
/// `TYPE_3DES_OFB` in the upstream enum.  Verified: every sample carrying id 1
/// inflates 100% of its `/FlateDecode` streams under OFB and 0% under CFB64.
pub const ALGO_3DES_OFB: u32 = 1;
/// `TYPE_3DES_CFB` in the upstream enum, with 64-bit segments.  Verified.
pub const ALGO_3DES_CFB64: u32 = 2;

/// Length in bytes of the Founder-RC4 key.
pub const RC4_KEY_LEN: usize = 16;

/// Builds a per-stream strategy from the file key recovered from the container.
///
/// This is the extension point: hand [`StreamStrategy::Custom`] one of these
/// and the pipeline will use it for every stream, with the object id and the
/// stream dictionary available through [`stream::StreamInfo`].
pub type StrategyFactory<'a> = &'a dyn Fn(&[u8]) -> Result<Box<dyn StreamDecryptor>>;

/// Which per-stream decryption strategy to use.
#[derive(Default)]
pub enum StreamStrategy<'a> {
    /// Dispatch on the container's algorithm id.  The default, and the only
    /// choice that never guesses.
    #[default]
    FromAlgorithmId,
    /// Use this mode whatever the container says.
    ForceMode(Option<Mode>),
    /// Build a strategy from the recovered file key.
    Custom(StrategyFactory<'a>),
}

/// The per-stream cipher an algorithm id selects, or why we will not pick one.
fn mode_for(id: u32) -> Result<Option<Mode>> {
    match id & !WRAPPED_KEY_FLAG {
        ALGO_NONE => Ok(None),
        ALGO_3DES_CFB64 => Ok(Some(Mode::Cfb64)),
        ALGO_3DES_OFB => Ok(Some(Mode::Ofb)),
        _ => Err(Error::UnknownAlgorithm { id }),
    }
}

pub struct Options<'a> {
    pub strategy: StreamStrategy<'a>,
    /// Run the post-conversion self-check: inflate every `/FlateDecode` stream
    /// and cross-check every `/Length`.  Costs a fraction of a second, and it
    /// is the only thing standing between a wrong guess and a silently broken
    /// PDF, so it is on by default.
    pub verify: bool,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options {
            strategy: StreamStrategy::default(),
            verify: true,
        }
    }
}

/// Everything we learned while converting, for `--verbose` and for the honesty
/// check at the end.
#[derive(Debug, Clone)]
pub struct Report {
    pub container_version: Version,
    pub sections: Vec<container::Section>,
    pub container_notes: Vec<String>,
    pub layout_complaints: Vec<String>,
    pub algorithm_id: u32,
    pub key_source: KeySource,
    pub key_len: usize,
    pub body_len: usize,
    pub streams: usize,
    pub stream_bytes: usize,
    pub strategy: String,
    /// True when the strategy came from `--force-mode` rather than the file.
    pub strategy_forced: bool,
    pub encrypt: EncryptRemoval,
    pub verification: Option<Verification>,
}

impl Report {
    /// True when nothing at all looks wrong.
    pub fn is_clean(&self) -> bool {
        self.complaints().is_empty()
    }

    /// Things worth telling the user that are not defects: how an ambiguous
    /// container was read, fonts that were never embedded, and so on.
    pub fn notes(&self) -> Vec<String> {
        let mut out = self.container_notes.clone();
        if let Some(v) = &self.verification {
            out.extend(v.notes.iter().cloned());
        }
        out
    }

    /// Everything that looks wrong, in plain words.  Empty means clean.
    pub fn complaints(&self) -> Vec<String> {
        let mut out = self.layout_complaints.clone();
        if let EncryptRemoval::Malformed { at } = self.encrypt {
            out.push(format!(
                "found `/Encrypt` at offset {at} but no closing `R` within 64 bytes; left it \
                 alone, so the output may still be flagged as encrypted"
            ));
        }
        if let Some(v) = &self.verification {
            out.extend(v.complaints());
        }
        out
    }
}

pub struct Conversion {
    pub pdf: Vec<u8>,
    pub report: Report,
}

/// Convert with the defaults.
pub fn convert(data: &[u8]) -> Result<Conversion> {
    convert_with(data, &Options::default())
}

/// Convert, choosing the per-stream strategy and whether to self-check.
pub fn convert_with(data: &[u8], opts: &Options<'_>) -> Result<Conversion> {
    let ceb = Container::parse(data)?;
    let layout = ceb.resolve()?;

    // -- layer 1: the Founder-RC4 wrapper around the whole body -------------
    let rc4_key = ceb.slice(layout.rc4_key);
    if rc4_key.len() != RC4_KEY_LEN {
        return Err(Error::BadKeyLength {
            ty: container::section::RC4_KEY,
            what: "Founder-RC4 key",
            len: rc4_key.len(),
            expected: "16 bytes",
        });
    }
    let mut pdf = ceb.slice(layout.body).to_vec();
    rc4::apply_body(rc4_key, &mut pdf);
    if !pdf::looks_like_pdf(&pdf) {
        return Err(Error::Rc4LayerFailed {
            head: pdf[..pdf.len().min(8)].to_vec(),
        });
    }

    // -- layer 2: which per-stream cipher, and with what key? ---------------
    let algorithm_id = read_algorithm_id(&ceb, &layout);
    let mut strategy_forced = false;
    let mode = match &opts.strategy {
        StreamStrategy::FromAlgorithmId => mode_for(algorithm_id)?,
        StreamStrategy::ForceMode(m) => {
            strategy_forced = true;
            *m
        }
        StreamStrategy::Custom(_) => None,
    };

    let (key, key_source) = if mode.is_none() && !matches!(opts.strategy, StreamStrategy::Custom(_))
    {
        (Vec::new(), KeySource::NotNeeded)
    } else {
        recover_key(&ceb, &layout, algorithm_id)?
    };

    let strategy: Box<dyn StreamDecryptor> = match (&opts.strategy, mode) {
        (StreamStrategy::Custom(f), _) => f(&key)?,
        (_, Some(m)) => Box::new(Tdes3::new(&key, m)?),
        (_, None) => Box::new(Identity),
    };

    // -- layer 3: run it over every stream ----------------------------------
    let streams = pdf::scan_streams(&pdf);
    let stream_bytes = streams.iter().map(|s| s.len()).sum();
    stream::decrypt_all(&mut pdf, &streams, &key, strategy.as_ref())?;

    // -- and blank the trailer's /Encrypt marker ----------------------------
    let encrypt = pdf::strip_encrypt(&mut pdf);

    let verification = opts.verify.then(|| Verification::run(&pdf, &streams));

    let mut container_notes = ceb.notes.clone();
    container_notes.extend(layout.notes.iter().cloned());

    let report = Report {
        container_version: ceb.version.clone(),
        sections: ceb.sections.clone(),
        container_notes,
        layout_complaints: ceb.layout_complaints(),
        algorithm_id,
        key_source,
        key_len: key.len(),
        body_len: pdf.len(),
        streams: streams.len(),
        stream_bytes,
        strategy: strategy.name().to_string(),
        strategy_forced,
        encrypt,
        verification,
    };
    Ok(Conversion { pdf, report })
}

/// The algorithm id, or 0 when the container has no such section.
///
/// Treating "absent" as 0 matches the upstream `if (algorithmID)` guard, and
/// the self-check is what proves it right: if the streams really were encrypted
/// none of them would inflate, and the report says so.
fn read_algorithm_id(ceb: &Container<'_>, layout: &Layout) -> u32 {
    match layout.algorithm {
        Some(s) => {
            let b = ceb.slice(s);
            let mut w = [0u8; 4];
            let n = b.len().min(4);
            w[..n].copy_from_slice(&b[..n]);
            u32::from_le_bytes(w)
        }
        None => ALGO_NONE,
    }
}

fn recover_key(
    ceb: &Container<'_>,
    layout: &Layout,
    algorithm_id: u32,
) -> Result<(Vec<u8>, KeySource)> {
    let blob = layout
        .key_blob
        .map(|s| ceb.slice(s))
        .ok_or(Error::MissingSection {
            ty: container::section::KEY_BLOB,
            what: container::section::name(container::section::KEY_BLOB),
        })?;
    // The wrap flag and the blob length agree on every sample; trust either.
    if algorithm_id & WRAPPED_KEY_FLAG != 0 || blob.len() == rsa::BYTES {
        Ok((rsa::unwrap_key(blob)?, KeySource::RsaWrapped))
    } else {
        Ok((blob.to_vec(), KeySource::Direct))
    }
}

/// Peek at a container without decrypting anything -- backs `--dump-meta`.
pub fn inspect(data: &[u8]) -> Result<Container<'_>> {
    Container::parse(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use container::section;

    const ZLIB_HELLO: &[u8] = &[
        0x78, 0xda, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
    ];
    const KEY24: &[u8] = b"0123456789abcdefABCDEFGH";

    fn plain_pdf() -> Vec<u8> {
        let mut d = b"%PDF-1.5\r1 0 obj\r<</Filter/FlateDecode /Length 13>>\rstream\r\n".to_vec();
        d.extend_from_slice(ZLIB_HELLO);
        d.extend_from_slice(b"\rendstream\rendobj\r");
        d.extend_from_slice(
            b"trailer\r<</Size 2 /Root 1 0 R /Encrypt 9 0 R>>\rstartxref\r0\r%%EOF",
        );
        d
    }

    /// Run the pipeline backwards to build a CEB we can then convert.
    fn synth_ceb(plain: &[u8], key: &[u8], algo: u32, mode: Option<Mode>) -> Vec<u8> {
        let mut body = plain.to_vec();
        if let Some(m) = mode {
            let c = tdes::Tdes::new(key, tdes::RESET).unwrap();
            for s in pdf::scan_streams(&body) {
                c.encrypt(m, &mut body[s.data.clone()]);
            }
        }
        rc4::apply_body(&key[..16], &mut body);
        container::tests::synth(&[
            (section::PDF_BODY, body),
            (section::RC4_KEY, key[..16].to_vec()),
            (section::KEY_BLOB, key.to_vec()),
            (section::ALGORITHM, algo.to_le_bytes().to_vec()),
        ])
    }

    #[test]
    fn round_trips_cfb64() {
        let plain = plain_pdf();
        let ceb = synth_ceb(&plain, KEY24, ALGO_3DES_CFB64, Some(Mode::Cfb64));
        let out = convert(&ceb).unwrap();

        assert_eq!(out.pdf.len(), plain.len(), "must be length-preserving");
        assert_eq!(out.report.key_source, KeySource::Direct);
        assert_eq!(out.report.streams, 1);
        assert!(
            out.report.strategy.contains("CFB64"),
            "{}",
            out.report.strategy
        );
        assert!(matches!(out.report.encrypt, EncryptRemoval::Blanked { .. }));

        let mut expect = plain.clone();
        pdf::strip_encrypt(&mut expect);
        assert_eq!(out.pdf, expect, "identical but for the blanked /Encrypt");
        assert!(out.report.is_clean(), "{:?}", out.report.complaints());
    }

    /// Algorithm id 0: no per-stream cipher at all.  This is the 2.99D branch.
    #[test]
    fn algorithm_id_zero_skips_the_stream_layer() {
        let plain = plain_pdf();
        let ceb = synth_ceb(&plain, KEY24, ALGO_NONE, None);
        let out = convert(&ceb).unwrap();
        assert_eq!(out.report.key_source, KeySource::NotNeeded);
        assert_eq!(out.report.key_len, 0);
        assert!(out.report.strategy.starts_with("none"));
        assert!(out.report.is_clean(), "{:?}", out.report.complaints());
    }

    /// The same thing via an absent algorithm-id section.
    #[test]
    fn absent_algorithm_section_means_no_stream_cipher() {
        let mut body = plain_pdf();
        rc4::apply_body(&KEY24[..16], &mut body);
        let ceb = container::tests::synth(&[
            (section::PDF_BODY, body),
            (section::RC4_KEY, KEY24[..16].to_vec()),
        ]);
        let out = convert(&ceb).unwrap();
        assert_eq!(out.report.algorithm_id, 0);
        assert!(out.report.is_clean(), "{:?}", out.report.complaints());
    }

    /// Decrypting CFB64 data as OFB has to fail the self-check -- this is the
    /// regression guard for the bug that cost the project a day.
    #[test]
    fn wrong_mode_is_caught_by_the_self_check() {
        let ceb = synth_ceb(&plain_pdf(), KEY24, ALGO_3DES_CFB64, Some(Mode::Cfb64));
        let out = convert_with(
            &ceb,
            &Options {
                strategy: StreamStrategy::ForceMode(Some(Mode::Ofb)),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(out.report.strategy_forced);
        assert!(!out.report.is_clean());
        assert_eq!(out.report.verification.as_ref().unwrap().bad_total, 1);
        assert!(out
            .report
            .complaints()
            .iter()
            .any(|c| c.contains("could not be decompressed")));
    }

    /// Algorithm id 1 selects OFB.  The upstream enum said so all along, and
    /// every sample carrying id 1 confirms it: 100% of their /FlateDecode
    /// streams inflate under OFB and none under CFB64.
    #[test]
    fn algorithm_id_one_selects_ofb() {
        let ceb = synth_ceb(&plain_pdf(), KEY24, ALGO_3DES_OFB, Some(Mode::Ofb));
        let out = convert(&ceb).unwrap();
        assert!(
            out.report.strategy.contains("OFB"),
            "{}",
            out.report.strategy
        );
        assert!(!out.report.strategy_forced);
        assert!(out.report.is_clean(), "{:?}", out.report.complaints());
    }

    /// ... and the two ids really do pick different ciphers: decrypting an OFB
    /// file as CFB64 must fail loudly rather than quietly.
    #[test]
    fn the_two_ids_are_not_interchangeable() {
        let ceb = synth_ceb(&plain_pdf(), KEY24, ALGO_3DES_OFB, Some(Mode::Ofb));
        let out = convert_with(
            &ceb,
            &Options {
                strategy: StreamStrategy::ForceMode(Some(Mode::Cfb64)),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!out.report.is_clean());
        assert_eq!(out.report.verification.as_ref().unwrap().bad_total, 1);
    }

    #[test]
    fn unknown_algorithm_id_is_refused() {
        let ceb = synth_ceb(&plain_pdf(), KEY24, 7, Some(Mode::Cfb64));
        let msg = match convert(&ceb) {
            Err(e @ Error::UnknownAlgorithm { id: 7 }) => e.to_string(),
            other => panic!("expected UnknownAlgorithm, got {:?}", other.err()),
        };
        assert!(msg.contains("--force-mode"), "{msg}");
    }

    #[test]
    fn rsa_wrapped_key_path() {
        // The real sample's key blob, so this exercises the actual RSA constants.
        let key = hex::decode("a1e7f815671f82812870e2315352f1569a4cb39584f08b03").unwrap();
        let blob = hex::decode(
            "a2c8c0244570858b23ccaf50cd41862fd3b0a159f4101be7d1208abcfe5e2df4\
             237032acf107c5130792876aff1cda946b5ecb70e0332ade601950ef1aa8fac4",
        )
        .unwrap();
        let mut body = plain_pdf();
        let c = tdes::Tdes::new(&key, tdes::RESET).unwrap();
        for s in pdf::scan_streams(&body) {
            c.encrypt(Mode::Cfb64, &mut body[s.data.clone()]);
        }
        rc4::apply_body(&key[..16], &mut body);

        let ceb = container::tests::synth(&[
            (section::PDF_BODY, body),
            (section::RC4_KEY, key[..16].to_vec()),
            (section::KEY_BLOB, blob),
            (
                section::ALGORITHM,
                (WRAPPED_KEY_FLAG | ALGO_3DES_CFB64).to_le_bytes().to_vec(),
            ),
        ]);
        let out = convert(&ceb).unwrap();
        assert_eq!(out.report.key_source, KeySource::RsaWrapped);
        assert_eq!(out.report.key_len, 24);
        assert!(out.report.is_clean(), "{:?}", out.report.complaints());
    }

    #[test]
    fn custom_strategy_is_reachable() {
        struct Shout;
        impl StreamDecryptor for Shout {
            fn name(&self) -> &str {
                "test strategy"
            }
            fn decrypt(&self, _i: &stream::StreamInfo<'_>, d: &mut [u8]) -> Result<()> {
                d.fill(b'!');
                Ok(())
            }
        }
        let ceb = synth_ceb(&plain_pdf(), KEY24, ALGO_3DES_CFB64, Some(Mode::Cfb64));
        let make: StrategyFactory<'_> = &|_k| Ok(Box::new(Shout));
        let out = convert_with(
            &ceb,
            &Options {
                strategy: StreamStrategy::Custom(make),
                verify: false,
            },
        )
        .unwrap();
        assert_eq!(out.report.strategy, "test strategy");
        assert!(out.pdf.windows(4).any(|w| w == b"!!!!"));
    }

    #[test]
    fn rejects_wrong_rc4_key_length() {
        let mut body = plain_pdf();
        rc4::apply_body(&KEY24[..16], &mut body);
        let ceb = container::tests::synth(&[
            (section::PDF_BODY, body),
            (section::RC4_KEY, KEY24[..8].to_vec()),
            (section::ALGORITHM, ALGO_NONE.to_le_bytes().to_vec()),
        ]);
        // An 8-byte "key" section cannot be found by type 4 here, so this also
        // covers the MissingSection path -- either error is acceptable, but it
        // must not panic or silently produce garbage.
        assert!(convert(&ceb).is_err());
    }

    #[test]
    fn rejects_a_body_that_is_not_a_pdf_after_rc4() {
        let ceb = container::tests::synth(&[
            (section::PDF_BODY, vec![0u8; 64]),
            (section::RC4_KEY, KEY24[..16].to_vec()),
            (section::ALGORITHM, ALGO_NONE.to_le_bytes().to_vec()),
        ]);
        match convert(&ceb) {
            Err(Error::Rc4LayerFailed { .. }) => {}
            other => panic!("expected Rc4LayerFailed, got {:?}", other.err()),
        }
    }

    #[test]
    fn mode_dispatch_table() {
        assert_eq!(mode_for(0).unwrap(), None);
        assert_eq!(mode_for(0x8000_0002).unwrap(), Some(Mode::Cfb64));
        assert_eq!(mode_for(2).unwrap(), Some(Mode::Cfb64));
        assert_eq!(mode_for(1).unwrap(), Some(Mode::Ofb));
        assert_eq!(mode_for(0x8000_0001).unwrap(), Some(Mode::Ofb));
        assert!(matches!(mode_for(9), Err(Error::UnknownAlgorithm { .. })));
    }
}

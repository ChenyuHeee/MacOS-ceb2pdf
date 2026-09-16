//! End-to-end tests over the public API, using containers this test suite
//! builds itself.  These run everywhere -- no sample files needed.

mod common;

use ceb2pdf::error::{Error, KeySource};
use ceb2pdf::tdes::Mode;
use ceb2pdf::{
    convert, convert_with, Options, StreamStrategy, ALGO_3DES_CFB64, ALGO_3DES_OFB, ALGO_NONE,
    WRAPPED_KEY_FLAG,
};
use common::{container, synth_ceb, tiny_pdf};

const KEY24: &[u8] = b"0123456789abcdefABCDEFGH";

/// What a caller would actually assert on: a real PDF came out, nothing is
/// still encrypted, and the length never changed.
fn assert_good_pdf(out: &ceb2pdf::Conversion, plain_len: usize) {
    assert!(out.pdf.starts_with(b"%PDF-"), "no PDF header");
    assert_eq!(out.pdf.len(), plain_len, "conversion must preserve length");
    assert!(
        !out.pdf.windows(8).any(|w| w == b"/Encrypt"),
        "/Encrypt survived"
    );
    assert!(out.report.is_clean(), "{:?}", out.report.complaints());
    let v = out.report.verification.as_ref().expect("verification ran");
    assert_eq!(v.flate_ok, v.flate_streams);
    assert!(v.flate_streams > 0, "fixture should have a flate stream");
}

#[test]
fn cfb64_round_trip() {
    let plain = tiny_pdf();
    let out = convert(&synth_ceb(
        &plain,
        KEY24,
        ALGO_3DES_CFB64,
        Some(Mode::Cfb64),
    ))
    .unwrap();
    assert_good_pdf(&out, plain.len());
    assert!(out.report.strategy.contains("CFB64"));
    assert_eq!(out.report.key_source, KeySource::Direct);
}

#[test]
fn ofb_round_trip() {
    let plain = tiny_pdf();
    let out = convert(&synth_ceb(&plain, KEY24, ALGO_3DES_OFB, Some(Mode::Ofb))).unwrap();
    assert_good_pdf(&out, plain.len());
    assert!(out.report.strategy.contains("OFB"));
}

#[test]
fn unencrypted_streams_round_trip() {
    let plain = tiny_pdf();
    let out = convert(&synth_ceb(&plain, KEY24, ALGO_NONE, None)).unwrap();
    assert_good_pdf(&out, plain.len());
    assert_eq!(out.report.key_source, KeySource::NotNeeded);
}

/// The RSA path, using the real sample's wrapped blob and the built-in
/// constants -- so this covers the hand-rolled 512-bit modular exponentiation
/// against a value produced by a real Founder tool.
#[test]
fn rsa_wrapped_key_round_trip() {
    let key = ceb2pdf::hex::decode("a1e7f815671f82812870e2315352f1569a4cb39584f08b03").unwrap();
    let blob = ceb2pdf::hex::decode(
        "a2c8c0244570858b23ccaf50cd41862fd3b0a159f4101be7d1208abcfe5e2df4\
         237032acf107c5130792876aff1cda946b5ecb70e0332ade601950ef1aa8fac4",
    )
    .unwrap();

    let plain = tiny_pdf();
    let mut body = plain.clone();
    let c = ceb2pdf::tdes::Tdes::new(&key, ceb2pdf::tdes::RESET).unwrap();
    for s in ceb2pdf::pdf::scan_streams(&body) {
        c.encrypt(Mode::Cfb64, &mut body[s.data.clone()]);
    }
    ceb2pdf::rc4::apply_body(&key[..16], &mut body);

    let ceb = container(
        &[0, 0, 3, 0],
        false,
        &[
            (3, body),
            (4, key[..16].to_vec()),
            (5, blob),
            (
                16,
                (WRAPPED_KEY_FLAG | ALGO_3DES_CFB64).to_le_bytes().to_vec(),
            ),
        ],
    );
    let out = convert(&ceb).unwrap();
    assert_good_pdf(&out, plain.len());
    assert_eq!(out.report.key_source, KeySource::RsaWrapped);
    assert_eq!(out.report.key_len, 24);
}

/// The legacy `Founder CEB ` + `2.99D` header, with a bare key and no
/// per-stream cipher.
#[test]
fn legacy_labelled_header_round_trip() {
    let plain = tiny_pdf();
    let mut body = plain.clone();
    ceb2pdf::rc4::apply_body(&KEY24[..16], &mut body);
    let mut vf = b"2.99D".to_vec();
    vf.extend_from_slice(&[0, 0, 0]);
    let ceb = container(
        &vf,
        true,
        &[(3, body), (4, KEY24[..16].to_vec()), (5, KEY24.to_vec())],
    );
    let out = convert(&ceb).unwrap();
    assert_good_pdf(&out, plain.len());
    assert_eq!(out.report.algorithm_id, 0);
}

/// The bug that cost this project a day: OFB and CFB64 agree on the first 8
/// bytes of every window, so a zlib header decodes either way.  Only inflating
/// the whole stream tells them apart -- and the report has to say so.
#[test]
fn the_wrong_mode_is_never_silently_accepted() {
    for (id, right, wrong) in [
        (ALGO_3DES_CFB64, Mode::Cfb64, Mode::Ofb),
        (ALGO_3DES_OFB, Mode::Ofb, Mode::Cfb64),
    ] {
        let ceb = synth_ceb(&tiny_pdf(), KEY24, id, Some(right));
        let out = convert_with(
            &ceb,
            &Options {
                strategy: StreamStrategy::ForceMode(Some(wrong)),
                ..Default::default()
            },
        )
        .unwrap();

        // The zlib header still survives -- that is the trap.
        let s = &ceb2pdf::pdf::scan_streams(&out.pdf)[0];
        assert_eq!(
            &out.pdf[s.data.start..s.data.start + 2],
            &[0x78, 0x9c],
            "{right:?} vs {wrong:?}: the header should still look valid"
        );
        // ... but the self-check is not fooled.
        assert!(!out.report.is_clean(), "{right:?} decoded as {wrong:?}");
        assert!(out
            .report
            .complaints()
            .iter()
            .any(|c| c.contains("could not be decompressed")));
    }
}

#[test]
fn unknown_algorithm_id_is_refused_with_a_way_out() {
    let ceb = synth_ceb(&tiny_pdf(), KEY24, 0x8000_0009, Some(Mode::Cfb64));
    let msg = match convert(&ceb) {
        Err(e @ Error::UnknownAlgorithm { .. }) => e.to_string(),
        other => panic!("expected UnknownAlgorithm, got {:?}", other.err()),
    };
    assert!(msg.contains("--force-mode"), "{msg}");
    assert!(msg.contains("0x80000009"), "{msg}");
}

#[test]
fn the_custom_strategy_hook_is_usable_from_outside_the_crate() {
    use ceb2pdf::stream::{StreamDecryptor, StreamInfo};

    struct PerObject;
    impl StreamDecryptor for PerObject {
        fn name(&self) -> &str {
            "per-object demo"
        }
        fn decrypt(&self, info: &StreamInfo<'_>, data: &mut [u8]) -> ceb2pdf::error::Result<()> {
            // Proof that a future strategy can key off the object id and the
            // stream dictionary without touching the rest of the pipeline.
            assert_eq!(info.object.unwrap().number, 1);
            assert!(info.dict_has(b"/FlateDecode"));
            assert_eq!(info.file_key.len(), 24);
            data.fill(0);
            Ok(())
        }
    }

    let ceb = synth_ceb(&tiny_pdf(), KEY24, ALGO_3DES_CFB64, Some(Mode::Cfb64));
    let make: ceb2pdf::StrategyFactory<'_> = &|_k| Ok(Box::new(PerObject));
    let out = convert_with(
        &ceb,
        &Options {
            strategy: StreamStrategy::Custom(make),
            verify: false,
        },
    )
    .unwrap();
    assert_eq!(out.report.strategy, "per-object demo");
}

#[test]
fn garbage_input_produces_actionable_errors() {
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("empty", Vec::new(), "Founder CEB"),
        (
            "truncated ceb",
            b"Founder CEB\0\0\0\x03\0".to_vec(),
            "truncated",
        ),
        ("zip", b"PK\x03\x04".repeat(20), "Founder CEB"),
        ("cebx", b"@XDA".repeat(20), "CEBX"),
    ];
    for (name, data, needle) in cases {
        let msg = convert(&data)
            .err()
            .unwrap_or_else(|| panic!("{name} should not convert"))
            .to_string();
        assert!(
            msg.to_lowercase().contains(&needle.to_lowercase()),
            "{name}: {msg}"
        );
    }
}

#[test]
fn a_wrong_rc4_key_fails_before_anything_is_written() {
    let plain = tiny_pdf();
    let mut body = plain.clone();
    ceb2pdf::rc4::apply_body(&KEY24[..16], &mut body);
    let ceb = container(
        &[0, 0, 3, 0],
        false,
        &[
            (3, body),
            (4, b"WRONGWRONGWRONG!".to_vec()),
            (16, ALGO_NONE.to_le_bytes().to_vec()),
        ],
    );
    match convert(&ceb) {
        Err(Error::Rc4LayerFailed { .. }) => {}
        other => panic!("expected Rc4LayerFailed, got {:?}", other.err()),
    }
}

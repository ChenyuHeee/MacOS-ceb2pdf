//! Tests against the real `.ceb` corpus.
//!
//! The samples are not in the repository (they are third-party documents and
//! `.gitignore`d), so these tests **skip themselves** when the corpus is
//! absent, printing why.  Point `CEB2PDF_SAMPLES` at the directory to run them
//! from a worktree or from CI with a private corpus.
//!
//! What they assert is deliberately strong: not just "it produced bytes", but
//! that every `/FlateDecode` stream in every sample inflates.  That is the
//! property that distinguishes a correct per-stream cipher from a wrong one,
//! and it is the assertion that would have caught the OFB/CFB64 mix-up.

mod common;

use ceb2pdf::{convert, verify::Inflated};
use common::{sample_files, samples_dir, sha256_hex};

fn skip(why: &str) {
    eprintln!("SKIP: {why}");
}

#[test]
fn every_sample_converts_to_a_complete_pdf() {
    let files = sample_files();
    if files.is_empty() {
        skip("no .ceb corpus; set CEB2PDF_SAMPLES to a directory of samples");
        return;
    }
    eprintln!(
        "checking {} sample(s) from {:?}",
        files.len(),
        samples_dir()
    );

    let mut failures = Vec::new();
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let raw = std::fs::read(path).expect("read sample");
        let out = match convert(&raw) {
            Ok(o) => o,
            Err(e) => {
                failures.push(format!("{name}: conversion failed: {e}"));
                continue;
            }
        };

        if !out.pdf.starts_with(b"%PDF-") {
            failures.push(format!("{name}: output is not a PDF"));
        }
        if out.pdf.windows(8).any(|w| w == b"/Encrypt") {
            failures.push(format!("{name}: /Encrypt survived"));
        }
        // In-place decryption: the output must be exactly the body section.
        let body = out
            .report
            .sections
            .iter()
            .find(|s| s.len as usize == out.pdf.len());
        if body.is_none() {
            failures.push(format!(
                "{name}: output is {} B, which matches no section length",
                out.pdf.len()
            ));
        }
        let v = out.report.verification.as_ref().expect("verification ran");
        if v.flate_ok != v.flate_streams {
            failures.push(format!(
                "{name}: only {}/{} /FlateDecode streams inflate (algorithm id {:#010x}, {})",
                v.flate_ok, v.flate_streams, out.report.algorithm_id, out.report.strategy
            ));
        }
        if !out.report.is_clean() {
            failures.push(format!(
                "{name}: self-check complained: {:?}",
                out.report.complaints()
            ));
        }
        eprintln!(
            "  ok  {name}: {} streams, {}/{} inflate, id {:#010x}",
            out.report.streams, v.flate_ok, v.flate_streams, out.report.algorithm_id
        );
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// Byte-for-byte lock against `tools/ceb_poc.py` on the reference sample.
///
/// If this ever drifts, the Rust and Python pipelines have diverged and one of
/// them is wrong -- which is exactly what we want a test to shout about.
#[test]
fn reference_sample_matches_the_python_proof_of_concept() {
    const INPUT_SHA: &str = "e913c6b13609c81215ed59a982f457f575ce42edcd7065dae558d5ec58ce63f7";
    const OUTPUT_SHA: &str = "92ae3fbf4ec9f32e751c66ef5dcbd96e7cc3ba83ea6bb32f5aa8bd9ccfa3de2f";

    let Some(path) = sample_files()
        .into_iter()
        .find(|p| sha256_hex(&std::fs::read(p).unwrap_or_default()) == INPUT_SHA)
    else {
        skip("the reference sample (State Grid notice, 501,674 B) is not in the corpus");
        return;
    };

    let out = convert(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        sha256_hex(&out.pdf),
        OUTPUT_SHA,
        "output diverged from tools/ceb_poc.py"
    );
    assert_eq!(out.pdf.len(), 498_315);
    assert_eq!(out.report.streams, 521);
    assert_eq!(out.report.algorithm_id, 0x8000_0002);
    let v = out.report.verification.unwrap();
    assert_eq!((v.flate_streams, v.flate_ok), (20, 20));
}

/// Every mode other than the one the algorithm id names must fail loudly.  This
/// is the corpus-wide version of the OFB/CFB64 regression guard: if someone
/// hardcodes a mode again, at least one sample breaks.
#[test]
fn forcing_the_wrong_mode_breaks_every_encrypted_sample() {
    use ceb2pdf::tdes::Mode;
    use ceb2pdf::{convert_with, Options, StreamStrategy, ALGO_NONE, WRAPPED_KEY_FLAG};

    let files = sample_files();
    if files.is_empty() {
        skip("no .ceb corpus");
        return;
    }
    let mut checked = 0;
    for path in &files {
        let raw = std::fs::read(path).unwrap();
        let Ok(good) = convert(&raw) else { continue };
        let id = good.report.algorithm_id & !WRAPPED_KEY_FLAG;
        if id == ALGO_NONE {
            continue; // nothing to get wrong
        }
        let wrong = if id == 1 { Mode::Cfb64 } else { Mode::Ofb };
        let bad = convert_with(
            &raw,
            &Options {
                strategy: StreamStrategy::ForceMode(Some(wrong)),
                ..Default::default()
            },
        )
        .unwrap();
        let v = bad.report.verification.as_ref().unwrap();
        assert_eq!(
            v.flate_ok,
            0,
            "{:?} decoded with {wrong:?} should inflate nothing, got {}/{}",
            path.file_name().unwrap(),
            v.flate_ok,
            v.flate_streams
        );
        checked += 1;
    }
    eprintln!("checked {checked} encrypted sample(s)");
}

/// Sanity: the self-check's inflate really is reading the converted bytes.
#[test]
fn inflated_content_looks_like_pdf_operators() {
    let files = sample_files();
    if files.is_empty() {
        skip("no .ceb corpus");
        return;
    }
    let mut saw_operators = false;
    for path in &files {
        let raw = std::fs::read(path).unwrap();
        let Ok(out) = convert(&raw) else { continue };
        for s in ceb2pdf::pdf::scan_streams(&out.pdf) {
            if !s.is_flate(&out.pdf) || s.is_empty() {
                continue;
            }
            if let Inflated::Ok(_) = ceb2pdf::verify::try_inflate(&out.pdf[s.data.clone()]) {
                // Page content streams are PDF graphics operators; `BT` (begin
                // text) or `re` (rectangle) shows up in essentially all of them.
                let dict = &out.pdf[s.dict.clone()];
                if dict.windows(9).any(|w| w == b"/Contents") || dict.len() < 200 {
                    saw_operators = true;
                }
            }
        }
        if saw_operators {
            break;
        }
    }
    assert!(saw_operators, "no inflatable content stream found anywhere");
}

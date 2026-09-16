//! Post-conversion self-check.
//!
//! The point of this module is honesty.  The per-stream layer is chosen from an
//! algorithm id whose meaning we know for two of its values and not for others,
//! and a tool that writes a PDF and says "done" when a fifth of the page content
//! is undecryptable garbage is lying.  So after conversion we look at the result
//! and report what is actually true: which streams inflate, which do not,
//! whether every `/Length` agrees with what we sliced, and whether the file is
//! structurally a PDF at all.
//!
//! This check is exactly what caught the OFB/CFB64 mix-up, and it is cheap, so
//! it runs by default.
//!
//! ## Why FFI instead of a Rust inflate crate
//!
//! `inflate` is needed for validation only, never to produce output.  `libz` is
//! part of the base system on macOS and on every Linux distro, so binding four
//! functions costs ~60 lines and zero bytes of binary, where `flate2` +
//! `miniz_oxide` would eat a real slice of the size budget.

use std::os::raw::{c_char, c_int, c_ulong, c_void};

use crate::pdf::{self, LengthMismatch, ObjectId, PdfStream};

#[repr(C)]
struct ZStream {
    next_in: *const u8,
    avail_in: u32,
    total_in: c_ulong,
    next_out: *mut u8,
    avail_out: u32,
    total_out: c_ulong,
    msg: *const c_char,
    state: *mut c_void,
    zalloc: *mut c_void,
    zfree: *mut c_void,
    opaque: *mut c_void,
    data_type: c_int,
    adler: c_ulong,
    reserved: c_ulong,
}

const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_NO_FLUSH: c_int = 0;
const ZLIB_VERSION: &[u8] = b"1.2.11\0";

#[link(name = "z")]
extern "C" {
    fn inflateInit_(strm: *mut ZStream, version: *const c_char, stream_size: c_int) -> c_int;
    fn inflate(strm: *mut ZStream, flush: c_int) -> c_int;
    fn inflateEnd(strm: *mut ZStream) -> c_int;
    fn zError(err: c_int) -> *const c_char;
}

/// What happened when we tried to inflate one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inflated {
    /// Decompressed cleanly; carries the uncompressed size.
    Ok(usize),
    /// zlib refused it.
    Failed(String),
}

/// Try to inflate `data`.  The output is discarded -- we only want the verdict.
pub fn try_inflate(data: &[u8]) -> Inflated {
    if data.is_empty() {
        return Inflated::Failed("empty stream".into());
    }
    let mut strm = ZStream {
        next_in: data.as_ptr(),
        avail_in: 0,
        total_in: 0,
        next_out: std::ptr::null_mut(),
        avail_out: 0,
        total_out: 0,
        msg: std::ptr::null(),
        state: std::ptr::null_mut(),
        zalloc: std::ptr::null_mut(),
        zfree: std::ptr::null_mut(),
        opaque: std::ptr::null_mut(),
        data_type: 0,
        adler: 0,
        reserved: 0,
    };

    // SAFETY: `strm` is a correctly shaped, fully initialised `z_stream` with
    // null allocator hooks (zlib then uses its own), every pointer handed to
    // zlib points into a live local buffer for the duration of the call, and
    // `inflateEnd` runs on every exit path.
    unsafe {
        let rc = inflateInit_(
            &mut strm,
            ZLIB_VERSION.as_ptr() as *const c_char,
            std::mem::size_of::<ZStream>() as c_int,
        );
        if rc != Z_OK {
            return Inflated::Failed(format!("inflateInit failed: {}", z_msg(rc)));
        }

        let mut scratch = vec![0u8; 64 * 1024];
        let mut consumed = 0usize;
        let mut produced = 0usize;
        let verdict = loop {
            if strm.avail_in == 0 {
                if consumed == data.len() {
                    break Inflated::Failed("truncated deflate stream".into());
                }
                let take = (data.len() - consumed).min(u32::MAX as usize);
                strm.next_in = data[consumed..].as_ptr();
                strm.avail_in = take as u32;
                consumed += take;
            }
            strm.next_out = scratch.as_mut_ptr();
            strm.avail_out = scratch.len() as u32;
            let before = strm.avail_out as usize;
            let rc = inflate(&mut strm, Z_NO_FLUSH);
            produced += before - strm.avail_out as usize;
            match rc {
                Z_STREAM_END => break Inflated::Ok(produced),
                Z_OK => continue,
                other => break Inflated::Failed(z_msg_of(&strm, other)),
            }
        };
        inflateEnd(&mut strm);
        verdict
    }
}

unsafe fn z_msg(rc: c_int) -> String {
    let p = zError(rc);
    if p.is_null() {
        format!("zlib error {rc}")
    } else {
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

unsafe fn z_msg_of(strm: &ZStream, rc: c_int) -> String {
    if strm.msg.is_null() {
        z_msg(rc)
    } else {
        std::ffi::CStr::from_ptr(strm.msg)
            .to_string_lossy()
            .into_owned()
    }
}

/// One stream that should have inflated and did not.
#[derive(Debug, Clone)]
pub struct BadStream {
    pub index: usize,
    pub object: Option<ObjectId>,
    pub offset: usize,
    pub len: usize,
    pub reason: String,
}

/// What the self-check found.
#[derive(Debug, Clone, Default)]
pub struct Verification {
    pub has_pdf_header: bool,
    pub has_eof_marker: bool,
    pub encrypt_removed: bool,
    pub streams: usize,
    pub flate_streams: usize,
    pub flate_ok: usize,
    /// The first few failures in detail; `bad_total` counts them all.
    pub bad: Vec<BadStream>,
    pub bad_total: usize,
    /// Streams whose payload length disagrees with the declared `/Length`.
    pub length_mismatches: Vec<LengthMismatch>,
    /// Uncompressed bytes recovered from the streams that did inflate.
    pub inflated_bytes: usize,
    /// True when the document names fonts but embeds none of them.
    pub fonts_are_external: bool,
    /// Things worth mentioning that are not defects in the conversion.
    pub notes: Vec<String>,
}

/// How many failing streams get described individually before we switch to a
/// bare count.
const MAX_REPORTED: usize = 5;

fn has(pdf: &[u8], needle: &[u8]) -> bool {
    pdf.windows(needle.len()).any(|w| w == needle)
}

/// Does the document name any font at all?
fn names_fonts(pdf: &[u8]) -> bool {
    has(pdf, b"/BaseFont")
}

/// Does it carry font programs, rather than just names?
fn embeds_fonts(pdf: &[u8]) -> bool {
    has(pdf, b"/FontFile")
}

impl Verification {
    pub fn run(pdf: &[u8], streams: &[PdfStream]) -> Self {
        let mut v = Verification {
            has_pdf_header: pdf::looks_like_pdf(pdf),
            has_eof_marker: pdf::has_eof_marker(pdf),
            encrypt_removed: !pdf::has_encrypt_key(pdf),
            streams: streams.len(),
            length_mismatches: pdf::length_mismatches(pdf, streams),
            ..Default::default()
        };
        v.fonts_are_external = names_fonts(pdf) && !embeds_fonts(pdf);
        if v.fonts_are_external {
            v.notes.push(
                "this document references fonts by name without embedding them (common in \
                 CEB, which relies on the Founder fonts the Apabi reader ships). Nothing was \
                 lost in conversion -- the font data was never in the file -- but on a \
                 machine without those fonts the viewer will substitute, and Founder's \
                 numeral fonts can then render digits as Chinese characters"
                    .into(),
            );
        }
        for s in streams {
            if s.is_empty() || !s.is_flate(pdf) {
                continue;
            }
            v.flate_streams += 1;
            match try_inflate(&pdf[s.data.clone()]) {
                Inflated::Ok(n) => {
                    v.flate_ok += 1;
                    v.inflated_bytes += n;
                }
                Inflated::Failed(reason) => {
                    v.bad_total += 1;
                    if v.bad.len() < MAX_REPORTED {
                        v.bad.push(BadStream {
                            index: s.index,
                            object: s.object,
                            offset: s.data.start,
                            len: s.data.len(),
                            reason,
                        });
                    }
                }
            }
        }
        v
    }

    /// True when the output is a PDF we are willing to call complete.
    pub fn is_clean(&self) -> bool {
        self.has_pdf_header
            && self.has_eof_marker
            && self.encrypt_removed
            && self.bad_total == 0
            && self.length_mismatches.is_empty()
    }

    /// Human-readable problems, most important first.  Empty when clean.
    pub fn complaints(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.has_pdf_header {
            out.push("the output does not start with `%PDF-`".into());
        }
        if !self.has_eof_marker {
            out.push("the output has no `%%EOF` marker near the end".into());
        }
        if !self.encrypt_removed {
            out.push("an `/Encrypt` key is still present in the output".into());
        }
        if self.bad_total > 0 {
            out.push(format!(
                "{} of {} /FlateDecode streams could not be decompressed, so the output is \
                 incomplete -- those pages will not render. The usual cause is the wrong \
                 per-stream cipher mode; try --force-mode with another value, and please \
                 report the file.",
                self.bad_total, self.flate_streams
            ));
            for b in &self.bad {
                let who = match b.object {
                    Some(o) => format!("object {o}"),
                    None => "object unknown".into(),
                };
                out.push(format!(
                    "  stream #{} ({who}, {} B at offset {}): {}",
                    b.index, b.len, b.offset, b.reason
                ));
            }
            if self.bad_total > self.bad.len() {
                out.push(format!(
                    "  ... and {} more",
                    self.bad_total - self.bad.len()
                ));
            }
        }
        if !self.length_mismatches.is_empty() {
            out.push(format!(
                "{} stream(s) were sliced to a length that disagrees with their /Length entry, \
                 so the naive `stream`/`endstream` scan cut them in the wrong place",
                self.length_mismatches.len()
            ));
            for m in self.length_mismatches.iter().take(MAX_REPORTED) {
                let who = match m.object {
                    Some(o) => format!("object {o}"),
                    None => "object unknown".into(),
                };
                out.push(format!(
                    "  stream #{} ({who}): /Length says {} but {} bytes were sliced",
                    m.index, m.declared, m.scanned
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// zlib of "hello", from Python's `zlib.compress`.  A fixed literal keeps
    /// the test independent of any compressor.
    const HELLO_Z: &[u8] = &[
        0x78, 0xda, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
    ];

    fn corrupt_body(z: &[u8]) -> Vec<u8> {
        // Keep the two header bytes, scramble the rest.  This is the exact shape
        // of the OFB failure: valid zlib header, garbage deflate stream.
        let mut bad = z.to_vec();
        for b in bad[2..].iter_mut() {
            *b ^= 0x5a;
        }
        bad
    }

    #[test]
    fn inflates_valid_zlib() {
        assert_eq!(try_inflate(HELLO_Z), Inflated::Ok(5));
    }

    #[test]
    fn rejects_garbage_behind_a_valid_header() {
        let bad = corrupt_body(HELLO_Z);
        assert_eq!(&bad[..2], &HELLO_Z[..2], "header must still look right");
        match try_inflate(&bad) {
            Inflated::Failed(msg) => assert!(!msg.is_empty()),
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_truncated_stream() {
        assert!(matches!(try_inflate(&HELLO_Z[..6]), Inflated::Failed(_)));
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(try_inflate(&[]), Inflated::Failed(_)));
    }

    #[test]
    fn inflates_more_than_the_scratch_buffer_holds() {
        let big = stored_deflate_zeros(200_000);
        assert_eq!(try_inflate(&big), Inflated::Ok(200_000));
    }

    /// Hand-rolled stored-block deflate, so the test needs no compressor.
    fn stored_deflate_zeros(n: usize) -> Vec<u8> {
        let mut out = vec![0x78, 0x01];
        let mut left = n;
        loop {
            let take = left.min(65535);
            left -= take;
            out.push(u8::from(left == 0)); // BFINAL, BTYPE = stored
            out.extend_from_slice(&(take as u16).to_le_bytes());
            out.extend_from_slice(&(!(take as u16)).to_le_bytes());
            out.resize(out.len() + take, 0);
            if left == 0 {
                break;
            }
        }
        // adler32 over n zero bytes: a stays 1, b counts the bytes.
        let (a, b) = (1u32, (n as u32) % 65521);
        out.extend_from_slice(&((b << 16) | a).to_be_bytes());
        out
    }

    fn doc_with(payload: &[u8]) -> Vec<u8> {
        let mut doc = format!(
            "%PDF-1.5\r1 0 obj\r<</Filter/FlateDecode /Length {}>>\rstream\r\n",
            payload.len()
        )
        .into_bytes();
        doc.extend_from_slice(payload);
        doc.extend_from_slice(b"\rendstream\rendobj\rtrailer<</Size 2>>\r%%EOF");
        doc
    }

    #[test]
    fn reports_a_clean_file() {
        let doc = doc_with(HELLO_Z);
        let v = Verification::run(&doc, &pdf::scan_streams(&doc));
        assert!(v.is_clean(), "{:?}", v.complaints());
        assert_eq!((v.streams, v.flate_streams, v.flate_ok), (1, 1, 1));
        assert_eq!(v.inflated_bytes, 5);
    }

    #[test]
    fn reports_a_broken_content_stream() {
        let doc = doc_with(&corrupt_body(HELLO_Z));
        let v = Verification::run(&doc, &pdf::scan_streams(&doc));
        assert!(!v.is_clean());
        assert_eq!(v.bad_total, 1);
        let text = v.complaints().join("\n");
        assert!(text.contains("could not be decompressed"), "{text}");
        assert!(text.contains("object 1 0"), "{text}");
        assert!(text.contains("--force-mode"), "{text}");
    }

    #[test]
    fn reports_a_length_mismatch() {
        let mut doc = doc_with(HELLO_Z);
        // Bump the declared length without changing the payload.
        let at = doc.windows(9).position(|w| w == b"/Length 1").unwrap();
        doc[at + 8] = b'9';
        let v = Verification::run(&doc, &pdf::scan_streams(&doc));
        assert!(!v.is_clean());
        assert_eq!(v.length_mismatches.len(), 1);
        assert!(v.complaints().join("\n").contains("/Length says"));
    }

    /// A document that names fonts without embedding them is flagged -- as a
    /// note, not a complaint: the font data was never in the CEB to begin with,
    /// so nothing was lost in conversion.
    #[test]
    fn external_fonts_are_noted_but_not_a_complaint() {
        let mut doc = doc_with(HELLO_Z);
        doc.extend_from_slice(b"\r5 0 obj<</Type/Font/BaseFont/FZFangSong-Z02>>endobj\r");
        let v = Verification::run(&doc, &pdf::scan_streams(&doc));
        assert!(v.fonts_are_external);
        assert!(v.is_clean(), "{:?}", v.complaints());
        assert!(v.notes.iter().any(|n| n.contains("without embedding")));

        let mut embedded = doc.clone();
        embedded.extend_from_slice(b"6 0 obj<</FontFile2 7 0 R>>endobj\r");
        let v = Verification::run(&embedded, &pdf::scan_streams(&embedded));
        assert!(!v.fonts_are_external);
        assert!(v.notes.is_empty());
    }

    #[test]
    fn notices_leftover_encrypt() {
        let doc = b"%PDF-1.5\rtrailer<</Encrypt 1 0 R>>\r%%EOF";
        let v = Verification::run(doc, &[]);
        assert!(!v.encrypt_removed);
        assert!(v.complaints().iter().any(|c| c.contains("/Encrypt")));
    }

    #[test]
    fn notices_a_missing_header_and_eof() {
        let v = Verification::run(b"not a pdf at all", &[]);
        assert!(!v.has_pdf_header && !v.has_eof_marker);
        assert_eq!(v.complaints().len(), 2);
    }
}

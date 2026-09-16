//! Just enough PDF lexing to find stream payloads and blank out `/Encrypt`.
//!
//! Deliberately not a PDF parser.  The file that comes out of the RC4 layer is
//! a byte-identical standard PDF and we want to hand it back untouched apart
//! from decrypting stream payloads in place, so anything that would require
//! rewriting object offsets is out of scope.

use std::ops::Range;

/// `N G obj` -- a PDF indirect object's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectId {
    pub number: u32,
    pub generation: u16,
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.number, self.generation)
    }
}

/// One `stream ... endstream` payload.
#[derive(Debug, Clone)]
pub struct PdfStream {
    /// Position of this stream in document order, 0-based.
    pub index: usize,
    /// Byte range of the payload: after the `stream` keyword and its EOL, up to
    /// the `endstream` keyword.
    pub data: Range<usize>,
    /// Bytes between the enclosing `obj` keyword and the `stream` keyword --
    /// the stream dictionary, unparsed.  Empty if no enclosing object was found.
    pub dict: Range<usize>,
    /// The object this stream lives in, when we could recover it.
    pub object: Option<ObjectId>,
}

impl PdfStream {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether the dictionary mentions `/FlateDecode`.  Used only by the
    /// self-check, so a substring test is good enough.
    pub fn is_flate(&self, pdf: &[u8]) -> bool {
        contains(&pdf[self.dict.clone()], b"/FlateDecode")
    }
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() || needle.is_empty() || needle.len() > hay.len() - from {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find_from(hay, needle, 0).is_some()
}

fn is_ws(b: u8) -> bool {
    matches!(b, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

/// Read an unsigned decimal at `at`, returning the value and the position after
/// it.
fn read_uint(pdf: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut p = at;
    let mut v: u64 = 0;
    while p < pdf.len() && pdf[p].is_ascii_digit() {
        v = v.checked_mul(10)?.checked_add(u64::from(pdf[p] - b'0'))?;
        p += 1;
    }
    (p > at).then_some((v, p))
}

fn skip_ws(pdf: &[u8], at: usize) -> usize {
    let mut p = at;
    while p < pdf.len() && is_ws(pdf[p]) {
        p += 1;
    }
    p
}

/// Collect `(end_of_obj_keyword, ObjectId)` for every `N G obj` header, in
/// document order.
fn object_headers(pdf: &[u8]) -> Vec<(usize, ObjectId)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(i) = find_from(pdf, b"obj", pos) {
        pos = i + 3;
        // Must be a standalone keyword, not the tail of e.g. "endobj".
        if i > 0 && !is_ws(pdf[i - 1]) {
            continue;
        }
        let mut p = i;
        let back = |p: &mut usize| -> Option<u64> {
            while *p > 0 && is_ws(pdf[*p - 1]) {
                *p -= 1;
            }
            let end = *p;
            while *p > 0 && pdf[*p - 1].is_ascii_digit() {
                *p -= 1;
            }
            (*p < end).then(|| read_uint(pdf, *p).map(|(v, _)| v))?
        };
        let Some(generation) = back(&mut p) else {
            continue;
        };
        let Some(number) = back(&mut p) else { continue };
        if generation > u64::from(u16::MAX) || number > u64::from(u32::MAX) {
            continue;
        }
        out.push((
            i + 3,
            ObjectId {
                number: number as u32,
                generation: generation as u16,
            },
        ));
    }
    out
}

/// Find every stream payload.
///
/// The scan itself is the same naive keyword walk the reference C++ and the
/// Python PoC use: find `stream`, skip `endstream`, take everything up to the
/// next `endstream`.  It ignores `/Length`, so a payload containing the nine
/// bytes `endstream` would be cut short.  Matching the producer's own behaviour
/// is what makes the round trip exact, so it stays naive -- but
/// [`length_mismatches`] cross-checks the result against every declared
/// `/Length` and the self-check reports any disagreement.
pub fn scan_streams(pdf: &[u8]) -> Vec<PdfStream> {
    // Pass 1: the keyword walk.  Keep the `stream` keyword position so we can
    // attribute the payload to an object afterwards.
    let mut raw: Vec<(usize, Range<usize>)> = Vec::new();
    let mut pos = 0usize;
    while let Some(i) = find_from(pdf, b"stream", pos) {
        if i > 0 && pdf[i - 1] == b'd' {
            // "endstream"
            pos = i + 6;
            continue;
        }
        let Some(end) = find_from(pdf, b"endstream", i) else {
            break;
        };
        let mut start = i + 6;
        while start < pdf.len() && matches!(pdf[start], b'\r' | b'\n') {
            start += 1;
        }
        raw.push((i, start.min(end)..end));
        pos = end + 9;
    }

    let headers = live_object_headers(pdf, &raw);

    raw.iter()
        .enumerate()
        .map(|(index, (kw, data))| {
            let hdr = headers.partition_point(|(p, _)| p <= kw);
            let (dict, object) = if hdr == 0 {
                (*kw..*kw, None)
            } else {
                let (obj_end, id) = headers[hdr - 1];
                (obj_end..*kw, Some(id))
            };
            PdfStream {
                index,
                data: data.clone(),
                dict,
                object,
            }
        })
        .collect()
}

/// Object headers that are not inside a stream payload -- binary image data
/// contains the bytes `obj` often enough to matter.
fn live_object_headers(pdf: &[u8], raw: &[(usize, Range<usize>)]) -> Vec<(usize, ObjectId)> {
    let inside = |p: usize| {
        let k = raw.partition_point(|(_, r)| r.start <= p);
        k > 0 && p < raw[k - 1].1.end
    };
    object_headers(pdf)
        .into_iter()
        .filter(|(p, _)| !inside(p.saturating_sub(3)))
        .collect()
}

/// A stream whose scanned payload length disagrees with its `/Length`.
#[derive(Debug, Clone)]
pub struct LengthMismatch {
    pub index: usize,
    pub object: Option<ObjectId>,
    pub scanned: usize,
    pub declared: u64,
}

/// Cross-check every stream against the `/Length` its dictionary declares,
/// resolving one level of indirection (`/Length 6 0 R`).
///
/// A trailing EOL is tolerated: the PDF spec puts one between the payload and
/// `endstream` and excludes it from `/Length`, so a keyword scan legitimately
/// picks up one or two extra bytes -- but only if they really are EOL bytes.
/// Anything else, in either direction, means the scan cut in the wrong place.
///
/// Streams whose `/Length` is missing or unresolvable are skipped rather than
/// reported -- we only want to hear about actual disagreements.
pub fn length_mismatches(pdf: &[u8], streams: &[PdfStream]) -> Vec<LengthMismatch> {
    let raw: Vec<(usize, Range<usize>)> = streams
        .iter()
        .map(|s| (s.dict.end, s.data.clone()))
        .collect();
    let headers = live_object_headers(pdf, &raw);
    let value_of = |id: ObjectId| -> Option<u64> {
        let (at, _) = headers.iter().find(|(_, h)| *h == id)?;
        read_uint(pdf, skip_ws(pdf, *at)).map(|(v, _)| v)
    };

    let mut out = Vec::new();
    for s in streams {
        let dict = &pdf[s.dict.clone()];
        let Some(k) = find_from(dict, b"/Length", 0) else {
            continue;
        };
        let base = s.dict.start + k + b"/Length".len();
        let Some((first, after)) = read_uint(pdf, skip_ws(pdf, base)) else {
            continue;
        };
        // `/Length N G R` is an indirect reference; `/Length N` is the value.
        let declared = match read_uint(pdf, skip_ws(pdf, after)) {
            Some((gen, after2))
                if pdf.get(skip_ws(pdf, after2)) == Some(&b'R')
                    && first <= u64::from(u32::MAX)
                    && gen <= u64::from(u16::MAX) =>
            {
                match value_of(ObjectId {
                    number: first as u32,
                    generation: gen as u16,
                }) {
                    Some(v) => v,
                    None => continue,
                }
            }
            _ => first,
        };
        let scanned = s.len() as u64;
        let agrees = if scanned == declared {
            true
        } else if scanned > declared && scanned - declared <= 2 {
            let slack = s.data.start + declared as usize..s.data.end;
            pdf[slack].iter().all(|b| matches!(b, b'\r' | b'\n'))
        } else {
            false
        };
        if !agrees {
            out.push(LengthMismatch {
                index: s.index,
                object: s.object,
                scanned: s.len(),
                declared,
            });
        }
    }
    out
}

/// Result of blanking the trailer's `/Encrypt` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptRemoval {
    /// Overwrote `/Encrypt N G R` with that many spaces.
    Blanked { at: usize, len: usize },
    /// No `/Encrypt` key present -- nothing to do.
    Absent,
    /// Found `/Encrypt` but could not find the closing `R` of the reference.
    Malformed { at: usize },
}

/// Overwrite the last `/Encrypt N G R` in the trailer with spaces.
///
/// Same width, so every byte offset in the `xref` table stays correct and the
/// cross-reference section never has to be rewritten.
pub fn strip_encrypt(pdf: &mut [u8]) -> EncryptRemoval {
    let Some(at) = rfind(pdf, b"/Encrypt") else {
        return EncryptRemoval::Absent;
    };
    // The value is an indirect reference, `N G R`; blank through the `R`.  Bound
    // the search so a missing `R` cannot eat the rest of the file.
    let limit = (at + 64).min(pdf.len());
    match find_from(&pdf[..limit], b"R", at) {
        Some(r) => {
            let len = r + 1 - at;
            pdf[at..at + len].fill(b' ');
            EncryptRemoval::Blanked { at, len }
        }
        None => EncryptRemoval::Malformed { at },
    }
}

/// Cheap structural checks on the decrypted body.
pub fn looks_like_pdf(pdf: &[u8]) -> bool {
    pdf.starts_with(b"%PDF-")
}

pub fn has_eof_marker(pdf: &[u8]) -> bool {
    contains(&pdf[pdf.len().saturating_sub(2048)..], b"%%EOF")
}

pub fn has_encrypt_key(pdf: &[u8]) -> bool {
    contains(pdf, b"/Encrypt")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &[u8] = b"%PDF-1.5\r\n\
4 0 obj\r<</Contents 5 0 R /Filter /FlateDecode /Length 5>>\rstream\r\nAAAA\rendstream\rendobj\r\
12 0 obj\r<</Length 4>>\rstream\nBBB\nendstream\nendobj\r\
trailer\r<</Size 13 /Root 1 0 R /Encrypt 99 0 R>>\rstartxref\r10\r%%EOF";

    #[test]
    fn finds_both_streams() {
        let s = scan_streams(DOC);
        assert_eq!(s.len(), 2, "{s:#?}");
        assert_eq!(&DOC[s[0].data.clone()], b"AAAA\r");
        assert_eq!(&DOC[s[1].data.clone()], b"BBB\n");
    }

    #[test]
    fn attributes_streams_to_their_objects() {
        let s = scan_streams(DOC);
        assert_eq!(s[0].object.unwrap().number, 4);
        assert_eq!(s[1].object.unwrap().number, 12);
        assert_eq!(s[0].object.unwrap().generation, 0);
    }

    #[test]
    fn exposes_the_dictionary() {
        let s = scan_streams(DOC);
        assert!(s[0].is_flate(DOC));
        assert!(!s[1].is_flate(DOC));
        assert!(contains(&DOC[s[1].dict.clone()], b"/Length 4"));
    }

    #[test]
    fn endobj_is_not_an_object_header() {
        assert_eq!(object_headers(DOC).len(), 2, "{:?}", object_headers(DOC));
    }

    #[test]
    fn direct_lengths_agree() {
        let s = scan_streams(DOC);
        assert!(
            length_mismatches(DOC, &s).is_empty(),
            "{:?}",
            length_mismatches(DOC, &s)
        );
    }

    /// The spec puts an EOL between the payload and `endstream` and leaves it
    /// out of /Length, so the keyword scan legitimately runs one or two bytes
    /// long.  That is not a mismatch.
    #[test]
    fn a_trailing_eol_is_not_a_mismatch() {
        let doc: &[u8] =
            b"%PDF-1.5\r1 0 obj\r<</Length 6>>\rstream\r\nabcdef\r\nendstream\rendobj\r%%EOF";
        let s = scan_streams(doc);
        assert_eq!(s[0].len(), 8, "scan includes the CRLF");
        assert!(length_mismatches(doc, &s).is_empty());
    }

    /// ... but two extra bytes that are *not* EOL are.
    #[test]
    fn trailing_non_eol_slack_is_a_mismatch() {
        let doc: &[u8] =
            b"%PDF-1.5\r1 0 obj\r<</Length 4>>\rstream\r\nabcdef\rendstream\rendobj\r%%EOF";
        let s = scan_streams(doc);
        assert_eq!(length_mismatches(doc, &s).len(), 1);
    }

    #[test]
    fn a_wrong_direct_length_is_reported() {
        let doc = DOC.to_vec();
        let doc = String::from_utf8_lossy(&doc)
            .replace("/Length 5>>", "/Length 9>>")
            .into_bytes();
        let s = scan_streams(&doc);
        let m = length_mismatches(&doc, &s);
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!((m[0].declared, m[0].scanned), (9, 5));
        assert!(
            m[0].scanned < m[0].declared as usize,
            "under-slice must be caught"
        );
    }

    #[test]
    fn indirect_lengths_are_resolved() {
        let doc: &[u8] = b"%PDF-1.5\r\
1 0 obj\r<</Length 2 0 R>>\rstream\r\nabcdef\rendstream\rendobj\r\
2 0 obj\r7\rendobj\r%%EOF";
        let s = scan_streams(doc);
        assert_eq!(s[0].len(), 7);
        assert!(length_mismatches(doc, &s).is_empty());

        let bad: &[u8] = b"%PDF-1.5\r\
1 0 obj\r<</Length 2 0 R>>\rstream\r\nabcdef\rendstream\rendobj\r\
2 0 obj\r99\rendobj\r%%EOF";
        let s = scan_streams(bad);
        let m = length_mismatches(bad, &s);
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].declared, 99);
    }

    #[test]
    fn an_unresolvable_length_is_skipped_not_reported() {
        let doc: &[u8] = b"%PDF-1.5\r1 0 obj\r<</Length 77 0 R>>\rstream\r\nabc\rendstream\r%%EOF";
        assert!(length_mismatches(doc, &scan_streams(doc)).is_empty());
    }

    #[test]
    fn strips_encrypt_in_place() {
        let mut doc = DOC.to_vec();
        let before = doc.len();
        match strip_encrypt(&mut doc) {
            EncryptRemoval::Blanked { len, .. } => assert_eq!(len, "/Encrypt 99 0 R".len()),
            other => panic!("{other:?}"),
        }
        assert_eq!(doc.len(), before, "the length must not change");
        assert!(!has_encrypt_key(&doc));
        assert!(contains(&doc, b"/Root 1 0 R"));
        assert!(contains(&doc, b"/Size 13"));
    }

    #[test]
    fn absent_encrypt_is_not_an_error() {
        let mut doc = b"%PDF-1.5\rtrailer<</Size 1>>\r%%EOF".to_vec();
        assert_eq!(strip_encrypt(&mut doc), EncryptRemoval::Absent);
    }

    #[test]
    fn malformed_encrypt_is_reported_not_applied() {
        let mut doc = b"%PDF-1.5\rtrailer<</Encrypt 1 0 ".to_vec();
        let copy = doc.clone();
        assert!(matches!(
            strip_encrypt(&mut doc),
            EncryptRemoval::Malformed { .. }
        ));
        assert_eq!(doc, copy, "must not modify anything when unsure");
    }

    #[test]
    fn empty_stream_has_zero_length() {
        let doc = b"%PDF-1.5\r1 0 obj\r<<>>\rstream\r\nendstream\rendobj\r%%EOF";
        let s = scan_streams(doc);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].len(), 0);
    }

    #[test]
    fn obj_inside_binary_payload_does_not_shift_attribution() {
        let mut doc = b"%PDF-1.5\r7 0 obj\r<</Length 20>>\rstream\r\n".to_vec();
        doc.extend_from_slice(b"\x00\x0199 0 obj\x00junk\x00");
        doc.extend_from_slice(b"\rendstream\rendobj\r%%EOF");
        let s = scan_streams(&doc);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].object.unwrap().number, 7);
    }

    #[test]
    fn structural_helpers() {
        assert!(looks_like_pdf(DOC));
        assert!(has_eof_marker(DOC));
        assert!(!looks_like_pdf(b"PK\x03\x04"));
    }
}

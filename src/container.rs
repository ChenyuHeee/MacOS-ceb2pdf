//! The `Founder CEB` container.
//!
//! ```text
//! 0x00  "Founder CEB"   11 B magic -- the only fixed bytes in the header
//! 0x0B  \0 or ' '       NUL, or a space when a version string follows
//! 0x0C  ...             NUL-terminated ASCII version ("", "2.50f", "2.99D")
//! 0x14  u16             section count
//! 0x16  u16 = 1
//! 0x18  7 B             reserved
//! 0x1F  section table, 17 B per entry:  off u32 | len u32 | type u8 | 8 B rsvd
//! ```
//!
//! Almost nothing else is stable across the 18 real files this was checked
//! against, so the parser leans on two things only: the count at `0x14` and the
//! table at `0x1F`.
//!
//! **There is no table-size field.**  Offset `0x10` falls *inside* the version
//! string, and it equals `count * 17` on a couple of files by pure coincidence
//! (`'f'` == 102 == 6*17 in "2.50f", `'D'` == 68 == 4*17 in "2.99D").  Reading
//! it as a length rejects five otherwise-fine samples, so it is ignored.
//!
//! **The type byte is not trustworthy either.**  The body is type 3 in a couple
//! of files and type 2 in sixteen of them -- usually next to a zero-length
//! type-3 decoy.  The algorithm-id section has shown up as type 16, 0 and 34.
//! And because the table can physically overlap the first section's data, the
//! last entry's type byte is sometimes uninitialised memory.
//!
//! What *is* stable is shape.  Sections are therefore identified by length:
//!
//! | role | shape |
//! |---|---|
//! | PDF body | the longest section |
//! | Founder-RC4 key | 16 bytes |
//! | 3DES key (bare or RSA-wrapped) | 24 or 64 bytes |
//! | algorithm id | 4 bytes |
//!
//! The type byte is still used, but only to break ties when several sections
//! have the same shape, and any guess is recorded in [`Layout::notes`].

use crate::error::{Error, Result};

pub const MAGIC: &[u8; 11] = b"Founder CEB";
/// Bytes before the section table.
pub const HEADER_LEN: usize = 0x1F;
/// Bytes per section-table entry.
pub const ENTRY_LEN: usize = 17;
/// The only numeric container version verified against a real file.
pub const SUPPORTED_VERSION: u16 = 3;
/// Sanity bound on the section count.  Real files have 4 to 7.
pub const MAX_SECTIONS: u16 = 64;

/// Section type ids.
pub mod section {
    /// GBK-encoded XML metadata.
    pub const XML_META: u8 = 0;
    /// The PDF body, RC4-encrypted as a whole.
    pub const PDF_BODY: u8 = 3;
    /// 16-byte Founder-RC4 key.
    pub const RC4_KEY: u8 = 4;
    /// 3DES key: 16/24 bytes bare, or 64 bytes RSA-wrapped.
    pub const KEY_BLOB: u8 = 5;
    /// u32 algorithm id.
    pub const ALGORITHM: u8 = 16;
    /// Producer info (`Maker 3.2`, build date, OS).
    pub const MAKER_INFO: u8 = 255;

    pub fn name(ty: u8) -> &'static str {
        match ty {
            XML_META => "XML metadata",
            PDF_BODY => "PDF body",
            RC4_KEY => "RC4 key",
            KEY_BLOB => "3DES key blob",
            ALGORITHM => "algorithm id",
            MAKER_INFO => "producer info",
            _ => "unrecognised",
        }
    }
}

/// How the container spells its version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// `Founder CEB\0`, u16 version at `0x0E`.  Verified: 3.
    Numeric(u16),
    /// `Founder CEB `, NUL-terminated ASCII version at `0x0C`.  Verified:
    /// `2.99D`.
    Labelled(String),
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Version::Numeric(v) => write!(f, "{v}"),
            Version::Labelled(s) => write!(f, "{s}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub ty: u8,
    pub offset: u32,
    pub len: u32,
}

impl Section {
    pub fn end(&self) -> u64 {
        u64::from(self.offset) + u64::from(self.len)
    }
}

/// The sections we actually need, after resolving them by type where possible
/// and by shape where the type byte is garbage.
#[derive(Debug, Clone)]
pub struct Layout {
    pub body: Section,
    pub rc4_key: Section,
    pub key_blob: Option<Section>,
    pub algorithm: Option<Section>,
    /// How anything ambiguous was resolved.  Surfaced by `--verbose` and, when
    /// a guess was involved, as a warning.
    pub notes: Vec<String>,
    /// True if any section had to be identified by shape rather than by type.
    pub guessed: bool,
}

#[derive(Debug)]
pub struct Container<'a> {
    data: &'a [u8],
    pub version: Version,
    pub sections: Vec<Section>,
    /// Header-level oddities worth mentioning but not worth failing on.
    pub notes: Vec<String>,
}

fn u16_at(d: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([d[at], d[at + 1]])
}

fn u32_at(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]])
}

impl<'a> Container<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        // Magic first: a short file that is obviously not a CEB deserves to
        // hear that, not "truncated header".
        if data.len() < MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
            return Err(Error::NotCeb {
                found: data[..MAGIC.len().min(data.len())].to_vec(),
            });
        }
        if data.len() < HEADER_LEN {
            return Err(Error::Truncated {
                what: "CEB header",
                need: HEADER_LEN,
                have: data.len(),
            });
        }

        let mut notes = Vec::new();

        // The version field: either two u16s or an ASCII string that can run
        // far enough to swallow the table-size field at 0x10.
        let label_end = data[0x0C..0x14]
            .iter()
            .position(|&b| b == 0)
            .map(|p| 0x0C + p)
            .unwrap_or(0x14);
        let version = if data[0x0B] == 0 {
            let v = u16_at(data, 0x0E);
            if v != SUPPORTED_VERSION {
                return Err(Error::UnsupportedVersion {
                    version: Version::Numeric(v),
                });
            }
            Version::Numeric(v)
        } else {
            let raw = &data[0x0C..label_end];
            if raw.is_empty() || !raw.iter().all(|b| b.is_ascii_graphic()) {
                return Err(Error::UnsupportedVersion {
                    version: Version::Labelled(
                        String::from_utf8_lossy(&data[0x0B..0x14]).into_owned(),
                    ),
                });
            }
            let label = String::from_utf8_lossy(raw).into_owned();
            notes.push(format!(
                "legacy header: version string `{label}` where v3 keeps two u16 fields"
            ));
            Version::Labelled(label)
        };

        let count = u16_at(data, 0x14);
        if count == 0 || count >= MAX_SECTIONS {
            return Err(Error::BadSectionTable { count });
        }

        let table_end = HEADER_LEN + count as usize * ENTRY_LEN;
        if data.len() < table_end {
            return Err(Error::Truncated {
                what: "CEB section table",
                need: table_end,
                have: data.len(),
            });
        }

        // Entries that point outside the file are dropped rather than fatal:
        // real files carry slots that were never filled in, and refusing them
        // would reject documents that convert perfectly.
        let mut sections = Vec::with_capacity(count as usize);
        let mut dropped = 0usize;
        for i in 0..count as usize {
            let p = HEADER_LEN + i * ENTRY_LEN;
            let s = Section {
                offset: u32_at(data, p),
                len: u32_at(data, p + 4),
                ty: data[p + 8],
            };
            if s.end() > data.len() as u64 {
                dropped += 1;
                continue;
            }
            sections.push(s);
        }
        if dropped > 0 {
            notes.push(format!(
                "{dropped} of {count} section-table entries point past the end of the file \
                 and were ignored"
            ));
        }
        if sections.is_empty() {
            return Err(Error::BadSectionTable { count });
        }

        let mut c = Container {
            data,
            version,
            sections,
            notes,
        };
        if let Some(first) = c.sections.iter().map(|s| s.offset as usize).min() {
            if first < table_end {
                c.notes.push(format!(
                    "section data starts at {first}, inside the {table_end}-byte header and \
                     table -- so the last table entry's type byte is really payload. Sections \
                     are identified by shape where that happens."
                ));
            }
        }
        Ok(c)
    }

    pub fn file_len(&self) -> usize {
        self.data.len()
    }

    pub fn find(&self, ty: u8) -> Option<Section> {
        self.sections.iter().copied().find(|s| s.ty == ty)
    }

    pub fn slice(&self, s: Section) -> &'a [u8] {
        &self.data[s.offset as usize..s.end() as usize]
    }

    pub fn bytes(&self, ty: u8) -> Option<&'a [u8]> {
        self.find(ty).map(|s| self.slice(s))
    }

    /// GBK-encoded XML metadata, if present.  Returned raw -- we do not carry a
    /// GBK decoder.
    pub fn xml_metadata(&self) -> Option<&'a [u8]> {
        self.bytes(section::XML_META)
    }

    /// Structural check: the sections tile one contiguous run ending at EOF.
    ///
    /// True on both known samples, so a violation is worth reporting -- but as
    /// a warning, since a file that breaks it may still convert.
    pub fn layout_complaints(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut sorted = self.sections.clone();
        sorted.sort_by_key(|s| s.offset);
        for w in sorted.windows(2) {
            if w[0].end() != u64::from(w[1].offset) {
                out.push(format!(
                    "sections at {} (+{}) and {} are not adjacent",
                    w[0].offset, w[0].len, w[1].offset
                ));
            }
        }
        if let Some(last) = sorted.last() {
            if last.end() != self.data.len() as u64 {
                out.push(format!(
                    "the last section ends at {} but the file is {} bytes",
                    last.end(),
                    self.data.len()
                ));
            }
        }
        out
    }

    /// Work out which section is which.
    ///
    /// Type bytes are used when they are present and sane; otherwise a section
    /// is identified by its shape (position and length) and a note is recorded.
    /// The 2.99D sample needs the fallback for its algorithm-id section.
    pub fn resolve(&self) -> Result<Layout> {
        let mut notes = Vec::new();
        let mut guessed = false;

        // The body first, and by size alone: "the longest section" is the one
        // rule that held on all 18 files, where the type byte did not.  Taking
        // it first also stops a 24- or 64-byte shape match from stealing it.
        let (body, body_sec) = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.len > 0)
            .max_by_key(|(_, s)| s.len)
            .ok_or(Error::MissingSection {
                ty: section::PDF_BODY,
                what: section::name(section::PDF_BODY),
            })?;
        if body_sec.ty != section::PDF_BODY {
            notes.push(format!(
                "PDF body: the longest section (offset {}, {} bytes) has type byte {}, not {}; \
                 identified by size",
                body_sec.offset,
                body_sec.len,
                body_sec.ty,
                section::PDF_BODY
            ));
        }
        let mut claimed: Vec<usize> = vec![body];

        // Then the keys and the algorithm id, also by shape.  The type byte is
        // only consulted to break a tie between sections of the same length.
        let mut by_shape = |lens: &[u32], ty: u8, what: &'static str, claimed: &mut Vec<usize>| {
            let cands: Vec<usize> = self
                .sections
                .iter()
                .enumerate()
                .filter(|(i, s)| !claimed.contains(i) && lens.contains(&s.len))
                .map(|(i, _)| i)
                .collect();
            let pick = match cands.len() {
                0 => return None,
                1 => cands[0],
                _ => {
                    let by_type = cands.iter().copied().find(|&i| self.sections[i].ty == ty);
                    guessed = true;
                    notes.push(format!(
                        "{} sections share the {what} shape; {}",
                        cands.len(),
                        match by_type {
                            Some(i) => format!(
                                "picked the one with type byte {ty} (offset {})",
                                self.sections[i].offset
                            ),
                            None => format!(
                                "none has type byte {ty}, so the first (offset {}) was used",
                                self.sections[cands[0]].offset
                            ),
                        }
                    ));
                    by_type.unwrap_or(cands[0])
                }
            };
            if self.sections[pick].ty != ty {
                notes.push(format!(
                    "{what}: section at offset {} has type byte {}, not {ty}; identified by \
                     its {}-byte length",
                    self.sections[pick].offset, self.sections[pick].ty, self.sections[pick].len
                ));
            }
            claimed.push(pick);
            Some(pick)
        };

        let rc4_key = by_shape(&[16], section::RC4_KEY, "RC4 key", &mut claimed).ok_or(
            Error::MissingSection {
                ty: section::RC4_KEY,
                what: section::name(section::RC4_KEY),
            },
        )?;
        let key_blob = by_shape(&[24, 64], section::KEY_BLOB, "3DES key", &mut claimed);
        let algorithm = by_shape(&[4], section::ALGORITHM, "algorithm id", &mut claimed);

        Ok(Layout {
            body: self.sections[body],
            rc4_key: self.sections[rc4_key],
            key_blob: key_blob.map(|i| self.sections[i]),
            algorithm: algorithm.map(|i| self.sections[i]),
            notes,
            guessed,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a well-formed v3 container in memory, with an 8-byte gap between
    /// the table and the data so it looks like the real thing.
    pub(crate) fn synth(secs: &[(u8, Vec<u8>)]) -> Vec<u8> {
        synth_version(&[0u8, 0, 3, 0], secs)
    }

    /// `version_field` is the four bytes at 0x0C..0x10 plus, for the legacy
    /// flavour, whatever spills into 0x10 -- callers pass the exact bytes.
    pub(crate) fn synth_version(version_field: &[u8], secs: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let count = secs.len();
        let table_end = HEADER_LEN + count * ENTRY_LEN;
        let mut out = vec![0u8; table_end];
        out[..MAGIC.len()].copy_from_slice(MAGIC);
        out[0x0C..0x0C + version_field.len()].copy_from_slice(version_field);
        // Only write the table-size field when the version string left it free.
        if version_field.len() <= 4 {
            out[0x10..0x14].copy_from_slice(&((count * ENTRY_LEN) as u32).to_le_bytes());
        }
        out[0x14..0x16].copy_from_slice(&(count as u16).to_le_bytes());
        out[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());

        let mut cursor = table_end as u32;
        for (i, (ty, body)) in secs.iter().enumerate() {
            let p = HEADER_LEN + i * ENTRY_LEN;
            out[p..p + 4].copy_from_slice(&cursor.to_le_bytes());
            out[p + 4..p + 8].copy_from_slice(&(body.len() as u32).to_le_bytes());
            out[p + 8] = *ty;
            cursor += body.len() as u32;
        }
        for (_, body) in secs {
            out.extend_from_slice(body);
        }
        out
    }

    /// A realistic shape: the body dwarfs every other section, which is what
    /// makes "longest section" a safe rule.
    fn body_bytes() -> Vec<u8> {
        let mut v = b"%PDF-1.5 body".to_vec();
        v.resize(4096, b'.');
        v
    }

    fn basic() -> Vec<(u8, Vec<u8>)> {
        vec![
            (section::PDF_BODY, body_bytes()),
            (section::RC4_KEY, vec![0xAB; 16]),
            (section::KEY_BLOB, vec![0xCD; 24]),
            (section::ALGORITHM, 2u32.to_le_bytes().to_vec()),
        ]
    }

    #[test]
    fn parses_v3() {
        let raw = synth(&basic());
        let c = Container::parse(&raw).unwrap();
        assert_eq!(c.version, Version::Numeric(3));
        assert_eq!(c.sections.len(), 4);
        assert_eq!(c.bytes(section::PDF_BODY).unwrap(), &body_bytes()[..]);
        assert!(
            c.layout_complaints().is_empty(),
            "{:?}",
            c.layout_complaints()
        );
        let l = c.resolve().unwrap();
        assert!(!l.guessed, "{:?}", l.notes);
        assert_eq!(l.rc4_key.len, 16);
        assert_eq!(l.key_blob.unwrap().len, 24);
        assert_eq!(l.algorithm.unwrap().len, 4);
    }

    fn legacy(secs: &[(u8, Vec<u8>)]) -> Vec<u8> {
        // "2.99D\0\0\0" starting at 0x0C, exactly like the 2.99D sample: the
        // `D` lands on the low byte of the table-size field at 0x10.
        let mut vf = b"2.99D".to_vec();
        vf.extend_from_slice(&[0, 0, 0]);
        let mut raw = synth_version(&vf, secs);
        raw[0x0B] = b' ';
        raw
    }

    #[test]
    fn parses_a_legacy_labelled_header() {
        let raw = legacy(&basic());
        let c = Container::parse(&raw).unwrap();
        assert_eq!(c.version, Version::Labelled("2.99D".into()));
        assert_eq!(c.sections.len(), 4);
        assert!(c.notes.iter().any(|n| n.contains("2.99D")), "{:?}", c.notes);
    }

    /// The 2.99D file's last table entry has an uninitialised type byte (the
    /// table overlaps the body).  Shape still finds the algorithm id.
    #[test]
    fn resolves_algorithm_section_with_a_garbage_type_byte() {
        let mut secs = basic();
        secs[3].0 = 0xB7; // as in the real file
        let raw = synth(&secs);
        let l = Container::parse(&raw).unwrap().resolve().unwrap();
        assert_eq!(l.algorithm.unwrap().len, 4);
        assert!(
            l.notes.iter().any(|n| n.contains("algorithm id")),
            "{:?}",
            l.notes
        );
    }

    /// Every type byte scrambled at once: shape alone must still work.
    #[test]
    fn resolves_with_every_type_byte_wrong() {
        let mut secs = basic();
        for (i, s) in secs.iter_mut().enumerate() {
            s.0 = 0x90 + i as u8;
        }
        let l = Container::parse(&synth(&secs)).unwrap().resolve().unwrap();
        assert_eq!(l.body.len, 4096);
        assert_eq!(l.rc4_key.len, 16);
        assert_eq!(l.key_blob.unwrap().len, 24);
        assert_eq!(l.algorithm.unwrap().len, 4);
    }

    #[test]
    fn resolves_body_by_size_when_its_type_byte_is_garbage() {
        let mut secs = basic();
        secs[0].1 = vec![b'x'; 5000];
        secs[0].0 = 0x99;
        let l = Container::parse(&synth(&secs)).unwrap().resolve().unwrap();
        assert_eq!(l.body.len, 5000);
    }

    /// Two sections of the same shape: the type byte breaks the tie, and the
    /// ambiguity is recorded.
    #[test]
    fn ambiguous_shapes_fall_back_to_the_type_byte() {
        let raw = synth(&[
            (section::PDF_BODY, vec![b'x'; 900]),
            (99, vec![0; 16]),
            (section::RC4_KEY, vec![7; 16]),
            (section::KEY_BLOB, vec![2; 24]),
            (section::ALGORITHM, 1u32.to_le_bytes().to_vec()),
        ]);
        let c = Container::parse(&raw).unwrap();
        let l = c.resolve().unwrap();
        assert_eq!(c.slice(l.rc4_key), &[7u8; 16]);
        assert!(l.guessed);
        assert!(
            l.notes
                .iter()
                .any(|n| n.contains("share the RC4 key shape")),
            "{:?}",
            l.notes
        );
    }

    #[test]
    fn missing_rc4_key_is_an_error() {
        let secs = vec![
            (section::PDF_BODY, body_bytes()),
            (section::ALGORITHM, 0u32.to_le_bytes().to_vec()),
        ];
        let raw = synth(&secs);
        let msg = Container::parse(&raw)
            .unwrap()
            .resolve()
            .unwrap_err()
            .to_string();
        assert!(msg.contains("type 4"), "{msg}");
    }

    #[test]
    fn algorithm_section_may_be_absent() {
        let secs = vec![
            (section::PDF_BODY, body_bytes()),
            (section::RC4_KEY, vec![1; 16]),
        ];
        let raw = synth(&secs);
        let l = Container::parse(&raw).unwrap().resolve().unwrap();
        assert!(l.algorithm.is_none());
        assert!(l.key_blob.is_none());
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut raw = synth(&basic());
        raw[3] = b'X';
        match Container::parse(&raw) {
            Err(Error::NotCeb { .. }) => {}
            other => panic!("expected NotCeb, got {other:?}"),
        }
    }

    #[test]
    fn rejects_cebx() {
        let mut raw = vec![0u8; 64];
        raw[..4].copy_from_slice(b"@XDA");
        let msg = Container::parse(&raw).unwrap_err().to_string();
        assert!(msg.contains("CEBX"), "{msg}");
    }

    #[test]
    fn rejects_unknown_numeric_version() {
        let raw = synth_version(&[0, 0, 4, 0], &basic());
        let msg = match Container::parse(&raw) {
            Err(e @ Error::UnsupportedVersion { .. }) => e.to_string(),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        };
        assert!(msg.contains('4'), "{msg}");
    }

    #[test]
    fn rejects_a_truncated_ceb() {
        let mut raw = MAGIC.to_vec();
        raw.extend_from_slice(&[0u8; 8]);
        match Container::parse(&raw) {
            Err(Error::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    /// A short file that is not a CEB at all should say so, not "truncated".
    #[test]
    fn short_non_ceb_is_reported_as_not_a_ceb() {
        match Container::parse(b"PK\x03\x04 zip") {
            Err(Error::NotCeb { .. }) => {}
            other => panic!("expected NotCeb, got {other:?}"),
        }
        assert!(matches!(Container::parse(&[]), Err(Error::NotCeb { .. })));
    }

    /// Offset 0x10 is inside the version string, and a 23 MB sample puts 1700
    /// there while having 6 sections.  Reading it as a table size rejects five
    /// otherwise-fine files, so nothing may depend on it.
    #[test]
    fn the_field_at_0x10_is_never_read() {
        for junk in [0u32, 1700, 0xffff_ffff] {
            let mut raw = synth(&basic());
            raw[0x10..0x14].copy_from_slice(&junk.to_le_bytes());
            let c = Container::parse(&raw)
                .unwrap_or_else(|e| panic!("0x10 = {junk} should not matter: {e}"));
            assert_eq!(c.sections.len(), 4);
        }
    }

    #[test]
    fn rejects_zero_sections() {
        let mut raw = synth(&basic());
        raw[0x14..0x16].copy_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            Container::parse(&raw),
            Err(Error::BadSectionTable { count: 0 })
        ));
    }

    /// Real files carry table slots that were never filled in, so an entry
    /// pointing past EOF is dropped with a note instead of killing the file.
    #[test]
    fn a_section_past_eof_is_dropped_not_fatal() {
        let mut raw = synth(&basic());
        let p = HEADER_LEN + 3 * ENTRY_LEN; // the 4-byte algorithm-id entry
        raw[p..p + 4].copy_from_slice(&999_999u32.to_le_bytes());
        let c = Container::parse(&raw).unwrap();
        assert_eq!(c.sections.len(), 3);
        assert!(
            c.notes.iter().any(|n| n.contains("past the end")),
            "{:?}",
            c.notes
        );
        // ... and the rest still resolves, just without an algorithm id.
        let l = c.resolve().unwrap();
        assert!(l.algorithm.is_none());
        assert_eq!(l.body.len, 4096);
    }

    #[test]
    fn a_table_with_nothing_usable_is_an_error() {
        let mut raw = synth(&basic());
        for i in 0..4 {
            let p = HEADER_LEN + i * ENTRY_LEN;
            raw[p..p + 4].copy_from_slice(&999_999u32.to_le_bytes());
        }
        assert!(matches!(
            Container::parse(&raw),
            Err(Error::BadSectionTable { .. })
        ));
    }

    #[test]
    fn rejects_an_absurd_section_count() {
        let mut raw = synth(&basic());
        raw[0x14..0x16].copy_from_slice(&5000u16.to_le_bytes());
        assert!(matches!(
            Container::parse(&raw),
            Err(Error::BadSectionTable { count: 5000 })
        ));
    }

    #[test]
    fn layout_complaints_flag_gaps() {
        let mut raw = synth(&[
            (section::PDF_BODY, body_bytes()),
            (section::RC4_KEY, vec![1; 16]),
        ]);
        let p = HEADER_LEN + ENTRY_LEN;
        let off = u32::from_le_bytes([raw[p], raw[p + 1], raw[p + 2], raw[p + 3]]);
        raw[p..p + 4].copy_from_slice(&(off + 1).to_le_bytes());
        raw.push(0);
        let c = Container::parse(&raw).unwrap();
        assert_eq!(
            c.layout_complaints().len(),
            1,
            "{:?}",
            c.layout_complaints()
        );
    }

    #[test]
    fn layout_complaints_flag_a_short_last_section() {
        let mut raw = synth(&basic());
        raw.push(0); // one stray byte past the last section
        let c = Container::parse(&raw).unwrap();
        assert_eq!(
            c.layout_complaints().len(),
            1,
            "{:?}",
            c.layout_complaints()
        );
    }

    #[test]
    fn notes_table_data_overlap() {
        // Point the body at an offset inside the table, like the 2.99D file.
        let mut secs = basic();
        secs[0].1 = vec![b'x'; 200];
        let mut raw = synth(&secs);
        let p = HEADER_LEN;
        raw[p..p + 4].copy_from_slice(&(HEADER_LEN as u32 - 5).to_le_bytes());
        let c = Container::parse(&raw).unwrap();
        assert!(
            c.notes.iter().any(|n| n.contains("inside the")),
            "{:?}",
            c.notes
        );
    }
}

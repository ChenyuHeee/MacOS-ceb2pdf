//! The per-stream decryption strategy -- a replaceable policy point.
//!
//! The container tells us which cipher to use through the low bits of its
//! algorithm id, and two of the three values we can name have been seen in a
//! real file.  Rather than branch on the id deep inside the conversion, the
//! choice is reified as a [`StreamDecryptor`] and everything a strategy might
//! need is handed to it in [`StreamInfo`] -- object number and generation, the
//! raw stream dictionary, the offset, the file key.
//!
//! That keeps two doors open: a new algorithm id only needs a new
//! implementation here, and a per-object key derivation (should any variant
//! turn out to use one) has the object id available without re-parsing.

use crate::error::Result;
use crate::pdf::{ObjectId, PdfStream};
use crate::tdes::{Mode, Tdes};

/// Everything known about one stream at decryption time.
#[derive(Debug, Clone, Copy)]
pub struct StreamInfo<'a> {
    /// Position in document order, 0-based.
    pub index: usize,
    /// Offset of the payload within the PDF body.
    pub offset: usize,
    /// Payload length in bytes.
    pub len: usize,
    /// `N G obj` this stream belongs to, when it could be recovered.
    pub object: Option<ObjectId>,
    /// Raw, unparsed stream dictionary.
    pub dict: &'a [u8],
    /// The file key recovered from the container.
    pub file_key: &'a [u8],
}

impl StreamInfo<'_> {
    pub fn dict_has(&self, needle: &[u8]) -> bool {
        self.dict.windows(needle.len()).any(|w| w == needle)
    }
}

/// A strategy for turning one encrypted stream payload into plaintext.
///
/// Implementations must be length-preserving: the whole design depends on
/// `xref` offsets staying valid, so `data` is decrypted in place.
pub trait StreamDecryptor: Send + Sync {
    /// Short description, shown by `--verbose`.
    fn name(&self) -> &str;

    /// Decrypt `data` in place.  `data.len() == info.len`.
    fn decrypt(&self, info: &StreamInfo<'_>, data: &mut [u8]) -> Result<()>;
}

/// 3DES with a chaining mode, the IV taken from the key, restarted every 256
/// bytes.  `Mode::Cfb64` is the verified configuration.
pub struct Tdes3 {
    cipher: Tdes,
    mode: Mode,
    name: String,
}

impl Tdes3 {
    pub fn new(key: &[u8], mode: Mode) -> Result<Self> {
        Self::with_reset(key, mode, crate::tdes::RESET)
    }

    pub fn with_reset(key: &[u8], mode: Mode, reset: usize) -> Result<Self> {
        Ok(Tdes3 {
            cipher: Tdes::new(key, reset)?,
            mode,
            name: format!(
                "{} (IV = key[..8], restarted every {reset} B)",
                mode.as_str()
            ),
        })
    }
}

impl StreamDecryptor for Tdes3 {
    fn name(&self) -> &str {
        &self.name
    }

    fn decrypt(&self, _info: &StreamInfo<'_>, data: &mut [u8]) -> Result<()> {
        self.cipher.decrypt(self.mode, data);
        Ok(())
    }
}

/// Leaves payloads untouched.  This is the *correct* strategy for algorithm id
/// 0 -- the 2.99D sample's streams are not encrypted at all -- and is also
/// useful for bisecting which layer broke a file.
pub struct Identity;

impl StreamDecryptor for Identity {
    fn name(&self) -> &str {
        "none (streams are not encrypted)"
    }

    fn decrypt(&self, _info: &StreamInfo<'_>, _data: &mut [u8]) -> Result<()> {
        Ok(())
    }
}

/// Run a strategy over every stream of an already-RC4-decrypted body.
pub fn decrypt_all(
    pdf: &mut [u8],
    streams: &[PdfStream],
    file_key: &[u8],
    strategy: &dyn StreamDecryptor,
) -> Result<()> {
    for s in streams {
        if s.is_empty() {
            continue;
        }
        // Copy the dictionary out so the payload can be borrowed mutably.
        let dict = pdf[s.dict.clone()].to_vec();
        let info = StreamInfo {
            index: s.index,
            offset: s.data.start,
            len: s.data.len(),
            object: s.object,
            dict: &dict,
            file_key,
        };
        strategy.decrypt(&info, &mut pdf[s.data.clone()])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::decode;
    use crate::pdf::scan_streams;

    const DOC: &[u8] = b"%PDF-1.5\r1 0 obj\r<</Filter/FlateDecode>>\rstream\r\n0123456789ABCDEF\rendstream\rendobj\r%%EOF";

    #[test]
    fn identity_leaves_bytes_alone() {
        let mut doc = DOC.to_vec();
        let streams = scan_streams(&doc);
        decrypt_all(&mut doc, &streams, &[], &Identity).unwrap();
        assert_eq!(doc, DOC);
    }

    #[test]
    fn tdes_strategy_touches_only_the_payload() {
        let key = decode("a1e7f815671f82812870e2315352f1569a4cb39584f08b03").unwrap();
        let mut doc = DOC.to_vec();
        let streams = scan_streams(&doc);
        let s = Tdes3::new(&key, Mode::Cfb64).unwrap();
        decrypt_all(&mut doc, &streams, &key, &s).unwrap();
        assert_ne!(doc, DOC);
        assert_eq!(doc.len(), DOC.len());
        assert!(doc.starts_with(b"%PDF-1.5\r1 0 obj\r<</Filter/FlateDecode>>\rstream\r\n"));
        assert!(doc.ends_with(b"endstream\rendobj\r%%EOF"));
    }

    #[test]
    fn modes_are_distinguishable_through_the_strategy() {
        let key = decode("a1e7f815671f82812870e2315352f1569a4cb39584f08b03").unwrap();
        let streams = scan_streams(DOC);
        let mut a = DOC.to_vec();
        let mut b = DOC.to_vec();
        decrypt_all(
            &mut a,
            &streams,
            &key,
            &Tdes3::new(&key, Mode::Cfb64).unwrap(),
        )
        .unwrap();
        decrypt_all(
            &mut b,
            &streams,
            &key,
            &Tdes3::new(&key, Mode::Ofb).unwrap(),
        )
        .unwrap();
        assert_ne!(a, b);
    }

    /// The hook a future strategy would use: object id and dictionary have to
    /// reach it.
    #[test]
    fn strategy_sees_object_and_dict() {
        struct Spy(std::sync::Mutex<Vec<(Option<ObjectId>, bool, usize)>>);
        impl StreamDecryptor for Spy {
            fn name(&self) -> &str {
                "spy"
            }
            fn decrypt(&self, info: &StreamInfo<'_>, _d: &mut [u8]) -> Result<()> {
                self.0.lock().unwrap().push((
                    info.object,
                    info.dict_has(b"/FlateDecode"),
                    info.len,
                ));
                Ok(())
            }
        }
        let mut doc = DOC.to_vec();
        let streams = scan_streams(&doc);
        let spy = Spy(std::sync::Mutex::new(Vec::new()));
        decrypt_all(&mut doc, &streams, b"k", &spy).unwrap();
        let seen = spy.0.into_inner().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0.unwrap().number, 1);
        assert!(seen[0].1, "the dictionary should reach the strategy");
        assert_eq!(seen[0].2, 17);
    }
}

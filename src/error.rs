//! Error type for the whole crate.
//!
//! Every variant carries enough context to tell the user what to do next --
//! which file, which section, which byte -- because a CLI that only says
//! "conversion failed" is useless when you are staring at an unknown `.ceb`.

use std::fmt;
use std::path::PathBuf;

use crate::container::Version;

pub type Result<T> = std::result::Result<T, Error>;

/// Where a per-stream key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// The algorithm id was 0: no per-stream cipher, so no key was needed.
    NotNeeded,
    /// The key blob held the key directly (16 or 24 bytes).
    Direct,
    /// The key blob was RSA-wrapped (64 bytes) and we unwrapped it.
    RsaWrapped,
}

#[derive(Debug)]
pub enum Error {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// File does not start with the `Founder CEB` magic.
    NotCeb { found: Vec<u8> },
    /// File is shorter than the structure we are about to read.
    Truncated {
        what: &'static str,
        need: usize,
        have: usize,
    },
    /// Container version we have never seen a sample of.
    UnsupportedVersion { version: Version },
    /// The section-table byte count and the section count disagree.
    BadSectionTable { count: u16 },
    /// A section we cannot work without is absent and could not be identified
    /// by shape either.
    MissingSection { ty: u8, what: &'static str },
    /// A key section has an implausible length.
    BadKeyLength {
        ty: u8,
        what: &'static str,
        len: usize,
        expected: &'static str,
    },
    /// An algorithm id we cannot even name.
    UnknownAlgorithm { id: u32 },
    /// RSA unwrap produced something that is not a key.
    RsaUnwrapFailed { reason: String },
    /// Decrypting the body did not yield a PDF header.
    Rc4LayerFailed { head: Vec<u8> },
    /// The output would overwrite something and `--force` was not given.
    OutputExists { path: PathBuf },
    /// The output path is one of the inputs.  Always refused.
    OutputIsInput { path: PathBuf },
    /// Two inputs would be written to the same output file.
    OutputCollision { path: PathBuf },
    /// `-o` named something that is not a directory, but there are several
    /// inputs to place.
    OutputNotADirectory { path: PathBuf, inputs: usize },
    /// Command-line usage problem.
    Usage(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { path, source } => write!(f, "{}: {}", path.display(), source),
            Error::NotCeb { found } => write!(
                f,
                "not a Founder CEB file: expected it to start with `Founder CEB`, found {:?}. \
                 (CEBX is a different format -- its files start with `@XDA` -- and is not \
                 supported.)",
                String::from_utf8_lossy(found),
            ),
            Error::Truncated { what, need, have } => write!(
                f,
                "file is truncated: reading {what} needs {need} bytes but the file has {have}"
            ),
            Error::UnsupportedVersion { version } => write!(
                f,
                "container version `{version}` has never been checked against a sample. \
                 Verified: {} (`Founder CEB\\0` header) and `2.99D`. Please open an issue \
                 at {} with the file.",
                crate::container::SUPPORTED_VERSION,
                env!("CARGO_PKG_REPOSITORY"),
            ),
            Error::BadSectionTable { count } => write!(
                f,
                "corrupt section table: the header declares {count} sections (real files have \
                 4 to 7, and the parser accepts up to {}), and none of them turned out to be \
                 usable",
                crate::container::MAX_SECTIONS,
            ),
            Error::MissingSection { ty, what } => write!(
                f,
                "no section of type {ty} ({what}), and none could be identified by shape. \
                 If this file came from a library loan it may be bound to a licence server, \
                 which this tool deliberately does not handle."
            ),
            Error::BadKeyLength {
                ty,
                what,
                len,
                expected,
            } => write!(
                f,
                "the {what} section (type {ty}) is {len} bytes, expected {expected}"
            ),
            Error::UnknownAlgorithm { id } => write!(
                f,
                "unknown algorithm id {id:#010x} (low bits {:#x}). Verified: {:#x} = no \
                 per-stream cipher, {:#x} = 3DES-OFB, {:#x} = 3DES-CFB64. Use \
                 `--force-mode <none|ofb|cfb64>` to override, and please open an issue at {} \
                 with the file.",
                id & !crate::WRAPPED_KEY_FLAG,
                crate::ALGO_NONE,
                crate::ALGO_3DES_OFB,
                crate::ALGO_3DES_CFB64,
                env!("CARGO_PKG_REPOSITORY"),
            ),
            Error::RsaUnwrapFailed { reason } => write!(
                f,
                "could not unwrap the 3DES key with the built-in RSA key: {reason}"
            ),
            Error::Rc4LayerFailed { head } => write!(
                f,
                "the RC4 layer did not produce a PDF: the body starts with {head:02x?} instead \
                 of `%PDF-`. Either the RC4 key section was misidentified or this file uses a \
                 variant we have not seen."
            ),
            Error::OutputExists { path } => write!(
                f,
                "{} already exists; pass --force to overwrite",
                path.display()
            ),
            Error::OutputIsInput { path } => write!(
                f,
                "refusing to write over an input file: {}. Give an explicit -o/--output path.",
                path.display()
            ),
            Error::OutputCollision { path } => write!(
                f,
                "two inputs would both be written to {}; give -o/--output a directory instead",
                path.display()
            ),
            Error::OutputNotADirectory { path, inputs } => write!(
                f,
                "{inputs} input files were given, so -o/--output must name an existing \
                 directory, and {} is not one",
                path.display()
            ),
            Error::Usage(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

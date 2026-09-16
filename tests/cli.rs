//! Black-box tests of the `ceb2pdf` binary: argument handling, exit codes, and
//! the safety rules that stop a glob from eating a sample file.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ceb2pdf::tdes::Mode;
use ceb2pdf::{ALGO_3DES_CFB64, ALGO_NONE};
use common::{synth_ceb, tiny_pdf};

const BIN: &str = env!("CARGO_BIN_EXE_ceb2pdf");
const KEY24: &[u8] = b"0123456789abcdefABCDEFGH";

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ceb2pdf-it-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Write a converting `.ceb` into the sandbox.
    fn ceb(&self, name: &str, algorithm_id: u32, mode: Option<Mode>) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, synth_ceb(&tiny_pdf(), KEY24, algorithm_id, mode)).unwrap();
        p
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(BIN).args(args).output().expect("run ceb2pdf")
}

fn out_of(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn converts_a_file_and_exits_zero() {
    let sb = Sandbox::new("basic");
    let input = sb.ceb("book.ceb", ALGO_3DES_CFB64, Some(Mode::Cfb64));
    let o = run([input.as_os_str()]);
    assert!(o.status.success(), "{}", out_of(&o));
    let pdf = sb.path("book.pdf");
    assert!(
        pdf.is_file(),
        "default output path not used: {}",
        out_of(&o)
    );
    assert!(std::fs::read(&pdf).unwrap().starts_with(b"%PDF-"));
}

#[test]
fn batch_converts_several_files_in_parallel() {
    let sb = Sandbox::new("batch");
    let dir = sb.path("out");
    std::fs::create_dir_all(&dir).unwrap();
    let a = sb.ceb("a.ceb", ALGO_3DES_CFB64, Some(Mode::Cfb64));
    let b = sb.ceb("b.ceb", ALGO_NONE, None);
    let c = sb.ceb("c.ceb", ALGO_3DES_CFB64, Some(Mode::Cfb64));

    let o = run([
        std::ffi::OsStr::new("-j"),
        std::ffi::OsStr::new("3"),
        std::ffi::OsStr::new("-o"),
        dir.as_os_str(),
        a.as_os_str(),
        b.as_os_str(),
        c.as_os_str(),
    ]);
    assert!(o.status.success(), "{}", out_of(&o));
    for n in ["a.pdf", "b.pdf", "c.pdf"] {
        assert!(dir.join(n).is_file(), "missing {n}: {}", out_of(&o));
    }
}

/// The accident that motivated this: `ceb2pdf samples/*.ceb out.pdf` used to be
/// able to overwrite the last sample.  Every positional is an input, and an
/// output that collides with an input is refused before anything is written.
#[test]
fn refuses_to_overwrite_an_input() {
    let sb = Sandbox::new("clobber");
    let a = sb.ceb("a.ceb", ALGO_NONE, None);
    let before = std::fs::read(&a).unwrap();

    let o = run([std::ffi::OsStr::new("-o"), a.as_os_str(), a.as_os_str()]);
    assert!(!o.status.success());
    assert!(
        out_of(&o).contains("refusing to write over an input"),
        "{}",
        out_of(&o)
    );
    assert_eq!(std::fs::read(&a).unwrap(), before, "input was modified");
}

#[test]
fn several_inputs_require_an_output_directory() {
    let sb = Sandbox::new("outdir");
    let a = sb.ceb("a.ceb", ALGO_NONE, None);
    let b = sb.ceb("b.ceb", ALGO_NONE, None);
    let o = run([
        std::ffi::OsStr::new("-o"),
        sb.path("nope.pdf").as_os_str(),
        a.as_os_str(),
        b.as_os_str(),
    ]);
    assert!(!o.status.success());
    assert!(
        out_of(&o).contains("must name an existing"),
        "{}",
        out_of(&o)
    );
}

#[test]
fn refuses_to_overwrite_without_force_and_obeys_force() {
    let sb = Sandbox::new("force");
    let input = sb.ceb("a.ceb", ALGO_NONE, None);
    let target = sb.path("a.pdf");
    std::fs::write(&target, b"do not lose me").unwrap();

    let o = run([input.as_os_str()]);
    assert!(!o.status.success());
    assert!(out_of(&o).contains("--force"), "{}", out_of(&o));
    assert_eq!(std::fs::read(&target).unwrap(), b"do not lose me");

    let o = run([std::ffi::OsStr::new("-f"), input.as_os_str()]);
    assert!(o.status.success(), "{}", out_of(&o));
    assert!(std::fs::read(&target).unwrap().starts_with(b"%PDF-"));
}

/// Exit status 3 means "written, but incomplete".  A script must be able to
/// tell that apart from success.
#[test]
fn incomplete_output_exits_three_and_says_so() {
    let sb = Sandbox::new("warn");
    let input = sb.ceb("a.ceb", ALGO_3DES_CFB64, Some(Mode::Cfb64));
    let o = run([
        std::ffi::OsStr::new("--force-mode"),
        std::ffi::OsStr::new("ofb"),
        input.as_os_str(),
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", out_of(&o));
    let text = out_of(&o);
    assert!(text.contains("INCOMPLETE"), "{text}");
    assert!(text.contains("could not be decompressed"), "{text}");
    // ... and the file is still written, so the user can look at it.
    assert!(sb.path("a.pdf").is_file());
}

#[test]
fn bad_input_exits_one_with_a_useful_message() {
    let sb = Sandbox::new("badinput");
    let p = sb.path("not-a-ceb.ceb");
    std::fs::write(&p, b"PK\x03\x04 this is a zip file").unwrap();
    let o = run([p.as_os_str()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(out_of(&o).contains("Founder CEB"), "{}", out_of(&o));
    assert!(!sb.path("not-a-ceb.pdf").exists(), "wrote output anyway");
}

#[test]
fn missing_file_reports_the_path() {
    let o = run(["/definitely/not/here.ceb"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(out_of(&o).contains("/definitely/not/here.ceb"));
}

#[test]
fn dump_meta_describes_without_writing() {
    let sb = Sandbox::new("dump");
    let input = sb.ceb("a.ceb", ALGO_3DES_CFB64, Some(Mode::Cfb64));
    let o = run([std::ffi::OsStr::new("--dump-meta"), input.as_os_str()]);
    assert!(o.status.success(), "{}", out_of(&o));
    let text = out_of(&o);
    assert!(text.contains("version"), "{text}");
    assert!(text.contains("PDF body"), "{text}");
    assert!(
        text.contains("0x80000002") || text.contains("0x00000002"),
        "{text}"
    );
    assert!(!sb.path("a.pdf").exists(), "--dump-meta must not write");
}

#[test]
fn verbose_reports_each_layer() {
    let sb = Sandbox::new("verbose");
    let input = sb.ceb("a.ceb", ALGO_3DES_CFB64, Some(Mode::Cfb64));
    let o = run([std::ffi::OsStr::new("-vv"), input.as_os_str()]);
    assert!(o.status.success(), "{}", out_of(&o));
    let text = out_of(&o);
    for needle in [
        "container version",
        "algorithm id",
        "stream cipher",
        "/Encrypt",
        "self-check",
        "sections:",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
    }
}

#[test]
fn quiet_prints_nothing_on_success() {
    let sb = Sandbox::new("quiet");
    let input = sb.ceb("a.ceb", ALGO_NONE, None);
    let o = run([std::ffi::OsStr::new("-q"), input.as_os_str()]);
    assert!(o.status.success());
    assert_eq!(out_of(&o), "", "quiet should be quiet");
}

#[test]
fn help_and_version() {
    let o = run(["--help"]);
    assert!(o.status.success());
    assert!(out_of(&o).contains("USAGE:"));
    let o = run(["-V"]);
    assert!(o.status.success());
    assert!(out_of(&o).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn no_arguments_prints_usage_and_fails() {
    let o = run(Vec::<&str>::new());
    assert_eq!(o.status.code(), Some(1));
    assert!(out_of(&o).contains("no input files"));
    assert!(out_of(&o).contains("USAGE:"));
}

#[test]
fn a_name_that_looks_like_a_flag_works_after_a_double_dash() {
    let sb = Sandbox::new("dashdash");
    let input = sb.ceb("-weird.ceb", ALGO_NONE, None);
    let dir = input.parent().unwrap();
    let o = Command::new(BIN)
        .current_dir(dir)
        .args(["--", "-weird.ceb"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out_of(&o));
    assert!(Path::new(dir).join("-weird.pdf").is_file());
}

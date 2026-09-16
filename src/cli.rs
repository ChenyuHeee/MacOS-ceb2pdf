//! Hand-rolled argument parsing.
//!
//! `clap` would cost several hundred kilobytes of the binary budget for a tool
//! with ten flags, so this is done by hand.  It handles the usual shapes:
//! `--flag`, `--opt value`, `--opt=value`, `-o value`, `-ovalue`, bundled short
//! flags (`-vf`), and `--` to end option parsing.

use std::path::{Path, PathBuf};

use ceb2pdf::error::Error;
use ceb2pdf::tdes::Mode;

pub const USAGE: &str = "\
ceb2pdf -- losslessly convert Founder Apabi .ceb files to PDF

USAGE:
    ceb2pdf [OPTIONS] <FILE.ceb>...

OPTIONS:
    -o, --output <PATH>      Output file (one input) or an existing directory
                             (several).  Default: next to each input, with the
                             extension replaced by .pdf
    -j, --jobs <N>           Worker threads.  Default: min(cpus, file count)
    -f, --force              Overwrite existing output files
    -v, --verbose            Report each layer; repeat for per-section detail
    -q, --quiet              Print nothing but errors and warnings
        --dump-meta          Print the container structure and exit without
                             converting or writing anything
        --no-verify          Skip the post-conversion self-check
        --force-mode <MODE>  Override the container's algorithm id.  One of
                             `none`, `ofb` or `cfb64`.  All three occur in real
                             files; the container normally picks the right one,
                             so only reach for this to diagnose an odd file
    -h, --help               Print this help
    -V, --version            Print the version

EXIT STATUS:
    0   converted, self-check clean
    1   failed
    3   converted, but the self-check found problems -- read the warnings

NOTES:
    Every positional argument is an input.  There is no positional output
    argument, so `ceb2pdf samples/*.ceb out.pdf` cannot silently eat a file;
    use -o for that.  Writing over an input is always refused.
";

#[derive(Debug, Default)]
pub struct Args {
    pub inputs: Vec<PathBuf>,
    pub output: Option<PathBuf>,
    pub jobs: Option<usize>,
    pub force: bool,
    pub verbose: u8,
    pub quiet: bool,
    pub dump_meta: bool,
    pub no_verify: bool,
    pub force_mode: Option<Option<Mode>>,
}

/// What `parse` decided the process should do.
pub enum Parsed {
    Run(Box<Args>),
    Help,
    Version,
}

fn usage_err(msg: impl Into<String>) -> Error {
    Error::Usage(msg.into())
}

pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Result<Parsed, Error> {
    let mut args = Args::default();
    let mut it = argv.into_iter();
    let mut only_positional = false;

    macro_rules! value {
        ($name:expr, $inline:expr) => {
            match $inline {
                Some(v) => v,
                None => it
                    .next()
                    .ok_or_else(|| usage_err(format!("{} needs a value", $name)))?,
            }
        };
    }

    while let Some(arg) = it.next() {
        if only_positional || arg == "-" {
            args.inputs.push(PathBuf::from(arg));
            continue;
        }
        if arg == "--" {
            only_positional = true;
            continue;
        }

        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            match name {
                "help" => return Ok(Parsed::Help),
                "version" => return Ok(Parsed::Version),
                "output" => args.output = Some(PathBuf::from(value!("--output", inline))),
                "jobs" => args.jobs = Some(parse_jobs(&value!("--jobs", inline))?),
                "force" => args.force = true,
                "verbose" => args.verbose = args.verbose.saturating_add(1),
                "quiet" => args.quiet = true,
                "dump-meta" => args.dump_meta = true,
                "no-verify" => args.no_verify = true,
                "force-mode" => {
                    args.force_mode = Some(parse_mode(&value!("--force-mode", inline))?)
                }
                other => {
                    return Err(usage_err(format!(
                        "unknown option `--{other}`. Run `ceb2pdf --help` for the list."
                    )))
                }
            }
            continue;
        }

        if arg.len() > 1 && arg.starts_with('-') {
            let body: Vec<char> = arg[1..].chars().collect();
            let mut i = 0;
            while i < body.len() {
                // Anything after a value-taking short flag is its value.
                let tail: String = body[i + 1..].iter().collect();
                let tail = tail.strip_prefix('=').map(str::to_string).unwrap_or(tail);
                let rest = (!tail.is_empty()).then_some(tail);
                match body[i] {
                    'h' => return Ok(Parsed::Help),
                    'V' => return Ok(Parsed::Version),
                    'f' => args.force = true,
                    'v' => args.verbose = args.verbose.saturating_add(1),
                    'q' => args.quiet = true,
                    'o' => {
                        args.output = Some(PathBuf::from(value!("-o", rest)));
                        break;
                    }
                    'j' => {
                        args.jobs = Some(parse_jobs(&value!("-j", rest))?);
                        break;
                    }
                    other => {
                        return Err(usage_err(format!(
                            "unknown option `-{other}`. Run `ceb2pdf --help` for the list."
                        )))
                    }
                }
                i += 1;
            }
            continue;
        }

        args.inputs.push(PathBuf::from(arg));
    }

    if args.inputs.is_empty() {
        return Err(usage_err(format!(
            "no input files.\n\n{}",
            USAGE.trim_end()
        )));
    }
    if args.quiet && args.verbose > 0 {
        return Err(usage_err("--quiet and --verbose cannot be combined"));
    }
    Ok(Parsed::Run(Box::new(args)))
}

fn parse_jobs(s: &str) -> Result<usize, Error> {
    match s.parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n),
        _ => Err(usage_err(format!(
            "--jobs expects a positive integer, got `{s}`"
        ))),
    }
}

fn parse_mode(s: &str) -> Result<Option<Mode>, Error> {
    match s.to_ascii_lowercase().as_str() {
        "none" | "off" | "plain" => Ok(None),
        "cfb" | "cfb64" | "3des-cfb64" => Ok(Some(Mode::Cfb64)),
        "ofb" | "3des-ofb" => Ok(Some(Mode::Ofb)),
        _ => Err(usage_err(format!(
            "--force-mode expects `none`, `cfb64` or `ofb`, got `{s}`"
        ))),
    }
}

/// Where a converted file should be written.
pub fn output_path(input: &Path, out: Option<&Path>, many: bool) -> PathBuf {
    match out {
        Some(p) if many || p.is_dir() => {
            let stem = input.file_stem().unwrap_or(input.as_os_str());
            p.join(stem).with_extension("pdf")
        }
        Some(p) => p.to_path_buf(),
        None => input.with_extension("pdf"),
    }
}

/// Work out every output path up front and refuse the dangerous ones.
///
/// Two failure modes are worth the check: clobbering an input (easy to do with
/// a glob, and unrecoverable), and two inputs landing on the same output.
pub fn plan_outputs(args: &Args) -> Result<Vec<PathBuf>, Error> {
    let many = args.inputs.len() > 1;
    if let Some(dir) = args.output.as_deref().filter(|_| many) {
        if !dir.is_dir() {
            return Err(Error::OutputNotADirectory {
                path: dir.to_path_buf(),
                inputs: args.inputs.len(),
            });
        }
    }
    let outs: Vec<PathBuf> = args
        .inputs
        .iter()
        .map(|i| output_path(i, args.output.as_deref(), many))
        .collect();

    let same = |a: &Path, b: &Path| -> bool {
        if a == b {
            return true;
        }
        match (a.canonicalize(), b.canonicalize()) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    };

    for out in &outs {
        if let Some(clash) = args.inputs.iter().find(|i| same(i, out)) {
            return Err(Error::OutputIsInput {
                path: clash.clone(),
            });
        }
    }
    for (i, a) in outs.iter().enumerate() {
        if outs[i + 1..].iter().any(|b| b == a) {
            return Err(Error::OutputCollision { path: a.clone() });
        }
    }
    Ok(outs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(a: &[&str]) -> Args {
        match parse(a.iter().map(|s| s.to_string())).unwrap() {
            Parsed::Run(args) => *args,
            _ => panic!("expected Run"),
        }
    }

    fn err(a: &[&str]) -> String {
        parse(a.iter().map(|s| s.to_string()))
            .err()
            .expect("expected an error")
            .to_string()
    }

    #[test]
    fn plain_invocation() {
        let a = run(&["book.ceb"]);
        assert_eq!(a.inputs, vec![PathBuf::from("book.ceb")]);
        assert!(a.output.is_none() && !a.no_verify && a.force_mode.is_none());
    }

    #[test]
    fn all_option_shapes() {
        for form in [
            &["-o", "out.pdf", "a.ceb"][..],
            &["-oout.pdf", "a.ceb"][..],
            &["--output", "out.pdf", "a.ceb"][..],
            &["--output=out.pdf", "a.ceb"][..],
        ] {
            let a = run(form);
            assert_eq!(a.output, Some(PathBuf::from("out.pdf")), "{form:?}");
            assert_eq!(a.inputs, vec![PathBuf::from("a.ceb")], "{form:?}");
        }
    }

    #[test]
    fn bundled_short_flags() {
        let a = run(&["-vvf", "a.ceb"]);
        assert_eq!(a.verbose, 2);
        assert!(a.force);
    }

    #[test]
    fn bundled_short_with_value() {
        let a = run(&["-vj4", "a.ceb"]);
        assert_eq!(a.verbose, 1);
        assert_eq!(a.jobs, Some(4));
    }

    #[test]
    fn multiple_inputs_and_end_of_options() {
        let a = run(&["a.ceb", "--", "-weird-name.ceb"]);
        assert_eq!(a.inputs.len(), 2);
        assert_eq!(a.inputs[1], PathBuf::from("-weird-name.ceb"));
    }

    #[test]
    fn force_mode_values() {
        assert_eq!(run(&["--force-mode=none", "a.ceb"]).force_mode, Some(None));
        assert_eq!(
            run(&["--force-mode", "cfb64", "a.ceb"]).force_mode,
            Some(Some(Mode::Cfb64))
        );
        assert_eq!(
            run(&["--force-mode", "OFB", "a.ceb"]).force_mode,
            Some(Some(Mode::Ofb))
        );
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert!(matches!(parse(["-h".to_string()]).unwrap(), Parsed::Help));
        assert!(matches!(
            parse(["--version".to_string()]).unwrap(),
            Parsed::Version
        ));
    }

    #[test]
    fn errors_are_actionable() {
        assert!(err(&[]).contains("no input files"));
        assert!(err(&["--nope", "a.ceb"]).contains("--help"));
        assert!(err(&["-z", "a.ceb"]).contains("--help"));
        assert!(err(&["-o"]).contains("needs a value"));
        assert!(err(&["--jobs", "zero", "a.ceb"]).contains("positive integer"));
        assert!(err(&["--jobs", "0", "a.ceb"]).contains("positive integer"));
        assert!(err(&["-q", "-v", "a.ceb"]).contains("cannot be combined"));
        assert!(err(&["--force-mode=cbc", "a.ceb"]).contains("`none`"));
    }

    #[test]
    fn output_paths() {
        let p = Path::new("/tmp/dir/book.ceb");
        assert_eq!(
            output_path(p, None, false),
            PathBuf::from("/tmp/dir/book.pdf")
        );
        assert_eq!(
            output_path(p, Some(Path::new("x.pdf")), false),
            PathBuf::from("x.pdf")
        );
        assert_eq!(
            output_path(p, Some(Path::new("/tmp/out")), true),
            PathBuf::from("/tmp/out/book.pdf")
        );
    }

    /// A name with several dots keeps everything but the last component.
    #[test]
    fn output_path_keeps_dotted_names() {
        assert_eq!(
            output_path(Path::new("Notice 2014.526 v2.ceb"), None, false),
            PathBuf::from("Notice 2014.526 v2.pdf")
        );
    }

    /// `ceb2pdf a.ceb b.ceb` with a shell glob must never treat `b.ceb` as the
    /// destination -- and `-o b.ceb` must be refused outright.
    #[test]
    fn refuses_to_write_over_an_input() {
        let args = Args {
            inputs: vec!["a.ceb".into()],
            output: Some("a.ceb".into()),
            ..Default::default()
        };
        match plan_outputs(&args) {
            Err(Error::OutputIsInput { .. }) => {}
            other => panic!("expected OutputIsInput, got {other:?}"),
        }
    }

    /// The accident the coordinator hit: `poc samples/*.ceb out.pdf` expanded
    /// to two inputs and ate the second file.  Here every positional is an
    /// input, so the only way to name an output is -o -- and with several
    /// inputs that has to be a directory.
    #[test]
    fn several_inputs_need_a_directory_for_output() {
        let args = Args {
            inputs: vec!["a.ceb".into(), "b.ceb".into()],
            output: Some("b.ceb".into()),
            ..Default::default()
        };
        match plan_outputs(&args) {
            Err(Error::OutputNotADirectory { inputs: 2, .. }) => {}
            other => panic!("expected OutputNotADirectory, got {other:?}"),
        }
    }

    #[test]
    fn refuses_colliding_outputs() {
        let dir = std::env::temp_dir().join("ceb2pdf-cli-test-out");
        std::fs::create_dir_all(&dir).unwrap();
        let args = Args {
            inputs: vec!["x/a.ceb".into(), "y/a.ceb".into()],
            output: Some(dir.clone()),
            ..Default::default()
        };
        let got = plan_outputs(&args);
        let _ = std::fs::remove_dir(&dir);
        match got {
            Err(Error::OutputCollision { .. }) => {}
            other => panic!("expected OutputCollision, got {other:?}"),
        }
    }

    #[test]
    fn normal_plans_are_accepted() {
        let args = Args {
            inputs: vec!["a.ceb".into(), "b.ceb".into()],
            ..Default::default()
        };
        assert_eq!(
            plan_outputs(&args).unwrap(),
            vec![PathBuf::from("a.pdf"), PathBuf::from("b.pdf")]
        );
    }
}

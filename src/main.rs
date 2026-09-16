//! `ceb2pdf` -- the command line front end.
//!
//! Batch conversion with a fixed worker pool over `std::thread::scope`; no
//! `rayon`, because a work queue of file indices is six lines and the crate is
//! not.

mod cli;

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use ceb2pdf::container::{section, Container};
use ceb2pdf::error::{Error, KeySource, Result};
use ceb2pdf::pdf::EncryptRemoval;
use ceb2pdf::{Conversion, Options, Report, StreamStrategy};

use cli::{Args, Parsed};

/// Converted, and the self-check found nothing wrong.
const EXIT_OK: i32 = 0;
/// Something failed outright.
const EXIT_FAIL: i32 = 1;
/// Output written, but the self-check has complaints.  A distinct code so a
/// script cannot mistake a partial conversion for a good one.
const EXIT_WARN: i32 = 3;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match cli::parse(argv) {
        Ok(Parsed::Help) => {
            print!("{}", cli::USAGE);
            return EXIT_OK;
        }
        Ok(Parsed::Version) => {
            println!("ceb2pdf {}", env!("CARGO_PKG_VERSION"));
            return EXIT_OK;
        }
        Ok(Parsed::Run(a)) => a,
        Err(e) => {
            eprintln!("ceb2pdf: {e}");
            return EXIT_FAIL;
        }
    };

    if args.dump_meta {
        return dump_all(&args);
    }

    let outputs = match cli::plan_outputs(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ceb2pdf: {e}");
            return EXIT_FAIL;
        }
    };

    let jobs = args
        .jobs
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
        .min(args.inputs.len())
        .max(1);

    let next = AtomicUsize::new(0);
    let worst = AtomicUsize::new(0);
    let out_lock = Mutex::new(());

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= args.inputs.len() {
                    break;
                }
                let code = convert_one(&args, &args.inputs[i], &outputs[i], &out_lock);
                worst.fetch_max(code as usize, Ordering::Relaxed);
            });
        }
    });

    worst.load(Ordering::Relaxed) as i32
}

fn convert_one(args: &Args, input: &Path, output: &Path, out_lock: &Mutex<()>) -> i32 {
    match convert_one_inner(args, input, output, out_lock) {
        Ok(code) => code,
        Err(e) => {
            let _g = out_lock.lock().unwrap_or_else(|p| p.into_inner());
            let _ = std::io::stdout().flush();
            eprintln!("ceb2pdf: {}: {e}", input.display());
            EXIT_FAIL
        }
    }
}

fn convert_one_inner(
    args: &Args,
    input: &Path,
    output: &Path,
    out_lock: &Mutex<()>,
) -> Result<i32> {
    if output.exists() && !args.force {
        return Err(Error::OutputExists {
            path: output.to_path_buf(),
        });
    }

    let raw = std::fs::read(input).map_err(|e| Error::io(input, e))?;
    let opts = Options {
        strategy: match args.force_mode {
            Some(m) => StreamStrategy::ForceMode(m),
            None => StreamStrategy::FromAlgorithmId,
        },
        verify: !args.no_verify,
    };
    let Conversion { pdf, report } = ceb2pdf::convert_with(&raw, &opts)?;

    std::fs::write(output, &pdf).map_err(|e| Error::io(output, e))?;

    let complaints = report.complaints();
    let mut text = String::new();
    if !args.quiet {
        text.push_str(&summary(input, output, raw.len(), &pdf, &report));
        if args.verbose > 0 {
            text.push_str(&detail(&report, args.verbose));
        }
    }

    let _g = out_lock.lock().unwrap_or_else(|p| p.into_inner());
    if !text.is_empty() {
        print!("{text}");
        let _ = std::io::stdout().flush();
    }
    if !complaints.is_empty() {
        eprintln!("ceb2pdf: {}: the output is INCOMPLETE:", input.display());
        for c in &complaints {
            eprintln!("  warning: {c}");
        }
        eprintln!(
            "  {} was still written so you can inspect it. Exit status {EXIT_WARN}.",
            output.display()
        );
        return Ok(EXIT_WARN);
    }
    Ok(EXIT_OK)
}

fn summary(input: &Path, output: &Path, in_len: usize, pdf: &[u8], report: &Report) -> String {
    let pages = report
        .verification
        .as_ref()
        .map(|v| {
            format!(
                ", {}/{} content streams inflate",
                v.flate_ok, v.flate_streams
            )
        })
        .unwrap_or_default();
    format!(
        "{} -> {}\n  {} -> {} B PDF, {} streams{}\n",
        input.display(),
        output.display(),
        human(in_len),
        human(pdf.len()),
        report.streams,
        pages,
    )
}

fn detail(report: &Report, verbose: u8) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "  container version : {}\n",
        report.container_version
    ));
    s.push_str(&format!(
        "  algorithm id      : {:#010x}{}\n",
        report.algorithm_id,
        if report.algorithm_id & ceb2pdf::WRAPPED_KEY_FLAG != 0 {
            " (key is RSA-wrapped)"
        } else {
            ""
        }
    ));
    s.push_str(&format!(
        "  stream cipher     : {}{}\n",
        report.strategy,
        if report.strategy_forced {
            "  [forced with --force-mode]"
        } else {
            ""
        }
    ));
    s.push_str(&format!(
        "  key               : {}\n",
        match report.key_source {
            KeySource::NotNeeded => "not needed (streams are not encrypted)".to_string(),
            KeySource::Direct => format!("{} bytes, stored directly", report.key_len),
            KeySource::RsaWrapped => format!("{} bytes, RSA-unwrapped", report.key_len),
        }
    ));
    s.push_str(&format!(
        "  /Encrypt          : {}\n",
        match report.encrypt {
            EncryptRemoval::Blanked { at, len } =>
                format!("blanked {len} bytes at offset {at} (length preserved)"),
            EncryptRemoval::Absent => "absent".into(),
            EncryptRemoval::Malformed { at } => format!("MALFORMED at offset {at}, left alone"),
        }
    ));
    s.push_str(&format!(
        "  stream payload    : {} B across {} streams\n",
        human(report.stream_bytes),
        report.streams
    ));
    if let Some(v) = &report.verification {
        s.push_str(&format!(
            "  self-check        : {}/{} /FlateDecode streams inflate ({} B recovered), \
             {} /Length mismatches\n",
            v.flate_ok,
            v.flate_streams,
            human(v.inflated_bytes),
            v.length_mismatches.len()
        ));
    }
    for n in report.notes() {
        // Wrap so a long note does not run off the terminal.
        let mut first = true;
        for line in wrap(&n, 68) {
            s.push_str(&format!(
                "  {:<18}: {line}\n",
                if first { "note" } else { "" }
            ));
            first = false;
        }
    }
    if verbose > 1 {
        s.push_str("  sections:\n");
        for sec in &report.sections {
            s.push_str(&format!(
                "    type {:3} {:<16} offset {:>9}  len {:>9}\n",
                sec.ty,
                section::name(sec.ty),
                sec.offset,
                sec.len
            ));
        }
    }
    s
}

fn dump_all(args: &Args) -> i32 {
    let mut code = EXIT_OK;
    for input in &args.inputs {
        match dump_one(input) {
            Ok(text) => print!("{text}"),
            Err(e) => {
                eprintln!("ceb2pdf: {}: {e}", input.display());
                code = EXIT_FAIL;
            }
        }
    }
    code
}

fn dump_one(input: &Path) -> Result<String> {
    let raw = std::fs::read(input).map_err(|e| Error::io(input, e))?;
    let ceb = Container::parse(&raw)?;
    let mut s = format!(
        "{}\n  file size    : {} B\n  version      : {}\n  sections     : {}\n",
        input.display(),
        human(raw.len()),
        ceb.version,
        ceb.sections.len()
    );
    for sec in &ceb.sections {
        s.push_str(&format!(
            "    type {:3} {:<16} offset {:>9}  len {:>9}\n",
            sec.ty,
            section::name(sec.ty),
            sec.offset,
            sec.len
        ));
    }
    match ceb.resolve() {
        Ok(layout) => {
            s.push_str(&format!(
                "  resolved     : body={} B, rc4_key={} B, key_blob={}, algorithm={}\n",
                layout.body.len,
                layout.rc4_key.len,
                layout
                    .key_blob
                    .map(|k| format!("{} B", k.len))
                    .unwrap_or_else(|| "absent".into()),
                layout
                    .algorithm
                    .map(|a| {
                        let b = ceb.slice(a);
                        let mut w = [0u8; 4];
                        let n = b.len().min(4);
                        w[..n].copy_from_slice(&b[..n]);
                        format!("{:#010x}", u32::from_le_bytes(w))
                    })
                    .unwrap_or_else(|| "absent (means: streams not encrypted)".into()),
            ));
            for n in layout.notes.iter().chain(ceb.notes.iter()) {
                s.push_str(&format!("  note         : {n}\n"));
            }
        }
        Err(e) => s.push_str(&format!("  resolved     : FAILED: {e}\n")),
    }
    for c in ceb.layout_complaints() {
        s.push_str(&format!("  warning      : {c}\n"));
    }
    if let Some(meta) = ceb.xml_metadata() {
        s.push_str(&format!(
            "  xml metadata : {} B, GBK-encoded (not decoded here)\n",
            meta.len()
        ));
    }
    if let Some(maker) = ceb.bytes(section::MAKER_INFO) {
        let printable: String = maker
            .iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { ' ' })
            .collect();
        s.push_str(&format!(
            "  producer     : {}\n",
            printable.split_whitespace().collect::<Vec<_>>().join(" ")
        ));
    }
    Ok(s)
}

/// Greedy word wrap for the note lines.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

/// Thousands separators, because six-digit byte counts are hard to read.
fn human(n: usize) -> String {
    let d = n.to_string();
    let mut out = String::with_capacity(d.len() + d.len() / 3);
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::human;

    #[test]
    fn wrap_breaks_on_words() {
        let w = super::wrap("one two three four five", 9);
        assert_eq!(w, vec!["one two", "three", "four five"]);
        assert!(super::wrap("", 10).is_empty());
        assert_eq!(
            super::wrap("supercalifragilistic", 5),
            vec!["supercalifragilistic"]
        );
    }

    #[test]
    fn human_groups_digits() {
        assert_eq!(human(0), "0");
        assert_eq!(human(999), "999");
        assert_eq!(human(1000), "1,000");
        assert_eq!(human(498_315), "498,315");
        assert_eq!(human(5_158_838), "5,158,838");
    }
}

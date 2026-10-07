#![allow(clippy::print_stdout, clippy::print_stderr)]
//! `aegis-bench` — measurements for QA-01/QA-05. REQ: QA-01, QA-05, T0-02, T0-04.
//!
//! `fp` scans a directory of ordinary open-source code and counts detections. Everything found
//! in such code is a false positive by construction, so the rate per 10 000 lines is the metric.

mod perf;
mod recall;
use aegis_core::detect::{DetectConfig, Dictionary, Pipeline};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Request transformation latency on a realistic long agent conversation (NFR-01..03).
    Perf {
        /// Approximate size of the conversation in KB of text (200k tokens is about 800 KB).
        #[arg(long, default_value_t = 800)]
        kb: usize,
        #[arg(long, default_value_t = 30)]
        iterations: usize,
        #[arg(long)]
        dir: PathBuf,
        /// Fail if warm p95 exceeds this many milliseconds.
        #[arg(long)]
        max_warm_p95_ms: Option<f64>,
    },
    /// Recall per type on a synthetic positive corpus.
    Recall {
        #[arg(long, default_value_t = 500)]
        n: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Fail (exit 1) if any type is below this recall (percent).
        #[arg(long)]
        min_recall: Option<f64>,
    },
    /// False positives per 10k lines on a negative corpus.
    Fp {
        #[arg(long)]
        dir: PathBuf,
        /// Comma-separated extensions to scan.
        #[arg(
            long,
            default_value = "rs,toml,md,json,yml,yaml,py,js,ts,go,java,c,h,cpp,sh,txt,cfg,ini,xml,html"
        )]
        ext: String,
        /// Samples printed per detector.
        #[arg(long, default_value_t = 5)]
        samples: usize,
        /// Fail (exit 1) if the rate per 10k lines exceeds this.
        #[arg(long)]
        max_per_10k: Option<f64>,
    },
}

fn walk(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, exts, out);
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| exts.contains(&x))
        {
            out.push(p);
        }
    }
}

fn main() {
    let (dir, ext, samples, max_per_10k) = match Cli::parse().cmd {
        Cmd::Perf {
            kb,
            iterations,
            dir,
            max_warm_p95_ms,
        } => return perf::run(kb, iterations, &dir, max_warm_p95_ms),
        Cmd::Fp {
            dir,
            ext,
            samples,
            max_per_10k,
        } => (dir, ext, samples, max_per_10k),
        Cmd::Recall {
            n,
            seed,
            min_recall,
        } => {
            let rep = recall::run(n, seed);
            let mut worst = 100.0f64;
            println!("{:<14} {:>6} {:>8}", "type", "cases", "recall");
            for (l, (total, hit)) in &rep.per_label {
                let pct = *hit as f64 * 100.0 / *total as f64;
                worst = worst.min(pct);
                println!("{l:<14} {total:>6} {pct:>7.1}%");
            }
            for (l, ms) in &rep.misses {
                println!("\nmisses {l}:");
                for m in ms {
                    println!("    {m}");
                }
            }
            if !rep.miss_ctx.is_empty() {
                println!("\nmisses by context template (label, ctx#): count");
                for ((l, c), n) in &rep.miss_ctx {
                    println!("    {l} ctx{c}: {n}");
                }
            }
            if let Some(min) = min_recall {
                if worst < min {
                    eprintln!("FAIL: lowest recall {worst:.1}% is below {min}%");
                    std::process::exit(1);
                }
            }
            return;
        }
    };
    let exts: Vec<&str> = ext.split(',').collect();
    let mut files = vec![];
    walk(&dir, &exts, &mut files);
    files.sort();
    let pipe = Pipeline::new(DetectConfig::default(), Dictionary::default());
    let (mut lines, mut bytes, mut nfiles) = (0usize, 0usize, 0usize);
    let mut by: BTreeMap<String, usize> = BTreeMap::new();
    let mut shown: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let t0 = std::time::Instant::now();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        if text.len() > 2_000_000 {
            continue; // generated data files
        }
        nfiles += 1;
        lines += text.lines().count();
        bytes += text.len();
        for e in pipe.scan(&text) {
            let key = format!("{:?}/{}", e.ty, e.detector);
            *by.entry(key.clone()).or_insert(0) += 1;
            let v = shown.entry(key).or_default();
            if v.len() < samples {
                let line_no = text[..e.span.start].matches('\n').count() + 1;
                let snippet: String = text[e.span.start..e.span.end].chars().take(60).collect();
                v.push(format!(
                    "{}:{line_no}: {}",
                    f.strip_prefix(&dir).unwrap_or(f).display(),
                    snippet.replace('\n', "\\n")
                ));
            }
        }
    }
    let total: usize = by.values().sum();
    let rate = total as f64 / (lines as f64 / 10_000.0);
    let secs = t0.elapsed().as_secs_f64();
    println!(
        "files: {nfiles}, lines: {lines}, MB: {:.1}, scan: {secs:.1}s ({:.1} MB/s)",
        bytes as f64 / 1e6,
        bytes as f64 / 1e6 / secs
    );
    println!("detections: {total}  =>  {rate:.2} per 10k lines");
    for (k, n) in &by {
        println!(
            "\n{k}: {n} ({:.2}/10k)",
            *n as f64 / (lines as f64 / 10_000.0)
        );
        for s in &shown[k] {
            println!("    {s}");
        }
    }
    if let Some(max) = max_per_10k {
        if rate > max {
            eprintln!("FAIL: {rate:.2} per 10k lines exceeds {max}");
            std::process::exit(1);
        }
    }
}

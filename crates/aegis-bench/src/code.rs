//! `aegis-bench code`: QA-10 for the fingerprint index (DET-20). REQ: QA-10, DET-20.
//!
//! One directory is taken as the closed repository and indexed. Fragments of N consecutive lines are
//! cut out of it at random (recall: they must be recognized), and the same number of fragments is cut
//! out of other directories (false matches: they must not be). The index, threshold and minimum
//! length are the ones the gateway uses by default.

use aegis_core::fingerprint::{CodeIndex, Fingerprinter, Repo};
use std::path::{Path, PathBuf};

const EXT: &[&str] = &[
    "rs", "py", "go", "java", "kt", "js", "ts", "tsx", "c", "h", "cc", "cpp", "hpp", "cs", "rb",
    "php", "swift", "scala", "sh",
];

pub struct Opts {
    pub closed: PathBuf,
    pub negatives: Vec<PathBuf>,
    pub lines: usize,
    pub samples: usize,
    pub seed: u64,
    pub threshold: f32,
    pub min_tokens: usize,
    pub min_recall: Option<f64>,
    pub max_false: Option<f64>,
    /// Print this many false matches (file and share).
    pub show: usize,
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut e: Vec<_> = rd.flatten().collect();
    e.sort_by_key(|x| x.file_name());
    for e in e {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            if ![".git", "target", "node_modules", "vendor"]
                .iter()
                .any(|s| name == *s)
            {
                walk(&p, out);
            }
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| EXT.contains(&x))
        {
            out.push(p);
        }
    }
}

fn files_of(dirs: &[PathBuf]) -> Vec<(PathBuf, Vec<String>)> {
    let mut paths = vec![];
    for d in dirs {
        walk(d, &mut paths);
    }
    paths
        .into_iter()
        .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.len() < 2 << 20))
        .filter_map(|p| {
            let text = std::fs::read_to_string(&p).ok()?;
            Some((p, text.lines().map(String::from).collect()))
        })
        .collect()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// `samples` fragments of `lines` consecutive lines, spread over the files in proportion to how many
/// such fragments each file can give.
fn fragments(
    files: &[(PathBuf, Vec<String>)],
    lines: usize,
    samples: usize,
    rng: &mut Rng,
) -> Vec<(String, String)> {
    let weights: Vec<usize> = files
        .iter()
        .map(|(_, l)| (l.len() + 1).saturating_sub(lines))
        .collect();
    let total: usize = weights.iter().sum();
    if total == 0 {
        return vec![];
    }
    (0..samples)
        .map(|_| {
            let mut pick = rng.below(total);
            let i = weights.iter().position(|w| {
                if pick < *w {
                    true
                } else {
                    pick -= *w;
                    false
                }
            });
            let (path, l) = &files[i.unwrap_or(0)];
            let start = pick.min(l.len().saturating_sub(lines));
            (
                format!("{}:{}", path.display(), start + 1),
                l[start..start + lines].join("\n"),
            )
        })
        .collect()
}

/// `clap_builder-4.6.0` -> `clap_builder`: another version of the same crate is the same code, not a
/// foreign one.
fn stem(p: &Path) -> String {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match name.rfind('-') {
        Some(i) if name[i + 1..].starts_with(|c: char| c.is_ascii_digit()) => name[..i].to_string(),
        _ => name.to_string(),
    }
}

pub fn run(mut o: Opts) -> bool {
    let own = stem(&o.closed);
    let before = o.negatives.len();
    o.negatives.retain(|d| stem(d) != own);
    if o.negatives.len() != before {
        println!(
            "left out {} other version(s) of {own} from the negative corpus",
            before - o.negatives.len()
        );
    }
    let key = Fingerprinter::new(b"aegis-bench-code-index-key");
    let closed = files_of(std::slice::from_ref(&o.closed));
    let negative = files_of(&o.negatives);
    let mut ix = CodeIndex::new(&key);
    let mut all = std::collections::BTreeSet::new();
    let mut tokens = 0usize;
    for (_, lines) in &closed {
        let (set, n) = key.of(&lines.join("\n"));
        tokens += n;
        all.extend(set);
    }
    let fingerprints = all.len();
    let _ = ix.set_repo(
        Repo {
            name: "closed".into(),
            classification: "closed".into(),
        },
        all,
    );
    println!(
        "indexed {}: {} files, {tokens} tokens, {fingerprints} fingerprints; negative corpus: {} files",
        o.closed.display(),
        closed.len(),
        negative.len()
    );
    println!(
        "fragments of {} lines, threshold {}, minimum {} tokens\n",
        o.lines, o.threshold, o.min_tokens
    );

    let mut rng = Rng(o.seed | 1);
    let positive = fragments(&closed, o.lines, o.samples, &mut rng);
    let others = fragments(&negative, o.lines, o.samples, &mut rng);
    if positive.is_empty() || others.is_empty() {
        println!("not enough files with {} lines", o.lines);
        return false;
    }

    let (mut hit, mut too_short, mut weak) = (0usize, 0usize, 0usize);
    let mut shares = vec![];
    for (origin, f) in &positive {
        let (_, n, words) = key.of_with_words(f);
        match ix.lookup(&key, f, o.threshold, o.min_tokens) {
            Some(m) => {
                hit += 1;
                shares.push(m.share);
            }
            None if n < o.min_tokens || words < aegis_core::fingerprint::MIN_WORDS => {
                too_short += 1
            }
            None => {
                weak += 1;
                if weak <= o.show {
                    let best = ix.lookup(&key, f, 0.0, 0).map_or(0.0, |m| m.share);
                    println!("  missed {origin} share {:.0} %", best * 100.0);
                }
            }
        }
    }
    let judgeable = positive.len() - too_short;
    let recall = 100.0 * hit as f64 / positive.len() as f64;
    let recall_judgeable = 100.0 * hit as f64 / judgeable.max(1) as f64;
    let mut false_matches = 0usize;
    for (origin, f) in &others {
        if let Some(m) = ix.lookup(&key, f, o.threshold, o.min_tokens) {
            false_matches += 1;
            if false_matches <= o.show {
                println!("  false match {origin} share {:.0} %", m.share * 100.0);
            }
        }
    }
    let false_pct = 100.0 * false_matches as f64 / others.len() as f64;
    shares.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    println!("recall (fragments of the closed repository)");
    println!(
        "  recognized            {hit} of {} = {recall:.1} %",
        positive.len()
    );
    println!("  not judged            {too_short} (fewer than {} tokens or {} identifiers in {} lines: comments, tables)", o.min_tokens, aegis_core::fingerprint::MIN_WORDS, o.lines);
    println!("  below the threshold   {weak}");
    println!("  recall of judgeable   {recall_judgeable:.1} %");
    if let Some(m) = shares.get(shares.len() / 20) {
        println!(
            "  share of fingerprints found, 5th percentile of the recognized: {:.0} %",
            m * 100.0
        );
    }
    println!("false matches (fragments of other code)");
    println!(
        "  matched               {false_matches} of {} = {false_pct:.2} %",
        others.len()
    );

    let mut ok = true;
    if let Some(min) = o.min_recall {
        if recall_judgeable < min {
            println!("\nFAIL: recall of judgeable fragments {recall_judgeable:.1} % < {min} %");
            ok = false;
        }
    }
    if let Some(max) = o.max_false {
        if false_pct > max {
            println!("\nFAIL: false matches {false_pct:.2} % > {max} %");
            ok = false;
        }
    }
    ok
}

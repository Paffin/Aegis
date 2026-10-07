//! REQ: DET-20, DET-21 — fingerprints of closed source code (winnowing over normalized tokens).
//!
//! A code block that the model should not see is recognized by what it is made of, not by what
//! it says: the text is cut into tokens (comments and spacing gone, string and number contents
//! gone, identifiers kept), tokens are grouped into overlapping runs of `K`, each run is hashed,
//! and from every window of `W` hashes the smallest is kept (winnowing, Schleimer et al.). Two
//! texts that share a stretch of at least `W + K - 1` tokens share a fingerprint, whatever else
//! changed. The index stores the fingerprints, keyed with HMAC so that it is not a dictionary of
//! guessable token runs, and the names of the repositories: no code.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{BTreeSet, HashMap};

/// Tokens in one hashed run.
pub const K: usize = 5;
/// Hashes in one window.
pub const W: usize = 4;

/// Normalized tokens of source code in any C-like, Python-like or Go-like language.
pub fn tokens(text: &str) -> Vec<String> {
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        let next = c.get(i + 1).copied();
        if ch.is_whitespace() {
            i += 1;
        } else if ch == '/' && next == Some('/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if ch == '/' && next == Some('*') {
            i += 2;
            while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if ch == '#' && next.is_none_or(|n| n.is_whitespace()) {
            // a Python, shell or YAML comment; `#include`, `#[derive]`, `#!` stay
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if ch == '"' || ch == '\'' || ch == '`' {
            let triple = c.get(i..i + 3).is_some_and(|t| t.iter().all(|x| *x == ch));
            let q = if triple { 3 } else { 1 };
            i += q;
            while i < c.len() {
                if c[i] == '\\' && ch != '`' {
                    i += 2;
                    continue;
                }
                if c[i] == ch
                    && (q == 1 || c.get(i..i + 3).is_some_and(|t| t.iter().all(|x| *x == ch)))
                {
                    i += q;
                    break;
                }
                // a quote that is not closed on its line is an apostrophe or a lifetime, not a string
                if q == 1 && c[i] == '\n' && ch != '`' {
                    break;
                }
                i += 1;
            }
            out.push("\u{1}S".to_string());
        } else if ch.is_ascii_digit() {
            while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_' || c[i] == '.') {
                i += 1;
            }
            out.push("\u{1}N".to_string());
        } else if ch.is_alphabetic() || ch == '_' || ch == '$' {
            let s = i;
            while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_' || c[i] == '$') {
                i += 1;
            }
            out.push(c[s..i].iter().collect());
        } else {
            out.push(ch.to_string());
            i += 1;
        }
    }
    out
}

fn fnv(bytes: &[u8], mut h: u64) -> u64 {
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Keys the fingerprints of one deployment.
pub struct Fingerprinter {
    key: [u8; 32],
}

impl Fingerprinter {
    /// `secret` is the tenant key; the index key is derived from it, so an index is useless
    /// without it and a leaked index does not leak the tenant key.
    pub fn new(secret: &[u8]) -> Self {
        let mut m = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
        m.update(b"aegis-code-index-v1");
        Self {
            key: m.finalize().into_bytes().into(),
        }
    }

    /// A value stored in the index file to tell a wrong key from a corrupt file.
    pub fn check(&self) -> [u8; 8] {
        let h = self.keyed(b"check");
        h.to_le_bytes()
    }

    fn keyed(&self, data: &[u8]) -> u64 {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes any key length");
        m.update(data);
        let d = m.finalize().into_bytes();
        u64::from_le_bytes(d[..8].try_into().expect("8 bytes"))
    }

    /// Winnowed fingerprints of a text (a set: each appears once) and the number of tokens.
    pub fn of(&self, text: &str) -> (BTreeSet<u64>, usize) {
        let toks = tokens(text);
        let n = toks.len();
        if n < K {
            return (BTreeSet::new(), n);
        }
        let th: Vec<u64> = toks
            .iter()
            .map(|t| fnv(t.as_bytes(), 0xcbf29ce484222325))
            .collect();
        let grams: Vec<u64> = th
            .windows(K)
            .map(|g| {
                g.iter()
                    .fold(0xcbf29ce484222325u64, |h, x| fnv(&x.to_le_bytes(), h))
            })
            .collect();
        let mut chosen: BTreeSet<usize> = BTreeSet::new();
        if grams.len() <= W {
            if let Some((i, _)) = grams
                .iter()
                .enumerate()
                .min_by_key(|(i, h)| (**h, std::cmp::Reverse(*i)))
            {
                chosen.insert(i);
            }
        } else {
            for win in 0..=grams.len() - W {
                // the rightmost smallest hash of the window
                let (off, _) = grams[win..win + W]
                    .iter()
                    .enumerate()
                    .min_by_key(|(i, h)| (**h, std::cmp::Reverse(*i)))
                    .expect("window is not empty");
                chosen.insert(win + off);
            }
        }
        let fps = chosen
            .into_iter()
            .map(|i| self.keyed(&grams[i].to_le_bytes()))
            .collect();
        (fps, n)
    }
}

/// The result of looking a block up.
#[derive(Debug, Clone, PartialEq)]
pub struct CodeMatch {
    pub repo: String,
    pub classification: String,
    /// Share of the block's fingerprints found in that repository, 0..=1.
    pub share: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Repo {
    pub name: String,
    pub classification: String,
}

/// Fingerprints of closed repositories. Lookups binary-search a sorted table.
#[derive(Debug, Default)]
pub struct CodeIndex {
    check: [u8; 8],
    repos: Vec<Repo>,
    /// (fingerprint, repository), sorted.
    table: Vec<(u64, u16)>,
}

#[derive(Debug)]
pub enum IndexError {
    Format,
    Key,
    TooManyRepos,
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            IndexError::Format => "файл индекса повреждён или не является индексом Aegis",
            IndexError::Key => "индекс построен с другим ключом",
            IndexError::TooManyRepos => "в индексе слишком много репозиториев",
        })
    }
}

const MAGIC: &[u8; 9] = b"AEGISIDX1";

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], IndexError> {
        let s = self
            .b
            .get(self.p..self.p.checked_add(n).ok_or(IndexError::Format)?)
            .ok_or(IndexError::Format)?;
        self.p += n;
        Ok(s)
    }
    fn left(&self) -> usize {
        self.b.len() - self.p
    }
}

impl CodeIndex {
    pub fn new(fp: &Fingerprinter) -> Self {
        Self {
            check: fp.check(),
            repos: vec![],
            table: vec![],
        }
    }

    pub fn repos(&self) -> &[Repo] {
        &self.repos
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Add or replace a repository (DET-21: a rebuilt repository replaces its old fingerprints).
    pub fn set_repo(&mut self, repo: Repo, fingerprints: BTreeSet<u64>) -> Result<(), IndexError> {
        let idx = match self.repos.iter().position(|r| r.name == repo.name) {
            Some(i) => {
                self.repos[i] = repo;
                self.table.retain(|(_, r)| *r as usize != i);
                i
            }
            None => {
                if self.repos.len() >= u16::MAX as usize {
                    return Err(IndexError::TooManyRepos);
                }
                self.repos.push(repo);
                self.repos.len() - 1
            }
        };
        self.table
            .extend(fingerprints.into_iter().map(|h| (h, idx as u16)));
        self.table.sort_unstable();
        self.table.dedup();
        Ok(())
    }

    /// The repository that best matches a block, if its share reaches `threshold`. Blocks shorter
    /// than `min_tokens` are not judged: a few lines of any code look like a few lines of other code.
    pub fn lookup(
        &self,
        fp: &Fingerprinter,
        text: &str,
        threshold: f32,
        min_tokens: usize,
    ) -> Option<CodeMatch> {
        let (set, n) = fp.of(text);
        if n < min_tokens || set.is_empty() {
            return None;
        }
        let mut hits: HashMap<u16, usize> = HashMap::new();
        for h in &set {
            let start = self.table.partition_point(|(x, _)| x < h);
            for (x, r) in &self.table[start..] {
                if x != h {
                    break;
                }
                *hits.entry(*r).or_default() += 1;
            }
        }
        let (r, count) = hits
            .into_iter()
            .max_by_key(|(r, c)| (*c, std::cmp::Reverse(*r)))?;
        let share = count as f32 / set.len() as f32;
        (share >= threshold).then(|| {
            let repo = &self.repos[r as usize];
            CodeMatch {
                repo: repo.name.clone(),
                classification: repo.classification.clone(),
                share,
            }
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.table.len() * 10);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.check);
        out.extend_from_slice(&(self.repos.len() as u32).to_le_bytes());
        for r in &self.repos {
            for s in [&r.name, &r.classification] {
                out.extend_from_slice(&(s.len() as u16).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
        }
        out.extend_from_slice(&(self.table.len() as u64).to_le_bytes());
        for (h, r) in &self.table {
            out.extend_from_slice(&h.to_le_bytes());
            out.extend_from_slice(&r.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(b: &[u8], fp: &Fingerprinter) -> Result<Self, IndexError> {
        let mut rd = Reader { b, p: 0 };
        let mut take = |n: usize| rd.take(n);
        if take(9)? != MAGIC {
            return Err(IndexError::Format);
        }
        let check: [u8; 8] = take(8)?.try_into().map_err(|_| IndexError::Format)?;
        if check != fp.check() {
            return Err(IndexError::Key);
        }
        let n_repos =
            u32::from_le_bytes(take(4)?.try_into().map_err(|_| IndexError::Format)?) as usize;
        if n_repos > u16::MAX as usize {
            return Err(IndexError::Format);
        }
        let mut repos = Vec::with_capacity(n_repos);
        for _ in 0..n_repos {
            let mut s = [String::new(), String::new()];
            for slot in &mut s {
                let len = u16::from_le_bytes(take(2)?.try_into().map_err(|_| IndexError::Format)?)
                    as usize;
                *slot = String::from_utf8(take(len)?.to_vec()).map_err(|_| IndexError::Format)?;
            }
            let [name, classification] = s;
            repos.push(Repo {
                name,
                classification,
            });
        }
        let n = u64::from_le_bytes(take(8)?.try_into().map_err(|_| IndexError::Format)?) as usize;
        if rd.left() != n.checked_mul(10).ok_or(IndexError::Format)? {
            return Err(IndexError::Format);
        }
        let mut table = Vec::with_capacity(n);
        for _ in 0..n {
            let h = u64::from_le_bytes(rd.take(8)?.try_into().map_err(|_| IndexError::Format)?);
            let r = u16::from_le_bytes(rd.take(2)?.try_into().map_err(|_| IndexError::Format)?);
            if r as usize >= repos.len() {
                return Err(IndexError::Format);
            }
            table.push((h, r));
        }
        if !table.windows(2).all(|w| w[0] <= w[1]) {
            return Err(IndexError::Format);
        }
        Ok(Self {
            check,
            repos,
            table,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = r#"
// Payment service: closed source
package payments

import "fmt"

type Ledger struct { entries []Entry; limit int64 }

func (l *Ledger) Post(e Entry) error {
    if e.Amount > l.limit {
        return fmt.Errorf("limit exceeded: %d", e.Amount) // hard stop
    }
    for _, old := range l.entries {
        if old.ID == e.ID {
            return ErrDuplicate
        }
    }
    l.entries = append(l.entries, e)
    return nil
}

func (l *Ledger) Balance(account string) int64 {
    var total int64 = 0
    for _, e := range l.entries {
        if e.Account == account {
            total += e.Amount
        }
    }
    return total
}
"#;

    const OTHER: &str = r#"
use std::collections::HashMap;

pub struct Cache<K, V> { map: HashMap<K, V>, cap: usize }

impl<K: std::hash::Hash + Eq, V> Cache<K, V> {
    pub fn new(cap: usize) -> Self { Self { map: HashMap::new(), cap } }
    pub fn put(&mut self, k: K, v: V) -> Option<V> {
        if self.map.len() >= self.cap { return None; }
        self.map.insert(k, v)
    }
    pub fn get(&self, k: &K) -> Option<&V> { self.map.get(k) }
}
"#;

    fn index() -> (Fingerprinter, CodeIndex) {
        let fp = Fingerprinter::new(b"tenant-secret-key");
        let mut ix = CodeIndex::new(&fp);
        ix.set_repo(
            Repo {
                name: "payments".into(),
                classification: "closed".into(),
            },
            fp.of(CODE).0,
        )
        .unwrap();
        (fp, ix)
    }

    // REQ: DET-20
    #[test]
    fn tokens_drop_comments_and_literal_contents() {
        let t = tokens("x := 42 // note\n/* block */ s = \"a b\" # py\ny = 'q' #[derive]");
        assert_eq!(
            t,
            [
                "x", ":", "=", "\u{1}N", "s", "=", "\u{1}S", "y", "=", "\u{1}S", "#", "[",
                "derive", "]"
            ]
        );
        // a lone apostrophe does not swallow the file
        assert!(tokens("fn f<'a>(x: &'a str) {\n let y = 1;\n}\n").contains(&"y".to_string()));
    }

    // REQ: DET-20
    #[test]
    fn the_same_code_is_found_through_edits_that_do_not_change_it() {
        let (fp, ix) = index();
        let m = ix.lookup(&fp, CODE, 0.5, 30).unwrap();
        assert_eq!(
            (m.repo.as_str(), m.classification.as_str()),
            ("payments", "closed")
        );
        assert!(m.share > 0.99);
        // other spacing, other comments, other numbers and strings
        let tweaked = CODE
            .replace("// hard stop", "/* never exceed */")
            .replace("limit exceeded: %d", "over the limit %d")
            .replace("    ", "\t")
            .replace("= 0\n", "= 0 \n\n");
        assert!(ix.lookup(&fp, &tweaked, 0.5, 30).unwrap().share > 0.9);
        // a pasted part of it (the Balance function) is still found
        let part = &CODE[CODE.find("func (l *Ledger) Balance").unwrap()..];
        assert!(ix.lookup(&fp, part, 0.5, 30).unwrap().share > 0.9);
    }

    // REQ: DET-20
    #[test]
    fn other_code_and_short_pieces_are_not_found() {
        let (fp, ix) = index();
        assert!(ix.lookup(&fp, OTHER, 0.3, 30).is_none());
        assert!(ix
            .lookup(
                &fp,
                "plain prose about nothing in particular, no code at all here",
                0.1,
                5
            )
            .is_none());
        // too short to judge, even though it is a verbatim line of the repository
        assert!(ix.lookup(&fp, "return ErrDuplicate", 0.5, 30).is_none());
        // renaming identifiers lowers the share (what the index sees is the token sequence);
        // a deliberate rewrite of the names is outside what it can recognize
        let renamed = CODE
            .replace("Ledger", "Book")
            .replace("Entry", "Row")
            .replace("entries", "rows")
            .replace("Amount", "Sum");
        let share = ix.lookup(&fp, &renamed, 0.0, 30).map_or(0.0, |m| m.share);
        assert!(share < 0.8, "{share}");
    }

    // REQ: DET-21
    #[test]
    fn a_repository_is_replaced_not_added_twice() {
        let (fp, mut ix) = index();
        let before = ix.len();
        ix.set_repo(
            Repo {
                name: "payments".into(),
                classification: "secret".into(),
            },
            fp.of(CODE).0,
        )
        .unwrap();
        assert_eq!(ix.len(), before);
        assert_eq!(ix.repos().len(), 1);
        assert_eq!(
            ix.lookup(&fp, CODE, 0.5, 30).unwrap().classification,
            "secret"
        );
        ix.set_repo(
            Repo {
                name: "cache".into(),
                classification: "closed".into(),
            },
            fp.of(OTHER).0,
        )
        .unwrap();
        assert_eq!(ix.lookup(&fp, OTHER, 0.5, 30).unwrap().repo, "cache");
        assert_eq!(ix.lookup(&fp, CODE, 0.5, 30).unwrap().repo, "payments");
    }

    // REQ: DET-20
    #[test]
    fn the_file_round_trips_and_refuses_the_wrong_key_and_damage() {
        let (fp, ix) = index();
        let bytes = ix.to_bytes();
        let back = CodeIndex::from_bytes(&bytes, &fp).unwrap();
        assert_eq!(back.len(), ix.len());
        assert!(back.lookup(&fp, CODE, 0.5, 30).is_some());
        assert!(matches!(
            CodeIndex::from_bytes(&bytes, &Fingerprinter::new(b"another key")),
            Err(IndexError::Key)
        ));
        assert!(CodeIndex::from_bytes(&bytes[..bytes.len() - 3], &fp).is_err());
        assert!(CodeIndex::from_bytes(b"not an index", &fp).is_err());
        for cut in [0, 5, 12, 40] {
            let mut b = bytes.clone();
            b.truncate(cut.min(b.len()));
            assert!(CodeIndex::from_bytes(&b, &fp).is_err());
        }
        // the fingerprints say nothing about the code: no identifier is in the file
        assert!(!bytes.windows(6).any(|w| w == b"Ledger" || w == b"Balanc"));
    }
}

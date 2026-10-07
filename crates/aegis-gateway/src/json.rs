//! REQ: PRO-04, IR-04, NFR-07 — span-aware JSON.
//!
//! The request body is parsed once into a tree that remembers the byte range of
//! every node. Edits are spliced into the original bytes, so key order, number
//! formatting, whitespace and every untouched string stay byte-identical.

use std::ops::Range;

pub const MAX_DEPTH: usize = 128;

#[derive(Debug)]
pub enum JsonError {
    Syntax(usize),
    TooDeep,
    /// The same key twice in one object: parsers disagree about which one wins, so the body
    /// could show different content to the scanner and to the provider.
    DuplicateKey,
    /// A string that a strict decoder rejects (lone surrogate, bad escape, invalid UTF-8).
    BadString,
}

impl JsonError {
    /// Value-free message for the client.
    pub fn message(&self) -> &'static str {
        match self {
            JsonError::Syntax(_) => "тело запроса не является корректным JSON",
            JsonError::TooDeep => "JSON глубже 128 уровней",
            JsonError::DuplicateKey => "JSON содержит повторяющийся ключ в одном объекте",
            JsonError::BadString => "JSON содержит строку, которую нельзя однозначно декодировать",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Node {
    Obj {
        span: Range<usize>,
        members: Vec<Member>,
    },
    Arr {
        span: Range<usize>,
        items: Vec<Node>,
    },
    /// String literal; the span includes the quotes.
    Str { span: Range<usize> },
    /// Number, `true`, `false`, `null`.
    Lit { span: Range<usize> },
}

#[derive(Debug, Clone)]
pub struct Member {
    pub key: String,
    pub value: Node,
}

impl Node {
    pub fn span(&self) -> Range<usize> {
        match self {
            Node::Obj { span, .. }
            | Node::Arr { span, .. }
            | Node::Str { span }
            | Node::Lit { span } => span.clone(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Obj { members, .. } => members.iter().find(|m| m.key == key).map(|m| &m.value),
            _ => None,
        }
    }

    pub fn items(&self) -> &[Node] {
        match self {
            Node::Arr { items, .. } => items,
            _ => &[],
        }
    }

    pub fn string(&self, src: &[u8]) -> Option<String> {
        match self {
            Node::Str { span } => serde_json::from_slice::<String>(&src[span.clone()]).ok(),
            _ => None,
        }
    }

    pub fn str_at(&self, key: &str, src: &[u8]) -> Option<String> {
        self.get(key)?.string(src)
    }

    pub fn raw<'a>(&self, src: &'a [u8]) -> &'a [u8] {
        &src[self.span()]
    }

    /// All string leaves below this node with their literal spans.
    pub fn string_leaves<'a>(&'a self, out: &mut Vec<&'a Node>) {
        match self {
            Node::Str { .. } => out.push(self),
            Node::Obj { members, .. } => members.iter().for_each(|m| m.value.string_leaves(out)),
            Node::Arr { items, .. } => items.iter().for_each(|i| i.string_leaves(out)),
            Node::Lit { .. } => {}
        }
    }
}

pub fn parse(src: &[u8]) -> Result<Node, JsonError> {
    let mut p = Parser { src, pos: 0 };
    p.ws();
    let n = p.value(0)?;
    p.ws();
    if p.pos != src.len() {
        return Err(JsonError::Syntax(p.pos));
    }
    Ok(n)
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.pos < self.src.len()
            && matches!(self.src[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn err<T>(&self) -> Result<T, JsonError> {
        Err(JsonError::Syntax(self.pos))
    }

    fn string_span(&mut self) -> Result<Range<usize>, JsonError> {
        let start = self.pos;
        if self.src.get(self.pos) != Some(&b'"') {
            return self.err();
        }
        self.pos += 1;
        while let Some(&c) = self.src.get(self.pos) {
            match c {
                b'"' => {
                    self.pos += 1;
                    let lit = &self.src[start..self.pos];
                    // pure ASCII without escapes needs no decoding; everything else must decode strictly
                    if (lit.iter().any(|b| *b == b'\\' || *b >= 0x80))
                        && serde_json::from_slice::<String>(lit).is_err()
                    {
                        return Err(JsonError::BadString);
                    }
                    return Ok(start..self.pos);
                }
                b'\\' => self.pos += 2,
                0..=0x1f => return self.err(),
                _ => self.pos += 1,
            }
        }
        self.err()
    }

    fn value(&mut self, depth: usize) -> Result<Node, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        match self.src.get(self.pos) {
            Some(b'{') => {
                let start = self.pos;
                self.pos += 1;
                let mut members = vec![];
                let mut seen: Option<std::collections::HashSet<String>> = None;
                self.ws();
                if self.src.get(self.pos) == Some(&b'}') {
                    self.pos += 1;
                    return Ok(Node::Obj {
                        span: start..self.pos,
                        members,
                    });
                }
                loop {
                    self.ws();
                    let ks = self.string_span()?;
                    let key = serde_json::from_slice::<String>(&self.src[ks])
                        .map_err(|_| JsonError::Syntax(self.pos))?;
                    self.ws();
                    if self.src.get(self.pos) != Some(&b':') {
                        return self.err();
                    }
                    self.pos += 1;
                    self.ws();
                    let value = self.value(depth + 1)?;
                    // linear scan for small objects, a set once the object grows (no quadratic blow-up)
                    let dup = if members.len() < 16 {
                        members.iter().any(|m: &Member| m.key == key)
                    } else {
                        let set = seen.get_or_insert_with(|| {
                            members
                                .iter()
                                .map(|m: &Member| m.key.clone())
                                .collect::<std::collections::HashSet<String>>()
                        });
                        !set.insert(key.clone())
                    };
                    if dup {
                        return Err(JsonError::DuplicateKey);
                    }
                    members.push(Member { key, value });
                    self.ws();
                    match self.src.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Node::Obj {
                                span: start..self.pos,
                                members,
                            });
                        }
                        _ => return self.err(),
                    }
                }
            }
            Some(b'[') => {
                let start = self.pos;
                self.pos += 1;
                let mut items = vec![];
                self.ws();
                if self.src.get(self.pos) == Some(&b']') {
                    self.pos += 1;
                    return Ok(Node::Arr {
                        span: start..self.pos,
                        items,
                    });
                }
                loop {
                    self.ws();
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.src.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Node::Arr {
                                span: start..self.pos,
                                items,
                            });
                        }
                        _ => return self.err(),
                    }
                }
            }
            Some(b'"') => Ok(Node::Str {
                span: self.string_span()?,
            }),
            Some(_) => {
                let start = self.pos;
                while self.pos < self.src.len()
                    && !matches!(
                        self.src[self.pos],
                        b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r'
                    )
                {
                    self.pos += 1;
                }
                if start == self.pos || !valid_literal(&self.src[start..self.pos]) {
                    self.pos = start;
                    return self.err();
                }
                Ok(Node::Lit {
                    span: start..self.pos,
                })
            }
            None => self.err(),
        }
    }
}

/// `true`, `false`, `null` or a number in JSON grammar; nothing else (no `01`, `1.`, `+1`, `NaN`).
fn valid_literal(l: &[u8]) -> bool {
    if matches!(l, b"true" | b"false" | b"null") {
        return true;
    }
    let mut i = 0;
    if l.get(i) == Some(&b'-') {
        i += 1;
    }
    match l.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while l.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return false,
    }
    if l.get(i) == Some(&b'.') {
        i += 1;
        let d = i;
        while l.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == d {
            return false;
        }
    }
    if matches!(l.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(l.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let d = i;
        while l.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == d {
            return false;
        }
    }
    i == l.len()
}

/// Byte-range replacements applied to the original body.
#[derive(Default, Debug)]
pub struct Edits {
    list: Vec<(Range<usize>, Vec<u8>)>,
}

impl Edits {
    pub fn replace(&mut self, range: Range<usize>, with: Vec<u8>) {
        self.list.push((range, with));
    }

    /// Replace a string literal with a new (unescaped) text.
    pub fn replace_string(&mut self, node: &Node, text: &str) {
        let lit = serde_json::to_vec(text).unwrap_or_default();
        self.replace(node.span(), lit);
    }

    pub fn insert(&mut self, at: usize, bytes: Vec<u8>) {
        self.list.push((at..at, bytes));
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Start offsets of the replaced ranges.
    pub fn starts(&self) -> impl Iterator<Item = usize> + '_ {
        self.list.iter().map(|(r, _)| r.start)
    }

    pub fn apply(mut self, src: &[u8]) -> Vec<u8> {
        self.list.sort_by_key(|(r, _)| (r.start, r.end));
        let mut out = Vec::with_capacity(src.len() + 256);
        let mut cur = 0;
        for (r, with) in self.list {
            debug_assert!(r.start >= cur, "overlapping edits");
            out.extend_from_slice(&src[cur..r.start]);
            out.extend_from_slice(&with);
            cur = r.end;
        }
        out.extend_from_slice(&src[cur..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "{ \"b\" : 1.50e3 ,\n \"a\":[\"x\\u00e9\\/y\", {\"k\":\"v\"}, null, true, 12345678901234567890],\"s\":\"h\\\"i\" }";

    // REQ: PRO-04
    #[test]
    fn untouched_edit_is_byte_identical() {
        let n = parse(SAMPLE.as_bytes()).unwrap();
        assert!(matches!(n, Node::Obj { .. }));
        assert_eq!(Edits::default().apply(SAMPLE.as_bytes()), SAMPLE.as_bytes());
    }

    // REQ: PRO-04, IR-04 — only the edited literal changes.
    #[test]
    fn splice_changes_only_target() {
        let src = SAMPLE.as_bytes();
        let n = parse(src).unwrap();
        let leaf = &n.get("a").unwrap().items()[0];
        assert_eq!(leaf.string(src).unwrap(), "xé/y");
        let mut e = Edits::default();
        e.replace_string(leaf, "NEW");
        let out = String::from_utf8(e.apply(src)).unwrap();
        assert_eq!(out, SAMPLE.replace("\"x\\u00e9\\/y\"", "\"NEW\""));
    }

    #[test]
    fn decodes_values_and_leaves() {
        let src = SAMPLE.as_bytes();
        let n = parse(src).unwrap();
        assert_eq!(n.str_at("s", src).unwrap(), "h\"i");
        let mut leaves = vec![];
        n.string_leaves(&mut leaves);
        assert_eq!(leaves.len(), 3);
    }

    // REQ: NFR-07
    #[test]
    fn depth_limit() {
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        assert!(matches!(parse(deep.as_bytes()), Err(JsonError::TooDeep)));
        let ok = format!("{}1{}", "[".repeat(100), "]".repeat(100));
        assert!(parse(ok.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "{",
            "{\"a\"}",
            "[1,]",
            "{\"a\":1} x",
            "\"abc",
            "{\"a\":\"\n\"}",
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    // REQ: SEC-10, NFR-07 — duplicate detection must not be a way to stall the gateway.
    #[test]
    fn huge_objects_parse_fast_and_duplicates_are_still_found() {
        let n = 200_000;
        let body = format!(
            "{{{}}}",
            (0..n)
                .map(|i| format!("\"k{i}\":1"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let t = std::time::Instant::now();
        assert!(parse(body.as_bytes()).is_ok());
        assert!(t.elapsed().as_secs_f64() < 2.0, "{:?}", t.elapsed());
        let dup = format!(
            "{{{},\"k150000\":2}}",
            (0..n)
                .map(|i| format!("\"k{i}\":1"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(matches!(
            parse(dup.as_bytes()),
            Err(JsonError::DuplicateKey)
        ));
    }

    // REQ: SEC-10 — the same objects at different nesting levels are not duplicates.
    #[test]
    fn same_key_in_different_objects_is_fine() {
        assert!(parse(br#"{"a":{"a":1},"b":[{"a":1},{"a":2}]}"#).is_ok());
        assert!(matches!(
            parse(br#"{"a":1,"b":{},"a":2}"#),
            Err(JsonError::DuplicateKey)
        ));
        // escaped and plain spellings of one key are the same key
        assert!(matches!(
            parse(br#"{"a":1,"\u0061":2}"#),
            Err(JsonError::DuplicateKey)
        ));
    }

    #[test]
    fn insert_at_position() {
        let src = b"{\"a\":1}";
        let mut e = Edits::default();
        e.insert(1, b"\"z\":0,".to_vec());
        assert_eq!(e.apply(src), b"{\"z\":0,\"a\":1}");
    }
}

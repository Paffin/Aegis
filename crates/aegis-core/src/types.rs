use std::fmt;

/// Half-open byte range `[start, end)` in the scanned text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }
    pub fn overlaps(&self, o: &Span) -> bool {
        self.start < o.end && o.start < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    Secret,
    Infra,
    Pii,
    Corp,
    /// Strings in the input that look like Aegis pseudonyms (PSE-11).
    Lit,
}

impl Class {
    pub fn as_str(&self) -> &'static str {
        match self {
            Class::Secret => "SECRET",
            Class::Infra => "INFRA",
            Class::Pii => "PII",
            Class::Corp => "CORP",
            Class::Lit => "LIT",
        }
    }
}

/// Catalogue of DET-04 types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityType {
    Secret,
    Ip,
    Host,
    Url,
    Db,
    Svc,
    Email,
    Phone,
    Passport,
    Snils,
    Inn,
    Card,
    Acct,
    Person,
    Project,
    System,
    Org,
    Lit,
}

impl EntityType {
    pub fn class(&self) -> Class {
        use EntityType::*;
        match self {
            Secret => Class::Secret,
            Ip | Host | Url | Db | Svc => Class::Infra,
            Email | Phone | Passport | Snils | Inn | Card | Acct | Person => Class::Pii,
            Project | System | Org => Class::Corp,
            Lit => Class::Lit,
        }
    }

    /// Marker type name; letters only, at most 10 (PSE-05).
    pub fn marker(&self) -> &'static str {
        use EntityType::*;
        match self {
            Secret => "SECRET",
            Ip => "IP",
            Host => "HOST",
            Url => "URL",
            Db => "DB",
            Svc => "SVC",
            Email => "EMAIL",
            Phone => "PHONE",
            Passport => "PASSPORT",
            Snils => "SNILS",
            Inn => "INN",
            Card => "CARD",
            Acct => "ACCT",
            Person => "PERSON",
            Project => "PROJECT",
            System => "SYSTEM",
            Org => "ORG",
            Lit => "LIT",
        }
    }

    pub fn from_marker(s: &str) -> Option<Self> {
        use EntityType::*;
        Some(match s {
            "SECRET" => Secret,
            "IP" => Ip,
            "HOST" => Host,
            "URL" => Url,
            "DB" => Db,
            "SVC" => Svc,
            "EMAIL" => Email,
            "PHONE" => Phone,
            "PASSPORT" => Passport,
            "SNILS" => Snils,
            "INN" => Inn,
            "CARD" => Card,
            "ACCT" => Acct,
            "PERSON" => Person,
            "PROJECT" => Project,
            "SYSTEM" => System,
            "ORG" => Org,
            "LIT" => Lit,
            _ => return None,
        })
    }
}

/// A detected value. The value itself lives only in the scanned text;
/// the entity carries position, type and attributes.
#[derive(Clone, PartialEq, Eq)]
pub struct Entity {
    pub span: Span,
    pub ty: EntityType,
    /// For secrets: `password`, `jwt`, `pem`, ... (the `kind` attribute).
    pub kind: Option<&'static str>,
    /// Detector that produced the entity (for audit, never the value).
    pub detector: &'static str,
    /// Person key for linking name and email (DET-07).
    pub person_key: Option<String>,
}

impl fmt::Debug for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Entity({:?} {}..{} {})",
            self.ty, self.span.start, self.span.end, self.detector
        )
    }
}

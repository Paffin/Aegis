//! Shared engine state: detection with cache (DET-02, DET-03), ingress policy (PSE-12),
//! per-request context.

use crate::json::Node;
use aegis_core::crypto::{Salt, TenantKeys};
use aegis_core::detect::{DetectConfig, Pipeline};
use aegis_core::policy::{Ingress, IngressPolicy, RestorePolicy, TrifectaConfig, TrifectaState};
use aegis_core::pseudo::{Mapping, PseudoConfig, Pseudonymizer, Source};
use aegis_core::types::{Class, Entity, EntityType};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

/// PSE-10 / API-05: constant per policy version so the prompt cache stays valid.
pub const NOTICE: &str = "Aegis notice: some values in this context are replaced with pseudonyms.\nMarkers like [[TYPE_id ...]], hostnames ending in .aegis.invalid, IPv4 addresses\nin 240.0.0.0/4 and IPv6 addresses in 3fff::/20 stand for real values.\nCopy them exactly as written. Do not modify them, do not build new names from them,\nand do not try to guess the real values. Treat them as valid in code and commands.";

pub const ATTACHMENT_NOTICE: &str = "[Aegis: вложение удалено политикой]";

pub struct Engine {
    pub keys: TenantKeys,
    pub pipeline: Pipeline,
    pub detect_cfg: DetectConfig,
    pub pseudo_cfg: PseudoConfig,
    pub restore_policy: RestorePolicy,
    pub trifecta: TrifectaConfig,
    pub ingress: IngressPolicy,
    cache: Mutex<DetectCache>,
    /// SHA-256 state after tenant and detector version; cloned per block (DET-02 cache key).
    hash_prefix: Sha256,
}

fn hash_prefix(tenant: &str, p: &Pipeline) -> Sha256 {
    let mut h = Sha256::new();
    h.update(tenant.as_bytes());
    h.update([0]);
    h.update(p.version_tag().as_bytes());
    h.update([0]);
    h
}

/// Result of scanning one block.
pub struct Scanned {
    pub entities: Vec<Entity>,
    /// The block contains something shaped like an Aegis pseudonym (PSE-11).
    pub grammar: bool,
    /// Served from the detection cache.
    pub hit: bool,
}

impl Engine {
    pub fn new(
        keys: TenantKeys,
        detect_cfg: DetectConfig,
        dict: aegis_core::detect::Dictionary,
    ) -> Self {
        let pipeline = Pipeline::new(detect_cfg.clone(), dict);
        Self {
            hash_prefix: hash_prefix(&keys.tenant, &pipeline),
            keys,
            pipeline,
            detect_cfg,
            pseudo_cfg: PseudoConfig::default(),
            restore_policy: RestorePolicy::default(),
            trifecta: TrifectaConfig::default(),
            ingress: IngressPolicy::default(),
            cache: Mutex::new(DetectCache::new(200_000)),
        }
    }

    /// Build the engine from a compiled bundle policy (CFG-01). Keys never come from the bundle.
    pub fn from_compiled(keys: TenantKeys, c: aegis_core::bundle::Compiled) -> Self {
        let mut pipeline = Pipeline::new(c.detect.clone(), c.dict);
        for d in c.custom {
            pipeline.add_detector(Box::new(d));
        }
        Self {
            hash_prefix: hash_prefix(&keys.tenant, &pipeline),
            keys,
            pipeline,
            detect_cfg: c.detect,
            pseudo_cfg: c.pseudo,
            restore_policy: c.restore,
            trifecta: c.trifecta,
            ingress: c.ingress,
            cache: Mutex::new(DetectCache::new(200_000)),
        }
    }

    /// Detection with a cache keyed by (tenant, block hash, detector version) (DET-02).
    /// The cache keeps positions and types only; the person key is stored hashed.
    pub fn scan(&self, text: &str) -> Scanned {
        let mut h = self.hash_prefix.clone();
        h.update(text.as_bytes());
        let key: [u8; 32] = h.finalize().into();
        if let Some((entities, grammar)) = self.cache.lock().ok().and_then(|mut c| c.get(&key)) {
            return Scanned {
                entities,
                grammar,
                hit: true,
            };
        }
        let mut ents = self.pipeline.scan(text);
        for e in &mut ents {
            if let Some(pk) = e.person_key.take() {
                let d = Sha256::digest(pk.as_bytes());
                e.person_key = Some(d[..8].iter().map(|b| format!("{b:02x}")).collect());
            }
        }
        let grammar = aegis_core::pseudo::has_aegis_grammar(text);
        if let Ok(mut c) = self.cache.lock() {
            c.put(key, (ents.clone(), grammar));
        }
        Scanned {
            entities: ents,
            grammar,
            hit: false,
        }
    }

    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|c| c.map.len()).unwrap_or(0)
    }
}

/// Entities of a block and whether it contains pseudonym-like text.
type CachedScan = (Vec<Entity>, bool);

/// Approximate LRU with a bounded number of entries; never persisted (DET-03).
struct DetectCache {
    cap: usize,
    tick: u64,
    map: HashMap<[u8; 32], (CachedScan, u64)>,
}

impl DetectCache {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            tick: 0,
            map: HashMap::new(),
        }
    }
    fn get(&mut self, k: &[u8; 32]) -> Option<CachedScan> {
        self.tick += 1;
        let t = self.tick;
        self.map.get_mut(k).map(|(v, tick)| {
            *tick = t;
            v.clone()
        })
    }
    fn put(&mut self, k: [u8; 32], v: CachedScan) {
        self.tick += 1;
        if self.map.len() >= self.cap {
            let mut ticks: Vec<u64> = self.map.values().map(|(_, t)| *t).collect();
            ticks.sort_unstable();
            let cut = ticks[ticks.len() / 10];
            self.map.retain(|_, (_, t)| *t > cut);
        }
        self.map.insert(k, (v, self.tick));
    }
}

/// Per-entity audit aggregate (AUD-01, AUD-02): hash, never the value.
#[derive(Debug, Clone)]
pub struct EntityAgg {
    pub count: u32,
    pub action: &'static str,
    pub rule: String,
}

/// One tool call decision on the response side (AUD-01).
#[derive(Debug, Clone)]
pub struct SinkAudit {
    pub tool: String,
    pub sink: &'static str,
    pub decision: &'static str,
    pub rule: String,
    pub classes: Vec<&'static str>,
}

/// Counters for `X-Aegis-Summary` (AUD-06) and audit.
#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub by_class: BTreeMap<&'static str, u32>,
    /// (type, kind, audit_hash) -> aggregate
    pub entities: BTreeMap<(&'static str, Option<&'static str>, String), EntityAgg>,
    pub sinks: Vec<SinkAudit>,
    pub timings_ms: BTreeMap<&'static str, f64>,
    pub denied: u32,
    pub blocks_total: u32,
    pub blocks_scanned: u32,
    pub rules: Vec<String>,
}

impl Stats {
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = self
            .by_class
            .iter()
            .map(|(c, n)| format!("{c}={n}"))
            .collect();
        if self.denied > 0 {
            parts.push(format!("denied={}", self.denied));
        }
        parts.join(";")
    }
}

/// Everything the response side needs from the request side.
pub struct RequestCtx {
    pub salt: Salt,
    pub mapping: Mapping,
    pub trifecta: TrifectaState,
    pub classes: HashSet<Class>,
    pub stats: Stats,
    pub request_id: String,
    /// Route of the request, for route-bound policy rules (POL-02).
    pub route: String,
    /// `HMAC(K_audit, salt)` for per-conversation reports (AUD-03).
    pub conversation_hash: String,
}

/// One scanned string literal of the request.
pub struct Blk<'n> {
    pub node: &'n Node,
    pub text: String,
    pub source: Source,
    /// Prepend the Aegis notice to this block (system prompt).
    pub is_system: bool,
}

fn record_entity(
    engine: &Engine,
    stats: &mut Stats,
    text: &str,
    e: &Entity,
    action: &'static str,
    rule: &str,
) {
    let canon = aegis_core::pseudo::canon(e, &text[e.span.start..e.span.end]);
    let h = aegis_core::crypto::audit_hash(&engine.keys, e.ty.marker(), &canon);
    let agg = stats
        .entities
        .entry((e.ty.marker(), e.kind, h))
        .or_insert(EntityAgg {
            count: 0,
            action,
            rule: rule.to_string(),
        });
    agg.count += 1;
}

pub struct Rendered {
    /// New text for each block (None: unchanged).
    pub texts: Vec<Option<String>>,
}

pub enum IngressError {
    Blocked { rule: String, ty: EntityType },
}

/// Phase 1 + 2 over all blocks of a request (INV-1: a block's output depends only on itself,
/// except for the own-marker escape rule of PSE-11).
pub fn process_blocks(
    engine: &Engine,
    ctx: &mut RequestCtx,
    blocks: &[Blk<'_>],
) -> Result<Rendered, IngressError> {
    let p = Pseudonymizer {
        keys: &engine.keys,
        salt: &ctx.salt,
        cfg: &engine.pseudo_cfg,
        detect: &engine.detect_cfg,
    };
    let mut kept: Vec<Vec<Entity>> = Vec::with_capacity(blocks.len());
    let mut dropped = vec![false; blocks.len()];
    let mut has_grammar: Vec<bool> = Vec::with_capacity(blocks.len());
    for (i, b) in blocks.iter().enumerate() {
        ctx.stats.blocks_total += 1;
        let t_scan = std::time::Instant::now();
        let Scanned {
            entities: ents,
            grammar,
            hit,
        } = engine.scan(&b.text);
        has_grammar.push(grammar);
        *ctx.stats.timings_ms.entry("detect").or_insert(0.0) +=
            t_scan.elapsed().as_secs_f64() * 1000.0;
        if !hit {
            ctx.stats.blocks_scanned += 1;
        }
        let mut keep = vec![];
        for e in ents {
            let (act, rule) = engine.ingress.decide(&e, &ctx.route);
            match act {
                Ingress::Allow => {}
                Ingress::Mask => {
                    *ctx.stats.by_class.entry(e.ty.class().as_str()).or_insert(0) += 1;
                    ctx.classes.insert(e.ty.class());
                    record_entity(engine, &mut ctx.stats, &b.text, &e, "mask", &rule);
                    keep.push(e);
                }
                Ingress::DropBlock => {
                    *ctx.stats.by_class.entry(e.ty.class().as_str()).or_insert(0) += 1;
                    record_entity(engine, &mut ctx.stats, &b.text, &e, "drop_block", &rule);
                    ctx.stats.rules.push(rule);
                    dropped[i] = true;
                }
                Ingress::BlockRequest => return Err(IngressError::Blocked { rule, ty: e.ty }),
            }
        }
        kept.push(keep);
    }
    for (b, ents) in blocks.iter().zip(&kept) {
        p.register(&b.text, ents, &b.source, &mut ctx.mapping);
    }
    let mut texts = Vec::with_capacity(blocks.len());
    for (i, (b, ents)) in blocks.iter().zip(&kept).enumerate() {
        let out = if dropped[i] {
            "[Aegis: блок не проверен и удалён]".to_string()
        } else {
            p.render_opt(&b.text, ents, &mut ctx.mapping, has_grammar[i])
        };
        let out = if b.is_system {
            format!("{NOTICE}\n\n{out}")
        } else {
            out
        };
        texts.push((out != b.text).then_some(out));
    }
    Ok(Rendered { texts })
}

impl RequestCtx {
    /// Context for requests that were rejected before any block was processed.
    pub fn empty(request_id: &str) -> Self {
        Self {
            salt: Salt([0; 32]),
            mapping: Mapping::default(),
            trifecta: TrifectaState::default(),
            classes: HashSet::new(),
            stats: Stats::default(),
            request_id: request_id.to_string(),
            route: String::new(),
            conversation_hash: String::new(),
        }
    }
}

impl std::fmt::Debug for RequestCtx {
    /// INV-6: the mapping holds values, so only counts are printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RequestCtx(request_id={}, bindings={})",
            self.request_id,
            self.mapping.len()
        )
    }
}

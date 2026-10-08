//! REQ: DET-20, DET-21 — the gateway side of the fingerprint index: a block of code that looks
//! like a closed repository is handled by the policy of that repository's classification.

use aegis_core::fingerprint::{CodeIndex, CodeMatch, Fingerprinter};
use arc_swap::ArcSwap;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// `code_index` in the gateway configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeIndexConfig {
    /// The file `aegis index build` wrote. Read again when it changes.
    pub path: String,
    /// Share of a block's fingerprints that must be found in one repository.
    #[serde(default = "d_threshold")]
    pub threshold: f32,
    /// Blocks with fewer tokens are not judged.
    #[serde(default = "d_min_tokens")]
    pub min_tokens: usize,
    /// What happens to a matching block, by classification of the repository:
    /// `warn` (audit only), `drop_block` (the block is replaced by a notice), `block_request`, or
    /// `route:<name>` (the whole request goes to that route, RTE-03).
    #[serde(default)]
    pub actions: BTreeMap<String, String>,
    /// For a classification not named in `actions`. Default `warn`.
    #[serde(default)]
    pub default_action: Option<String>,
}

fn d_threshold() -> f32 {
    0.9
}
fn d_min_tokens() -> usize {
    50
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeAction {
    Warn,
    DropBlock,
    BlockRequest,
    /// RTE-03: the request goes to this route (an internal model).
    Route(String),
}

impl CodeAction {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "warn" => Ok(Self::Warn),
            "drop_block" => Ok(Self::DropBlock),
            "block_request" => Ok(Self::BlockRequest),
            o => match o.strip_prefix("route:") {
                Some(n)
                    if !n.is_empty()
                        && n.chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) =>
                {
                    Ok(Self::Route(n.to_string()))
                }
                _ => Err(format!(
                    "code_index: действие «{o}», нужно warn, drop_block, block_request или route:<имя маршрута>"
                )),
            },
        }
    }
}

pub struct CodeGuard {
    fp: Fingerprinter,
    index: ArcSwap<CodeIndex>,
    generation: AtomicU64,
    threshold: f32,
    min_tokens: usize,
    actions: BTreeMap<String, CodeAction>,
    default_action: CodeAction,
    path: String,
}

impl CodeGuard {
    pub fn load(cfg: &CodeIndexConfig, tenant_key: &[u8]) -> Result<Arc<Self>, String> {
        if !(0.05..=1.0).contains(&cfg.threshold) {
            return Err("code_index.threshold: от 0,05 до 1".into());
        }
        let fp = Fingerprinter::new(tenant_key);
        let bytes =
            std::fs::read(&cfg.path).map_err(|e| format!("code_index {}: {e}", cfg.path))?;
        let index = CodeIndex::from_bytes(&bytes, &fp)
            .map_err(|e| format!("code_index {}: {e}", cfg.path))?;
        let mut actions = BTreeMap::new();
        for (k, v) in &cfg.actions {
            actions.insert(k.clone(), CodeAction::parse(v)?);
        }
        let default_action = cfg
            .default_action
            .as_deref()
            .map_or(Ok(CodeAction::Warn), CodeAction::parse)?;
        Ok(Arc::new(Self {
            fp,
            index: ArcSwap::from_pointee(index),
            generation: AtomicU64::new(1),
            threshold: cfg.threshold,
            min_tokens: cfg.min_tokens,
            actions,
            default_action,
            path: cfg.path.clone(),
        }))
    }

    /// Changes with every reload; part of the detection cache key, so that a new index is not
    /// answered from results of the old one.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn lookup(&self, text: &str) -> Option<CodeMatch> {
        self.index
            .load()
            .lookup(&self.fp, text, self.threshold, self.min_tokens)
    }

    pub fn action_for(&self, m: &CodeMatch) -> CodeAction {
        self.actions
            .get(&m.classification)
            .unwrap_or(&self.default_action)
            .clone()
    }

    /// Names of the routes the actions send requests to (to check they exist).
    pub fn route_names(&self) -> Vec<String> {
        self.actions
            .values()
            .chain(std::iter::once(&self.default_action))
            .filter_map(|a| {
                if let CodeAction::Route(n) = a {
                    Some(n.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn repos(&self) -> usize {
        self.index.load().repos().len()
    }

    /// Look at the file every `every`; a changed file that loads replaces the index, one that does
    /// not leaves the old index in place (DET-21).
    pub fn watch(self: &Arc<Self>, every: Duration) {
        let me = self.clone();
        tokio::spawn(async move {
            let stamp = |p: &str| std::fs::metadata(p).and_then(|m| m.modified()).ok();
            let mut seen: Option<SystemTime> = stamp(&me.path);
            loop {
                tokio::time::sleep(every).await;
                let now = stamp(&me.path);
                if now == seen {
                    continue;
                }
                match std::fs::read(&me.path)
                    .map_err(|e| e.to_string())
                    .and_then(|b| CodeIndex::from_bytes(&b, &me.fp).map_err(|e| e.to_string()))
                {
                    Ok(ix) => {
                        me.index.store(Arc::new(ix));
                        me.generation.fetch_add(1, Ordering::Relaxed);
                        seen = now;
                        tracing::info!("code index reloaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "code index not reloaded, the old one stays")
                    }
                }
            }
        });
    }
}

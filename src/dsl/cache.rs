use super::parser::{Expr, parse_expression};
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;

const REGEX_CACHE_CAPACITY: usize = 256;
const REGEX_CACHE_EVICTION_BATCH_SIZE: usize = 128;
const DSL_AST_CACHE_CAPACITY: usize = 256;
const DSL_AST_CACHE_EVICTION_BATCH_SIZE: usize = 128;

thread_local! {
    pub(super) static REGEX_CACHE: RefCell<RegexCache> = RefCell::new(RegexCache::new());
    pub(super) static DSL_AST_CACHE: RefCell<AstCache> = RefCell::new(AstCache::new());
}

#[derive(Default)]
pub(super) struct RegexCache {
    pub(super) entries: HashMap<String, CachedRegex>,
    next_tick: u64,
}

impl RegexCache {
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn get_or_compile(&mut self, pattern: &str) -> Result<Regex, regex::Error> {
        self.next_tick = self.next_tick.wrapping_add(1);

        if let Some(entry) = self.entries.get_mut(pattern) {
            entry.last_used = self.next_tick;
            return Ok(entry.regex.clone());
        }

        let compiled = Regex::new(pattern)?;
        self.entries.insert(
            pattern.to_string(),
            CachedRegex {
                regex: compiled.clone(),
                last_used: self.next_tick,
            },
        );

        if self.entries.len() > REGEX_CACHE_CAPACITY {
            self.evict_lru();
        }

        Ok(compiled)
    }

    fn evict_lru(&mut self) {
        let eviction_count = self.entries.len().min(REGEX_CACHE_EVICTION_BATCH_SIZE);
        if eviction_count == 0 {
            return;
        }
        let mut times: Vec<u64> = self.entries.values().map(|v| v.last_used).collect();
        times.sort_unstable();
        let threshold = times[eviction_count - 1];

        let mut removed = 0;
        self.entries.retain(|_, v| {
            if v.last_used <= threshold && removed < eviction_count {
                removed += 1;
                false
            } else {
                true
            }
        });
    }
}

pub(super) struct CachedRegex {
    regex: Regex,
    last_used: u64,
}

#[derive(Default)]
pub(super) struct AstCache {
    pub(super) entries: HashMap<String, CachedAst>,
    next_tick: u64,
}

impl AstCache {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn get_or_parse(&mut self, expression: &str) -> Option<&Expr> {
        self.next_tick = self.next_tick.wrapping_add(1);

        if !self.entries.contains_key(expression) {
            let parsed = parse_expression(expression);
            self.entries.insert(
                expression.to_string(),
                CachedAst {
                    expr: parsed,
                    last_used: self.next_tick,
                },
            );

            if self.entries.len() > DSL_AST_CACHE_CAPACITY {
                self.evict_lru();
            }
        }

        let entry = self.entries.get_mut(expression)?;
        entry.last_used = self.next_tick;
        entry.expr.as_ref()
    }

    fn evict_lru(&mut self) {
        let eviction_count = self.entries.len().min(DSL_AST_CACHE_EVICTION_BATCH_SIZE);
        if eviction_count == 0 {
            return;
        }
        let mut times: Vec<u64> = self.entries.values().map(|v| v.last_used).collect();
        times.sort_unstable();
        let threshold = times[eviction_count - 1];

        let mut removed = 0;
        self.entries.retain(|_, v| {
            if v.last_used <= threshold && removed < eviction_count {
                removed += 1;
                false
            } else {
                true
            }
        });
    }
}

pub(super) struct CachedAst {
    pub(super) expr: Option<Expr>,
    last_used: u64,
}

pub(super) fn ast_cache<T>(f: impl FnOnce(&mut AstCache) -> T) -> T {
    DSL_AST_CACHE.with(|cache| f(&mut cache.borrow_mut()))
}

/// Compiles a regex or retrieves it from the thread-local cache.
pub fn cached_regex(pattern: &str) -> Result<Regex, regex::Error> {
    REGEX_CACHE.with(|cache| cache.borrow_mut().get_or_compile(pattern))
}

//! Compiled matcher database that batches template patterns into shared automata.

use aho_corasick::AhoCorasick;
// Byte-oriented regex engines so the scanner matches directly against the raw
// response bytes. A non-UTF-8 response segment must still be scanned (matching
// the valid-UTF-8 islands within it) instead of being silently skipped, which
// would be an invisible recall loss on binary/mixed bodies (Law-10).
use regex::bytes::{Regex, RegexSet};
use rustc_hash::FxHashMap;
use secir::Result;
use secir::matcher::Match;
use secir::template::{MatchPart, MatcherCondition, MatcherDef, MatcherKind, Template};

mod compile;
mod regex_scan;
mod scan;

/// Compiled match database that batches template matchers into shared automata.
pub struct CompiledDatabase {
    word_automaton: Option<AhoCorasick>,
    patterns: Vec<String>,
    /// Pattern refs grouped by UNIQUE raw pattern bytes, parallel to the
    /// automaton's pattern IDs. Identical word/binary patterns (across
    /// templates or matchers) share one automaton slot; every ref in the
    /// group must fire when that slot matches, otherwise all but the first
    /// would be silent false negatives.
    word_groups: Vec<Vec<PatternRef>>,
    named_word_patterns: FxHashMap<String, Vec<PatternRef>>,
    regex_matchers: Vec<RegexEntry>,
    named_regex_matchers: FxHashMap<String, Vec<RegexEntry>>,
    regex_sets_body: Vec<(RegexSet, Vec<usize>)>,
    regex_sets_header: Vec<(RegexSet, Vec<usize>)>,
    regex_sets_all: Vec<(RegexSet, Vec<usize>)>,
    status_index: FxHashMap<u16, Vec<PatternRef>>,
    size_index: FxHashMap<usize, Vec<PatternRef>>,
    dsl_matchers: Vec<StoredMatcher>,
    /// Every negative matcher-value, flattened once at compile time. A negative
    /// matcher is inverted: it emits a match when its pattern is ABSENT and
    /// nothing when present. The positive scan cannot surface an absence, so
    /// these are enumerated up front and resolved in a dedicated pass (see
    /// `scan`), which emits one `Match { negative: true }` per entry whose
    /// pattern did NOT fire during the positive phases.
    negative_matchers: Vec<NegativeMatcher>,
    template_ids: Vec<String>,
    template_count: usize,
}

#[derive(Debug, Clone)]
struct PatternRef {
    template_idx: u32,
    request_index: u16,
    matcher_index: u16,
    value_index: u16,
    kind: MatcherKind,
    pattern_index: u32,
    part: MatchPart,
    negative: bool,
    condition: MatcherCondition,
    internal: bool,
}

impl PatternRef {
    #[inline]
    fn dedup_key(&self) -> (u32, u16, u16, u16) {
        (
            self.template_idx,
            self.request_index,
            self.matcher_index,
            self.value_index,
        )
    }

    fn to_matcher_def(&self, pattern: &str) -> MatcherDef {
        MatcherDef {
            kind: self.kind,
            values: vec![pattern.to_string()],
            part: self.part.clone(),
            negative: self.negative,
            condition: self.condition,
            internal: self.internal,
        }
    }
}

struct RegexEntry {
    regex: Regex,
    pattern_ref: PatternRef,
}

#[derive(Clone)]
struct StoredMatcher {
    def: MatcherDef,
    template_idx: u32,
    request_index: u16,
    matcher_index: u16,
}

/// One negative matcher-value, flattened at compile time. It carries everything
/// needed to emit its inverted (`negative: true`) match without re-deriving it,
/// plus the `key` used to test whether the underlying pattern fired during the
/// positive scan (in which case the negative matcher must emit nothing).
#[derive(Clone)]
struct NegativeMatcher {
    key: (u32, u16, u16, u16),
    template_idx: u32,
    request_index: u16,
    matcher_index: u16,
    value_index: u16,
    matcher: MatcherDef,
    value: String,
}

type SeenMatches = smallvec::SmallVec<[(u32, u16, u16, u16); 16]>;

impl CompiledDatabase {
    /// Compile parsed templates into a reusable database optimized for scanning.
    #[must_use = "compilation can fail; handle the returned database or error"]
    pub fn compile(templates: &[Template]) -> Result<Self> {
        Self::compile_impl(templates)
    }

    #[inline]
    fn template_id(&self, index: u32) -> &str {
        &self.template_ids[index as usize]
    }

    #[inline]
    fn pattern(&self, pattern_ref: &PatternRef) -> &str {
        &self.patterns[pattern_ref.pattern_index as usize]
    }

    #[inline]
    fn emit_match(&self, pattern_ref: &PatternRef, matched_value: String, offset: usize) -> Match {
        Match {
            template_id: self.template_id(pattern_ref.template_idx).to_string(),
            request_index: pattern_ref.request_index as usize,
            matcher_index: pattern_ref.matcher_index as usize,
            value_index: pattern_ref.value_index as usize,
            matcher: pattern_ref.to_matcher_def(self.pattern(pattern_ref)),
            matched_value,
            offset,
            negative: pattern_ref.negative,
        }
    }

    /// Handle a pattern that fired (its bytes were present in the scanned part).
    ///
    /// For a positive matcher this emits the match once (deduped by `seen`), with
    /// `matched_value` computed lazily so a deduped repeat costs no allocation.
    /// For a negative matcher a hit means the matcher does NOT fire, so nothing is
    /// emitted here; instead the key is recorded in `fired` so the absence pass in
    /// [`Self::scan`] skips it. This is the single place that inverts a hit into
    /// the correct positive-emit / negative-suppress decision (ONE-PLACE).
    #[inline]
    fn record_hit<F: FnOnce() -> String>(
        &self,
        pattern_ref: &PatternRef,
        offset: usize,
        matched_value: F,
        matches: &mut Vec<Match>,
        seen: &mut SeenMatches,
        fired: &mut SeenMatches,
    ) {
        if pattern_ref.negative {
            Self::insert_seen(fired, pattern_ref.dedup_key());
        } else if Self::insert_seen(seen, pattern_ref.dedup_key()) {
            matches.push(self.emit_match(pattern_ref, matched_value(), offset));
        }
    }

    /// Build the inverted match for a negative matcher whose pattern was ABSENT.
    #[inline]
    fn emit_negative(&self, nm: &NegativeMatcher) -> Match {
        Match {
            template_id: self.template_id(nm.template_idx).to_string(),
            request_index: nm.request_index as usize,
            matcher_index: nm.matcher_index as usize,
            value_index: nm.value_index as usize,
            matcher: nm.matcher.clone(),
            matched_value: nm.value.clone(),
            offset: 0,
            negative: true,
        }
    }

    #[inline]
    fn insert_seen(seen: &mut SeenMatches, key: (u32, u16, u16, u16)) -> bool {
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    }
}

#[cfg(test)]
mod tests;

use super::{BinaryEntry, CompiledDatabase, NegativeMatcher, PatternRef, RegexEntry, StoredMatcher};
use aho_corasick::{AhoCorasick, AhoCorasickKind};
use rayon::prelude::*;
// Byte-oriented RegexSet so scan patterns match raw response bytes (see the
// note in `mod.rs`). The `pcre_compat_fix` helper below keeps a `str` regex,
// as it rewrites pattern *text*, not haystack bytes.
use regex::bytes::RegexSet;
use rustc_hash::FxHashMap;
use secir::template::{MatchPart, MatcherKind, Template};
use secir::{Error, Result};

#[derive(Default)]
struct TemplatePatternBatch {
    patterns: Vec<String>,
    word_patterns_raw: Vec<Vec<u8>>,
    word_patterns: Vec<PatternRef>,
    named_word_patterns: FxHashMap<String, Vec<PatternRef>>,
    named_binary_matchers: FxHashMap<String, Vec<BinaryEntry>>,
    regex_matchers: Vec<RegexEntry>,
    named_regex_matchers: FxHashMap<String, Vec<RegexEntry>>,
    status_patterns: Vec<(u16, PatternRef)>,
    size_patterns: Vec<(usize, PatternRef)>,
    dsl_matchers: Vec<StoredMatcher>,
}

impl TemplatePatternBatch {
    fn push_word_or_binary(&mut self, pattern_ref: PatternRef, bytes: Vec<u8>) {
        if let MatchPart::Named(name) = &pattern_ref.part {
            let key = name.to_ascii_lowercase();
            if pattern_ref.kind == MatcherKind::Binary {
                self.named_binary_matchers
                    .entry(key)
                    .or_default()
                    .push(BinaryEntry { bytes, pattern_ref });
            } else {
                self.named_word_patterns
                    .entry(key)
                    .or_default()
                    .push(pattern_ref);
            }
        } else {
            self.word_patterns_raw.push(bytes);
            self.word_patterns.push(pattern_ref);
        }
    }

    fn push_regex_entry(&mut self, entry: RegexEntry) {
        if let MatchPart::Named(name) = &entry.pattern_ref.part {
            self.named_regex_matchers
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(entry);
        } else {
            self.regex_matchers.push(entry);
        }
    }
}

/// Turn `hello-{{suffix}}` into a Rust regex by substituting template holes.
fn template_var_regex_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let bytes = pattern.as_bytes();
    let mut i = 0;
    // Start of the current run of literal (non-template) text. Escaping a whole
    // run in one regex::escape call is identical to escaping each char and
    // concatenating (escape is char-local, never merges across chars), but does
    // O(#holes + 1) allocations instead of O(#chars).
    let mut literal_start = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(end) = pattern[i + 2..].find("}}") {
                if literal_start < i {
                    out.push_str(&regex::escape(&pattern[literal_start..i]));
                }
                out.push_str(".+");
                i += 2 + end + 2;
                literal_start = i;
                continue;
            }
        }
        i += match pattern[i..].chars().next() {
            Some(ch) => ch.len_utf8(),
            // Unreachable: `i < bytes.len()` and `pattern` is valid UTF-8, so a
            // char always starts at `i`. Break instead of panicking if that
            // invariant is ever violated.
            None => break,
        };
    }
    if literal_start < bytes.len() {
        out.push_str(&regex::escape(&pattern[literal_start..]));
    }
    out
}

/// Append `pattern_ref` to `out` as a [`NegativeMatcher`] if it is negated.
/// Resolves the pattern text from the shared arena so the absence pass can emit
/// the inverted match without holding a reference back into the database.
fn collect_negative(pattern_ref: &PatternRef, patterns: &[String], out: &mut Vec<NegativeMatcher>) {
    if !pattern_ref.negative {
        return;
    }
    let value = patterns[pattern_ref.pattern_index as usize].clone();
    out.push(NegativeMatcher {
        key: pattern_ref.dedup_key(),
        template_idx: pattern_ref.template_idx,
        request_index: pattern_ref.request_index,
        matcher_index: pattern_ref.matcher_index,
        value_index: pattern_ref.value_index,
        matcher: pattern_ref.to_matcher_def(&value),
        value,
    });
}

fn hex_decode(hex: &str) -> std::result::Result<Vec<u8>, ()> {
    let hex = hex.trim().replace(' ', "");
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(());
    }

    bytes
        .chunks_exact(2)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .map_err(|_| ())
                .and_then(|pair| u8::from_str_radix(pair, 16).map_err(|_| ()))
        })
        .collect()
}

/// Convert an index to `u16`, failing closed when it would truncate.
///
/// PatternRef stores request/matcher/value indices as `u16` for compactness.
/// A silent `as u16` cast wraps at 65536, which would attribute a match to
/// the WRONG matcher: an invisible corruption of scan results.
fn checked_u16_index(value: usize, template_id: &str, what: &str) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::TemplateValidation {
        id: template_id.to_string(),
        reason: format!(
            "{what} index {value} exceeds 65535; split the template into smaller units so matcher attribution stays exact"
        ),
    })
}

impl CompiledDatabase {
    /// Intern a pattern string into the batch arena, returning its index.
    ///
    /// # Errors
    /// Returns [`Error::TemplateValidation`] when the arena would exceed
    /// `u32::MAX` entries (over four billion patterns in one database).
    fn intern_pattern(
        batch: &mut TemplatePatternBatch,
        value: &str,
        template_id: &str,
    ) -> Result<u32> {
        let index = u32::try_from(batch.patterns.len()).map_err(|_| {
            Error::TemplateValidation {
                id: template_id.to_string(),
                reason: "pattern arena exceeds u32::MAX entries; split the template set into smaller databases".to_string(),
            }
        })?;
        batch.patterns.push(value.to_string());
        Ok(index)
    }

    pub(crate) fn build_word_automaton_with<Primary, Fallback, PrimaryError, FallbackError>(
        primary: Primary,
        fallback: Fallback,
    ) -> Result<AhoCorasick>
    where
        Primary: FnOnce() -> std::result::Result<AhoCorasick, PrimaryError>,
        Fallback: FnOnce() -> std::result::Result<AhoCorasick, FallbackError>,
        PrimaryError: std::fmt::Display,
        FallbackError: std::fmt::Display,
    {
        match primary() {
            Ok(automaton) => Ok(automaton),
            Err(error) => {
                tracing::warn!(error = %error, "falling back to alternate aho-corasick builder; primary builder failed");
                fallback().map_err(|fallback_error| Error::PatternCompile {
                    pattern: "<aho-corasick automaton>".to_string(),
                    source: format!(
                        "aho-corasick build failed (primary: {error}; fallback: {fallback_error})"
                    ),
                })
            }
        }
    }

    fn build_word_automaton(patterns: &[Vec<u8>]) -> Result<AhoCorasick> {
        // The automaton must support overlapping search (`find_overlapping_iter`):
        // scan relies on it so that two word patterns sharing a start position
        // (for example `password` and `password123`) BOTH report. A DFA cannot
        // run an overlapping search, so the primary builder is always an NFA.
        Self::build_word_automaton_with(
            || {
                let mut builder = AhoCorasick::builder();
                builder
                    .ascii_case_insensitive(true)
                    .kind(Some(AhoCorasickKind::NoncontiguousNFA));
                builder.build(patterns)
            },
            || {
                let mut builder = AhoCorasick::builder();
                builder
                    .ascii_case_insensitive(true)
                    .kind(Some(AhoCorasickKind::ContiguousNFA));
                builder.build(patterns)
            },
        )
    }

    pub(super) fn compile_impl(templates: &[Template]) -> Result<Self> {
        if templates.len() > u32::MAX as usize {
            return Err(Error::TemplateValidation {
                id: "<database>".to_string(),
                reason: format!(
                    "{} templates exceed the u32 template-index limit; split the set into smaller databases",
                    templates.len()
                ),
            });
        }
        let mut template_ids = Vec::with_capacity(templates.len());
        for template in templates {
            template_ids.push(template.id.clone());
        }

        let pattern_batches: Vec<TemplatePatternBatch> = templates
            .par_iter()
            .enumerate()
            .map(|(template_idx, template)| -> Result<TemplatePatternBatch> {
                let mut batch = TemplatePatternBatch::default();

                for (request_index, request) in template.requests.iter().enumerate() {
                    for (matcher_index, matcher) in request.matchers.iter().enumerate() {
                        if matcher.kind == MatcherKind::Dsl {
                            batch.dsl_matchers.push(StoredMatcher {
                                def: matcher.clone(),
                                template_idx: template_idx as u32,
                                request_index: checked_u16_index(
                                    request_index,
                                    &template.id,
                                    "request",
                                )?,
                                matcher_index: checked_u16_index(
                                    matcher_index,
                                    &template.id,
                                    "matcher",
                                )?,
                            });
                            continue;
                        }

                        if matcher.values.len() > u16::MAX as usize {
                            return Err(Error::TemplateValidation {
                                id: template.id.clone(),
                                reason: format!(
                                    "matcher {} in request {} has {} values, exceeding the 65535 value-index limit; split it into multiple matchers",
                                    matcher_index + 1,
                                    request_index + 1,
                                    matcher.values.len()
                                ),
                            });
                        }

                        for (value_index, value) in matcher.values.iter().enumerate() {
                            // Empty values: an empty word/binary pattern would match
                            // at every byte offset (pathological), and an empty
                            // status/size is an authoring bug, so skip them loudly.
                            // An empty REGEX is kept: the regex crate defines it as
                            // matching the empty string, which is well-defined and
                            // cheap to report once.
                            if value.is_empty() && matcher.kind != MatcherKind::Regex {
                                tracing::warn!(
                                    template_id = %template.id,
                                    request_index = request_index + 1,
                                    matcher_index = matcher_index + 1,
                                    value_index,
                                    kind = ?matcher.kind,
                                    "skipping empty matcher value; it can never fire"
                                );
                                continue;
                            }

                            let pattern_ref = PatternRef {
                                template_idx: template_idx as u32,
                                request_index: checked_u16_index(
                                    request_index,
                                    &template.id,
                                    "request",
                                )?,
                                matcher_index: checked_u16_index(
                                    matcher_index,
                                    &template.id,
                                    "matcher",
                                )?,
                                value_index: checked_u16_index(
                                    value_index,
                                    &template.id,
                                    "value",
                                )?,
                                kind: matcher.kind,
                                pattern_index: Self::intern_pattern(&mut batch, value, &template.id)?,
                                part: matcher.part.clone(),
                                negative: matcher.negative,
                                condition: matcher.condition,
                                internal: matcher.internal,
                            };

                            match matcher.kind {
                                MatcherKind::Word => {
                                    batch.push_word_or_binary(pattern_ref, value.as_bytes().to_vec());
                                }
                                MatcherKind::Regex if value.contains("{{") => {
                                    let runtime = template_var_regex_pattern(value);
                                    match regex::bytes::Regex::new(&runtime) {
                                        Ok(regex) => {
                                            let pattern_index =
                                                Self::intern_pattern(&mut batch, &runtime, &template.id)?;
                                            let mut runtime_ref = pattern_ref;
                                            runtime_ref.pattern_index = pattern_index;
                                            tracing::debug!(
                                                template_id = %template.id,
                                                regex = %value,
                                                runtime = %runtime,
                                                "compiled runtime regex with template-variable holes"
                                            );
                                            batch.push_regex_entry(RegexEntry {
                                                regex,
                                                pattern_ref: runtime_ref,
                                            });
                                        }
                                        Err(err) => {
                                            return Err(Error::PatternCompile {
                                                pattern: value.clone(),
                                                source: format!(
                                                    "template '{}' request {} matcher {} has invalid runtime regex after variable-hole expansion: {err}",
                                                    template.id,
                                                    request_index + 1,
                                                    matcher_index + 1,
                                                ),
                                            });
                                        }
                                    }
                                }
                                MatcherKind::Regex => match regex::bytes::Regex::new(value) {
                                    Ok(regex) => {
                                            batch.push_regex_entry(RegexEntry { regex, pattern_ref });
                                    }
                                    Err(err) => {
                                        let mut fixed = false;
                                        if let Some(fixed_value) = pcre_compat_fix(value)
                                            && let Ok(fixed_regex) =
                                                regex::bytes::RegexBuilder::new(&fixed_value)
                                                    .size_limit(10 * 1024 * 1024)
                                                    .build()
                                        {
                                            tracing::warn!(
                                                template_id = %template.id,
                                                original = %value,
                                                fixed = %fixed_value,
                                                "applied PCRE-to-Rust regex compat fix"
                                            );
                                            let pattern_index =
                                                Self::intern_pattern(&mut batch, &fixed_value, &template.id)?;
                                            let mut fixed_pattern_ref = pattern_ref.clone();
                                            fixed_pattern_ref.pattern_index = pattern_index;
                                            batch.push_regex_entry(RegexEntry {
                                                regex: fixed_regex,
                                                pattern_ref: fixed_pattern_ref,
                                            });
                                            fixed = true;
                                        }

                                        if !fixed {
                                            return Err(Error::PatternCompile {
                                                pattern: value.clone(),
                                                source: format!(
                                                    "template '{}' request {} matcher {} has invalid regex: {err}. Fix the pattern or remove PCRE-only syntax unsupported by Rust regex.",
                                                    template.id,
                                                    request_index + 1,
                                                    matcher_index + 1,
                                                ),
                                            });
                                        }
                                    }
                                },
                                MatcherKind::Status => match value.parse::<u16>() {
                                    Ok(code) => batch.status_patterns.push((code, pattern_ref)),
                                    Err(_) => {
                                        return Err(Error::PatternCompile {
                                            pattern: value.clone(),
                                            source: format!(
                                                "template '{}' request {} matcher {} uses invalid status code '{}'. Use an integer HTTP status such as 200 or 404.",
                                                template.id,
                                                request_index + 1,
                                                matcher_index + 1,
                                                value,
                                            ),
                                        });
                                    }
                                },
                                MatcherKind::Size => match value.parse::<usize>() {
                                    Ok(size) => batch.size_patterns.push((size, pattern_ref)),
                                    Err(_) => {
                                        return Err(Error::PatternCompile {
                                            pattern: value.clone(),
                                            source: format!(
                                                "template '{}' request {} matcher {} uses invalid size '{}'. Use a non-negative integer byte count.",
                                                template.id,
                                                request_index + 1,
                                                matcher_index + 1,
                                                value,
                                            ),
                                        });
                                    }
                                },
                                MatcherKind::Binary => match hex_decode(value) {
                                    Ok(bytes) => {
                                        batch.push_word_or_binary(pattern_ref, bytes);
                                    }
                                    Err(()) => {
                                        return Err(Error::PatternCompile {
                                            pattern: value.clone(),
                                            source: format!(
                                                "template '{}' request {} matcher {} has invalid hex pattern '{}'. Use an even-length hexadecimal string such as '504f5354'.",
                                                template.id,
                                                request_index + 1,
                                                matcher_index + 1,
                                                value,
                                            ),
                                        });
                                    }
                                },
                                _ => {}
                            }
                        }
                    }
                }

                Ok(batch)
            })
            .collect::<Result<Vec<_>>>()?;

        let mut patterns = Vec::new();
        let mut word_patterns_raw: Vec<Vec<u8>> = Vec::new();
        let mut word_patterns = Vec::new();
        let mut named_word_patterns: FxHashMap<String, Vec<PatternRef>> = FxHashMap::default();
        let mut named_binary_matchers: FxHashMap<String, Vec<BinaryEntry>> = FxHashMap::default();
        let mut regex_matchers = Vec::new();
        let mut named_regex_matchers: FxHashMap<String, Vec<RegexEntry>> = FxHashMap::default();
        let mut status_index: FxHashMap<u16, Vec<PatternRef>> = FxHashMap::default();
        let mut size_index: FxHashMap<usize, Vec<PatternRef>> = FxHashMap::default();
        let mut dsl_matchers = Vec::new();

        for mut batch in pattern_batches {
            let pattern_offset = u32::try_from(patterns.len()).map_err(|_| {
                Error::TemplateValidation {
                    id: "<database>".to_string(),
                    reason: "pattern arena exceeds u32::MAX entries; split the template set into smaller databases".to_string(),
                }
            })?;
            patterns.append(&mut batch.patterns);
            for pattern_ref in &mut batch.word_patterns {
                pattern_ref.pattern_index += pattern_offset;
            }
            for refs in batch.named_word_patterns.values_mut() {
                for pattern_ref in refs {
                    pattern_ref.pattern_index += pattern_offset;
                }
            }
            for entries in batch.named_binary_matchers.values_mut() {
                for entry in entries {
                    entry.pattern_ref.pattern_index += pattern_offset;
                }
            }
            for entry in &mut batch.regex_matchers {
                entry.pattern_ref.pattern_index += pattern_offset;
            }
            for entries in batch.named_regex_matchers.values_mut() {
                for entry in entries {
                    entry.pattern_ref.pattern_index += pattern_offset;
                }
            }
            for (_, pattern_ref) in &mut batch.status_patterns {
                pattern_ref.pattern_index += pattern_offset;
            }
            for (_, pattern_ref) in &mut batch.size_patterns {
                pattern_ref.pattern_index += pattern_offset;
            }
            word_patterns_raw.append(&mut batch.word_patterns_raw);
            word_patterns.append(&mut batch.word_patterns);
            regex_matchers.append(&mut batch.regex_matchers);
            for (name, mut refs) in batch.named_word_patterns {
                named_word_patterns
                    .entry(name)
                    .or_default()
                    .append(&mut refs);
            }
            for (name, mut entries) in batch.named_binary_matchers {
                named_binary_matchers
                    .entry(name)
                    .or_default()
                    .append(&mut entries);
            }
            for (name, mut entries) in batch.named_regex_matchers {
                named_regex_matchers
                    .entry(name)
                    .or_default()
                    .append(&mut entries);
            }
            dsl_matchers.append(&mut batch.dsl_matchers);
            for (status, pattern_ref) in batch.status_patterns {
                status_index.entry(status).or_default().push(pattern_ref);
            }
            for (size, pattern_ref) in batch.size_patterns {
                size_index.entry(size).or_default().push(pattern_ref);
            }
        }

        // Dedupe identical raw word/binary patterns into groups. Aho-Corasick
        // reports only ONE pattern ID for identical patterns, so without
        // grouping, two templates (or two matchers in one template) sharing an
        // identical pattern would see only the first PatternRef fire: a silent
        // false negative for every other one (Law-10).
        let mut unique_word_raw: Vec<Vec<u8>> = Vec::new();
        let mut word_groups: Vec<Vec<PatternRef>> = Vec::new();
        let mut raw_to_group: FxHashMap<&[u8], u32> = FxHashMap::default();
        for (raw, pattern_ref) in word_patterns_raw.iter().zip(&word_patterns) {
            match raw_to_group.get(raw.as_slice()) {
                Some(&group) => word_groups[group as usize].push(pattern_ref.clone()),
                None => {
                    let group = u32::try_from(unique_word_raw.len()).map_err(|_| {
                        Error::TemplateValidation {
                            id: "<database>".to_string(),
                            reason: "word pattern arena exceeds u32::MAX entries; split the template set into smaller databases".to_string(),
                        }
                    })?;
                    raw_to_group.insert(raw.as_slice(), group);
                    unique_word_raw.push(raw.clone());
                    word_groups.push(vec![pattern_ref.clone()]);
                }
            }
        }
        drop(raw_to_group);
        drop(word_patterns_raw);
        drop(word_patterns);

        let word_automaton = if unique_word_raw.is_empty() {
            None
        } else {
            Some(Self::build_word_automaton(&unique_word_raw)?)
        };

        let mut regex_body_patterns = Vec::new();
        let mut regex_body_indices = Vec::new();
        let mut regex_header_patterns = Vec::new();
        let mut regex_header_indices = Vec::new();
        let mut regex_all_patterns = Vec::new();
        let mut regex_all_indices = Vec::new();

        for (index, entry) in regex_matchers.iter().enumerate() {
            match entry.pattern_ref.part {
                MatchPart::Body => {
                    regex_body_patterns
                        .push(patterns[entry.pattern_ref.pattern_index as usize].as_str());
                    regex_body_indices.push(index);
                }
                MatchPart::Header => {
                    regex_header_patterns
                        .push(patterns[entry.pattern_ref.pattern_index as usize].as_str());
                    regex_header_indices.push(index);
                }
                MatchPart::All => {
                    regex_all_patterns
                        .push(patterns[entry.pattern_ref.pattern_index as usize].as_str());
                    regex_all_indices.push(index);
                }
                _ => {}
            }
        }

        // Build RegexSets in chunks to avoid O(n²) DFA state explosion.
        // A single RegexSet::new() with 10K+ patterns can take 120+ seconds.
        // Chunking into groups of 200 keeps compile time under 5 seconds total
        // while maintaining efficient matching (each chunk is its own DFA).
        let build_regex_sets = |patterns: &[&str],
                                indices: &[usize],
                                part_name: &str|
         -> Result<Vec<(RegexSet, Vec<usize>)>> {
            if patterns.is_empty() {
                return Ok(Vec::new());
            }

            // Small sets compile fine as a single RegexSet
            if patterns.len() <= 200 {
                match RegexSet::new(patterns) {
                    Ok(set) => return Ok(vec![(set, indices.to_vec())]),
                    Err(e) => {
                        tracing::debug!(error = %e, part = part_name, "small RegexSet failed");
                    }
                }
            }

            // Chunk into groups of 200 for predictable compile time
            let mut sets = Vec::new();
            let mut invalid: Vec<(String, String)> = Vec::new();
            for (chunk_patterns, chunk_indices) in patterns.chunks(200).zip(indices.chunks(200)) {
                match RegexSet::new(chunk_patterns) {
                    Ok(set) => sets.push((set, chunk_indices.to_vec())),
                    Err(chunk_err) => {
                        // A chunk fails to compile if ANY single pattern in it is
                        // invalid. Recompile each pattern individually - only on
                        // this rare error path, so the normal fast chunked compile
                        // is unaffected - to name the EXACT offending pattern(s)
                        // instead of a bare count. Same bytes engine as the set.
                        tracing::debug!(error = %chunk_err, part = part_name, chunk_size = chunk_patterns.len(), "chunked RegexSet failed; isolating invalid pattern(s)");
                        for pattern in chunk_patterns {
                            if let Err(pattern_err) = regex::bytes::Regex::new(pattern) {
                                invalid.push(((*pattern).to_string(), pattern_err.to_string()));
                            }
                        }
                    }
                }
            }
            if !invalid.is_empty() {
                // Fail closed: a scan missing patterns silently loses recall
                // (Law-10). Report EVERY uncompilable pattern with its exact text
                // and compile error so the operator can fix the specific rule.
                let detail = invalid
                    .iter()
                    .map(|(pattern, error)| format!("`{pattern}` ({error})"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(Error::PatternCompile {
                    pattern: invalid[0].0.clone(),
                    source: format!(
                        "{} uncompilable regex pattern(s) in {part_name} set: {detail}",
                        invalid.len()
                    ),
                });
            }
            Ok(sets)
        };

        let regex_sets_body = build_regex_sets(&regex_body_patterns, &regex_body_indices, "body")?;
        let regex_sets_header =
            build_regex_sets(&regex_header_patterns, &regex_header_indices, "header")?;
        let regex_sets_all = build_regex_sets(&regex_all_patterns, &regex_all_indices, "all")?;

        drop(regex_body_patterns);
        drop(regex_header_patterns);
        drop(regex_all_patterns);

        // Flatten every negative matcher-value once. Negative matchers are
        // inverted (emit on ABSENCE), which the positive scan cannot surface, so
        // they are enumerated here and resolved in a dedicated absence pass in
        // `scan`. Word/binary/regex/status/size matchers are all PatternRef-backed;
        // DSL matchers carry their own def.
        let mut negative_matchers = Vec::new();
        for group in &word_groups {
            for pattern_ref in group {
                collect_negative(pattern_ref, &patterns, &mut negative_matchers);
            }
        }
        for refs in named_word_patterns.values() {
            for pattern_ref in refs {
                collect_negative(pattern_ref, &patterns, &mut negative_matchers);
            }
        }
        for entries in named_binary_matchers.values() {
            for entry in entries {
                collect_negative(&entry.pattern_ref, &patterns, &mut negative_matchers);
            }
        }
        for entry in &regex_matchers {
            collect_negative(&entry.pattern_ref, &patterns, &mut negative_matchers);
        }
        for entries in named_regex_matchers.values() {
            for entry in entries {
                collect_negative(&entry.pattern_ref, &patterns, &mut negative_matchers);
            }
        }
        for refs in status_index.values() {
            for pattern_ref in refs {
                collect_negative(pattern_ref, &patterns, &mut negative_matchers);
            }
        }
        for refs in size_index.values() {
            for pattern_ref in refs {
                collect_negative(pattern_ref, &patterns, &mut negative_matchers);
            }
        }
        for stored in &dsl_matchers {
            if stored.def.negative {
                for (value_index, expression) in stored.def.values.iter().enumerate() {
                    // Value counts were validated during collection, so this
                    // conversion cannot truncate; fail loudly if that
                    // invariant is ever broken rather than attributing the
                    // negative matcher to the wrong value.
                    let value_index_u16 = u16::try_from(value_index).map_err(|_| {
                        Error::TemplateValidation {
                            id: template_ids[stored.template_idx as usize].clone(),
                            reason: format!(
                                "DSL value index {value_index} exceeds 65535; split the matcher into multiple matchers"
                            ),
                        }
                    })?;
                    negative_matchers.push(NegativeMatcher {
                        key: (
                            stored.template_idx,
                            stored.request_index,
                            stored.matcher_index,
                            value_index_u16,
                        ),
                        template_idx: stored.template_idx,
                        request_index: stored.request_index,
                        matcher_index: stored.matcher_index,
                        value_index: value_index_u16,
                        matcher: stored.def.clone(),
                        value: expression.clone(),
                    });
                }
            }
        }

        Ok(Self {
            word_automaton,
            patterns,
            word_groups,
            named_word_patterns,
            named_binary_matchers,
            regex_matchers,
            named_regex_matchers,
            regex_sets_body,
            regex_sets_header,
            regex_sets_all,
            status_index,
            size_index,
            dsl_matchers,
            negative_matchers,
            template_ids,
            template_count: templates.len(),
        })
    }
}

/// Hand-rolled `{,N}` → `{0,N}` rewrite, matching the semantics of the
/// former `\{,(\d+)\}` regex replacement without a lazily compiled static
/// (whose infallible-looking construction required a panic path).
fn fix_brace_quantifiers(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let mut out = String::new();
    let mut copied = 0;
    let mut modified = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' && i + 2 < bytes.len() && bytes[i + 1] == b',' {
            let digits_start = i + 2;
            let mut j = digits_start;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > digits_start && j < bytes.len() && bytes[j] == b'}' {
                out.push_str(&pattern[copied..i]);
                out.push_str("{0,");
                out.push_str(&pattern[digits_start..j]);
                out.push('}');
                copied = j + 1;
                i = j + 1;
                modified = true;
                continue;
            }
        }
        i += 1;
    }
    if !modified {
        return None;
    }
    out.push_str(&pattern[copied..]);
    Some(out)
}

fn pcre_compat_fix(pattern: &str) -> Option<String> {
    let mut fixed = pattern.to_string();
    let mut modified = false;

    // Fix {,N} → {0,N}
    if let Some(replaced) = fix_brace_quantifiers(&fixed) {
        fixed = replaced;
        modified = true;
    }

    // Fix [^] → [\s\S] (PCRE empty negated char class = match any char including newline)
    if fixed.contains("[^]") {
        fixed = fixed.replace("[^]", "[\\s\\S]");
        modified = true;
    }

    // Skip bare { fix if pattern contains template variables ({{var}})
    // Template variables are substituted at runtime, not at compile time.
    if fixed.contains("{{") {
        return if modified { Some(fixed) } else { None };
    }

    // Fix bare { that aren't valid quantifiers.
    let chars: Vec<char> = fixed.chars().collect();
    let mut i = 0;
    let mut new_chars = Vec::new();

    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            new_chars.push(chars[i]);
            new_chars.push(chars[i + 1]);
            i += 2;
            continue;
        }

        if chars[i] == '{' {
            let mut j = i + 1;
            let mut is_valid = false;
            let mut num_commas = 0;
            let mut num_digits = 0;

            while j < chars.len() {
                if chars[j].is_ascii_digit() {
                    num_digits += 1;
                } else if chars[j] == ',' {
                    num_commas += 1;
                } else if chars[j] == '}' {
                    if num_digits > 0 && num_commas <= 1 {
                        is_valid = true;
                    }
                    break;
                } else {
                    break;
                }
                j += 1;
            }

            if !is_valid {
                new_chars.push('\\');
                modified = true;
            }
        }
        new_chars.push(chars[i]);
        i += 1;
    }

    let final_fixed: String = new_chars.into_iter().collect();

    if modified { Some(final_fixed) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference implementation: the original char-by-char escape. The batched
    // version must produce byte-identical output because regex::escape is
    // char-local (escaping a run == concatenating per-char escapes).
    fn template_var_regex_pattern_charwise(pattern: &str) -> String {
        let mut out = String::new();
        let bytes = pattern.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'{' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                if let Some(end) = pattern[i + 2..].find("}}") {
                    out.push_str(".+");
                    i += 2 + end + 2;
                    continue;
                }
            }
            let ch = pattern[i..].chars().next().unwrap();
            out.push_str(&regex::escape(ch.encode_utf8(&mut [0; 4])));
            i += ch.len_utf8();
        }
        out
    }

    #[test]
    fn template_var_regex_pattern_batches_but_stays_identical() {
        let cases = [
            "hello-{{suffix}}",
            "a.b+c*d?{{x}}(e)[f]|g^h${{y}}\\z",
            "{{only_hole}}",
            "no-holes.at.all+plus",
            "café-{{ünïcode}}-π", // multibyte literal + hole
            "trailing{{",         // unterminated hole -> treated as literal
            "",
        ];
        for p in cases {
            let batched = template_var_regex_pattern(p);
            let reference = template_var_regex_pattern_charwise(p);
            assert_eq!(batched, reference, "mismatch for pattern {p:?}");
            // And the escaped literals must actually compile as a regex.
            assert!(
                regex::Regex::new(&batched).is_ok(),
                "produced invalid regex for {p:?}: {batched}"
            );
        }
    }

    use secir::matcher::MatchDatabase;
    use secir::template::{
        MatchPart, MatcherCondition, MatcherDef, MatcherKind, RequestDef, Template, TemplateInfo,
        TemplateMeta,
    };
    use secir::{Protocol, Severity};
    use std::collections::HashMap;

    fn create_test_template(id: &str, matchers: Vec<MatcherDef>) -> Template {
        Template {
            depends_on: vec![],
            id: id.to_string(),
            ir_version: 1,
            extends: None,
            imports: vec![],
            info: TemplateInfo {
                name: id.to_string(),
                author: vec!["test".to_string()],
                severity: Severity::Info,
                description: None,
                reference: vec![],
                tags: vec![],
                metadata: TemplateMeta::default(),
            },
            requests: vec![RequestDef {
                call: None,
                compute: vec![],
                method: "GET".to_string(),
                raw: None,
                paths: vec!["{{BaseURL}}".to_string()],
                headers: HashMap::new(),
                body: None,
                port: None,
                inputs: vec![],
                payloads: HashMap::new(),
                attack: secir::AttackType::BatteringRam,
                matchers,
                matchers_condition: MatcherCondition::Or,
                extractors: vec![],
                redirects: true,
                max_redirects: 10,
                stop_at_first_match: false,
                encoding: None,
                differential: false,
                max_response_time_ms: None,
                cookie_reuse: false,
                condition: None,
                iterate: None,
                transforms: vec![],
                label: None,
                goto: None,
                headless_actions: vec![],
            }],
            protocol: Protocol::Http,
            self_contained: false,
            variables: HashMap::new(),
            cli_variables: HashMap::new(),
            source_path: None,
            flow: None,
            workflows: vec![],
            extensions: HashMap::new(),
            parallel_groups: vec![],
            exports: vec![],
        }
    }

    fn create_word_matcher(values: Vec<String>) -> MatcherDef {
        MatcherDef {
            kind: MatcherKind::Word,
            values,
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }
    }

    fn create_regex_matcher(patterns: Vec<String>) -> MatcherDef {
        MatcherDef {
            kind: MatcherKind::Regex,
            values: patterns,
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }
    }

    fn create_status_matcher(codes: Vec<String>) -> MatcherDef {
        MatcherDef {
            kind: MatcherKind::Status,
            values: codes,
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }
    }

    fn create_binary_matcher(hex_values: Vec<String>) -> MatcherDef {
        MatcherDef {
            kind: MatcherKind::Binary,
            values: hex_values,
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }
    }

    #[test]
    fn verify_runtime_regex_with_variables_is_not_silently_dropped() {
        let matcher = create_regex_matcher(vec![r"hello-{{suffix}}".to_string()]);
        let template = create_test_template("runtime-regex", vec![matcher]);
        let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");
        let response = secir::matcher::ResponseData::new(200, vec![], b"hello-world".to_vec());
        let matches = db.scan(&response).expect("scan should succeed");
        assert!(
            !matches.is_empty(),
            "regex matchers containing template variables must be evaluated at runtime"
        );
    }

    #[test]
    fn test_pcre_compat_fix() {
        assert_eq!(pcre_compat_fix("a{,60}b").unwrap(), "a{0,60}b");
        assert_eq!(pcre_compat_fix("^{foo").unwrap(), "^\\{foo");
        assert_eq!(pcre_compat_fix("a{1,2}b"), None);
        assert_eq!(pcre_compat_fix("a{1,}b"), None);
        assert_eq!(pcre_compat_fix("a{1}b"), None);
        assert_eq!(pcre_compat_fix("\\{foo"), None);
        // [^] → [\s\S] (PCRE empty negated class)
        assert_eq!(
            pcre_compat_fix("[^]{0,128}?src").unwrap(),
            "[\\s\\S]{0,128}?src"
        );
        assert_eq!(pcre_compat_fix("[^a]"), None); // normal negated class  -  don't touch
    }

    #[test]
    fn pcre_compat_fix_boundaries_and_empty() {
        // Empty and no-op inputs return None (no change).
        assert_eq!(pcre_compat_fix(""), None);
        assert_eq!(pcre_compat_fix("abc\\d+xyz"), None);
        assert_eq!(pcre_compat_fix("(foo|bar)+"), None);

        // Bare `{` that is not a valid quantifier gets escaped.
        assert_eq!(pcre_compat_fix("{").unwrap(), "\\{");
        assert_eq!(pcre_compat_fix("{}").unwrap(), "\\{}");
        assert_eq!(pcre_compat_fix("{abc}").unwrap(), "\\{abc}");
        // `{,}` has no digits so it is NOT the {,N} rule and NOT a valid
        // quantifier -> the bare-brace escaper handles it.
        assert_eq!(pcre_compat_fix("{,}").unwrap(), "\\{,}");
        // `{a}` first char is a non-digit non-comma -> invalid -> escaped.
        assert_eq!(pcre_compat_fix("x{a}").unwrap(), "x\\{a}");

        // Valid quantifiers (incl. open-ended {N,}) are left untouched.
        assert_eq!(pcre_compat_fix("a{2,}b"), None);
        assert_eq!(pcre_compat_fix("a{0,128}?"), None);
        // An already-escaped brace must not be double-escaped.
        assert_eq!(pcre_compat_fix("\\{,}"), None);
        assert_eq!(pcre_compat_fix("a\\{b\\}c"), None);

        // {,N} with a leading zero / multi-digit / single-digit.
        assert_eq!(pcre_compat_fix("a{,0}").unwrap(), "a{0,0}");
        assert_eq!(pcre_compat_fix("a{,007}").unwrap(), "a{0,007}");
    }

    #[test]
    fn pcre_compat_fix_template_vars_and_combined() {
        // A pattern with template vars ({{var}}) skips the bare-{ escaper but
        // STILL applies the {,N} and [^] rewrites; the {{var}} braces stay.
        assert_eq!(pcre_compat_fix("{{host}}"), None);
        assert_eq!(
            pcre_compat_fix("a{,5}{{host}}").unwrap(),
            "a{0,5}{{host}}"
        );
        // Combined: {,N} + [^] + a bare invalid brace in ONE pattern.
        assert_eq!(
            pcre_compat_fix("x{,3}[^]{bad}").unwrap(),
            "x{0,3}[\\s\\S]\\{bad}"
        );
    }

    #[test]
    fn pcre_compat_fix_outputs_compile_as_regex() {
        // The entire purpose of the fix is to turn PCRE-isms that the Rust regex
        // engine rejects into equivalents it accepts. Every rewritten output MUST
        // compile with the same engine used to scan (regex::bytes).
        let inputs = [
            "a{,60}b",
            "^{foo",
            "[^]{0,128}?src",
            "{",
            "{}",
            "{abc}",
            "{,}",
            "x{a}",
            "a{,0}",
            "a{,007}",
            "x{,3}[^]{bad}",
            "a{,5}{{host}}",
        ];
        for input in inputs {
            let Some(fixed) = pcre_compat_fix(input) else {
                panic!("expected {input:?} to be rewritten");
            };
            // The template-var case still contains {{host}} which is substituted
            // before compilation; skip the compile check for that one.
            if fixed.contains("{{") {
                continue;
            }
            assert!(
                regex::bytes::Regex::new(&fixed).is_ok(),
                "rewritten pattern {fixed:?} (from {input:?}) must compile"
            );
        }
    }

    // Test 1: Template with 10,000 word patterns
    #[test]
    fn template_with_10000_word_patterns() {
        let values: Vec<String> = (0..10000).map(|i| format!("pattern{}", i)).collect();
        let matcher = create_word_matcher(values);
        let template = create_test_template("many-patterns", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 10000);
    }

    // Test 2: Template with regex that takes exponential time
    #[test]
    fn template_with_slow_regex() {
        // This regex can cause catastrophic backtracking on certain inputs
        let evil_regex = r"(a+)+$";
        let matcher = create_regex_matcher(vec![evil_regex.to_string()]);
        let template = create_test_template("slow-regex", vec![matcher]);

        // Should compile successfully (the regex library handles it)
        let result = CompiledDatabase::compile(&[template]);
        assert!(result.is_ok());
    }

    // Test 3: Template with empty matcher values
    #[test]
    fn template_with_empty_matcher_values() {
        let matcher = create_word_matcher(vec!["".to_string(), "valid".to_string()]);
        let template = create_test_template("empty-values", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        // Empty values should be skipped
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 1); // Only "valid" should be counted
    }

    // Test 4: Binary matcher with invalid hex
    #[test]
    fn binary_matcher_with_invalid_hex() {
        let matcher = create_binary_matcher(vec![
            "48656c6c6f".to_string(), // Valid "Hello"
            "GGHHIIJJ".to_string(),   // Invalid hex
            "776f726c64".to_string(), // Valid "world"
        ]);
        let template = create_test_template("binary-invalid", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        // Should fail due to invalid hex
        assert!(result.is_err());
    }

    // Test 5: Mixed word and regex matchers on same template
    #[test]
    fn mixed_word_and_regex_matchers_same_template() {
        let word_matcher = create_word_matcher(vec!["admin".to_string(), "login".to_string()]);
        let regex_matcher = create_regex_matcher(vec![r"\d{4}-\d{2}-\d{2}".to_string()]);

        let template = create_test_template("mixed-matchers", vec![word_matcher, regex_matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        // Should have both word and regex patterns
        assert!(db.pattern_count() >= 3);
    }

    // Test 6: Status matcher with non-numeric value
    #[test]
    fn status_matcher_with_non_numeric_value() {
        let matcher = create_status_matcher(vec![
            "200".to_string(),
            "not-a-number".to_string(),
            "404".to_string(),
        ]);
        let template = create_test_template("status-invalid", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        let error = match result {
            Ok(_) => panic!("expected invalid status code to fail compilation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("invalid status code 'not-a-number'"));
        assert!(error.contains("Use an integer HTTP status such as 200 or 404."));
    }

    // ==================================================================
    // NEW TESTS - 15 additional tests for comprehensive compile coverage
    // ==================================================================

    // Test 7: Compile 5000 word patterns
    #[test]
    fn compile_5000_word_patterns() {
        let values: Vec<String> = (0..5000).map(|i| format!("word-pattern-{}", i)).collect();
        let matcher = create_word_matcher(values);
        let template = create_test_template("5000-words", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 5000);
    }

    // Test 8: Compile 1000 regex patterns
    #[test]
    fn compile_1000_regex_patterns() {
        let patterns: Vec<String> = (0..1000)
            .map(|i| format!(r"pattern{}-\d{{3}}", i))
            .collect();
        let matcher = create_regex_matcher(patterns);
        let template = create_test_template("1000-regex", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 1000);
    }

    // Test 9: PCRE compat {,N} fix
    #[test]
    fn pcre_compat_brace_n_fix() {
        // {,N} should become {0,N}
        let fixed = pcre_compat_fix("a{,60}b");
        assert_eq!(fixed, Some("a{0,60}b".to_string()));

        // Valid quantifiers should not be modified
        assert_eq!(pcre_compat_fix("a{1,2}b"), None);
        assert_eq!(pcre_compat_fix("a{1,}b"), None);
        assert_eq!(pcre_compat_fix("a{5}b"), None);
    }

    // Test 10: PCRE compat [^] fix
    #[test]
    fn pcre_compat_empty_negated_class_fix() {
        // [^] should become [\s\S] to match any char including newline
        let fixed = pcre_compat_fix("[^]{0,128}?src");
        assert_eq!(fixed, Some(r"[\s\S]{0,128}?src".to_string()));

        // Normal negated class should not be touched
        assert_eq!(pcre_compat_fix("[^a-z]"), None);
        assert_eq!(pcre_compat_fix("[^\\n]"), None);
    }

    // Test 11: Template with all matcher types
    #[test]
    fn template_with_all_matcher_types() {
        let word_matcher = create_word_matcher(vec!["admin".to_string(), "login".to_string()]);
        let regex_matcher = create_regex_matcher(vec![r"\d{4}-\d{2}-\d{2}".to_string()]);
        let status_matcher = create_status_matcher(vec!["200".to_string(), "301".to_string()]);
        let binary_matcher = create_binary_matcher(vec!["48656c6c6f".to_string()]);

        let template = create_test_template(
            "all-matchers",
            vec![word_matcher, regex_matcher, status_matcher, binary_matcher],
        );

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        // Should have patterns from all matchers
        assert!(db.pattern_count() >= 6);
    }

    // Test 12: Empty template list
    #[test]
    fn empty_template_list() {
        let templates: Vec<Template> = vec![];

        let result = CompiledDatabase::compile(&templates);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 0);
        assert_eq!(db.template_count(), 0);
    }

    // Test 13: Template with 100 matchers
    #[test]
    fn template_with_100_matchers() {
        let matchers: Vec<_> = (0..100)
            .map(|i| create_word_matcher(vec![format!("pattern{}", i)]))
            .collect();

        let template = create_test_template("100-matchers", matchers);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 100);
    }

    // Test 14: Regex with template variables deferred
    #[test]
    fn regex_with_template_variables_deferred() {
        // Pattern with template variable should be skipped during compilation
        let matcher = create_regex_matcher(vec![
            r"^User: {{username}}$".to_string(),
            r"fixed-pattern".to_string(),
        ]);
        let template = create_test_template("deferred-regex", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        // Template-variable regex compiles as runtime hole-expanded pattern + fixed literal.
        assert_eq!(db.pattern_count(), 2);
    }

    // Test 15: Binary pattern compilation
    #[test]
    fn binary_pattern_compilation() {
        let matcher = create_binary_matcher(vec![
            "48656c6c6f".to_string(), // "Hello"
            "576f726c64".to_string(), // "World"
            "FFD8FFE0".to_string(),   // JPEG magic bytes
        ]);
        let template = create_test_template("binary-patterns", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 3);
    }

    // Test 16: Status matcher with multiple values
    #[test]
    fn status_matcher_multiple_values() {
        let matcher = create_status_matcher(vec![
            "200".to_string(),
            "201".to_string(),
            "301".to_string(),
            "302".to_string(),
            "401".to_string(),
            "403".to_string(),
            "404".to_string(),
            "500".to_string(),
        ]);
        let template = create_test_template("status-multi", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 8);
    }

    // Test 17: Hex decode with spaces
    #[test]
    fn hex_decode_with_spaces() {
        // hex_decode should handle spaces in hex string
        let matcher = create_binary_matcher(vec![
            "48 65 6c 6c 6f".to_string(), // "Hello" with spaces
        ]);
        let template = create_test_template("hex-spaces", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 1);
    }

    // Test 18: Empty matcher values skipped
    #[test]
    fn empty_matcher_values_skipped() {
        let matcher = create_word_matcher(vec![
            "".to_string(), // Empty
            "valid1".to_string(),
            "".to_string(), // Empty
            "valid2".to_string(),
            "".to_string(), // Empty
        ]);
        let template = create_test_template("empty-skipped", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 2);
    }

    // Test 19: Multiple templates compiled together
    #[test]
    fn multiple_templates_compiled_together() {
        let template1 = create_test_template(
            "t1",
            vec![create_word_matcher(vec![
                "word1".to_string(),
                "word2".to_string(),
            ])],
        );
        let template2 =
            create_test_template("t2", vec![create_regex_matcher(vec![r"\d+".to_string()])]);
        let template3 =
            create_test_template("t3", vec![create_status_matcher(vec!["200".to_string()])]);

        let result = CompiledDatabase::compile(&[template1, template2, template3]);

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.template_count(), 3);
        assert_eq!(db.pattern_count(), 4); // 2 + 1 + 1
    }

    // Test 20: Invalid regex patterns handled gracefully
    #[test]
    fn invalid_regex_patterns_handled() {
        let matcher = create_regex_matcher(vec![
            r"valid-pattern".to_string(),
            r"(unclosed paren".to_string(), // Invalid
            r"another-valid".to_string(),
            r"[invalid range z-a]".to_string(), // Invalid
        ]);
        let template = create_test_template("invalid-regex", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        let error = match result {
            Ok(_) => panic!("expected invalid regex patterns to fail compilation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("invalid regex"));
        assert!(error.contains("Fix the pattern"));
    }

    // Test 21: Bare brace escape fix
    #[test]
    fn bare_brace_escape_fix() {
        // Bare { should be escaped
        let fixed = pcre_compat_fix("^{foo}");
        assert_eq!(fixed, Some(r"^\{foo}".to_string()));

        // Already escaped should not be modified
        assert_eq!(pcre_compat_fix(r"\{foo}"), None);
    }

    // Test 22: Combined PCRE fixes
    #[test]
    fn combined_pcre_fixes() {
        // Pattern with both issues
        let fixed = pcre_compat_fix("[^{,10}]");
        // [^] -> [\s\S], {,10} -> {0,10}
        assert!(fixed.is_some());
    }

    // Test 23: Binary pattern with odd hex length
    #[test]
    fn binary_pattern_odd_hex_length() {
        // Odd number of hex digits should fail
        let matcher = create_binary_matcher(vec![
            "48656".to_string(), // 5 chars - odd
        ]);
        let template = create_test_template("odd-hex", vec![matcher]);

        let result = CompiledDatabase::compile(&[template]);

        // Should fail due to invalid hex
        assert!(result.is_err());
    }

    // Test 24: Template with DSL matcher
    #[test]
    fn template_with_dsl_matcher() {
        use secir::template::{MatchPart, MatcherCondition, MatcherDef, MatcherKind};

        let dsl_matcher = MatcherDef {
            kind: MatcherKind::Dsl,
            values: vec!["status_code == 200".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        };

        let template = create_test_template("dsl-matcher", vec![dsl_matcher]);

        let result = CompiledDatabase::compile(&[template]);

        assert!(result.is_ok());
        // DSL matchers are stored separately
    }

    // Test 25: Large batch compilation performance
    #[test]
    fn large_batch_compilation_performance() {
        let templates: Vec<Template> = (0..100)
            .map(|i| {
                let matcher =
                    create_word_matcher((0..50).map(|j| format!("pattern-{}-{}", i, j)).collect());
                create_test_template(&format!("template-{}", i), vec![matcher])
            })
            .collect();

        let start = std::time::Instant::now();
        let result = CompiledDatabase::compile(&templates);
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.pattern_count(), 5000);
        // Should complete in reasonable time (5000ms budget for debug builds)
        assert!(
            elapsed.as_millis() < 5000,
            "Compilation took too long: {:?}",
            elapsed
        );
    }
}

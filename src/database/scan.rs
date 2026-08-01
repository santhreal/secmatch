use super::{CompiledDatabase, SeenMatches};
use crate::dsl::evaluate_dsl;
use secir::matcher::{Match, MatchDatabase, ResponseData};
use secir::template::MatchPart;

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

impl MatchDatabase for CompiledDatabase {
    fn scan(&self, response: &ResponseData) -> secir::Result<Vec<Match>> {
        let status_match_count = self
            .status_index
            .get(&response.status)
            .map_or(0, Vec::len)
            .min(8);
        let size_match_count = self
            .size_index
            .get(&response.content_length)
            .map_or(0, Vec::len)
            .min(8);
        let estimated_capacity = self
            .word_groups
            .len()
            .min(32)
            .saturating_add(self.regex_matchers.len().min(24))
            .saturating_add(self.dsl_matchers.len().min(8))
            .saturating_add(status_match_count)
            .saturating_add(size_match_count);
        let mut matches = Vec::with_capacity(estimated_capacity);
        let mut seen = SeenMatches::new();
        // Keys of negative matchers whose pattern was PRESENT. A present negative
        // matcher does not fire, so the absence pass at the end must skip it.
        let mut fired = SeenMatches::new();

        if let Some(automaton) = &self.word_automaton {
            // Scan the combined headers+body buffer once. Each match is dispatched
            // to the correct `MatchPart` based on its byte offset, avoiding three
            // redundant Aho-Corasick scans over overlapping views.
            let all = response.all_bytes();
            let header_len = response.headers.len();
            // Overlapping search: two word patterns sharing a start position
            // (for example `password` and `password123`) must BOTH report.
            // Plain `find_iter` (any match kind) reports at most one pattern
            // per start position, silently dropping the other (Law-10).
            for found in automaton.find_overlapping_iter(all) {
                for pattern_ref in &self.word_groups[found.pattern().as_usize()] {
                    let (should_record, offset) = match pattern_ref.part {
                        MatchPart::All => (true, found.start()),
                        MatchPart::Header if found.end() <= header_len => (true, found.start()),
                        MatchPart::Body if found.start() >= header_len => {
                            (true, found.start() - header_len)
                        }
                        _ => (false, 0),
                    };
                    if should_record {
                        self.record_hit(
                            pattern_ref,
                            offset,
                            || self.pattern(pattern_ref).to_string(),
                            &mut matches,
                            &mut seen,
                            &mut fired,
                        );
                    }
                }
            }
        }

        for (header_name, header_index) in &response.header_index {
            let Some((_, header_value)) = response.header_map.get(*header_index) else {
                continue;
            };

            if let Some(pattern_refs) = self.named_word_patterns.get(header_name) {
                for pattern_ref in pattern_refs {
                    if contains_ascii_case_insensitive(header_value, self.pattern(pattern_ref)) {
                        self.record_hit(
                            pattern_ref,
                            0,
                            || self.pattern(pattern_ref).to_string(),
                            &mut matches,
                            &mut seen,
                            &mut fired,
                        );
                    }
                }
            }

            if let Some(entries) = self.named_regex_matchers.get(header_name) {
                for entry in entries {
                    // `regex` is now a byte regex; match against the header value's
                    // bytes and recover the matched text lossily.
                    if let Some(found) = entry.regex.find(header_value.as_bytes()) {
                        self.record_hit(
                            &entry.pattern_ref,
                            found.start(),
                            || String::from_utf8_lossy(found.as_bytes()).into_owned(),
                            &mut matches,
                            &mut seen,
                            &mut fired,
                        );
                    }
                }
            }
        }

        for (regex_set, indices) in &self.regex_sets_body {
            self.regex_set_scan(
                regex_set,
                indices,
                &response.body,
                &mut matches,
                &mut seen,
                &mut fired,
                response,
            );
        }
        for (regex_set, indices) in &self.regex_sets_header {
            self.regex_set_scan(
                regex_set,
                indices,
                &response.headers,
                &mut matches,
                &mut seen,
                &mut fired,
                response,
            );
        }
        for (regex_set, indices) in &self.regex_sets_all {
            self.regex_set_scan(
                regex_set,
                indices,
                response.all_bytes(),
                &mut matches,
                &mut seen,
                &mut fired,
                response,
            );
        }

        if let Some(patterns) = self.status_index.get(&response.status) {
            for pattern_ref in patterns {
                self.record_hit(
                    pattern_ref,
                    0,
                    || self.pattern(pattern_ref).to_string(),
                    &mut matches,
                    &mut seen,
                    &mut fired,
                );
            }
        }

        if let Some(patterns) = self.size_index.get(&response.content_length) {
            for pattern_ref in patterns {
                self.record_hit(
                    pattern_ref,
                    0,
                    || self.pattern(pattern_ref).to_string(),
                    &mut matches,
                    &mut seen,
                    &mut fired,
                );
            }
        }

        for stored in &self.dsl_matchers {
            for (value_index, expression) in stored.def.values.iter().enumerate() {
                if !evaluate_dsl(expression, response) {
                    continue;
                }
                // Value counts were validated at compile time, so this cannot
                // truncate; fail the scan loudly if that invariant is broken
                // instead of keying the dedup on the wrong value index.
                let value_index_u16 = u16::try_from(value_index).map_err(|_| {
                    secir::Error::MatchScan {
                        reason: format!(
                            "DSL value index {value_index} exceeds 65535 during scan"
                        ),
                    }
                })?;
                let key = (
                    stored.template_idx,
                    stored.request_index,
                    stored.matcher_index,
                    value_index_u16,
                );
                if stored.def.negative {
                    // The DSL expression is TRUE, so this negative matcher does
                    // not fire; record it so the absence pass skips it.
                    Self::insert_seen(&mut fired, key);
                } else if Self::insert_seen(&mut seen, key) {
                    matches.push(Match {
                        template_id: self.template_id(stored.template_idx).to_string(),
                        request_index: stored.request_index as usize,
                        matcher_index: stored.matcher_index as usize,
                        value_index,
                        matcher: stored.def.clone(),
                        matched_value: expression.clone(),
                        offset: 0,
                        negative: false,
                    });
                }
            }
        }

        // Absence pass: every negative matcher whose pattern did NOT fire above
        // emits an inverted match. This is the only place a negative matcher can
        // produce output, and the positive phases never emit for negatives, so a
        // key here cannot collide with a positive emission.
        for negative in &self.negative_matchers {
            if !fired.contains(&negative.key) && Self::insert_seen(&mut seen, negative.key) {
                matches.push(self.emit_negative(negative));
            }
        }

        Ok(matches)
    }

    fn pattern_count(&self) -> usize {
        self.word_groups.iter().map(Vec::len).sum::<usize>()
            + self
                .named_word_patterns
                .values()
                .map(Vec::len)
                .sum::<usize>()
            + self.regex_matchers.len()
            + self
                .named_regex_matchers
                .values()
                .map(Vec::len)
                .sum::<usize>()
            + self.status_index.values().map(Vec::len).sum::<usize>()
            + self.size_index.values().map(Vec::len).sum::<usize>()
            + self
                .dsl_matchers
                .iter()
                .map(|matcher| matcher.def.values.len())
                .sum::<usize>()
    }

    fn template_count(&self) -> usize {
        self.template_count
    }
}

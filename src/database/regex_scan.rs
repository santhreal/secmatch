use super::{CompiledDatabase, SeenMatches};
use regex::bytes::RegexSet;
use secir::matcher::{Match, ResponseData};
use std::collections::HashSet;

impl CompiledDatabase {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn regex_set_scan(
        &self,
        regex_set: &RegexSet,
        regex_indices: &[usize],
        bytes: &[u8],
        matches: &mut Vec<Match>,
        seen: &mut SeenMatches,
        fired: &mut SeenMatches,
        _response: &ResponseData,
    ) {
        // Scan the raw bytes with a byte-oriented RegexSet. A non-UTF-8 response
        // segment must NOT abort the scan (the previous `from_utf8` gate silently
        // skipped the ENTIRE set, an invisible recall loss on binary/mixed
        // bodies, Law-10). Byte regexes still match the valid-UTF-8 content and
        // simply do not match across invalid bytes.
        for matched in &regex_set.matches(bytes) {
            let entry = &self.regex_matchers[regex_indices[matched]];
            let pattern_ref = &entry.pattern_ref;

            // A negative regex that matched means the matcher does not fire;
            // record it so the absence pass suppresses its inverted match.
            if pattern_ref.negative {
                Self::insert_seen(fired, pattern_ref.dedup_key());
                continue;
            }

            if !Self::insert_seen(seen, pattern_ref.dedup_key()) {
                continue;
            }

            // A regex can match several times; emit each DISTINCT matched value
            // once (dedup by matched TEXT). The same value repeated in the body,
            // or present in both the header and body under MatchPart::All,
            // collapses to a single result, while genuinely different values
            // (e.g. `\d+` over "1 2 3" -> "1","2","3") each produce a result.
            // This is the unified emission contract shared with the word path
            // (one result per distinct matched value) and the correct scanning
            // contract: report every distinct value, never the same one twice.
            let mut emitted: HashSet<&[u8]> = HashSet::new();
            for found in entry.regex.find_iter(bytes) {
                if !emitted.insert(found.as_bytes()) {
                    continue;
                }
                matches.push(self.emit_match(
                    pattern_ref,
                    String::from_utf8_lossy(found.as_bytes()).into_owned(),
                    found.start(),
                ));
            }
        }
    }
}

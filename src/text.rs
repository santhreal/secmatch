//! Shared text-based matching logic used by all non-HTTP protocol scanners.
//!
//! DNS, TCP, SSL, Code, File, Whois, and WebSocket crates all perform the same
//! matcher evaluation against text/byte responses. This module eliminates the
//! duplication by providing generic matching functions that operate on `&str`.

use secir::template::{MatchPart, MatcherCondition, MatcherDef, MatcherKind, RequestDef};
use std::collections::HashSet;

/// Check whether all matchers on a request are satisfied against the given text.
///
/// Returns `false` if the request has no matchers (prevents false positives).
#[must_use]
pub fn request_matches_text(request: &RequestDef, text: &str) -> bool {
    if request.matchers.is_empty() {
        return false;
    }

    match request.matchers_condition {
        MatcherCondition::And => request
            .matchers
            .iter()
            .all(|m| matcher_satisfied_text(m, text)),
        MatcherCondition::Or | _ => request
            .matchers
            .iter()
            .any(|m| matcher_satisfied_text(m, text)),
    }
}

/// Collect all matched values from non-internal matchers that are satisfied.
#[must_use]
pub fn collect_matched_values_text(request: &RequestDef, text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();

    for matcher in &request.matchers {
        if matcher.internal || !matcher_satisfied_text(matcher, text) {
            continue;
        }
        for matched in matcher_values_text(matcher, text) {
            if seen.insert(matched.clone()) {
                values.push(matched);
            }
        }
    }

    values
}

/// Check whether a single matcher is satisfied against text.
#[must_use]
pub fn matcher_satisfied_text(matcher: &MatcherDef, text: &str) -> bool {
    let hit_count = matcher_values_text(matcher, text).len();
    let positive = match matcher.condition {
        MatcherCondition::And => !matcher.values.is_empty() && hit_count == matcher.values.len(),
        MatcherCondition::Or => hit_count > 0,
        _ => hit_count > 0,
    };

    if matcher.negative {
        !positive
    } else {
        positive
    }
}

/// Return all values from a matcher that match against the given text.
#[must_use]
pub fn matcher_values_text(matcher: &MatcherDef, text: &str) -> Vec<String> {
    match matcher.part {
        MatchPart::Body | MatchPart::All => {}
        MatchPart::Header | MatchPart::Named(_) => {
            // Raw text matching (non-HTTP protocol scanners) operates on body payload text.
            // Matchers targeting header or named header parts cannot match raw text without
            // structured header data; fail closed to avoid matching header patterns against body text.
            return Vec::new();
        }
        _ => {
            // Fail closed on unhandled non-exhaustive MatchPart variants.
            return Vec::new();
        }
    }
    match matcher.kind {
        MatcherKind::Word => {
            let bytes = text.as_bytes();
            matcher
                .values
                .iter()
                .filter(|v| {
                    if v.is_empty() {
                        return false;
                    }
                    let needle = v.as_bytes();
                    if needle.len() > bytes.len() {
                        return false;
                    }
                    bytes
                        .windows(needle.len())
                        .any(|w| w.eq_ignore_ascii_case(needle))
                })
                .cloned()
                .collect()
        }
        MatcherKind::Regex => matcher
            .values
            .iter()
            .filter_map(|v| {
                crate::dsl::cache::cached_regex(v)
                    .ok()?
                    .find(text)
                    .map(|m| m.as_str().to_string())
            })
            .collect(),
        MatcherKind::Status => {
            // Status matching: parse text for a numeric status code.
            // Protocols provide the status in different ways  -  this handles
            // the common case where the status is passed as the text itself
            // or where protocol-specific handling has already been done.
            matcher
                .values
                .iter()
                .filter(|v| text.contains(v.as_str()))
                .cloned()
                .collect()
        }
        MatcherKind::Size => {
            let size = text.len();
            matcher
                .values
                .iter()
                .filter(|v| v.parse::<usize>().ok() == Some(size))
                .cloned()
                .collect()
        }
        MatcherKind::Binary => {
            let bytes = text.as_bytes();
            matcher
                .values
                .iter()
                .filter(|v| {
                    let cleaned = v.trim().replace(' ', "");
                    if let Ok(needle) = hex::decode(cleaned) {
                        if needle.is_empty() || needle.len() > bytes.len() {
                            return false;
                        }
                        bytes.windows(needle.len()).any(|w| w == needle)
                    } else {
                        false
                    }
                })
                .cloned()
                .collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secir::template::MatchPart;

    fn word_matcher(value: &str) -> MatcherDef {
        MatcherDef {
            kind: MatcherKind::Word,
            values: vec![value.to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }
    }

    fn regex_matcher(value: &str) -> MatcherDef {
        MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![value.to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }
    }

    #[test]
    fn word_match_case_insensitive() {
        assert!(matcher_satisfied_text(
            &word_matcher("nginx"),
            "Server: Nginx/1.25"
        ));
        assert!(!matcher_satisfied_text(
            &word_matcher("apache"),
            "Server: Nginx/1.25"
        ));
    }

    #[test]
    fn regex_match_extracts_value() {
        let values = matcher_values_text(&regex_matcher(r"nginx/(\d+\.\d+)"), "Server: nginx/1.25");
        assert_eq!(values, vec!["nginx/1.25"]);
    }

    #[test]
    fn negative_matcher_inverts() {
        let mut matcher = word_matcher("error");
        matcher.negative = true;
        assert!(matcher_satisfied_text(&matcher, "all good"));
        assert!(!matcher_satisfied_text(&matcher, "error occurred"));
    }

    #[test]
    fn and_condition_requires_all() {
        let matcher = MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["hello".to_string(), "world".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        };
        assert!(matcher_satisfied_text(&matcher, "hello world"));
        assert!(!matcher_satisfied_text(&matcher, "hello there"));
    }

    #[test]
    fn size_matcher() {
        let matcher = MatcherDef {
            kind: MatcherKind::Size,
            values: vec!["5".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        };
        assert!(matcher_satisfied_text(&matcher, "hello"));
        assert!(!matcher_satisfied_text(&matcher, "hi"));
    }

    #[test]
    fn empty_matchers_returns_false() {
        use secir::template::AttackType;
        let request = RequestDef {
            method: "GET".to_string(),
            raw: None,
            paths: vec![],
            headers: std::collections::HashMap::new(),
            body: None,
            port: None,
            inputs: Vec::new(),
            payloads: std::collections::HashMap::new(),
            attack: AttackType::BatteringRam,
            matchers: vec![],
            matchers_condition: MatcherCondition::Or,
            extractors: vec![],
            redirects: false,
            max_redirects: 0,
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
            call: None,
            compute: vec![],
        };
        assert!(!request_matches_text(&request, "anything"));
    }

    #[test]
    fn collect_skips_internal_matchers() {
        use secir::template::AttackType;
        let request = RequestDef {
            method: "GET".to_string(),
            raw: None,
            paths: vec![],
            headers: std::collections::HashMap::new(),
            body: None,
            port: None,
            inputs: Vec::new(),
            payloads: std::collections::HashMap::new(),
            attack: AttackType::BatteringRam,
            matchers: vec![MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["secret".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: true,
            }],
            matchers_condition: MatcherCondition::Or,
            extractors: vec![],
            redirects: false,
            max_redirects: 0,
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
            call: None,
            compute: vec![],
        };
        assert_eq!(
            collect_matched_values_text(&request, "secret data").len(),
            0,
            "internal-only matchers should not collect matched values"
        );
    }

    #[test]
    fn match_part_header_or_named_fails_closed_on_raw_text() {
        let header_matcher = MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string()],
            part: MatchPart::Header,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        };
        let named_matcher = MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string()],
            part: MatchPart::Named("server".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        };
        assert!(matcher_values_text(&header_matcher, "Server: nginx").is_empty());
        assert!(matcher_values_text(&named_matcher, "Server: nginx").is_empty());
        assert!(!matcher_satisfied_text(&header_matcher, "Server: nginx"));
        assert!(!matcher_satisfied_text(&named_matcher, "Server: nginx"));
    }

    #[test]
    fn binary_matcher_matches_hex_values_on_raw_text() {
        let binary_matcher = MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["504f5354".to_string()], // "POST" in hex
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        };
        assert_eq!(
            matcher_values_text(&binary_matcher, "POST /api/v1 HTTP/1.1"),
            vec!["504f5354".to_string()]
        );
        assert!(matcher_satisfied_text(&binary_matcher, "POST /api/v1 HTTP/1.1"));
        assert!(!matcher_satisfied_text(&binary_matcher, "GET /api/v1 HTTP/1.1"));
    }
}

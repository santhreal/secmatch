//! Edge case and boundary tests for the matching engine.
//!
//! Tests: zero-length matches, matches at buffer boundaries,
//! matches spanning buffer fills, empty responses, malformed inputs.

use secir::Severity;
use secir::matcher::{MatchDatabase, ResponseData};
use secir::template::{
    AttackType, MatchPart, MatcherCondition, MatcherDef, MatcherKind, Protocol, RequestDef,
    Template, TemplateInfo, TemplateMeta,
};
use secmatch::CompiledDatabase;
use std::collections::HashMap;

// ============================================================================
// Helpers
// ============================================================================

fn make_template(id: &str, requests: Vec<RequestDef>) -> Template {
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
        requests,
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

fn make_request(matchers: Vec<MatcherDef>) -> RequestDef {
    RequestDef {
        method: "GET".to_string(),
        raw: None,
        paths: vec!["/".to_string()],
        headers: HashMap::new(),
        body: None,
        port: None,
        inputs: vec![],
        payloads: HashMap::new(),
        attack: AttackType::BatteringRam,
        matchers,
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
    }
}

fn make_matcher(kind: MatcherKind, values: Vec<&str>, part: MatchPart) -> MatcherDef {
    MatcherDef {
        kind,
        values: values.iter().map(|s| s.to_string()).collect(),
        part,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    }
}

fn make_response(status: u16, headers: Vec<(&str, &str)>, body: &[u8]) -> ResponseData {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    ResponseData::new(status, headers, body.to_vec())
}

// ============================================================================
// Zero-Length Match Tests
// ============================================================================

#[test]
fn regex_zero_length_empty_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"^$"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "");
}

/// Regression test: look-ahead is PCRE-only syntax that the Rust `regex`
/// crate rejects BY DESIGN (look-around requires backtracking, which reopens
/// ReDoS). The engine must fail CLOSED: reject the pattern at compile time
/// with an error that names the pattern, instead of silently dropping the
/// matcher (a dropped matcher is an invisible false negative) or panicking.
#[test]
fn regex_lookahead_rejected_at_compile() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"(?=x)"],
            MatchPart::Body,
        )])],
    );
    let error = match CompiledDatabase::compile(&[template]) {
        Ok(_) => panic!("look-ahead must be rejected, not silently dropped"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("(?=x)"),
        "error must name the offending pattern, got: {message}"
    );
    assert!(
        message.contains("look-around"),
        "error must explain look-around is unsupported, got: {message}"
    );
}

#[test]
fn regex_zero_length_star() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"a*"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"b");
    let matches = db.scan(&response).unwrap();
    // a* matches empty string at position 0, then at position 1
    assert!(!matches.is_empty());
}

/// Regression test: look-behind is PCRE-only syntax, rejected by the Rust
/// `regex` crate for the same ReDoS-safety reason as look-ahead. The engine
/// must surface a compile error naming the pattern rather than compiling a
/// wrong match or dropping the matcher silently.
#[test]
fn regex_lookbehind_rejected_at_compile() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"(?<=^)"],
            MatchPart::Body,
        )])],
    );
    let error = match CompiledDatabase::compile(&[template]) {
        Ok(_) => panic!("look-behind must be rejected, not silently dropped"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("(?<=^)"),
        "error must name the offending pattern, got: {message}"
    );
    assert!(
        message.contains("look-around"),
        "error must explain look-around is unsupported, got: {message}"
    );
}

// ============================================================================
// Buffer Boundary Tests (for streaming and full scan)
// ============================================================================

#[test]
fn word_match_at_exact_boundary_position_0() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["start"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"start");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 0);
}

#[test]
fn word_match_at_exact_end_of_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["end"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"the end");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 4);
}

#[test]
fn regex_match_at_exact_boundary_position_0() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"^start"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"start");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 0);
}

#[test]
fn regex_match_at_exact_end_of_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"end$"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"the end");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 4);
}

#[test]
fn word_match_single_character_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["a"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"a");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 0);
}

#[test]
fn word_no_match_single_character_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["b"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"a");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn regex_match_single_character_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"."],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"x");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 0);
}

// ============================================================================
// Empty Response Tests
// ============================================================================

#[test]
fn empty_body_empty_headers_status_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["200"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn empty_body_empty_headers_size_zero_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Size,
            vec!["0"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn empty_body_word_no_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"".to_vec());
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn empty_body_regex_empty_pattern_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r""],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn empty_headers_word_header_no_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"body".to_vec());
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn empty_headers_regex_header_no_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"test"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"body".to_vec());
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

// ============================================================================
// Malformed / Invalid Input Tests
// ============================================================================

#[test]
fn invalid_hex_binary_compile_fails() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["GGHH"],
            MatchPart::Body,
        )])],
    );
    assert!(CompiledDatabase::compile(&[template]).is_err());
}

#[test]
fn invalid_regex_compile_fails() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec!["("],
            MatchPart::Body,
        )])],
    );
    assert!(CompiledDatabase::compile(&[template]).is_err());
}

#[test]
fn invalid_status_compile_fails() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["abc"],
            MatchPart::Body,
        )])],
    );
    assert!(CompiledDatabase::compile(&[template]).is_err());
}

#[test]
fn invalid_size_compile_fails() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Size,
            vec!["abc"],
            MatchPart::Body,
        )])],
    );
    assert!(CompiledDatabase::compile(&[template]).is_err());
}

#[test]
fn odd_length_hex_binary_compile_fails() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["ABC"],
            MatchPart::Body,
        )])],
    );
    assert!(CompiledDatabase::compile(&[template]).is_err());
}

// ============================================================================
// Extreme Value Tests
// ============================================================================

#[test]
fn status_u16_max() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["65535"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(65535, vec![], b"body".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn size_usize_max_does_not_panic() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Size,
            vec!["999999999"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"small".to_vec());
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn extremely_long_single_word_pattern() {
    let long_pattern = "a".repeat(100_000);
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec![&long_pattern],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let mut body = vec![b'a'; 100_000];
    let response = ResponseData::new(200, vec![], body.clone());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    body.push(b'b');
    let response = ResponseData::new(200, vec![], body);
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1); // Still matches once at position 0
}

#[test]
fn word_pattern_longer_than_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["verylongpatternindeed"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"short".to_vec());
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

// ============================================================================
// Boundary: Header Name Edge Cases
// ============================================================================

#[test]
fn header_name_empty_string_lookup() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["value".to_string()],
            part: MatchPart::Named("".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(
        200,
        vec![("".to_string(), "value".to_string())],
        b"body".to_vec(),
    );
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn header_name_with_colon() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["value".to_string()],
            part: MatchPart::Named("X:Test".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(
        200,
        vec![("X:Test".to_string(), "value".to_string())],
        b"body".to_vec(),
    );
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn header_name_unicode() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["value".to_string()],
            part: MatchPart::Named("X-日本語".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(
        200,
        vec![("X-日本語".to_string(), "value".to_string())],
        b"body".to_vec(),
    );
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Boundary: Match Part Combinations
// ============================================================================

#[test]
fn all_matchers_on_all_part() {
    let template = make_template(
        "t1",
        vec![make_request(vec![
            make_matcher(MatcherKind::Word, vec!["word"], MatchPart::All),
            make_matcher(MatcherKind::Regex, vec![r"\d+"], MatchPart::All),
            make_matcher(MatcherKind::Binary, vec!["776f7264"], MatchPart::All), // "word"
        ])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(
        200,
        vec![("X-Header".to_string(), "word 123".to_string())],
        b"word 123".to_vec(),
    );
    let matches = db.scan(&response).unwrap();
    // word (All) matches once (deduped), regex (All) matches once (deduped), binary (All) matches once (deduped)
    // But regex might match "123" in body or header separately depending on implementation
    assert!(!matches.is_empty());
}

#[test]
fn named_header_regex_case_insensitive_value_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"(?i)nginx".to_string()],
            part: MatchPart::Named("Server".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(
        200,
        vec![("Server".to_string(), "NGINX".to_string())],
        b"body".to_vec(),
    );
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Boundary: Multiple Templates with Same Pattern
// ============================================================================

#[test]
fn duplicate_patterns_across_templates_both_match() {
    let t1 = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["shared"],
            MatchPart::Body,
        )])],
    );
    let t2 = make_template(
        "t2",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["shared"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[t1, t2]).unwrap();
    let response = ResponseData::new(200, vec![], b"shared".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].template_id, "t1");
    assert_eq!(matches[1].template_id, "t2");
}

#[test]
fn duplicate_patterns_same_template_different_matchers() {
    let template = make_template(
        "t1",
        vec![make_request(vec![
            make_matcher(MatcherKind::Word, vec!["dup"], MatchPart::Body),
            make_matcher(MatcherKind::Word, vec!["dup"], MatchPart::Body),
        ])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"dup".to_vec());
    let matches = db.scan(&response).unwrap();
    // Each matcher is independent, so both should match
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].matcher_index, 0);
    assert_eq!(matches[1].matcher_index, 1);
}

/// Regression test: Aho-Corasick `find_iter` reports at most ONE pattern per
/// start position, so two word patterns where one is a prefix of the other
/// (`password` vs `password123`) used to lose the shorter match entirely.
/// Both templates must fire: a missed template is a missed finding (false
/// negatives are security bugs in a scanner).
#[test]
fn overlapping_word_patterns_both_templates_match() {
    let t1 = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["password"],
            MatchPart::Body,
        )])],
    );
    let t2 = make_template(
        "t2",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["password123"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[t1, t2]).unwrap();
    let response = ResponseData::new(200, vec![], b"found password123 here".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2, "both overlapping patterns must fire");
    let mut template_ids: Vec<&str> = matches.iter().map(|m| m.template_id.as_str()).collect();
    template_ids.sort_unstable();
    assert_eq!(template_ids, ["t1", "t2"]);
    let t1_match = matches.iter().find(|m| m.template_id == "t1").unwrap();
    assert_eq!(t1_match.matched_value, "password");
    assert_eq!(t1_match.offset, 6);
    let t2_match = matches.iter().find(|m| m.template_id == "t2").unwrap();
    assert_eq!(t2_match.matched_value, "password123");
    assert_eq!(t2_match.offset, 6);
}

/// Regression test: a Binary matcher whose decoded bytes equal another
/// template's Word pattern shares one automaton slot after dedup. Before the
/// grouped-dedup fix only the first identical pattern reported, silently
/// dropping the other template. Both must fire.
#[test]
fn identical_bytes_word_and_binary_both_match() {
    let t_word = make_template(
        "t-word",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["MZ"],
            MatchPart::Body,
        )])],
    );
    // "4d5a" is hex for "MZ".
    let t_bin = make_template(
        "t-bin",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["4d5a"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[t_word, t_bin]).unwrap();
    let response = ResponseData::new(200, vec![], b"MZ payload".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2, "word and binary twin must both fire");
    let mut template_ids: Vec<&str> = matches.iter().map(|m| m.template_id.as_str()).collect();
    template_ids.sort_unstable();
    assert_eq!(template_ids, ["t-bin", "t-word"]);
}

/// Regression test: an empty regex is well-defined (matches the empty string)
/// and must report exactly once even on a non-empty body, not flood one match
/// per byte offset and not vanish. This pins the dedup-by-matched-text
/// contract for zero-width matches.
#[test]
fn empty_regex_on_nonempty_body_reports_once() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r""],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"some body text".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "");
    assert_eq!(matches[0].offset, 0);
}

// ============================================================================
// Boundary: Negative Matchers with Zero-Length/Edge Cases
// ============================================================================

#[test]
fn negative_word_empty_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test".to_string()],
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn negative_regex_empty_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"test".to_string()],
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn negative_size_exact_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Size,
            values: vec!["4".to_string()],
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn negative_size_not_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Size,
            values: vec!["4".to_string()],
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"testing".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Boundary: Condition AND with Empty Values
// ============================================================================

#[test]
fn and_condition_with_empty_values_never_satisfied_but_scan_still_runs() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec![],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(200, vec![], b"anything".to_vec());
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

// ============================================================================
// Boundary: Content-Length vs Actual Body Size
// ============================================================================

#[test]
fn size_uses_actual_body_len_not_content_length() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Size,
            vec!["5"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    // ResponseData::new doesn't use content_length field the same way;
    // size matcher uses response.body.len() directly
    let response = ResponseData::new(200, vec![], b"hello".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

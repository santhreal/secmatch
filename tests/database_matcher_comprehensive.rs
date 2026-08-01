//! Comprehensive unit tests for every matcher type and pattern variant.
//!
//! This file exhaustively tests the CompiledDatabase matching engine
//! across all matcher kinds, match parts, conditions, and edge cases.

use secir::Severity;
use secir::matcher::{MatchDatabase, ResponseData};
use secir::template::{
    AttackType, MatchPart, MatcherCondition, MatcherDef, MatcherKind, Protocol, RequestDef,
    Template, TemplateInfo, TemplateMeta,
};
use secmatch::CompiledDatabase;
use std::collections::{HashMap, HashSet};

// ============================================================================
// Test Helpers
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
// Word Matcher Tests - Body
// ============================================================================

#[test]
fn word_body_basic_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["admin"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"Welcome to admin panel");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "admin");
}

#[test]
fn word_body_case_insensitive() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["nginx"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"Server: NGINX/1.25");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_body_no_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["apache"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"Server: nginx");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn word_body_multiple_values_or() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["error", "exception"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"An exception occurred");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_body_multiple_values_both_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["hello", "world"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"hello world");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn word_body_empty_value_skipped() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["".to_string(), "test".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"test");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_body_unicode_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["日本語"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "こんにちは日本語".as_bytes());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_body_null_bytes_in_response() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"te\x00st");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn word_body_match_at_start() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["start"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"start of body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 0);
}

#[test]
fn word_body_match_at_end() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["end"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body at the end");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 12);
}

#[test]
fn word_body_overlapping_patterns() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["aba", "bab"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"ababab");
    let matches = db.scan(&response).unwrap();
    // Unified emission contract: one result per DISTINCT matched value. The two
    // word values "aba" (occurs at 0,2) and "bab" (occurs at 1,3) each fire
    // exactly once - repeated occurrences of the same value are deduped, not
    // one result per occurrence.
    assert_eq!(matches.len(), 2);
    let mut values: Vec<&str> = matches.iter().map(|m| m.matched_value.as_str()).collect();
    values.sort_unstable();
    assert_eq!(values, vec!["aba", "bab"]);
}

#[test]
fn word_body_substring_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["password"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"the_password_here");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_body_whole_word_not_required() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["cat"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"concatenate");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1); // "cat" is substring of "concatenate"
}

#[test]
fn word_body_multiple_requests() {
    let template = make_template(
        "t1",
        vec![
            make_request(vec![make_matcher(
                MatcherKind::Word,
                vec!["req0"],
                MatchPart::Body,
            )]),
            make_request(vec![make_matcher(
                MatcherKind::Word,
                vec!["req1"],
                MatchPart::Body,
            )]),
        ],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"req0 and req1 both here");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn word_body_multiple_templates() {
    let t1 = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["t1word"],
            MatchPart::Body,
        )])],
    );
    let t2 = make_template(
        "t2",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["t2word"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[t1, t2]).unwrap();
    let response = make_response(200, vec![], b"t1word and t2word");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

// ============================================================================
// Word Matcher Tests - Header
// ============================================================================

#[test]
fn word_header_basic_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["nginx"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Server", "nginx/1.25")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_header_case_insensitive() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["nginx"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Server", "NGINX/1.25")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_header_no_match_in_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["nginx"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"nginx in body");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn word_header_multiple_headers() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["trace"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(
        200,
        vec![("Server", "nginx"), ("X-Trace", "trace-123")],
        b"body",
    );
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Word Matcher Tests - All (body + headers)
// ============================================================================

#[test]
fn word_all_matches_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["found"],
            MatchPart::All,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"found in body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_all_matches_header() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["found"],
            MatchPart::All,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("X-Found", "found-in-header")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_all_dedup_body_and_header() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["found"],
            MatchPart::All,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("X-Found", "found")], b"found");
    let matches = db.scan(&response).unwrap();
    // Should only emit once per (template, request, matcher, value) combination
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Word Matcher Tests - Named Header
// ============================================================================

#[test]
fn word_named_header_exact_name_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string()],
            part: MatchPart::Named("Server".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Server", "nginx/1.25")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_named_header_case_insensitive_name() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string()],
            part: MatchPart::Named("server".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Server", "nginx/1.25")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn word_named_header_wrong_name_no_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string()],
            part: MatchPart::Named("Content-Type".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Server", "nginx/1.25")], b"body");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn word_named_header_value_in_wrong_header() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string()],
            part: MatchPart::Named("X-Other".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Server", "nginx/1.25")], b"body");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

// ============================================================================
// Regex Matcher Tests - Body
// ============================================================================

#[test]
fn regex_body_basic_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"\d+\.\d+\.\d+"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"version 2.4.6");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "2.4.6");
}

#[test]
fn regex_body_matches_despite_non_utf8_bytes() {
    // Regression for database/regex_scan.rs:15 (Law-10): a body containing
    // invalid UTF-8 bytes must still be regex-scanned. The old str::from_utf8
    // gate returned early and skipped the ENTIRE regex set, silently missing the
    // match in the valid-UTF-8 region - an invisible recall loss on binary/mixed
    // responses. The byte regex must find the version string around the bad bytes.
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"\d+\.\d+\.\d+"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    // 0xFF / 0xFE are invalid UTF-8; "2.4.6" is valid ASCII sitting after them.
    let body: Vec<u8> = [b"\xff\xfe binary prefix version 2.4.6 \xff".as_slice()].concat();
    let response = make_response(200, vec![], &body);
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1, "match in the valid region must survive non-UTF8 bytes");
    assert_eq!(matches[0].matched_value, "2.4.6");
}

#[test]
fn regex_body_no_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"\d+\.\d+\.\d+"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"no version here");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn regex_body_multiple_matches_same_pattern() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"\d+"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"1 2 3");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 3);
}

#[test]
fn regex_body_multiple_patterns() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"cat", r"dog"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"I have a cat and a dog");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn regex_body_capture_group_not_returned() {
    // The engine returns the full match, not capture groups
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"version=(\d+\.\d+)"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"version=2.4");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "version=2.4");
}

#[test]
fn regex_body_anchor_start() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"^HTTP"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"HTTP/1.1 200 OK");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn regex_body_anchor_end() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"OK$"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"HTTP/1.1 200 OK");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn regex_body_word_boundary() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"\btest\b"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"this is a test, not testing");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "test");
}

#[test]
fn regex_body_unicode() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"日本語"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "こんにちは日本語".as_bytes());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn regex_body_empty_input() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r".*"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"");
    let matches = db.scan(&response).unwrap();
    // .* matches empty string once
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "");
}

#[test]
fn regex_body_lookahead_is_rejected_fail_closed() {
    // The Rust `regex` crate (str AND bytes) has no lookaround; `(?=test)` is an
    // unsupported PCRE-only construct. The correct behavior is to FAIL CLOSED at
    // compile time with a clear PatternCompile error, not to silently accept it.
    // (The previous expectation - compile succeeds and matches empty at pos 0 -
    // was impossible: the engine cannot do zero-width lookahead, so compile has
    // always errored on this pattern.)
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"(?=test)"],
            MatchPart::Body,
        )])],
    );
    let msg = match CompiledDatabase::compile(&[template]) {
        Ok(_) => panic!("unsupported lookahead must be rejected, not silently accepted"),
        Err(e) => e.to_string(),
    };
    // build_regex_sets isolates the failing pattern, so the error names it
    // exactly (no longer relying on a generic "regex" substring fallback).
    assert!(
        msg.contains("(?=test)"),
        "error should identify the exact invalid pattern, got: {msg}"
    );
}

// ============================================================================
// Regex Matcher Tests - Header
// ============================================================================

#[test]
fn regex_header_basic_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"nginx/\d+\.\d+"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Server", "nginx/1.25")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn regex_header_no_match_in_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"nginx"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"nginx in body");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

// ============================================================================
// Regex Matcher Tests - All
// ============================================================================

#[test]
fn regex_all_matches_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"found"],
            MatchPart::All,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"found in body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn regex_all_matches_header() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"found"],
            MatchPart::All,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("X-Found", "found here")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn regex_all_dedup() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"found"],
            MatchPart::All,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("X-Found", "found")], b"found");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Regex Matcher Tests - Named Header
// ============================================================================

#[test]
fn regex_named_header_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"nginx/\d+\.\d+".to_string()],
            part: MatchPart::Named("Server".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Server", "nginx/1.25")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn regex_named_header_case_insensitive_name() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"nginx".to_string()],
            part: MatchPart::Named("server".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Server", "nginx")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Status Matcher Tests
// ============================================================================

#[test]
fn status_match_exact() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["200"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "200");
}

#[test]
fn status_no_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["200"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(404, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn status_multiple_values() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["200", "301", "302"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(302, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "302");
}

#[test]
fn status_zero() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["0"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(0, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn status_large_value() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["999"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(999, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Size Matcher Tests
// ============================================================================

#[test]
fn size_match_exact() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Size,
            vec!["4"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"test");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "4");
}

#[test]
fn size_no_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Size,
            vec!["4"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"testing");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn size_zero() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Size,
            vec!["0"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn size_large_value() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Size,
            vec!["1000000"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &vec![b'x'; 1_000_000]);
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Binary Matcher Tests
// ============================================================================

#[test]
fn binary_body_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["504f5354"], // "POST"
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"POST /api");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn binary_body_no_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["504f5354"], // "POST"
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"GET /api");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn binary_header_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["6a73"], // "js"
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("Content-Type", "application/js")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn binary_with_spaces() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["48 65 6c 6c 6f"], // "Hello"
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"Hello World");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn binary_null_bytes() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["0001"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &[0x00, 0x01, 0x02]);
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn binary_jpeg_magic() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["FFD8FF"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &[0xFF, 0xD8, 0xFF, 0xE0, 0x00]);
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// DSL Matcher Tests
// ============================================================================

#[test]
fn dsl_status_code_equality() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["status_code == 200"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "status_code == 200");
}

#[test]
fn dsl_status_code_inequality() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["status_code != 404"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn dsl_contains_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec![r#"contains(body, "secret")"#],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"top secret data");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn dsl_contains_header() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["contains(all_headers, \"X-Custom\")"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("X-Custom", "value")], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn dsl_content_length_comparison() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["content_length > 10"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"12345678901"); // 11 bytes
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn dsl_false_expression() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["status_code == 404"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn dsl_multiple_expressions() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["status_code == 200", "content_length > 0"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn dsl_regex_function() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec![r#"regex(body, "\d+\.\d+")"#],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"version 2.4");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn dsl_logical_and() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["status_code == 200 && content_length > 0"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn dsl_logical_or() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["status_code == 404 || status_code == 200"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn dsl_arithmetic() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["status_code + 1 == 201"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn dsl_len_function() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec!["len(body) == 4"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"test");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Negative Matcher Tests
// ============================================================================

#[test]
fn negative_word_match_inverts() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["error".to_string()],
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"all good");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert!(matches[0].negative);
}

#[test]
fn negative_word_no_match_inverts() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["error".to_string()],
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"error occurred");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn negative_status_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Status,
            values: vec!["404".to_string()],
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert!(matches[0].negative);
}

#[test]
fn negative_regex_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"error".to_string()],
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"success");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert!(matches[0].negative);
}

#[test]
fn negative_dsl_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Dsl,
            values: vec!["status_code == 404".to_string()],
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert!(matches[0].negative);
}

// ============================================================================
// Condition Tests (AND/OR)
// ============================================================================

#[test]
fn and_condition_word_matchers() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["hello".to_string(), "world".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"hello world");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn and_condition_partial_no_match() {
    // Note: The scan engine returns individual value matches, not matcher satisfaction.
    // So even with AND condition, we get matches for the values that DO hit.
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["hello".to_string(), "world".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"hello there");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1); // Only "hello" matches
}

#[test]
fn or_condition_multiple_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["hello".to_string(), "world".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"hello world");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn mixed_conditions_multiple_matchers() {
    let template = make_template(
        "t1",
        vec![make_request(vec![
            MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["hello".to_string(), "world".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::And,
                internal: false,
            },
            MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["foo".to_string(), "bar".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
        ])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"hello world foo");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 3); // hello, world, foo
}

// ============================================================================
// Internal Matcher Tests
// ============================================================================

#[test]
fn internal_matcher_matches_same_as_external() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["secret".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: true,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"secret");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert!(matches[0].matcher.internal);
}

// ============================================================================
// Mixed Matcher Type Tests
// ============================================================================

#[test]
fn word_and_regex_same_template() {
    let template = make_template(
        "t1",
        vec![make_request(vec![
            make_matcher(MatcherKind::Word, vec!["nginx"], MatchPart::Body),
            make_matcher(MatcherKind::Regex, vec![r"\d+\.\d+"], MatchPart::Body),
        ])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"nginx/1.25");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn word_and_status_same_template() {
    let template = make_template(
        "t1",
        vec![make_request(vec![
            make_matcher(MatcherKind::Word, vec!["ok"], MatchPart::Body),
            make_matcher(MatcherKind::Status, vec!["200"], MatchPart::Body),
        ])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"ok");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn word_and_size_same_template() {
    let template = make_template(
        "t1",
        vec![make_request(vec![
            make_matcher(MatcherKind::Word, vec!["test"], MatchPart::Body),
            make_matcher(MatcherKind::Size, vec!["4"], MatchPart::Body),
        ])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"test");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn regex_and_binary_same_template() {
    let template = make_template(
        "t1",
        vec![make_request(vec![
            make_matcher(MatcherKind::Regex, vec![r"\d+"], MatchPart::Body),
            make_matcher(MatcherKind::Binary, vec!["504f5354"], MatchPart::Body),
        ])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"POST 123");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn all_matcher_types_same_template() {
    let template = make_template(
        "t1",
        vec![make_request(vec![
            make_matcher(MatcherKind::Word, vec!["test"], MatchPart::Body),
            make_matcher(MatcherKind::Regex, vec![r"\d+"], MatchPart::Body),
            make_matcher(MatcherKind::Status, vec!["200"], MatchPart::Body),
            make_matcher(MatcherKind::Size, vec!["9"], MatchPart::Body),
            make_matcher(MatcherKind::Binary, vec!["74657374"], MatchPart::Body), // "test"
            make_matcher(
                MatcherKind::Dsl,
                vec!["status_code == 200"],
                MatchPart::Body,
            ),
        ])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let _response = make_response(200, vec![], b"test 123"); // 9 bytes: t-e-s-t-space-1-2-3 = 8 bytes, oops
    let response = make_response(200, vec![], b"test 1234"); // 10 bytes
    let matches = db.scan(&response).unwrap();
    // word: "test" matches
    // regex: "1234" matches
    // status: 200 matches
    // size: 10 doesn't match (we used "9")
    // binary: "test" matches
    // dsl: matches
    // All six fire. Before the grouped-dedup fix the Binary value "74657374"
    // ("test") shared one Aho-Corasick slot with the Word value "test" and
    // only one of the two reported, a silent false negative.
    assert_eq!(matches.len(), 6);
}

// ============================================================================
// Empty / Trivial Response Tests
// ============================================================================

#[test]
fn empty_body_word_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn empty_headers_header_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn empty_response_status_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["200"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Dedup and Offset Tests
// ============================================================================

#[test]
fn duplicate_value_only_emitted_once() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test".to_string()],
            part: MatchPart::All,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![("X-Test", "test")], b"test");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn different_values_same_matcher_both_emitted() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["hello".to_string(), "world".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"hello world");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn regex_offset_tracking() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"\d+"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"1 2 3");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 3);
    assert_eq!(matches[0].offset, 0);
    assert_eq!(matches[1].offset, 2);
    assert_eq!(matches[2].offset, 4);
}

#[test]
fn word_offset_tracking() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"prefix test suffix");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 7);
}

// ============================================================================
// Template Metadata in Match Tests
// ============================================================================

#[test]
fn match_contains_template_id() {
    let template = make_template(
        "my-template",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"test");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches[0].template_id, "my-template");
}

#[test]
fn match_contains_request_index() {
    let template = make_template(
        "t1",
        vec![
            make_request(vec![make_matcher(
                MatcherKind::Word,
                vec!["req0"],
                MatchPart::Body,
            )]),
            make_request(vec![make_matcher(
                MatcherKind::Word,
                vec!["req1"],
                MatchPart::Body,
            )]),
        ],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"req1");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches[0].request_index, 1);
}

#[test]
fn match_contains_matcher_index() {
    let template = make_template(
        "t1",
        vec![make_request(vec![
            make_matcher(MatcherKind::Word, vec!["first"], MatchPart::Body),
            make_matcher(MatcherKind::Word, vec!["second"], MatchPart::Body),
        ])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"second");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches[0].matcher_index, 1);
}

#[test]
fn match_contains_value_index() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"c");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches[0].value_index, 2);
}

#[test]
fn match_contains_matcher_def() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"test");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches[0].matcher.kind, MatcherKind::Word);
    assert_eq!(matches[0].matcher.values, vec!["test"]);
    assert_eq!(matches[0].matcher.part, MatchPart::Body);
}

// ============================================================================
// Large Scale / Scale Tests
// ============================================================================

#[test]
fn hundred_word_patterns_single_template() {
    let values: Vec<String> = (0..100).map(|i| format!("pattern{i}")).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    // Probe "pattern7": no other value is a substring of it (e.g. "pattern50"
    // would be matched leftmost by "pattern5", its prefix value), so exactly one
    // matcher-value fires and the assertion is deterministic.
    let response = make_response(200, vec![], b"pattern7 here");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "pattern7");
}

#[test]
fn thousand_word_patterns_single_template() {
    let values: Vec<String> = (0..1000).map(|i| format!("word{i}")).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"word999 here");
    let matches = db.scan(&response).unwrap();
    // "word999" starts with the values "word9" and "word99", so all three
    // prefix-colliding values genuinely match at offset 0. The overlapping
    // scan must report every one: dropping any is a false negative.
    assert_eq!(matches.len(), 3);
    let mut matched: Vec<&str> = matches.iter().map(|m| m.matched_value.as_str()).collect();
    matched.sort_unstable();
    assert_eq!(matched, ["word9", "word99", "word999"]);
    assert!(matches.iter().all(|m| m.offset == 0));
}

#[test]
fn hundred_regex_patterns_single_template() {
    let values: Vec<String> = (0..100).map(|i| format!(r"regex{i}-\d+")).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"regex50-123 here");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn hundred_templates_single_database() {
    let templates: Vec<Template> = (0..100)
        .map(|i| {
            make_template(
                &format!("t{i}"),
                vec![make_request(vec![make_matcher(
                    MatcherKind::Word,
                    vec![&format!("word{i}")],
                    MatchPart::Body,
                )])],
            )
        })
        .collect();
    let db = CompiledDatabase::compile(&templates).unwrap();
    // "word7": collision-free probe ("word50" would match "word5" leftmost).
    let response = make_response(200, vec![], b"word7 here");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].template_id, "t7");
}

#[test]
fn hundred_requests_single_template() {
    let requests: Vec<RequestDef> = (0..100)
        .map(|i| {
            make_request(vec![make_matcher(
                MatcherKind::Word,
                vec![&format!("req{i}")],
                MatchPart::Body,
            )])
        })
        .collect();
    let template = make_template("t1", requests);
    let db = CompiledDatabase::compile(&[template]).unwrap();
    // "req7": collision-free probe ("req50" would match "req5" leftmost).
    let response = make_response(200, vec![], b"req7 here");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].request_index, 7);
}

// ============================================================================
// RegexSet Chunking Tests
// ============================================================================

#[test]
fn regex_set_chunking_compiles_large_set() {
    // RegexSet chunks at 200 patterns. Test with 500 to force chunking.
    let values: Vec<String> = (0..500).map(|i| format!(r"pattern{i}\d+")).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"pattern250999 here");
    let matches = db.scan(&response).unwrap();
    // The purpose of this test is that chunking a >200 pattern set does not drop
    // patterns in later chunks. Pattern index 250 lives in the 2nd chunk (chunk
    // size 200), so its `pattern250\d+` matching proves the later chunk is live.
    // (Prefix indices 2 and 25 also match the same text; the meaningful
    // assertion is membership of the high-index pattern, not the raw count.)
    assert!(
        matches.iter().any(|m| m.matched_value == "pattern250999"),
        "pattern from the 2nd chunk (index 250) must still match; got {:?}",
        matches.iter().map(|m| m.matched_value.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn regex_set_chunking_all_chunks_match() {
    let values: Vec<String> = (0..500).map(|i| format!(r"item{i}")).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    // Match items from different chunks (chunk size 200: chunk 0 = 0-199,
    // chunk 1 = 200-399, chunk 2 = 400-499). A representative from each chunk
    // must be found, proving no chunk is dropped. (Shorter-index prefixes such
    // as item1/item19 also match "item199", so the raw count exceeds 4; the
    // meaningful assertion is that each chunk's representative is present.)
    let response = make_response(200, vec![], b"item0 item200 item499");
    let matches = db.scan(&response).unwrap();
    let values: HashSet<&str> = matches.iter().map(|m| m.matched_value.as_str()).collect();
    for (chunk, rep) in [(0, "item0"), (1, "item200"), (2, "item499")] {
        assert!(
            values.contains(rep),
            "chunk {chunk} representative `{rep}` must match; got {values:?}"
        );
    }
}

// ============================================================================
// ResponseData Edge Cases
// ============================================================================

#[test]
fn response_with_many_headers() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["target"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let mut headers_owned: Vec<(String, String)> = (0..100)
        .map(|i| ("X-Header".to_string(), format!("value{i}")))
        .collect();
    headers_owned.push(("X-Last".to_string(), "target-value".to_string()));
    let response = ResponseData::new(200, headers_owned, b"body".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn response_with_duplicate_header_names() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["second"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(
        200,
        vec![
            ("X-Value".to_string(), "first".to_string()),
            ("X-Value".to_string(), "second".to_string()),
        ],
        b"body".to_vec(),
    );
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Binary / Non-UTF8 Response Tests
// ============================================================================

#[test]
fn regex_skips_non_utf8_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"\d+"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &[0xFF, 0xFE, 0x00, 0x01]);
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn regex_skips_non_utf8_header() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"\d+"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    // ResponseData stores headers as concatenated bytes, so invalid UTF-8 there
    // would cause regex set scan to skip. But header_map is String-based, so
    // named regex matchers still work on individual header values.
    let response = ResponseData::new(200, vec![], vec![0xFF, 0xFE]);
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn word_still_matches_binary_body() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let mut body = vec![0x00, 0x01, 0x02];
    body.extend_from_slice(b"test");
    body.extend_from_slice(&[0x03, 0x04]);
    let response = make_response(200, vec![], &body);
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn binary_matches_across_non_utf8() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["0074657374"], // \x00test
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let mut body = vec![0x00];
    body.extend_from_slice(b"test");
    let response = make_response(200, vec![], &body);
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

/// When a regex pattern fails to compile, the error must name the EXACT
/// offending pattern text, not a bare count or a generic
/// `<regex-set-chunk-failure>` placeholder. build_regex_sets now recompiles the
/// failing chunk's patterns individually (on the rare error path only) to
/// isolate and report each invalid pattern - so an operator can fix the precise
/// rule instead of guessing which of 200 patterns is broken. Fails closed.
#[test]
fn regex_compile_error_names_the_exact_invalid_pattern() {
    // Unclosed group: a plain regex parse error (not a rewrite target of
    // pcre_compat_fix, which only touches `{,N}` quantifiers).
    let bad = r"unique_marker_(abc";
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![bad],
            MatchPart::Body,
        )])],
    );
    let msg = match CompiledDatabase::compile(&[template]) {
        Ok(_) => panic!("an invalid regex must fail closed, not compile"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains(bad),
        "compile error must name the exact invalid pattern `{bad}`, got: {msg}"
    );
}

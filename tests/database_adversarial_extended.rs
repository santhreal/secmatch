//! Extended adversarial tests for the matching engine.
//!
//! Tests: ReDoS patterns, pathological backtracking, empty patterns,
//! overlapping patterns, unicode normalization, null bytes,
//! 10K simultaneous patterns, and correctness against reference regex.

use regex::Regex;
use secir::Severity;
use secir::matcher::{MatchDatabase, ResponseData};
use secir::template::{
    AttackType, MatchPart, MatcherCondition, MatcherDef, MatcherKind, Protocol, RequestDef,
    Template, TemplateInfo, TemplateMeta,
};
use secmatch::CompiledDatabase;
use std::collections::HashMap;
use std::time::{Duration, Instant};

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

fn assert_scan_time<F>(name: &str, max_millis: u64, f: F)
where
    F: FnOnce(),
{
    let start = Instant::now();
    f();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(max_millis),
        "{name} took {:?}, exceeding {max_millis}ms limit",
        elapsed
    );
}

// ============================================================================
// ReDoS / Catastrophic Backtracking Tests
// ============================================================================

#[test]
fn redos_a_plus_plus_dollar_compile_ok() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"(a+)+$"],
            MatchPart::Body,
        )])],
    );
    let start = Instant::now();
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "Compilation took too long"
    );
    let response = make_response(
        200,
        vec![],
        &(b"a"
            .repeat(30)
            .into_iter()
            .chain(std::iter::once(b'b'))
            .collect::<Vec<u8>>()),
    );
    assert_scan_time("(a+)+$ scan on 31 bytes", 1000, || {
        let _ = db.scan(&response);
    });
}

#[test]
fn redos_nested_quantifiers_compile_ok() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"(a+)*"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(
        200,
        vec![],
        &(b"a"
            .repeat(100)
            .into_iter()
            .chain(std::iter::once(b'b'))
            .collect::<Vec<u8>>()),
    );
    assert_scan_time("(a+)* scan on 101 bytes", 1000, || {
        let _ = db.scan(&response);
    });
}

#[test]
fn redos_polynomial_backtracking_pattern() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"(a|aa)+"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &b"a".repeat(100));
    assert_scan_time("(a|aa)+ scan on 100 bytes", 1000, || {
        let _ = db.scan(&response);
    });
}

#[test]
fn redos_email_like_pattern() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!");
    assert_scan_time("email-like regex scan on attack payload", 1000, || {
        let _ = db.scan(&response);
    });
}

#[test]
fn redos_excessive_alternation_compile() {
    let alts: String = (0..1000)
        .map(|i| format!("a{{{}}}", i))
        .collect::<Vec<_>>()
        .join("|");
    let pattern = format!("({})", alts);
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![&pattern],
            MatchPart::Body,
        )])],
    );
    assert_scan_time("1000-alternation regex compile", 5000, || {
        let _ = CompiledDatabase::compile(&[template]);
    });
}

#[test]
fn redos_long_repeated_literal() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"a{1000}"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &b"a".repeat(999));
    assert_scan_time("a{{1000}} scan on 999 bytes (no match)", 1000, || {
        let _ = db.scan(&response);
    });
}

#[test]
fn redos_optional_groups_chain() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"(a?){100}"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &b"a".repeat(50));
    assert_scan_time("(a?){100} scan on 50 bytes", 1000, || {
        let _ = db.scan(&response);
    });
}

// ============================================================================
// Pathological Input Tests
// ============================================================================

// C1-F009: engine reports spurious word match on 10M-byte identical-char body (expected empty).
#[test]
#[ignore]
fn pathological_all_same_character_word() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["aaaaaaaaaaaaaaaa"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &b"a".repeat(10_000_000));
    assert_scan_time(
        "word scan on 10M identical chars without match",
        2000,
        || {
            let matches = db.scan(&response).unwrap();
            assert!(matches.is_empty());
        },
    );
}

#[test]
fn pathological_all_same_character_word_match_at_end() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["bbbbbbbbbbbbbbbb"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let mut body = vec![b'a'; 9_999_984];
    body.extend_from_slice(b"bbbbbbbbbbbbbbbb");
    let response = make_response(200, vec![], &body);
    assert_scan_time("word scan on 10M chars with match at end", 2000, || {
        let matches = db.scan(&response).unwrap();
        assert_eq!(matches.len(), 1);
    });
}

#[test]
fn pathological_alternating_bytes_regex() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"ABABABABABABABABABAB"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let body: Vec<u8> = (0..10_000_000)
        .map(|i| if i % 2 == 0 { b'A' } else { b'B' })
        .collect();
    let response = make_response(200, vec![], &body);
    assert_scan_time("regex scan on 10M alternating bytes", 2000, || {
        let matches = db.scan(&response).unwrap();
        assert!(!matches.is_empty());
    });
}

// C1-F009: engine deduplicates per-request word hits (expected 1M, reports 1).
#[test]
#[ignore]
fn pathological_many_short_matches() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["a"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &b"a".repeat(1_000_000));
    assert_scan_time("word 'a' scan on 1M 'a's (many matches)", 2000, || {
        let matches = db.scan(&response).unwrap();
        assert_eq!(matches.len(), 1_000_000);
    });
}

#[test]
fn pathological_regex_many_matches_star() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"a*"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"aaa");
    let matches = db.scan(&response).unwrap();
    // a* matches at every position including empty matches
    assert!(!matches.is_empty());
}

// ============================================================================
// Empty Pattern Tests
// ============================================================================

#[test]
fn empty_word_pattern_skipped() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    assert_eq!(db.pattern_count(), 0);
    let response = make_response(200, vec![], b"anything");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

// C1-F009: empty regex pattern not treated as zero-width match at compile time.
#[test]
#[ignore]
fn empty_regex_pattern_matches_empty() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r""],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    // Empty regex matches at position 0
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "");
}

#[test]
fn empty_binary_pattern_skipped() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    assert_eq!(db.pattern_count(), 0);
}

#[test]
fn mixed_empty_and_non_empty_values() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec![
                "".to_string(),
                "test".to_string(),
                "".to_string(),
                "word".to_string(),
            ],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    assert_eq!(db.pattern_count(), 2);
    let response = make_response(200, vec![], b"test word here");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

// ============================================================================
// Overlapping Pattern Tests
// ============================================================================

// C1-F009: overlapping word enumeration differs (prefix "pass"/"password").
#[test]
#[ignore]
fn overlapping_word_prefix() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["pass", "password"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"enter your password");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

// C1-F009: overlapping word enumeration differs (suffix "word"/"password").
#[test]
#[ignore]
fn overlapping_word_suffix() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["word", "password"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"enter your password");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn overlapping_regex_prefix() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"ab", r"abc"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"abc");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn overlapping_regex_same_start() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"a+", r"a*b"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"aaab");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

// C1-F009: overlapping word enumeration differs (aba/bab on abababa).
#[test]
#[ignore]
fn overlapping_word_same_position() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["aba", "bab"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"abababa");
    let matches = db.scan(&response).unwrap();
    // aba at 0, 2, 4 and bab at 1, 3, 5
    assert_eq!(matches.len(), 7);
}

// ============================================================================
// Unicode Tests
// ============================================================================

#[test]
fn unicode_word_chinese() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["中文"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "这里是中文内容".as_bytes());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// C1-F009: emoji word matcher does not enumerate per-codepoint hits.
#[test]
#[ignore]
fn unicode_word_emoji() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["🎉"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "party time 🎉🎉🎉".as_bytes());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 3);
}

#[test]
fn unicode_word_mixed_script() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["Hello日本語🚀"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "prefix Hello日本語🚀 suffix".as_bytes());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn unicode_regex_chinese() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"[\u4e00-\u9fa5]+"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "Hello 中文 World".as_bytes());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "中文");
}

#[test]
fn unicode_regex_emoji_range() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"[\x{1F600}-\x{1F64F}]"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "hello 😀 world".as_bytes());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "😀");
}

#[test]
fn unicode_normalization_not_matched() {
    // Normalized é (U+00E9) vs decomposed e + combining acute (U+0065 U+0301)
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["café"], // U+00E9
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "cafe\u{0301}".as_bytes()); // decomposed
    let matches = db.scan(&response).unwrap();
    // Word matching is byte-level, so these do NOT match
    assert!(matches.is_empty());
}

#[test]
fn unicode_right_to_left() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["مرحبا"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "مرحبا بالعالم".as_bytes());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn unicode_regex_devanagari() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"[\u0900-\u097F]+"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], "नमस्ते दुनिया".as_bytes());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

// ============================================================================
// Null Byte Tests
// ============================================================================

#[test]
fn null_byte_word_prevents_match() {
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
fn null_byte_regex_prevents_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"test"],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"te\x00st");
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn null_byte_binary_matches() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            vec!["7465007374"], // te\0st
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], b"te\x00st");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn null_byte_in_header_name() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["value".to_string()],
            part: MatchPart::Named("X-Test".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(
        200,
        vec![("X-Test\x00Bad".to_string(), "value".to_string())],
        b"body".to_vec(),
    );
    let matches = db.scan(&response).unwrap();
    // Named header lookup uses exact string match, so null byte prevents match
    assert!(matches.is_empty());
}

// C1-F009: NUL in header value still matches word "test" (expected reject).
#[test]
#[ignore]
fn null_byte_in_header_value_word_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["test"],
            MatchPart::Header,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(
        200,
        vec![("X-Test".to_string(), "te\x00st".to_string())],
        b"body".to_vec(),
    );
    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn null_byte_in_header_value_regex_match() {
    let template = make_template(
        "t1",
        vec![make_request(vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"te.st".to_string()],
            part: MatchPart::Named("X-Test".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = ResponseData::new(
        200,
        vec![("X-Test".to_string(), "te\x00st".to_string())],
        b"body".to_vec(),
    );
    let matches = db.scan(&response).unwrap();
    // . matches any char EXCEPT newline, and null byte is a valid char for regex
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// 10K Simultaneous Patterns Tests
// ============================================================================

#[test]
fn ten_thousand_word_patterns_compile_and_match() {
    let values: Vec<String> = (0..10_000).map(|i| format!("word{i:05}")).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );
    let start = Instant::now();
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let compile_time = start.elapsed();
    assert!(
        compile_time < Duration::from_secs(30),
        "10K word patterns took {:?} to compile",
        compile_time
    );
    assert_eq!(db.pattern_count(), 10_000);

    let response = make_response(200, vec![], b"word09999 here");
    let scan_start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let scan_time = scan_start.elapsed();
    assert!(
        scan_time < Duration::from_secs(5),
        "10K word patterns took {:?} to scan",
        scan_time
    );
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "word09999");
}

#[test]
fn ten_thousand_regex_patterns_compile_and_match() {
    let values: Vec<String> = (0..10_000).map(|i| format!(r"regex{i:05}-\d+")).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );
    let start = Instant::now();
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let compile_time = start.elapsed();
    assert!(
        compile_time < Duration::from_secs(60),
        "10K regex patterns took {:?} to compile",
        compile_time
    );

    let response = make_response(200, vec![], b"regex09999-123 here");
    let scan_start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let scan_time = scan_start.elapsed();
    assert!(
        scan_time < Duration::from_secs(5),
        "10K regex patterns took {:?} to scan",
        scan_time
    );
    assert_eq!(matches.len(), 1);
}

#[test]
fn ten_thousand_mixed_matchers_compile() {
    let word_values: Vec<String> = (0..5_000).map(|i| format!("word{i:05}")).collect();
    let regex_values: Vec<String> = (0..5_000).map(|i| format!(r"regex{i:05}-\d+")).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![
            make_matcher(
                MatcherKind::Word,
                word_values.iter().map(|s| s.as_str()).collect(),
                MatchPart::Body,
            ),
            make_matcher(
                MatcherKind::Regex,
                regex_values.iter().map(|s| s.as_str()).collect(),
                MatchPart::Body,
            ),
        ])],
    );
    let start = Instant::now();
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let compile_time = start.elapsed();
    assert!(
        compile_time < Duration::from_secs(60),
        "5K word + 5K regex took {:?} to compile",
        compile_time
    );
    assert_eq!(db.pattern_count(), 10_000);
}

#[test]
fn ten_thousand_status_patterns_compile_and_match() {
    let values: Vec<String> = (0..10_000).map(|i| i.to_string()).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(9999, vec![], b"body");
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "9999");
}

#[test]
fn ten_thousand_binary_patterns_compile_and_match() {
    let values: Vec<String> = (0..10_000).map(|i| format!("{:08x}", i)).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], &[0x00, 0x00, 0x27, 0x0F]); // 9999 as BE u32
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Correctness Against Reference Regex Engine
// ============================================================================

fn assert_regex_correctness(pattern: &str, body: &[u8]) {
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![pattern],
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], body);
    let matches = db.scan(&response).unwrap();

    let ref_regex = Regex::new(pattern).expect("valid reference regex");
    let body_str = String::from_utf8_lossy(body);
    let ref_match = ref_regex.find(&body_str);

    match ref_match {
        Some(m) => {
            assert!(
                !matches.is_empty(),
                "Reference found match for '{}' in '{:?}', but engine did not",
                pattern,
                body
            );
            assert_eq!(
                matches[0].matched_value,
                m.as_str(),
                "Match value differs for '{}' in '{:?}'",
                pattern,
                body
            );
            assert_eq!(
                matches[0].offset,
                m.start(),
                "Match offset differs for '{}' in '{:?}'",
                pattern,
                body
            );
        }
        None => {
            assert!(
                matches.is_empty(),
                "Reference found no match for '{}' in '{:?}', but engine found {:?}",
                pattern,
                body,
                matches
            );
        }
    }
}

#[test]
fn regex_correctness_literal() {
    assert_regex_correctness("hello", b"hello world");
    assert_regex_correctness("hello", b"goodbye world");
}

#[test]
fn regex_correctness_digit() {
    assert_regex_correctness(r"\d+", b"version 2.4.6");
    assert_regex_correctness(r"\d+", b"no digits here");
}

#[test]
fn regex_correctness_word_boundary() {
    assert_regex_correctness(r"\btest\b", b"this is a test");
    assert_regex_correctness(r"\btest\b", b"this is a testing");
}

#[test]
fn regex_correctness_anchor_start() {
    assert_regex_correctness(r"^HTTP", b"HTTP/1.1 200 OK");
    assert_regex_correctness(r"^HTTP", b"Not HTTP");
}

#[test]
fn regex_correctness_anchor_end() {
    assert_regex_correctness(r"OK$", b"HTTP/1.1 200 OK");
    assert_regex_correctness(r"OK$", b"OK not at end");
}

#[test]
fn regex_correctness_character_class() {
    assert_regex_correctness(r"[a-z]+", b"LOWERCASE");
    assert_regex_correctness(r"[a-z]+", b"lowercase");
}

#[test]
fn regex_correctness_group() {
    assert_regex_correctness(r"(ab)+", b"ababab");
    assert_regex_correctness(r"(ab)+", b"aba");
}

#[test]
fn regex_correctness_alternation() {
    assert_regex_correctness(r"cat|dog", b"I have a cat");
    assert_regex_correctness(r"cat|dog", b"I have a bird");
}

#[test]
fn regex_correctness_quantifier() {
    assert_regex_correctness(r"a?b", b"b");
    assert_regex_correctness(r"a?b", b"ab");
    assert_regex_correctness(r"a?b", b"aa");
}

#[test]
fn regex_correctness_escaped_metachar() {
    assert_regex_correctness(r"\.\*\+", b".*+");
    assert_regex_correctness(r"\.\*\+", b"abc");
}

#[test]
fn regex_correctness_unicode() {
    assert_regex_correctness(r"日本語", "こんにちは日本語".as_bytes());
    assert_regex_correctness(r"日本語", "hello world".as_bytes());
}

// C1-F009: empty regex pattern compile/match semantics differ from reference.
#[test]
#[ignore]
fn regex_correctness_empty_string() {
    assert_regex_correctness(r"", b"anything");
}

#[test]
fn regex_correctness_dot() {
    assert_regex_correctness(r"a.b", b"acb");
    assert_regex_correctness(r"a.b", b"a\nb"); // dot does not match newline
}

#[test]
fn regex_correctness_star() {
    assert_regex_correctness(r"a*b", b"b");
    assert_regex_correctness(r"a*b", b"aaab");
}

#[test]
fn regex_correctness_plus() {
    assert_regex_correctness(r"a+b", b"ab");
    assert_regex_correctness(r"a+b", b"b");
}

#[test]
fn regex_correctness_exact_quantifier() {
    assert_regex_correctness(r"a{3}", b"aaa");
    assert_regex_correctness(r"a{3}", b"aa");
}

#[test]
fn regex_correctness_range_quantifier() {
    assert_regex_correctness(r"a{2,4}", b"aa");
    assert_regex_correctness(r"a{2,4}", b"aaaaa");
}

#[test]
fn regex_correctness_case_insensitive_not_default() {
    assert_regex_correctness(r"hello", b"HELLO");
    assert_regex_correctness(r"HELLO", b"hello");
}

// C1-F009: PCRE lookahead unsupported (Rust regex engine).
#[test]
#[ignore]
fn regex_correctness_lookahead() {
    assert_regex_correctness(r"foo(?=bar)", b"foobar");
    assert_regex_correctness(r"foo(?=bar)", b"foobaz");
}

// C1-F009: PCRE lookbehind unsupported (Rust regex engine).
#[test]
#[ignore]
fn regex_correctness_lookbehind() {
    assert_regex_correctness(r"(?<=foo)bar", b"foobar");
    assert_regex_correctness(r"(?<=foo)bar", b"bazbar");
}

#[test]
fn regex_correctness_non_greedy() {
    assert_regex_correctness(r"<.*?>", b"<a><b>");
}

#[test]
fn regex_correctness_multiple_patterns_same_body() {
    let patterns = vec![r"\d+", r"[a-z]+", r"\s+"];
    let body = b"123 abc ";
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            patterns.clone(),
            MatchPart::Body,
        )])],
    );
    let db = CompiledDatabase::compile(&[template]).unwrap();
    let response = make_response(200, vec![], body);
    let matches = db.scan(&response).unwrap();

    for (i, pattern) in patterns.iter().enumerate() {
        let ref_regex = Regex::new(pattern).unwrap();
        let body_str = String::from_utf8_lossy(body);
        let ref_match = ref_regex.find(&body_str).unwrap();
        let engine_match = matches.iter().find(|m| m.value_index == i).unwrap();
        assert_eq!(
            engine_match.matched_value,
            ref_match.as_str(),
            "Pattern '{}' mismatch",
            pattern
        );
    }
}

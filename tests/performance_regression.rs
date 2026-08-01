//! Performance regression tests for the matching engine.
//!
//! These tests verify that matching operations maintain their expected
//! asymptotic complexity. Any accidental O(n²) behavior should fail.

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

/// Verifies that f() scales linearly (or better) with input size.
/// We run at two sizes and assert the larger is not more than 5x slower.
fn assert_linear_scaling<F>(name: &str, size_small: usize, size_large: usize, prepare: F)
where
    F: Fn(usize) -> ResponseData,
{
    let db = CompiledDatabase::compile(&[make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["needle"],
            MatchPart::Body,
        )])],
    )])
    .unwrap();

    let response_small = prepare(size_small);
    let response_large = prepare(size_large);

    // Warm up BOTH sizes: the first scan of a response lazily builds the
    // combined headers+body buffer (OnceLock), and cold caches dominate when
    // only a handful of iterations are timed. Without warmup the large side
    // pays one-time costs that read as superlinear scaling.
    for _ in 0..3 {
        let _ = db.scan(&response_small);
        let _ = db.scan(&response_large);
    }

    let start = Instant::now();
    for _ in 0..20 {
        let _ = db.scan(&response_small);
    }
    let time_small = start.elapsed();

    let start = Instant::now();
    for _ in 0..20 {
        let _ = db.scan(&response_large);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    let size_ratio = size_large as f64 / size_small as f64;

    assert!(
        ratio <= size_ratio * 5.0,
        "{name} does not scale linearly: small={size_small} in {:?}, large={size_large} in {:?}, ratio={ratio:.2}x (expected ~{size_ratio:.1}x)",
        time_small,
        time_large
    );
}

// ============================================================================
// Word Matcher O(n) Tests
// ============================================================================

#[test]
fn word_match_scales_linearly_with_body_size() {
    assert_linear_scaling("word match body size", 100_000, 1_000_000, |size| {
        make_response(200, vec![], &vec![b'x'; size])
    });
}

#[test]
fn word_match_scales_linearly_with_pattern_count() {
    fn build_db(pattern_count: usize) -> (CompiledDatabase, ResponseData) {
        let values: Vec<String> = (0..pattern_count)
            .map(|i| format!("pattern{i:08}"))
            .collect();
        let template = make_template(
            "t1",
            vec![make_request(vec![make_matcher(
                MatcherKind::Word,
                values.iter().map(|s| s.as_str()).collect(),
                MatchPart::Body,
            )])],
        );
        let db = CompiledDatabase::compile(&[template]).unwrap();
        let response = make_response(200, vec![], b"pattern99999999 here");
        (db, response)
    }

    let (db_small, response) = build_db(1_000);
    let start = Instant::now();
    for _ in 0..10 {
        let _ = db_small.scan(&response);
    }
    let time_small = start.elapsed();

    let (db_large, response) = build_db(10_000);
    let start = Instant::now();
    for _ in 0..10 {
        let _ = db_large.scan(&response);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    assert!(
        ratio <= 10.0,
        "Pattern count scaling too slow: 1K in {:?}, 10K in {:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

#[test]
fn word_no_match_scales_linearly_with_body_size() {
    assert_linear_scaling("word no-match body size", 100_000, 1_000_000, |size| {
        make_response(200, vec![], &vec![b'x'; size])
    });
}

// ============================================================================
// Regex Matcher O(n) Tests
// ============================================================================

#[test]
fn regex_match_scales_linearly_with_body_size() {
    let db_small = CompiledDatabase::compile(&[make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"\d{3}-\d{3}-\d{4}"],
            MatchPart::Body,
        )])],
    )])
    .unwrap();

    fn build_body(size: usize) -> Vec<u8> {
        let mut body = Vec::with_capacity(size);
        while body.len() < size {
            body.extend_from_slice(b"555-123-4567 ");
        }
        body.truncate(size);
        body
    }

    let body_small = build_body(100_000);
    let body_large = build_body(1_000_000);

    let response_small = make_response(200, vec![], &body_small);
    let response_large = make_response(200, vec![], &body_large);

    let start = Instant::now();
    for _ in 0..5 {
        let _ = db_small.scan(&response_small);
    }
    let time_small = start.elapsed();

    let start = Instant::now();
    for _ in 0..5 {
        let _ = db_small.scan(&response_large);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    assert!(
        ratio <= 15.0,
        "Regex match scaling too slow: 100K in {:?}, 1M in {:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

#[test]
fn regex_no_match_scales_linearly_with_body_size() {
    let db = CompiledDatabase::compile(&[make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            vec![r"ZZZZZZZZZ"],
            MatchPart::Body,
        )])],
    )])
    .unwrap();

    let response_small = make_response(200, vec![], &vec![b'x'; 100_000]);
    let response_large = make_response(200, vec![], &vec![b'x'; 1_000_000]);

    // Warm up both sizes, then time enough iterations that one-time lazy
    // buffer construction and scheduler noise cannot dominate the ratio.
    for _ in 0..3 {
        let _ = db.scan(&response_small);
        let _ = db.scan(&response_large);
    }

    let start = Instant::now();
    for _ in 0..20 {
        let _ = db.scan(&response_small);
    }
    let time_small = start.elapsed();

    let start = Instant::now();
    for _ in 0..20 {
        let _ = db.scan(&response_large);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    // 10x data: linear behavior lands near 10x. The 30x ceiling still fails
    // any quadratic regression (an O(n^2) scan measures ~100x here).
    assert!(
        ratio <= 30.0,
        "Regex no-match scaling too slow: 100K in {:?}, 1M in {:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

#[test]
fn regex_set_match_scales_linearly_with_pattern_count() {
    fn build_db(pattern_count: usize) -> (CompiledDatabase, ResponseData) {
        let values: Vec<String> = (0..pattern_count)
            .map(|i| format!(r"regex{i:08}}}-\d+"))
            .collect();
        let template = make_template(
            "t1",
            vec![make_request(vec![make_matcher(
                MatcherKind::Regex,
                values.iter().map(|s| s.as_str()).collect(),
                MatchPart::Body,
            )])],
        );
        let db = CompiledDatabase::compile(&[template]).unwrap();
        let response = make_response(200, vec![], b"regex09999999-123 here");
        (db, response)
    }

    let (db_small, response) = build_db(200);
    let start = Instant::now();
    for _ in 0..10 {
        let _ = db_small.scan(&response);
    }
    let time_small = start.elapsed();

    let (db_large, response) = build_db(1_000);
    let start = Instant::now();
    for _ in 0..10 {
        let _ = db_large.scan(&response);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    assert!(
        ratio <= 10.0,
        "RegexSet pattern count scaling too slow: 200 in {:?}, 1000 in {:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

// ============================================================================
// Status / Size Matcher O(1) Tests
// ============================================================================

#[test]
fn status_match_is_independent_of_body_size() {
    let db = CompiledDatabase::compile(&[make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Status,
            vec!["200"],
            MatchPart::Body,
        )])],
    )])
    .unwrap();

    let response_small = make_response(200, vec![], &vec![b'x'; 100]);
    let response_large = make_response(200, vec![], &vec![b'x'; 10_000_000]);

    let start = Instant::now();
    for _ in 0..100 {
        let _ = db.scan(&response_small);
    }
    let time_small = start.elapsed();

    let start = Instant::now();
    for _ in 0..100 {
        let _ = db.scan(&response_large);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    assert!(
        ratio <= 5.0,
        "Status match should be O(1) regardless of body size: small={:?}, large={:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

#[test]
fn size_match_is_independent_of_header_count() {
    let db = CompiledDatabase::compile(&[make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Size,
            vec!["4"],
            MatchPart::Body,
        )])],
    )])
    .unwrap();

    let headers_small: Vec<(&str, &str)> = (0..10).map(|_i| ("X-Header", "value")).collect();
    let headers_large: Vec<(&str, &str)> = (0..1000).map(|_i| ("X-Header", "value")).collect();

    let response_small = ResponseData::new(
        200,
        headers_small
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        b"test".to_vec(),
    );
    let response_large = ResponseData::new(
        200,
        headers_large
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        b"test".to_vec(),
    );

    let start = Instant::now();
    for _ in 0..100 {
        let _ = db.scan(&response_small);
    }
    let time_small = start.elapsed();

    let start = Instant::now();
    for _ in 0..100 {
        let _ = db.scan(&response_large);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    assert!(
        ratio <= 5.0,
        "Size match should be O(1) regardless of header count: small={:?}, large={:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

// ============================================================================
// Header Matcher O(headers) Tests
// ============================================================================

#[test]
fn header_word_match_scales_linearly_with_header_count() {
    fn build_response(header_count: usize) -> ResponseData {
        let headers: Vec<(String, String)> = (0..header_count)
            .map(|i| (format!("X-Header-{i}"), "value".to_string()))
            .collect();
        ResponseData::new(200, headers, b"body".to_vec())
    }

    let db = CompiledDatabase::compile(&[make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Word,
            vec!["needle"],
            MatchPart::Header,
        )])],
    )])
    .unwrap();

    let response_small = build_response(100);
    let response_large = build_response(1_000);

    // Warm up both responses (see assert_linear_scaling for why), then time
    // enough iterations that scheduler noise cannot dominate the ratio.
    for _ in 0..3 {
        let _ = db.scan(&response_small);
        let _ = db.scan(&response_large);
    }

    let start = Instant::now();
    for _ in 0..50 {
        let _ = db.scan(&response_small);
    }
    let time_small = start.elapsed();

    let start = Instant::now();
    for _ in 0..50 {
        let _ = db.scan(&response_large);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    // 10x headers: linear behavior lands near 10x. The 30x ceiling still
    // fails any quadratic regression (an O(n^2) scan measures ~100x here).
    assert!(
        ratio <= 30.0,
        "Header word match scaling too slow: 100 headers in {:?}, 1000 in {:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

// ============================================================================
// Compilation Performance Tests
// ============================================================================

#[test]
fn word_pattern_compilation_scales_linearly() {
    fn build_template(pattern_count: usize) -> Template {
        let values: Vec<String> = (0..pattern_count).map(|i| format!("word{i:08}")).collect();
        make_template(
            "t1",
            vec![make_request(vec![make_matcher(
                MatcherKind::Word,
                values.iter().map(|s| s.as_str()).collect(),
                MatchPart::Body,
            )])],
        )
    }

    // Best-of-several-rounds: a preempted round only inflates its own time,
    // so the minimum ratio is the contention-robust estimate.
    let mut best_ratio = f64::INFINITY;
    for _round in 0..3 {
        let start = Instant::now();
        let _ = CompiledDatabase::compile(&[build_template(1_000)]);
        let time_small = start.elapsed();

        let start = Instant::now();
        let _ = CompiledDatabase::compile(&[build_template(10_000)]);
        let time_large = start.elapsed();

        best_ratio =
            best_ratio.min(time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9));
    }

    // 10x patterns: linear compile lands near 10x. The 30x ceiling still
    // fails a quadratic regression decisively.
    assert!(
        best_ratio <= 30.0,
        "Word compilation scaling too slow: best ratio over 3 rounds = {best_ratio:.2}x"
    );
}

#[test]
fn regex_pattern_compilation_does_not_explode() {
    // RegexSet compilation is chunked at 200 patterns to avoid DFA explosion.
    // 500 patterns should complete in a reasonable time.
    let values: Vec<String> = (0..500).map(|i| format!(r"pattern{i:05}}}-\d+")).collect();
    let template = make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Regex,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    );

    let start = Instant::now();
    let _ = CompiledDatabase::compile(&[template]).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(30),
        "500 regex patterns took {:?} to compile  -  possible DFA explosion",
        elapsed
    );
}

#[test]
fn binary_pattern_compilation_scales_linearly() {
    fn build_template(pattern_count: usize) -> Template {
        let values: Vec<String> = (0..pattern_count).map(|i| format!("{:016x}", i)).collect();
        make_template(
            "t1",
            vec![make_request(vec![make_matcher(
                MatcherKind::Binary,
                values.iter().map(|s| s.as_str()).collect(),
                MatchPart::Body,
            )])],
        )
    }

    let start = Instant::now();
    let _ = CompiledDatabase::compile(&[build_template(1_000)]);
    let time_small = start.elapsed();

    let start = Instant::now();
    let _ = CompiledDatabase::compile(&[build_template_10k(10_000)]);
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    assert!(
        ratio <= 20.0,
        "Binary compilation scaling too slow: 1K in {:?}, 10K in {:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

fn build_template_10k(pattern_count: usize) -> Template {
    let values: Vec<String> = (0..pattern_count).map(|i| format!("{:016x}", i)).collect();
    make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Binary,
            values.iter().map(|s| s.as_str()).collect(),
            MatchPart::Body,
        )])],
    )
}

// ============================================================================
// DSL Performance Tests
// ============================================================================

#[test]
fn dsl_contains_scales_linearly_with_body_size() {
    let db = CompiledDatabase::compile(&[make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec![r#"contains(body, "needle")"#],
            MatchPart::Body,
        )])],
    )])
    .unwrap();

    let response_small = make_response(200, vec![], &vec![b'x'; 100_000]);
    let response_large = make_response(200, vec![], &vec![b'x'; 1_000_000]);

    let start = Instant::now();
    for _ in 0..5 {
        let _ = db.scan(&response_small);
    }
    let time_small = start.elapsed();

    let start = Instant::now();
    for _ in 0..5 {
        let _ = db.scan(&response_large);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    assert!(
        ratio <= 15.0,
        "DSL contains scaling too slow: 100K in {:?}, 1M in {:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

#[test]
fn dsl_regex_scales_linearly_with_body_size() {
    let db = CompiledDatabase::compile(&[make_template(
        "t1",
        vec![make_request(vec![make_matcher(
            MatcherKind::Dsl,
            vec![r#"regex(body, "\d{3}-\d{3}-\d{4}")"#],
            MatchPart::Body,
        )])],
    )])
    .unwrap();

    fn build_body(size: usize) -> Vec<u8> {
        let mut body = Vec::with_capacity(size);
        while body.len() < size {
            body.extend_from_slice(b"555-123-4567 ");
        }
        body.truncate(size);
        body
    }

    let response_small = make_response(200, vec![], &build_body(100_000));
    let response_large = make_response(200, vec![], &build_body(1_000_000));

    let start = Instant::now();
    for _ in 0..5 {
        let _ = db.scan(&response_small);
    }
    let time_small = start.elapsed();

    let start = Instant::now();
    for _ in 0..5 {
        let _ = db.scan(&response_large);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9);
    assert!(
        ratio <= 15.0,
        "DSL regex scaling too slow: 100K in {:?}, 1M in {:?}, ratio={ratio:.2}x",
        time_small,
        time_large
    );
}

// ============================================================================
// Streaming Matcher Performance Tests
// ============================================================================

use aho_corasick::AhoCorasick;
use secmatch::streaming::StreamingMatcher;

fn test_automaton(patterns: &[&str]) -> AhoCorasick {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(patterns)
        .unwrap()
}

#[test]
fn streaming_matcher_scales_linearly_with_chunk_count() {
    let ac = test_automaton(&["password"]);
    let chunk = b"x".repeat(1024);

    // Warm up both matchers so allocator growth and cold caches cannot
    // dominate the short timed loops.
    let mut warmup = StreamingMatcher::new(ac.clone(), 1024 * 1024);
    for _ in 0..10 {
        let _ = warmup.feed(&chunk);
    }

    // Best-of-several-rounds: a preempted round only inflates its own time,
    // so the minimum ratio is the contention-robust estimate. Each round
    // builds fresh matchers so buffer growth state matches a cold start.
    let mut best_ratio = f64::INFINITY;
    for _round in 0..3 {
        let mut matcher_small = StreamingMatcher::new(ac.clone(), 1024 * 1024);
        let start = Instant::now();
        for _ in 0..100 {
            let _ = matcher_small.feed(&chunk);
        }
        let time_small = start.elapsed();

        let mut matcher_large = StreamingMatcher::new(ac.clone(), 1024 * 1024);
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = matcher_large.feed(&chunk);
        }
        let time_large = start.elapsed();

        best_ratio = best_ratio.min(time_large.as_secs_f64() / time_small.as_secs_f64().max(1e-9));
    }

    // 10x chunks: linear behavior lands near 10x. The 30x ceiling still fails
    // a quadratic regression decisively (the pre-fix O(n^2) rescan measured
    // ~98x here).
    assert!(
        best_ratio <= 30.0,
        "Streaming matcher chunk scaling too slow: best ratio over 3 rounds = {best_ratio:.2}x"
    );
}

#[test]
fn streaming_matcher_early_cancel_avoids_work() {
    let ac = test_automaton(&["early_match"]);
    let prefix = b"early_match".to_vec();
    let suffix = vec![b'x'; 10_000_000];

    let mut matcher = StreamingMatcher::new(ac, 1024 * 1024);
    let start = Instant::now();
    let _ = matcher.feed(&prefix);
    let _ = matcher.feed(&suffix);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "Streaming matcher should cancel early and not process 10MB suffix, took {:?}",
        elapsed
    );
}

//! Matching Gap Tests
//!
//! These tests expose gaps in the matching engine's handling of:
//! - Previous request status references in DSL
//! - PCRE backreferences in regex
//! - DSL helper functions like rand_base()

use crate::database::CompiledDatabase;
use crate::dsl::{evaluate_dsl, evaluate_dsl_with_variables};
use secir::Severity;
use secir::matcher::{MatchDatabase, ResponseData};
use secir::template::{
    MatchPart, MatcherCondition, MatcherDef, MatcherKind, Template, TemplateInfo, TemplateMeta,
};
use std::collections::HashMap;

fn make_template_with_matchers(id: &str, matchers: Vec<MatcherDef>) -> Template {
    Template {
        depends_on: vec![],
        id: id.to_string(),
        ir_version: 1,
        extends: None,
        imports: Vec::new(),
        parallel_groups: Vec::new(),
        info: TemplateInfo {
            name: id.to_string(),
            author: vec!["test".to_string()],
            severity: Severity::Info,
            description: None,
            reference: vec![],
            tags: vec![],
            metadata: TemplateMeta::default(),
        },
        protocol: secir::Protocol::Http,
        requests: vec![secir::RequestDef {
            call: None,
            compute: vec![],
            condition: None,
            goto: None,
            headless_actions: Vec::new(),
            iterate: None,
            label: None,
            transforms: Vec::new(),
            method: "GET".to_string(),
            raw: None,
            paths: vec!["{{BaseURL}}".to_string()],
            headers: HashMap::new(),
            body: None,
            port: None,
            inputs: Vec::new(),
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
        }],
        self_contained: false,
        variables: HashMap::new(),
        cli_variables: HashMap::new(),
        source_path: None,
        flow: None,
        workflows: Vec::new(),
        extensions: HashMap::new(),
        exports: Vec::new(),
    }
}

/// GAP TEST 5: DSL expression referencing previous request status
///
/// CLAIM: DSL expressions can reference status_code_1, status_code_2, etc.
///        to access previous request status codes.
///
/// GAP: status_code_N variables are not defined - only current status_code works.
#[test]
fn dsl_expression_references_previous_request_status_code() {
    // Current response
    let response = ResponseData::new(
        200,
        vec![("Content-Type".to_string(), "text/html".to_string())],
        b"success".to_vec(),
    );

    // This should work: status_code == 200
    let result_current = evaluate_dsl("status_code == 200", &response);
    assert!(result_current, "Current status_code should work");

    // GAP: status_code_1 must not alias the current response until chain support exists.
    let result_previous =
        evaluate_dsl_with_variables("status_code_1 == 200", &response, &HashMap::new());
    assert!(
        !result_previous,
        "GAP: status_code_1 must not alias current status_code (multi-request chain unimplemented)"
    );
}

/// GAP TEST 6: Regex with PCRE backreference
///
/// CLAIM: Regex patterns support PCRE features like backreferences (\1, \2).
///
/// GAP: Backreferences cause regex compilation to fail or are ignored.
#[test]
fn regex_with_pcre_backreference_graceful_handling() {
    // Pattern that matches repeated words using backreference
    let pattern = r"(\w+)\s+\1";

    let matchers = vec![MatcherDef {
        kind: MatcherKind::Regex,
        values: vec![pattern.to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    }];

    let template = make_template_with_matchers("backref-test", matchers);

    // Attempt to compile
    let compile_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CompiledDatabase::compile(&[template])
    }));

    // GAP: Should compile successfully
    assert!(
        compile_result.is_ok(),
        "GAP: Regex pattern with backreference '{}' should compile successfully. \
         This exposes that PCRE backreferences are not supported in the regex engine.",
        pattern
    );
}

/// GAP TEST 7: DSL rand_base function
///
/// CLAIM: DSL supports rand_base(length, charset) to generate random strings.
///
/// GAP: rand_base function is not implemented in the DSL evaluator.
#[test]
fn dsl_function_rand_base_generates_correct_charset() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());

    // GAP: rand_base(10, "abc") should return a 10-char string with only a, b, c
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evaluate_dsl("len(rand_base(10, \"abc\")) == 10", &response)
    }));

    // The function should at least be parseable
    assert!(
        result.is_ok(),
        "GAP: DSL function rand_base(10, \"abc\") should be parseable without panicking. \
         This exposes that rand_base is not implemented in the DSL."
    );

    if let Ok(eval_result) = result {
        assert!(
            eval_result,
            "GAP: rand_base(10, \"abc\") should return a 10-character string. \
             The len() comparison failed."
        );
    }
}

/// Additional test: DSL should support status_code_N for all previous requests
#[test]
fn dsl_supports_multiple_previous_status_references() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());

    let expressions = vec![
        "status_code_1 == 200",
        "status_code_2 == 404",
        "status_code_1 == status_code_2",
        "status_code_1 != status_code_3",
    ];

    for expr in &expressions {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluate_dsl_with_variables(expr, &response, &HashMap::new())
        }));

        assert!(
            result.is_ok(),
            "GAP: DSL expression '{}' should not panic. \
             This exposes that multi-request status references are not implemented.",
            expr
        );
    }
}

#[test]
fn named_binary_matcher_matches_decoded_bytes_not_hex_text() {
    let matcher = MatcherDef {
        kind: MatcherKind::Binary,
        values: vec!["4141".to_string()], // Hex for b"AA"
        part: MatchPart::Named("server".to_string()),
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    };
    let template = make_template_with_matchers("named_binary_test", vec![matcher]);
    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Case 1: Header "server" contains binary bytes b"AA" ("xAAx") -> MUST MATCH
    let resp_bytes = ResponseData::new(200, vec![("server".to_string(), "xAAx".to_string())], b"".to_vec());
    let matches_bytes = db.scan(&resp_bytes).expect("scan should succeed");
    assert_eq!(
        matches_bytes.len(),
        1,
        "named binary matcher with hex 4141 must match header value 'xAAx' containing raw bytes 0x41 0x41"
    );

    // Case 2: Header "server" contains literal hex string "x4141x" (b"x4141x") -> MUST NOT MATCH
    let resp_hex = ResponseData::new(200, vec![("server".to_string(), "x4141x".to_string())], b"".to_vec());
    let matches_hex = db.scan(&resp_hex).expect("scan should succeed");
    assert_eq!(
        matches_hex.len(),
        0,
        "named binary matcher with hex 4141 must NOT match header value 'x4141x' containing literal hex text"
    );
}

#[test]
fn build_word_automaton_with_fallback_invoked_and_handles_errors() {
    let primary_called = std::cell::Cell::new(false);
    let fallback_called = std::cell::Cell::new(false);

    let res = CompiledDatabase::build_word_automaton_with(
        || {
            primary_called.set(true);
            Err("primary builder error")
        },
        || {
            fallback_called.set(true);
            aho_corasick::AhoCorasick::builder().build(&["test"])
        },
    );

    assert!(res.is_ok());
    assert!(primary_called.get());
    assert!(fallback_called.get());

    let both_failed = CompiledDatabase::build_word_automaton_with(
        || Err("primary failed"),
        || Err("fallback failed"),
    );
    assert!(both_failed.is_err());
}

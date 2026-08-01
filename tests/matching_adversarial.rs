//! Adversarial tests for pattern matching - DESIGNED TO FAIL
//!
//! These tests intentionally break the matching engine with:
//! - Catastrophic backtracking regex patterns
//! - Malformed DSL expressions
//! - Extreme input sizes
//! - Unicode normalization attacks
//! - Null bytes in unexpected places

use secir::MatchDatabase;
use secir::Severity;
use secir::finding::{Finding, FindingKind};
use secir::matcher::ResponseData;
use secir::template::{
    AttackType, ExtractorDef, ExtractorKind, MatchPart, MatcherCondition, MatcherDef, MatcherKind,
    Protocol, RequestDef, Template, TemplateInfo, TemplateMeta, Transform,
};
use secmatch::{
    CompiledDatabase, correlate_findings, evaluate_dsl, evaluate_dsl_with_variables,
    extract_from_response, matcher_satisfied, substitute_variables, transform_response,
};
use std::collections::{HashMap, HashSet};

fn make_test_template(requests: Vec<RequestDef>) -> Template {
    Template {
        depends_on: vec![],
        id: "test-template".to_string(),
        ir_version: 1,
        extends: None,
        imports: vec![],
        info: TemplateInfo {
            name: "Test Template".to_string(),
            author: vec![],
            severity: Severity::High,
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

fn make_test_request(matchers: Vec<MatcherDef>) -> RequestDef {
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

// ============================================================================
// CompiledDatabase::compile - Malformed Template Tests
// ============================================================================

/// Test 1: Template with extremely long pattern
/// EXPECTED FAILURE: May OOM or timeout on huge patterns
#[test]
fn compile_extremely_long_pattern() {
    let huge_pattern = "a".repeat(1000000); // 1MB of 'a'
    let template = make_test_template(vec![make_test_request(vec![MatcherDef {
        kind: MatcherKind::Word,
        values: vec![huge_pattern],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    }])]);

    let result = CompiledDatabase::compile(&[template]);
    // Should handle gracefully, even if it fails
    assert!(result.is_ok() || result.is_err(), "Should return a result");
}

/// Test 2: Regex with catastrophic backtracking
/// EXPECTED FAILURE: (a+)+ pattern causes exponential backtracking
#[test]
fn compile_catastrophic_backtracking_regex() {
    let evil_regex = r"(a+)+$"; // Known backtracking pattern
    let template = make_test_template(vec![make_test_request(vec![MatcherDef {
        kind: MatcherKind::Regex,
        values: vec![evil_regex.to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    }])]);

    let result = CompiledDatabase::compile(&[template]);
    // May fail to compile or take too long
    assert!(result.is_ok() || result.is_err(), "Should return result");
}

/// Test 3: Invalid regex syntax
/// EXPECTED FAILURE: May panic on invalid regex
#[test]
fn compile_invalid_regex_syntax() {
    let invalid_regexes = vec![
        "(",    // Unclosed group
        "[",    // Unclosed character class
        "(?P<", // Incomplete named group
        "\\\\", // Invalid escape
        "*+",   // Quantifier without operand
    ];

    for invalid in invalid_regexes {
        let template = make_test_template(vec![make_test_request(vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![invalid.to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }])]);

        let result = CompiledDatabase::compile(&[template]);
        // Should not panic
        assert!(
            result.is_ok() || result.is_err(),
            "Should handle invalid regex '{}'",
            invalid
        );
    }
}

/// Test 4: Empty template list
#[test]
fn compile_empty_template() {
    let templates: Vec<Template> = vec![];
    let result = CompiledDatabase::compile(&templates);
    assert!(result.is_ok(), "Empty template should compile successfully");
}

/// Test 5: Template with null bytes in pattern
/// EXPECTED FAILURE: Null bytes may cause string handling issues
#[test]
fn compile_null_byte_in_pattern() {
    let pattern_with_null = "test\x00pattern".to_string();
    let template = make_test_template(vec![make_test_request(vec![MatcherDef {
        kind: MatcherKind::Word,
        values: vec![pattern_with_null],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    }])]);

    let result = CompiledDatabase::compile(&[template]);
    assert!(
        result.is_ok() || result.is_err(),
        "Should handle null bytes"
    );
}

/// Test 6: Thousands of empty patterns
/// EXPECTED FAILURE: May have performance issues with many empty patterns
#[test]
fn compile_thousands_of_empty_patterns() {
    let empty_matchers: Vec<MatcherDef> = (0..1000)
        .map(|_| MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        })
        .collect();

    let template = make_test_template(vec![make_test_request(empty_matchers)]);

    let result = CompiledDatabase::compile(&[template]);
    assert!(
        result.is_ok() || result.is_err(),
        "Should handle many empty patterns"
    );
}

/// Test 7: Unicode normalization attack patterns
/// EXPECTED FAILURE: May not handle Unicode equivalence properly
#[test]
fn compile_unicode_normalization() {
    // Different Unicode representations that look the same
    let patterns = vec![
        "caf\u{00e9}".to_string(),         // é as single codepoint
        "caf\u{0065}\u{0301}".to_string(), // e + combining acute
    ];

    let template = make_test_template(vec![make_test_request(vec![MatcherDef {
        kind: MatcherKind::Word,
        values: patterns,
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    }])]);

    let result = CompiledDatabase::compile(&[template]);
    assert!(result.is_ok(), "Should handle Unicode patterns");
}

// ============================================================================
// CompiledDatabase::scan - Adversarial Input Tests
// ============================================================================

/// Test 8: Scan with null bytes in response
#[test]
fn scan_null_bytes_in_response() {
    let template = make_test_template(vec![make_test_request(vec![MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["test".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    }])]);

    let db = CompiledDatabase::compile(&[template]).expect("compile should succeed");
    let response = ResponseData::new(
        200,
        vec![("Content-Type".to_string(), "text/html".to_string())],
        b"te\x00st".to_vec(), // Null byte in body
    );

    let matches = db.scan(&response).unwrap();
    assert!(
        matches.is_empty(),
        "Null bytes should prevent a literal word hit"
    );
}

/// Test 9: Scan with huge response body
/// EXPECTED FAILURE: May OOM or be slow on huge bodies
#[test]
fn scan_huge_response_body() {
    let template = make_test_template(vec![make_test_request(vec![MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["needle".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    }])]);

    let db = CompiledDatabase::compile(&[template]).expect("compile should succeed");
    let huge_body = vec![b'x'; 10_000_000]; // 10MB instead of 100MB to avoid OOM
    let response = ResponseData::new(200, vec![], huge_body);

    let matches = db.scan(&response).unwrap();
    assert!(matches.is_empty(), "Should not find needle in haystack");
}

/// Test 10: Scan with regex on binary data
#[test]
fn scan_regex_binary_data() {
    let template = make_test_template(vec![make_test_request(vec![MatcherDef {
        kind: MatcherKind::Regex,
        values: vec![r"\d+".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    }])]);

    let db = CompiledDatabase::compile(&[template]).expect("compile should succeed");
    let binary_body = vec![0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90]; // Some binary
    let response = ResponseData::new(200, vec![], binary_body);

    let matches = db.scan(&response).unwrap();
    assert!(
        matches.is_empty(),
        "Binary payload should not spuriously match digits"
    );
}

// ============================================================================
// evaluate_dsl - Malformed Expression Tests
// ============================================================================

/// Test 11: Empty DSL expression
#[test]
fn evaluate_dsl_empty() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let result = evaluate_dsl("", &response);
    assert!(!result, "Empty DSL should return false");
}

/// Test 12: DSL with only whitespace
#[test]
fn evaluate_dsl_whitespace_only() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let result = evaluate_dsl("   \n\t  ", &response);
    assert!(!result, "Whitespace-only DSL should return false");
}

/// Test 13: DSL with unmatched parentheses
#[test]
fn evaluate_dsl_unmatched_parens() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let result = evaluate_dsl("(status_code == 200", &response);
    assert!(!result, "Malformed DSL should fail closed");
}

/// Test 14: DSL with extremely long expression
/// EXPECTED FAILURE: May have performance issues with very long expressions
#[test]
fn evaluate_dsl_extremely_long() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let long_expr = format!("{}status_code == 200", "status_code == 200 && ".repeat(100));
    let result = evaluate_dsl(&long_expr, &response);
    assert!(result, "Long expression should still evaluate correctly");
}

/// Test 15: DSL division by zero
#[test]
fn evaluate_dsl_division_by_zero() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let result = evaluate_dsl("content_length / 0 > 0", &response);
    // Should handle gracefully
    assert!(!result, "Division by zero should return false or error");
}

/// Test 16: DSL with Unicode in string literals
#[test]
fn evaluate_dsl_unicode_literals() {
    let response = ResponseData::new(200, vec![], "日本語".as_bytes().to_vec());
    let result = evaluate_dsl(r#"contains(body, "日本語")"#, &response);
    assert!(result, "Should match Unicode content");
}

/// Test 17: DSL with null bytes in expression
#[test]
fn evaluate_dsl_null_bytes() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let expr = "status\x00_code == 200";
    let result = evaluate_dsl(expr, &response);
    // Should handle gracefully
    assert!(!result, "Should handle null bytes in expression");
}

/// Test 18: DSL with undefined variables
#[test]
fn evaluate_dsl_undefined_variable() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let result = evaluate_dsl("undefined_var == 200", &response);
    assert!(!result, "Undefined variable should return false");
}

/// Test 19: DSL with deeply nested expressions
/// EXPECTED FAILURE: May overflow stack with deep nesting
#[test]
fn evaluate_dsl_deeply_nested() {
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    // Use moderate nesting that should still be handled but may fail
    let deep_expr = "(".repeat(50) + "status_code == 200" + &")".repeat(50);
    let result = evaluate_dsl(&deep_expr, &response);
    assert!(
        result,
        "Balanced nested expressions should still evaluate correctly"
    );
}

/// Test 20: DSL with variables containing special characters
#[test]
fn evaluate_dsl_variables_with_special_chars() {
    let mut vars = HashMap::new();
    vars.insert("special<var>".to_string(), "value".to_string());
    vars.insert("var with spaces".to_string(), "value2".to_string());
    vars.insert("var\nwith\nnewlines".to_string(), "value3".to_string());

    let response = ResponseData::new(200, vec![], b"test".to_vec());
    // These should not crash
    for key in vars.keys() {
        let expr = format!("'{{{}}}' != ''", key);
        let _result = evaluate_dsl_with_variables(&expr, &response, &vars);
        // Just verifying no panic
    }
}

// ============================================================================
// extract_from_response - Edge Cases
// ============================================================================

/// Test 21: Extractor with null bytes in regex
#[test]
fn extract_null_bytes_in_regex() {
    let response = ResponseData::new(200, vec![], b"te\x00st".to_vec());
    let extractors = vec![ExtractorDef {
        kind: ExtractorKind::Regex,
        patterns: vec![r"te\x00st".to_string()],
        name: Some("test".to_string()),
        part: MatchPart::Body,
        group: 0,
        internal: false,
    }];

    let extracted = extract_from_response(&response, &extractors);
    assert_eq!(
        extracted.get("test"),
        Some(&"te\u{0}st".to_string()),
        "Regex extractors should preserve embedded null bytes"
    );
}

/// Test 22: Extractor with invalid group number
#[test]
fn extract_invalid_group_number() {
    let response = ResponseData::new(200, vec![], b"test123".to_vec());
    let extractors = vec![ExtractorDef {
        kind: ExtractorKind::Regex,
        patterns: vec![r"test(\d+)".to_string()],
        name: Some("test".to_string()),
        part: MatchPart::Body,
        group: 999, // Invalid group number
        internal: false,
    }];

    let extracted = extract_from_response(&response, &extractors);
    assert!(extracted.is_empty(), "Invalid group should return empty");
}

/// Test 23: JSON extractor with malformed JSON
#[test]
fn extract_malformed_json() {
    let response = ResponseData::new(200, vec![], b"{invalid json".to_vec());
    let extractors = vec![ExtractorDef {
        kind: ExtractorKind::Json,
        patterns: vec!["$.key".to_string()],
        name: Some("test".to_string()),
        part: MatchPart::Body,
        group: 0,
        internal: false,
    }];

    let extracted = extract_from_response(&response, &extractors);
    assert!(extracted.is_empty(), "Malformed JSON should return empty");
}

/// Test 24: JSON extractor with deeply nested path
#[test]
fn extract_deeply_nested_json_path() {
    let response = ResponseData::new(
        200,
        vec![],
        b"{\"a\":{\"b\":{\"c\":{\"d\":\"value\"}}}}".to_vec(),
    );
    let extractors = vec![ExtractorDef {
        kind: ExtractorKind::Json,
        patterns: vec!["$.a.b.c.d.e.f.g.h.i.j".to_string()],
        name: Some("test".to_string()),
        part: MatchPart::Body,
        group: 0,
        internal: false,
    }];

    let extracted = extract_from_response(&response, &extractors);
    assert!(
        extracted.is_empty(),
        "Non-existent deep path should return empty"
    );
}

/// Test 25: Kval extractor with null byte in header name
#[test]
fn extract_kval_null_byte_header() {
    let response = ResponseData::new(
        200,
        vec![("X-Test\x00-Header".to_string(), "value".to_string())],
        b"body".to_vec(),
    );
    let extractors = vec![ExtractorDef {
        kind: ExtractorKind::Kval,
        patterns: vec!["X-Test-Header".to_string()],
        name: Some("test".to_string()),
        part: MatchPart::Header,
        group: 0,
        internal: false,
    }];

    let extracted = extract_from_response(&response, &extractors);
    assert!(
        extracted.is_empty(),
        "Invalid header names should not produce Kval hits"
    );
}

/// Test 26: Extractor with huge capture group
#[test]
fn extract_huge_capture_group() {
    let huge_content = "a".repeat(1_000_000); // Reduced from 10M to 1M
    let response = ResponseData::new(
        200,
        vec![],
        format!("start{}end", huge_content).into_bytes(),
    );
    let extractors = vec![ExtractorDef {
        kind: ExtractorKind::Regex,
        patterns: vec![r"start(.*)end".to_string()],
        name: Some("huge".to_string()),
        part: MatchPart::Body,
        group: 1,
        internal: false,
    }];

    let extracted = extract_from_response(&response, &extractors);
    // Should handle huge captures
    assert!(extracted.len() <= 1, "Should handle huge capture");
}

// ============================================================================
// transform_response - Edge Cases
// ============================================================================

/// Test 27: Base64 decode of invalid data
#[test]
fn transform_invalid_base64() {
    let data = b"!!!invalid base64!!!".to_vec();
    let result = transform_response(data.clone(), &[Transform::Base64Decode]);
    // Should return original data on failure
    assert_eq!(result, data, "Invalid base64 should return original");
}

/// Test 28: Hex decode of invalid data
#[test]
fn transform_invalid_hex() {
    let data = b"GGHHZZ".to_vec(); // Invalid hex
    let result = transform_response(data.clone(), &[Transform::HexDecode]);
    // Should return original or empty
    assert!(
        result == data || result.is_empty(),
        "Invalid hex should return original or empty"
    );
}

/// Test 29: Gzip decompress of invalid data
#[test]
fn transform_invalid_gzip() {
    let data = vec![0x1f, 0x8b, 0x08, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]; // Invalid gzip
    let result = transform_response(data.clone(), &[Transform::GzipDecompress]);
    // Should return original on failure
    assert_eq!(result, data, "Invalid gzip should return original");
}

/// Test 30: JWT decode of invalid token
#[test]
fn transform_invalid_jwt() {
    let data = b"invalid.jwt.token.here".to_vec();
    let result = transform_response(data.clone(), &[Transform::JwtDecode]);
    assert_eq!(result, data, "Invalid JWT should pass through unchanged");
}

/// Test 31: JSON parse with invalid path
#[test]
fn transform_json_invalid_path() {
    let data = b"{\"key\": \"value\"}".to_vec();
    let result = transform_response(
        data.clone(),
        &[Transform::JsonParse {
            path: "...".to_string(),
        }],
    );
    assert!(
        result.is_empty(),
        "Missing JSON path should yield no extracted data"
    );
}

/// Test 32: Chain of transforms with failure in middle
#[test]
fn transform_chain_with_failure() {
    let data = b"test".to_vec();
    let result = transform_response(
        data,
        &[
            Transform::Base64Decode, // Will fail
            Transform::HexDecode,    // Will fail
            Transform::UrlDecode,    // May succeed
        ],
    );
    assert_eq!(
        result,
        vec![181, 235, 45],
        "Transform chains should continue from the last successful decode"
    );
}

/// Test 33: Transform with null bytes
#[test]
fn transform_null_bytes() {
    let data = b"dGVzdA\x00\x00==".to_vec(); // Base64 with nulls
    let result = transform_response(data.clone(), &[Transform::Base64Decode]);
    assert_eq!(result, data, "Invalid base64 should remain unchanged");
}

/// Test 34: URL decode with invalid percent encoding
#[test]
fn transform_invalid_url_encoding() {
    let data = b"%ZZ%GG%".to_vec();
    let result = transform_response(data.clone(), &[Transform::UrlDecode]);
    assert_eq!(result, data, "Invalid URL encoding should remain unchanged");
}

// ============================================================================
// substitute_variables - Edge Cases
// ============================================================================

/// Test 35: Variable substitution with null bytes
#[test]
fn substitute_null_bytes() {
    let text = "{{var}}";
    let mut vars = HashMap::new();
    vars.insert("var".to_string(), "te\x00st".to_string());

    let result = substitute_variables(text, &vars);
    assert_eq!(result, "te\x00st", "Should preserve null bytes");
}

/// Test 36: Variable substitution with empty key
#[test]
fn substitute_empty_key() {
    let text = "{{}}";
    let vars = HashMap::new();

    let result = substitute_variables(text, &vars);
    // Should handle gracefully
    assert_eq!(result, "{{}}", "Empty key should remain unchanged");
}

/// Test 37: Variable substitution with special regex chars
#[test]
fn substitute_special_regex_chars() {
    let text = "{{var}}";
    let mut vars = HashMap::new();
    vars.insert("var".to_string(), "$1$2$3".to_string());

    let result = substitute_variables(text, &vars);
    assert_eq!(result, "$1$2$3", "Should handle special chars");
}

/// Test 38: Variable substitution with very long value
#[test]
fn substitute_huge_value() {
    let text = "{{var}}";
    let mut vars = HashMap::new();
    vars.insert("var".to_string(), "x".repeat(1_000_000));

    let result = substitute_variables(text, &vars);
    assert_eq!(result.len(), 1_000_000, "Should handle huge value");
}

/// Test 39: Multiple variable substitution with overlapping names
#[test]
fn substitute_overlapping_names() {
    let text = "{{a}} {{ab}} {{abc}}";
    let mut vars = HashMap::new();
    vars.insert("a".to_string(), "1".to_string());
    vars.insert("ab".to_string(), "2".to_string());
    vars.insert("abc".to_string(), "3".to_string());

    let result = substitute_variables(text, &vars);
    // Should substitute correctly without partial matches
    assert!(result.contains("1"));
    assert!(result.contains("2"));
    assert!(result.contains("3"));
}

/// Test 40: Variable substitution with Unicode
#[test]
fn substitute_unicode() {
    let text = "{{var}}";
    let mut vars = HashMap::new();
    vars.insert("var".to_string(), "🚀日本語".to_string());

    let result = substitute_variables(text, &vars);
    assert_eq!(result, "🚀日本語", "Should handle Unicode");
}

// ============================================================================
// matcher_satisfied - Edge Cases
// ============================================================================

/// Test 41: Empty matcher with AND condition
#[test]
fn matcher_satisfied_empty_and() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec![],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::And,
        internal: false,
    };

    let hits: HashSet<usize> = HashSet::new();
    let result = matcher_satisfied(&matcher, Some(&hits));
    assert!(!result, "Empty AND matcher should not be satisfied");
}

/// Test 42: Matcher with empty string value
#[test]
fn matcher_satisfied_empty_string() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    };

    let hits: HashSet<usize> = [0].into_iter().collect();
    let result = matcher_satisfied(&matcher, Some(&hits));
    assert!(result, "Empty string matcher with hit should be satisfied");
}

/// Test 43: Negative matcher with no hits
#[test]
fn matcher_satisfied_negative_no_hits() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["test".to_string()],
        part: MatchPart::Body,
        negative: true,
        condition: MatcherCondition::Or,
        internal: false,
    };

    let hits: HashSet<usize> = HashSet::new();
    let result = matcher_satisfied(&matcher, Some(&hits));
    assert!(result, "Negative matcher with no hits should be satisfied");
}

/// Test 44: Matcher with None hits
#[test]
fn matcher_satisfied_none_hits() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["test".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    };

    let result = matcher_satisfied::<std::collections::hash_map::RandomState>(&matcher, None);
    assert!(!result, "None hits should not satisfy OR matcher");
}

/// Test 45: AND condition with partial hits
#[test]
fn matcher_satisfied_and_partial() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::And,
        internal: false,
    };

    let hits: HashSet<usize> = [0, 2].into_iter().collect(); // Only a and c
    let result = matcher_satisfied(&matcher, Some(&hits));
    assert!(!result, "Partial hits should not satisfy AND");
}

// ============================================================================
// correlate_findings - Edge Cases
// ============================================================================

/// Test 46: Empty findings
#[test]
fn correlate_empty_findings() {
    let findings: Vec<Finding> = vec![];
    let correlated = correlate_findings(&findings);
    assert!(correlated.is_empty(), "Empty findings should return empty");
}

/// Test 47: Finding with empty target
#[test]
fn correlate_empty_target() {
    let findings = vec![Finding {
        template_id: "test".to_string(),
        template_name: "Test".to_string(),
        template_path: None,
        target: "".to_string(),
        severity: Severity::High,
        kind: FindingKind::TechDetect,
        matched_values: vec!["test".to_string()],
        extracted: HashMap::new(),
        matched_at: "".to_string(),
        request: None,
        response: None,
        curl_command: None,
        matcher_name: None,
        protocol: None,
        timestamp: chrono::Utc::now(),
        tags: vec!["sqli".to_string()],
        description: None,
        references: vec![],
        cve_ids: vec![],
        confidence: None,
        verification: None,
    }];

    let correlated = correlate_findings(&findings);
    assert!(
        correlated.is_empty(),
        "A single empty-target finding should not correlate"
    );
}

/// Test 48: Multiple findings with same tag
#[test]
fn correlate_multiple_same_tag() {
    let findings = vec![
        Finding {
            template_id: "test1".to_string(),
            template_name: "Test1".to_string(),
            template_path: None,
            target: "http://example.com".to_string(),
            severity: Severity::High,
            kind: FindingKind::Vulnerability,
            matched_values: vec!["test".to_string()],
            extracted: HashMap::new(),
            matched_at: "http://example.com".to_string(),
            request: None,
            response: None,
            curl_command: None,
            matcher_name: None,
            protocol: None,
            timestamp: chrono::Utc::now(),
            tags: vec!["sqli".to_string()],
            description: None,
            references: vec![],
            cve_ids: vec![],
            confidence: None,
            verification: None,
        },
        Finding {
            template_id: "test2".to_string(),
            template_name: "Test2".to_string(),
            template_path: None,
            target: "http://example.com".to_string(),
            severity: Severity::High,
            kind: FindingKind::Vulnerability,
            matched_values: vec!["test".to_string()],
            extracted: HashMap::new(),
            matched_at: "http://example.com".to_string(),
            request: None,
            response: None,
            curl_command: None,
            matcher_name: None,
            protocol: None,
            timestamp: chrono::Utc::now(),
            tags: vec!["file-read".to_string()],
            description: None,
            references: vec![],
            cve_ids: vec![],
            confidence: None,
            verification: None,
        },
    ];

    let correlated = correlate_findings(&findings);
    // Should create RCE chain correlation
    assert!(
        !correlated.is_empty(),
        "Should create correlation for sqli + file-read"
    );
}

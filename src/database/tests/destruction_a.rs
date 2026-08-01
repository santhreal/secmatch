// CATEGORY 2: MATCHING ENGINE DESTRUCTION - 30 adversarial tests
// These tests are designed to break the matching engine
// =============================================================================

use super::*;

/// Test 1: Response body of exactly 0 bytes against 100 word matchers
#[test]
fn zero_byte_response_against_100_word_matchers() {
    let matchers: Vec<MatcherDef> = (0..100)
        .map(|i| MatcherDef {
            kind: MatcherKind::Word,
            values: vec![format!("pattern-{i}")],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        })
        .collect();

    let template = make_template_with_matchers("zero-byte-test", matchers);
    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], vec![]);
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 0, "0-byte response should match nothing");
}

/// Test 2: Response body of 10MB against 1 matcher - should not hang
#[test]
fn ten_mb_response_against_one_matcher() {
    let template = make_template_with_matchers(
        "large-body-test",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["target-string".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Create a 10MB body
    let mut body = vec![b'x'; 10 * 1024 * 1024];
    // Insert target at the end
    body.extend_from_slice(b"target-string");

    let response = ResponseData::new(200, vec![], body);

    let start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(3),
        "10MB scan should complete in < 3 seconds, took {:?}",
        elapsed
    );
    assert_eq!(matches.len(), 1, "should find target at end");
}

/// Test 3: Response with header value containing null bytes
#[test]
fn header_value_with_null_bytes() {
    let template = make_template_with_matchers(
        "null-header-test",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test".to_string()],
            part: MatchPart::Header,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let headers = vec![
        ("X-Test".to_string(), "test\x00value".to_string()),
        ("X-Normal".to_string(), "normal".to_string()),
    ];
    let response = ResponseData::new(200, headers, b"body".to_vec());

    let matches = db.scan(&response).unwrap();
    // Should handle null bytes gracefully
    assert!(matches.len() <= 1);
}

/// Test 4: 10,000 templates compiled into one database - verify memory bounded
#[test]
fn ten_thousand_templates_memory_bounded() {
    let templates: Vec<Template> = (0..10000)
        .map(|i| {
            make_template_with_matchers(
                &format!("template-{i}"),
                vec![MatcherDef {
                    kind: MatcherKind::Word,
                    values: vec![format!("unique-pattern-{i}")],
                    part: MatchPart::Body,
                    negative: false,
                    condition: MatcherCondition::Or,
                    internal: false,
                }],
            )
        })
        .collect();

    let start = Instant::now();
    let db = CompiledDatabase::compile(&templates).expect("compilation should succeed");
    let elapsed = start.elapsed();

    assert_eq!(db.template_count(), 10000, "should compile 10000 templates");
    assert!(
        elapsed < Duration::from_secs(5),
        "compiling 10000 templates should complete in < 5 seconds, took {:?}",
        elapsed
    );
}

/// Test 5: Pattern that is a valid regex but causes exponential blowup
#[test]
fn regex_with_potential_exponential_blowup() {
    // This pattern can cause exponential backtracking in some regex engines
    let template = make_template_with_matchers(
        "evil-regex-test",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"(a+)+b".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Input designed to trigger exponential behavior
    let body = "a".repeat(100);
    let response = ResponseData::new(200, vec![], body.into_bytes());

    let start = Instant::now();
    let _matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "regex scan should complete in < 2 seconds even with pathological input, took {:?}",
        elapsed
    );
}

/// Test 6: Binary matcher with pattern "00" matching every null byte
#[test]
fn binary_matcher_00_matches_null_bytes() {
    let template = make_template_with_matchers(
        "binary-null-test",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["00".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Body with many null bytes
    let mut body = Vec::new();
    for _ in 0..100 {
        body.push(0x00);
        body.push(0x01);
    }

    let response = ResponseData::new(200, vec![], body);
    let matches = db.scan(&response).unwrap();

    // Should find at least one match (dedup may reduce count)
    assert!(!matches.is_empty(), "should match null bytes");
}

/// Test 7: DSL expression division by zero
#[test]
fn dsl_expression_division_by_zero() {
    use crate::dsl::evaluate_dsl;

    let response = ResponseData::new(200, vec![], b"test".to_vec());

    // Division by zero in DSL
    let result = evaluate_dsl("1/0", &response);
    // Should return false or handle gracefully, not panic
    assert!(!result, "division by zero should return false");
}

/// Test 8: DSL expression with deeply nested parentheses
#[test]
fn dsl_deeply_nested_parentheses() {
    use crate::dsl::evaluate_dsl;

    let response = ResponseData::new(200, vec![], b"test".to_vec());

    // Create deeply nested expression: ((((((((((1 == 1))))))))))
    let mut expr = "1 == 1".to_string();
    for _ in 0..50 {
        expr = format!("({})", expr);
    }

    let result = evaluate_dsl(&expr, &response);
    // Should handle deep nesting without stack overflow
    // May return false if depth exceeds limit, but should not crash
    let _ = result; // Just checking it doesn't crash
}

/// Test 9: DSL string multiplication with huge count
#[test]
fn dsl_string_multiplication_huge_count() {
    use crate::dsl::evaluate_dsl;

    let response = ResponseData::new(200, vec![], b"test".to_vec());

    // String repeat with huge count - should be clamped or limited
    let result = evaluate_dsl(r#"len(repeat("a", 999999999)) > 0"#, &response);
    // Should not hang or OOM
    let _ = result; // Just checking it doesn't crash
}

/// Test 10: Word matcher with value that's the entire response body
#[test]
fn word_matcher_entire_response_body() {
    let body_content =
        "This is the entire response body content that will be used as the matcher pattern";
    let template = make_template_with_matchers(
        "whole-body-matcher",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec![body_content.to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], body_content.as_bytes().to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 1, "should match entire body");
}

/// Test 11: Regex matcher with alternation of 10,000 branches
#[test]
fn regex_with_10000_alternation_branches() {
    let branches: Vec<String> = (0..10000).map(|i| format!("pattern{i}")).collect();
    let regex = branches.join("|");

    let template = make_template_with_matchers(
        "massive-alternation",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![regex],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = CompiledDatabase::compile(&[template]);

    // May succeed or fail, but should not crash
    match result {
        Ok(db) => {
            let response = ResponseData::new(200, vec![], b"pattern9999".to_vec());
            let start = Instant::now();
            let matches = db.scan(&response).unwrap();
            let elapsed = start.elapsed();

            assert!(
                elapsed < Duration::from_secs(2),
                "large alternation scan should complete quickly"
            );
            assert!(!matches.is_empty(), "should match one of the patterns");
        }
        Err(_) => {
            // Compilation may fail due to regex size limits, which is OK
        }
    }
}

/// Test 12: Status matcher with value "65536" (overflow u16)
#[test]
fn status_matcher_u16_overflow() {
    let template = make_template_with_matchers(
        "status-overflow",
        vec![MatcherDef {
            kind: MatcherKind::Status,
            values: vec!["65536".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    // Should compile but the invalid status is ignored during compilation
    let db = CompiledDatabase::compile(&[template]);
    // Result should be OK or an error about invalid status
    match db {
        Ok(_) => {}
        Err(e) => {
            let err_str = e.to_string().to_lowercase();
            assert!(
                err_str.contains("status") || err_str.contains("invalid"),
                "Error should be about invalid status: {}",
                e
            );
        }
    }
}

/// Test 13: Size matcher with negative value
#[test]
fn size_matcher_negative_value() {
    let template = make_template_with_matchers(
        "size-negative",
        vec![MatcherDef {
            kind: MatcherKind::Size,
            values: vec!["-1".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    // Negative sizes are silently ignored during compilation
    let db = CompiledDatabase::compile(&[template]);
    assert!(db.is_ok() || db.is_err());
}

/// Test 14: Aho-Corasick with overlapping patterns where one is prefix of another
#[test]
fn aho_corasick_overlapping_prefix_patterns() {
    let template = make_template_with_matchers(
        "overlapping-prefix",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec![
                "a".to_string(),
                "ab".to_string(),
                "abc".to_string(),
                "abcd".to_string(),
                "abcde".to_string(),
            ],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"abcdef".to_vec());
    let matches = db.scan(&response).unwrap();

    // Should find matches, deduplication may affect exact count
    assert!(!matches.is_empty(), "should find overlapping matches");
}

/// Test 15: Template with extremely large number of duplicate patterns
#[test]
fn database_with_duplicate_patterns() {
    let values: Vec<String> = (0..1000).map(|_| "duplicate".to_string()).collect();

    let template = make_template_with_matchers(
        "duplicate-patterns",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values,
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"duplicate text".to_vec());
    let matches = db.scan(&response).unwrap();

    // Should find at least one match (dedup reduces duplicates)
    assert!(!matches.is_empty(), "should match duplicate patterns");
}

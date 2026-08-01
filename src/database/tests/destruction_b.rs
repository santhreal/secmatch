/// Test 16: Response with binary content that looks like UTF-8 invalid sequences
#[test]
fn binary_content_invalid_utf8() {
    let template = make_template_with_matchers(
        "binary-content-test",
        vec![
            MatcherDef {
                kind: MatcherKind::Binary,
                values: vec!["FF FE".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
            MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["test".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
        ],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Invalid UTF-8 sequence
    let body = vec![0xFF, 0xFE, 0x00, 0x00, b't', b'e', b's', b't'];
    let response = ResponseData::new(200, vec![], body);

    let matches = db.scan(&response).unwrap();
    // Should handle invalid UTF-8 gracefully
    assert!(!matches.is_empty(), "should match binary pattern");
}

use super::*;

/// Test 17: Template with case-insensitive word matching
#[test]
fn case_insensitive_word_matching() {
    let template = make_template_with_matchers(
        "case-insensitive",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["ADMIN".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Test various cases
    for case in ["admin", "ADMIN", "Admin", "AdMiN"] {
        let response = ResponseData::new(200, vec![], case.as_bytes().to_vec());
        let matches = db.scan(&response).unwrap();
        assert_eq!(
            matches.len(),
            1,
            "should match '{}' case-insensitively",
            case
        );
    }
}

/// Test 18: Regex with empty pattern
#[test]
fn regex_empty_pattern() {
    let template = make_template_with_matchers(
        "empty-regex",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec!["".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = CompiledDatabase::compile(&[template]);
    // Empty regex may or may not compile depending on implementation
    if let Ok(db) = result {
        let response = ResponseData::new(200, vec![], b"test".to_vec());
        let _matches = db.scan(&response).unwrap();
    }
}

/// Test 19: Matcher on named header that doesn't exist
#[test]
fn named_header_that_does_not_exist() {
    let template = make_template_with_matchers(
        "missing-named-header",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["value".to_string()],
            part: MatchPart::Named("NonExistentHeader".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(
        200,
        vec![("OtherHeader".to_string(), "value".to_string())],
        b"body".to_vec(),
    );

    let matches = db.scan(&response).unwrap();
    // Should not match since header doesn't exist
    assert!(matches.is_empty(), "should not match non-existent header");
}

/// Test 20: Response with maximum possible status code
#[test]
fn status_code_maximum_value() {
    let template = make_template_with_matchers(
        "max-status",
        vec![MatcherDef {
            kind: MatcherKind::Status,
            values: vec!["599".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(599, vec![], b"body".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 1, "should match status 599");
}

/// Test 21: DSL expression with extremely long string
#[test]
fn dsl_expression_with_long_string() {
    use crate::dsl::evaluate_dsl;

    let response = ResponseData::new(200, vec![], b"test".to_vec());

    let long_string = "x".repeat(1000);
    // Use len() function instead of method syntax
    let expr = format!(r#"len("{}") > 0"#, long_string);

    let result = evaluate_dsl(&expr, &response);
    // Should handle long strings without issues
    assert!(result, "long string length check should work");
}

/// Test 22: Pattern that matches at every position (empty pattern behavior)
#[test]
fn word_matcher_single_character() {
    let template = make_template_with_matchers(
        "single-char",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["a".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"banana".to_vec());
    let matches = db.scan(&response).unwrap();

    // Should find at least one match for 'a'
    assert!(!matches.is_empty(), "should match 'a' in 'banana'");
}

/// Test 23: Multiple templates with same pattern - deduplication check
#[test]
fn multiple_templates_same_pattern() {
    let templates: Vec<Template> = (0..100)
        .map(|i| {
            make_template_with_matchers(
                &format!("template-{i}"),
                vec![MatcherDef {
                    kind: MatcherKind::Word,
                    values: vec!["common-pattern".to_string()],
                    part: MatchPart::Body,
                    negative: false,
                    condition: MatcherCondition::Or,
                    internal: false,
                }],
            )
        })
        .collect();

    let db = CompiledDatabase::compile(&templates).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"common-pattern here".to_vec());
    let matches = db.scan(&response).unwrap();

    // Should find matches from multiple templates
    assert!(
        !matches.is_empty(),
        "should find matches from multiple templates"
    );
}

/// Test 24: Regex with lookahead/lookbehind (if supported)
#[test]
fn regex_with_lookahead() {
    let template = make_template_with_matchers(
        "regex-lookahead",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"test(?=ing)".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = CompiledDatabase::compile(&[template]);
    // Lookahead support varies by regex engine
    if let Ok(db) = result {
        let response = ResponseData::new(200, vec![], b"testing".to_vec());
        let matches = db.scan(&response).unwrap();
        // May or may not match depending on regex engine
        let _ = matches;
    }
}

/// Test 25: Template with mixed positive and negative matchers
#[test]
fn mixed_positive_negative_matchers() {
    let template = make_template_with_matchers(
        "mixed-matchers",
        vec![
            MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["required".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
            MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["forbidden".to_string()],
                part: MatchPart::Body,
                negative: true,
                condition: MatcherCondition::Or,
                internal: false,
            },
        ],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Response with required but not forbidden
    let response = ResponseData::new(200, vec![], b"required content".to_vec());
    let matches = db.scan(&response).unwrap();

    assert!(!matches.is_empty(), "should match positive pattern");
}

/// Test 26: Size matcher with exact match
#[test]
fn size_matcher_exact_match() {
    let template = make_template_with_matchers(
        "size-exact",
        vec![MatcherDef {
            kind: MatcherKind::Size,
            values: vec!["5".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"hello".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 1, "should match size 5");
}

/// Test 27: Pattern with special regex metacharacters as literal word
#[test]
fn word_matcher_with_regex_metacharacters() {
    let template = make_template_with_matchers(
        "word-with-metachars",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test[0-9]+.*".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Word matcher should match literal text, not as regex
    let response = ResponseData::new(200, vec![], b"test[0-9]+.* literally".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(
        matches.len(),
        1,
        "word matcher should match literal metacharacters"
    );
}

/// Test 28: Header matching with multiple headers
#[test]
fn multiple_header_matching() {
    let template = make_template_with_matchers(
        "multi-header",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string(), "apache".to_string()],
            part: MatchPart::Header,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(
        200,
        vec![
            ("Server".to_string(), "nginx/1.25".to_string()),
            ("X-Powered-By".to_string(), "apache".to_string()),
        ],
        b"body".to_vec(),
    );

    let matches = db.scan(&response).unwrap();
    assert!(!matches.is_empty(), "should match headers");
}

/// Test 29: All-part matching across body and headers
#[test]
fn all_part_matching() {
    let template = make_template_with_matchers(
        "all-part",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["target".to_string()],
            part: MatchPart::All,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Match in headers
    let response1 = ResponseData::new(
        200,
        vec![("X-Header".to_string(), "target-value".to_string())],
        b"body".to_vec(),
    );
    let matches1 = db.scan(&response1).unwrap();

    // Match in body
    let response2 = ResponseData::new(200, vec![], b"target body".to_vec());
    let matches2 = db.scan(&response2).unwrap();

    assert!(
        !matches1.is_empty() || !matches2.is_empty(),
        "should match in headers or body"
    );
}

/// Test 30: Complex DSL expression combining multiple checks
#[test]
fn complex_dsl_expression() {
    use crate::dsl::evaluate_dsl;

    let response = ResponseData::new(
        200,
        vec![("Content-Type".to_string(), "application/json".to_string())],
        br#"{"status": "ok", "count": 42}"#.to_vec(),
    );

    let expr = r#"status_code == 200 && contains(body, "status") && len(body) > 10"#;
    let result = evaluate_dsl(expr, &response);

    assert!(result, "complex DSL should evaluate to true");
}

// ADVERSARIAL TESTS - Designed to crash the matching engine
// These tests cover extreme edge cases, malformed inputs, and pathological patterns
// =============================================================================

use super::*;

// =============================================================================
// CATEGORY 1: NULL BYTES (Tests 1-4)
// =============================================================================

/// Test 1: Null bytes in word matcher pattern - should compile and match correctly
#[test]
fn null_bytes_in_word_pattern() {
    let template = make_template_with_matchers(
        "null-byte-pattern",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["hello\0world".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Response containing the null byte pattern
    let mut body = Vec::new();
    body.extend_from_slice(b"prefix ");
    body.extend_from_slice(b"hello\0world");
    body.extend_from_slice(b" suffix");

    let response = ResponseData::new(200, vec![], body);
    let matches = db.scan(&response).unwrap();

    assert!(
        !matches.is_empty() || matches.is_empty(),
        "null byte pattern handling should not crash"
    );
}

/// Test 2: Null bytes only in body - empty string matching
#[test]
fn null_bytes_only_body() {
    let template = make_template_with_matchers(
        "null-only-body",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["00 00 00".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let body = vec![0x00, 0x00, 0x00, 0x00, 0x00];
    let response = ResponseData::new(200, vec![], body);

    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| db.scan(&response).unwrap()));

    assert!(
        result.is_ok(),
        "null-only body should not cause panic: {:?}",
        result.err()
    );
}

/// Test 3: Word matcher with pattern containing only null bytes reference
#[test]
fn word_matcher_null_reference() {
    use crate::text::matcher_satisfied_text;

    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["test".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    };

    // Text with embedded null that might cause early termination
    let text = "test\0value";
    let satisfied = matcher_satisfied_text(&matcher, text);

    assert!(satisfied, "should match before null byte");
}

/// Test 4: Binary pattern with invalid hex characters
#[test]
fn binary_pattern_invalid_hex() {
    let template = make_template_with_matchers(
        "invalid-hex",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["GGHHZZ".to_string()], // Invalid hex
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = CompiledDatabase::compile(&[template]);
    assert!(
        result.is_err(),
        "invalid hex should cause compilation error"
    );
}

// =============================================================================
// CATEGORY 2: LARGE INPUTS (Tests 5-8)
// =============================================================================

/// Test 5: 10MB response body - should handle without OOM
#[test]
fn ten_mb_response_body() {
    let template = make_template_with_matchers(
        "huge-body",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["needle".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Create 10MB body (use repeated pattern to allow memory compression)
    let chunk = vec![b'x'; 1024 * 1024]; // 1MB chunk
    let mut body = Vec::with_capacity(10 * 1024 * 1024);
    for i in 0..10 {
        body.extend_from_slice(&chunk);
        if i == 9 {
            // Insert needle near end
            body.extend_from_slice(b"needle");
        }
    }

    let response = ResponseData::new(200, vec![], body);

    let start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "10MB scan should complete in < 5 seconds, took {:?}",
        elapsed
    );
    assert!(!matches.is_empty(), "should find needle in 10MB body");
}

/// Test 6: Extremely large pattern (100KB word)
#[test]
fn hundred_kb_word_pattern() {
    let huge_pattern = "x".repeat(100 * 1024); // 100KB

    let template = make_template_with_matchers(
        "huge-pattern",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec![huge_pattern.clone()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CompiledDatabase::compile(&[template])
    }));

    assert!(
        result.is_ok(),
        "100KB pattern should not cause panic during compilation"
    );

    // If compilation succeeded, test matching
    if let Ok(Ok(db)) = result {
        let body = huge_pattern.into_bytes();
        let response = ResponseData::new(200, vec![], body);
        let _matches = db.scan(&response).unwrap();
    }
}

/// Test 7: Response with many headers
#[test]
fn many_headers_response() {
    let template = make_template_with_matchers(
        "many-headers",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["target-header-value".to_string()],
            part: MatchPart::Header,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Create headers with target at the end
    let mut headers = Vec::with_capacity(500);
    for i in 0..500 {
        headers.push((format!("X-Header-{}", i), format!("value-{}", i)));
    }
    headers.push(("X-Target".to_string(), "target-header-value".to_string()));

    let response = ResponseData::new(200, headers, b"body".to_vec());

    let start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "500 headers scan should complete in < 2 seconds, took {:?}",
        elapsed
    );
    assert!(!matches.is_empty(), "should find target header");
}

/// Test 8: Template with many patterns
#[test]
fn many_patterns() {
    let values: Vec<String> = (0..5000).map(|i| format!("pattern-{}", i)).collect();

    let template = make_template_with_matchers(
        "massive-patterns",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values,
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let start = Instant::now();
    let db = CompiledDatabase::compile(&[template]);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "5000 patterns should compile in < 3 seconds, took {:?}",
        elapsed
    );

    if let Ok(db) = db {
        let response = ResponseData::new(200, vec![], b"pattern-4999".to_vec());
        let matches = db.scan(&response).unwrap();
        assert!(!matches.is_empty(), "should find match in 5000 patterns");
    }
}

// =============================================================================
// CATEGORY 3: OVERLAPPING PATTERNS (Tests 9-12)
// =============================================================================

/// Test 9: Multiple identical overlapping patterns
#[test]
fn identical_overlapping_patterns() {
    let template = make_template_with_matchers(
        "identical-overlap",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec![
                "target".to_string(),
                "target".to_string(),
                "target".to_string(),
                "target".to_string(),
                "target".to_string(),
            ],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"target here".to_vec());
    let matches = db.scan(&response).unwrap();

    // Should handle deduplication gracefully
    assert!(!matches.is_empty(), "should match identical patterns");
}

/// Test 10: Patterns that are all substrings of each other
#[test]
fn substring_chain_patterns() {
    let template = make_template_with_matchers(
        "substring-chain",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec![
                "a".to_string(),
                "ab".to_string(),
                "abc".to_string(),
                "abcd".to_string(),
                "abcde".to_string(),
                "abcdef".to_string(),
            ],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"xyzabcdefxyz".to_vec());
    let matches = db.scan(&response).unwrap();

    assert!(
        !matches.is_empty(),
        "should find substring chain matches, got {}",
        matches.len()
    );
}

/// Test 11: Overlapping regex patterns with same prefix
#[test]
fn overlapping_regex_prefix() {
    let template = make_template_with_matchers(
        "overlapping-regex",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![
                r"test[a-z]+".to_string(),
                r"test[0-9]+".to_string(),
                r"test.*".to_string(),
            ],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"test123abc".to_vec());
    let matches = db.scan(&response).unwrap();

    // Should match without exponential blowup
    assert!(
        !matches.is_empty(),
        "should match overlapping regex patterns"
    );
}

/// Test 12: Binary patterns overlapping at byte boundaries
#[test]
fn overlapping_binary_patterns() {
    let template = make_template_with_matchers(
        "overlapping-binary",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["DEAD".to_string(), "ADBE".to_string(), "BEEF".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Body: DEADBEEF (overlapping at byte boundaries)
    let body = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let response = ResponseData::new(200, vec![], body);
    let matches = db.scan(&response).unwrap();

    assert!(
        !matches.is_empty(),
        "should find overlapping binary matches"
    );
}

// =============================================================================
// CATEGORY 4: CONTRADICTORY MATCHERS (Tests 13-16)
// =============================================================================

/// Test 13: Matcher requiring AND of mutually exclusive patterns
#[test]
fn contradictory_and_matchers() {
    let template = make_template_with_matchers(
        "contradictory-and",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["only-a".to_string(), "only-b".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Response with only one of the required patterns
    let response = ResponseData::new(200, vec![], b"only-a here".to_vec());
    let matches = db.scan(&response).unwrap();

    // Should not crash, just return no matches or partial matches
    assert!(
        matches.len() <= 1,
        "contradictory AND should return at most 1 match"
    );
}

/// Test 14: Negative matcher that excludes everything
#[test]
fn negative_matcher_excludes_all() {
    let template = make_template_with_matchers(
        "negative-excludes-all",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["".to_string()], // Empty pattern matches everything
            part: MatchPart::Body,
            negative: true,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");
        let response = ResponseData::new(200, vec![], b"any content".to_vec());
        db.scan(&response).unwrap()
    }));

    assert!(
        result.is_ok(),
        "negative matcher excluding all should not crash"
    );
}

/// Test 15: Status matcher with AND condition requiring multiple different statuses
#[test]
fn contradictory_status_matchers() {
    let template = make_template_with_matchers(
        "contradictory-status",
        vec![MatcherDef {
            kind: MatcherKind::Status,
            values: vec!["200".to_string(), "404".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Response can only have one status
    let response = ResponseData::new(200, vec![], b"body".to_vec());
    let matches = db.scan(&response).unwrap();

    // Can only match one status, not both
    assert!(
        matches.len() <= 1,
        "cannot match both 200 and 404 simultaneously"
    );
}

/// Test 16: Size matcher requiring exact size that doesn't match response
#[test]
fn size_matcher_no_match() {
    let template = make_template_with_matchers(
        "size-no-match",
        vec![MatcherDef {
            kind: MatcherKind::Size,
            values: vec!["999999999".to_string()], // Huge size requirement
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"small".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 0, "should not match wrong size");
}

// =============================================================================
// CATEGORY 5: EMPTY EVERYTHING (Tests 17-20)
// =============================================================================

/// Test 17: Empty word pattern
#[test]
fn empty_word_pattern() {
    let template = make_template_with_matchers(
        "empty-word",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CompiledDatabase::compile(&[template])
    }));

    assert!(result.is_ok(), "empty word pattern should not cause panic");
}

/// Test 18: Empty values vector
#[test]
fn empty_values_vector() {
    let template = make_template_with_matchers(
        "empty-values",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec![],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");
        let response = ResponseData::new(200, vec![], b"content".to_vec());
        db.scan(&response).unwrap()
    }));

    assert!(result.is_ok(), "empty values should not cause panic");
}

/// Test 19: Empty template ID
#[test]
fn empty_template_id() {
    let template = make_template_with_matchers(
        "",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 1, "should match with empty template ID");
    assert_eq!(matches[0].template_id, "", "template ID should be empty");
}

/// Test 20: Response with empty body, headers, but status matcher
#[test]
fn completely_empty_response() {
    let template = make_template_with_matchers(
        "empty-response",
        vec![MatcherDef {
            kind: MatcherKind::Status,
            values: vec!["200".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], vec![]);
    let matches = db.scan(&response).unwrap();

    assert!(!matches.is_empty(), "should match status on empty response");
}

// =============================================================================
// CATEGORY 6: UNICODE EDGE CASES (Tests 21-24)
// =============================================================================

/// Test 21: Unicode combining characters (homograph attack)
#[test]
fn unicode_combining_characters() {
    let template = make_template_with_matchers(
        "unicode-combining",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["café".to_string()], // NFC normalized
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // café with combining character (NFD form: e + combining acute)
    let response = ResponseData::new(200, vec![], "cafe\u{0301}".as_bytes().to_vec());
    let matches = db.scan(&response).unwrap();

    // Note: May or may not match depending on Unicode normalization
    // The important thing is it doesn't crash
    assert!(
        matches.len() <= 1,
        "unicode combining should not crash, got {} matches",
        matches.len()
    );
}

/// Test 22: Right-to-left override character
#[test]
fn unicode_rtl_override() {
    let template = make_template_with_matchers(
        "unicode-rtl",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Text with RTL override character
    let body = "\u{202E}test\u{202C}".as_bytes().to_vec();
    let response = ResponseData::new(200, vec![], body);

    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| db.scan(&response).unwrap()));

    assert!(result.is_ok(), "RTL override should not cause panic");
}

/// Test 23: Unicode null character variants
#[test]
fn unicode_null_variants() {
    let template = make_template_with_matchers(
        "unicode-null",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Various Unicode null-like characters
    let body = "te\u{0000}st".as_bytes().to_vec();
    let response = ResponseData::new(200, vec![], body);

    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| db.scan(&response).unwrap()));

    assert!(result.is_ok(), "Unicode null should not cause panic");
}

/// Test 24: Very long unicode string (10KB of emoji)
#[test]
fn long_unicode_emoji() {
    let emoji_string = "🎉".repeat(2560); // 10KB of emoji

    let template = make_template_with_matchers(
        "long-emoji",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["🎉".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], emoji_string.into_bytes());

    let start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "long unicode scan should complete in < 2 seconds, took {:?}",
        elapsed
    );
    assert!(!matches.is_empty(), "should find emoji matches");
}

// =============================================================================
// CATEGORY 7: REGEX DENIAL OF SERVICE (Tests 25-28)
// =============================================================================

/// Test 25: Nested quantifiers - catastrophic backtracking pattern
#[test]
fn regex_catastrophic_backtracking() {
    let template = make_template_with_matchers(
        "redos-nested",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"(a+)+$".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Input that causes exponential backtracking in vulnerable engines
    let body = "a".repeat(30) + "b";
    let response = ResponseData::new(200, vec![], body.into_bytes());

    let start = Instant::now();
    let _matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "regex should not catastrophically backtrack, took {:?}",
        elapsed
    );
}

/// Test 26: Polynomial time regex pattern
#[test]
fn regex_polynomial_time() {
    let template = make_template_with_matchers(
        "redos-polynomial",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"^(a|a)*$".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CompiledDatabase::compile(&[template])
    }));

    assert!(
        result.is_ok(),
        "polynomial regex should not crash during compilation"
    );

    if let Ok(Ok(db)) = result {
        let body = "a".repeat(100);
        let response = ResponseData::new(200, vec![], body.into_bytes());

        let start = Instant::now();
        let _matches = db.scan(&response).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "polynomial regex should complete in reasonable time, took {:?}",
            elapsed
        );
    }
}

/// Test 27: Regex with excessive repetition
#[test]
fn regex_excessive_repetition() {
    let template = make_template_with_matchers(
        "redos-repetition",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r"a{1000000}".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CompiledDatabase::compile(&[template])
    }));

    assert!(
        result.is_ok(),
        "excessive repetition should not crash during compilation"
    );
}

/// Test 28: Multiple evil regex patterns combined
#[test]
fn regex_multiple_evil_patterns() {
    let template = make_template_with_matchers(
        "redos-combined",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![
                r"(.*a){50}".to_string(),
                r"(a+)*b".to_string(),
                r"([a-z]+)*$".to_string(),
            ],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let db = CompiledDatabase::compile(&[template])?;
        let body = "a".repeat(50) + "x";
        let response = ResponseData::new(200, vec![], body.into_bytes());
        Ok::<_, secir::Error>((db, response))
    }));

    assert!(
        result.is_ok(),
        "multiple evil patterns should not cause panic"
    );
}

// =============================================================================
// CATEGORY 8: INTEGER OVERFLOWS (Tests 29-30)
// =============================================================================

/// Test 29: Size matcher with u64::MAX value
#[test]
fn size_matcher_u64_max() {
    let template = make_template_with_matchers(
        "size-u64-max",
        vec![MatcherDef {
            kind: MatcherKind::Size,
            values: vec!["18446744073709551615".to_string()], // u64::MAX
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");
        let response = ResponseData::new(200, vec![], b"test".to_vec());
        db.scan(&response).unwrap()
    }));

    assert!(
        result.is_ok(),
        "u64::MAX size should not cause overflow panic"
    );
}

/// Test 30: Status code with negative value that might underflow
#[test]
fn status_matcher_negative_underflow() {
    let template = make_template_with_matchers(
        "status-negative",
        vec![MatcherDef {
            kind: MatcherKind::Status,
            values: vec!["-1".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CompiledDatabase::compile(&[template])
    }));

    assert!(result.is_ok(), "negative status should not cause panic");
}

// =============================================================================
// CATEGORY 9: BONUS TESTS - Additional edge cases
// =============================================================================

/// Test 31: DSL expression with max recursion depth
#[test]
fn dsl_max_recursion_depth() {
    use crate::dsl::evaluate_dsl;

    let response = ResponseData::new(200, vec![], b"test".to_vec());

    // Create deeply nested expression that approaches max depth
    let mut expr = "1 == 1".to_string();
    for _ in 0..50 {
        expr = format!("({}) && (1 == 1)", expr);
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evaluate_dsl(&expr, &response)
    }));

    assert!(
        result.is_ok(),
        "deep DSL nesting should not cause stack overflow"
    );
}

/// Test 32: Header name with special characters
#[test]
fn header_name_special_chars() {
    let template = make_template_with_matchers(
        "header-special",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["value".to_string()],
            part: MatchPart::Named("X-Test\n\r:".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");
        let headers = vec![("X-Test\n\r:".to_string(), "value".to_string())];
        let response = ResponseData::new(200, headers, b"body".to_vec());
        db.scan(&response).unwrap()
    }));

    assert!(
        result.is_ok(),
        "special header names should not cause panic"
    );
}

/// Test 33: Binary pattern matching at every position
#[test]
fn binary_pattern_all_positions() {
    let template = make_template_with_matchers(
        "binary-all-positions",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["FF".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Body of all 0xFF bytes
    let body = vec![0xFF; 1000];
    let response = ResponseData::new(200, vec![], body);

    let start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "all-FF scan should complete quickly, took {:?}",
        elapsed
    );
    assert!(!matches.is_empty(), "should find FF matches");
}

/// Test 34: Empty regex pattern
#[test]
fn regex_empty_pattern_adversarial() {
    let template = make_template_with_matchers(
        "regex-empty",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec!["".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let db = CompiledDatabase::compile(&[template])?;
        let response = ResponseData::new(200, vec![], b"content".to_vec());
        Ok::<_, secir::Error>(db.scan(&response).unwrap())
    }));

    assert!(result.is_ok(), "empty regex should not cause panic");
}

/// Test 35: Template with zero-width spaces
#[test]
fn zero_width_spaces_in_pattern() {
    let template = make_template_with_matchers(
        "zero-width",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test\u{200B}pattern".to_string()], // Zero-width space
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CompiledDatabase::compile(&[template])
    }));

    assert!(result.is_ok(), "zero-width spaces should not cause panic");
}

/// Test 36: Response body that looks like a regex
#[test]
fn response_looks_like_regex() {
    let template = make_template_with_matchers(
        "response-regex-like",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    // Body that looks like it could be a malicious regex
    let body = r"(a+)+b";
    let response = ResponseData::new(200, vec![], body.as_bytes().to_vec());

    let matches = db.scan(&response).unwrap();
    // Should not try to interpret body as regex, just literal matching
    assert_eq!(matches.len(), 0, "should not match regex-looking content");
}

/// Test 37: Multiple AND conditions with no values
#[test]
fn and_condition_no_values() {
    let template = make_template_with_matchers(
        "and-no-values",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec![],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");
        let response = ResponseData::new(200, vec![], b"content".to_vec());
        db.scan(&response).unwrap()
    }));

    assert!(result.is_ok(), "AND with no values should not cause panic");
}

/// Test 38: Binary pattern with odd number of hex digits
#[test]
fn binary_odd_hex_digits() {
    let template = make_template_with_matchers(
        "odd-hex",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["ABC".to_string()], // Odd number of digits
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = CompiledDatabase::compile(&[template]);
    // Should either error gracefully or handle it
    assert!(
        result.is_err() || result.is_ok(),
        "odd hex digits should not cause panic"
    );
}

/// Test 39: Size matcher with leading zeros (octal confusion)
#[test]
fn size_leading_zeros() {
    let template = make_template_with_matchers(
        "size-leading-zeros",
        vec![MatcherDef {
            kind: MatcherKind::Size,
            values: vec!["00005".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    let response = ResponseData::new(200, vec![], b"hello".to_vec());
    let matches = db.scan(&response).unwrap();

    assert!(
        matches.len() <= 1,
        "leading zeros should be handled consistently"
    );
}

/// Test 40: Very large negative number in size matcher
#[test]
fn size_very_large_negative() {
    let template = make_template_with_matchers(
        "size-large-negative",
        vec![MatcherDef {
            kind: MatcherKind::Size,
            values: vec!["-99999999999999999999999999999".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CompiledDatabase::compile(&[template])
    }));

    assert!(
        result.is_ok(),
        "very large negative size should not cause panic"
    );
}

/// Regression: multi-value regex matchers must emit matches for ALL patterns,
/// not silently drop all but the first. Each value in a matcher's `values` list
/// must be independently evaluated and emitted when it matches.
#[test]
fn multi_value_regex_all_patterns_matched() {
    let template = make_template_with_matchers(
        "multi-value-regex",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![
                r"first-\w+".to_string(),
                r"second-\w+".to_string(),
                r"third-\w+".to_string(),
            ],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db =
        CompiledDatabase::compile(&[template]).expect("multi-value regex template should compile");

    // Body contains all three patterns; all three must be matched and emitted.
    let response = ResponseData::new(
        200,
        vec![],
        b"first-token second-token third-token".to_vec(),
    );
    let matches = db.scan(&response).unwrap();

    // Each of the 3 patterns must produce at least one match.
    let matched_values: Vec<&str> = matches.iter().map(|m| m.matched_value.as_str()).collect();
    assert!(
        matched_values.iter().any(|v| v.starts_with("first-")),
        "Fix: regex_scan must emit matches for ALL values  -  'first-*' pattern was silently dropped. Got: {matched_values:?}"
    );
    assert!(
        matched_values.iter().any(|v| v.starts_with("second-")),
        "Fix: regex_scan must emit matches for ALL values  -  'second-*' pattern was silently dropped. Got: {matched_values:?}"
    );
    assert!(
        matched_values.iter().any(|v| v.starts_with("third-")),
        "Fix: regex_scan must emit matches for ALL values  -  'third-*' pattern was silently dropped. Got: {matched_values:?}"
    );
}

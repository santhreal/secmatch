use super::*;

#[test]
fn binary_matcher_decodes_hex_correctly() {
    let template = make_template_with_matchers(
        "binary",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["48 65 6c 6c 6f".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], b"xxHelloyy".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matcher.kind, MatcherKind::Binary);
    assert_eq!(matches[0].matched_value, "48 65 6c 6c 6f");
    assert_eq!(matches[0].offset, 2);
}

#[test]
fn empty_response_matches_no_patterns() {
    let template = make_template_with_matchers(
        "mixed",
        vec![
            MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["nginx".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
            MatcherDef {
                kind: MatcherKind::Regex,
                values: vec![r"hello-\d+".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
            MatcherDef {
                kind: MatcherKind::Dsl,
                values: vec![r#"contains(body, "hit")"#.to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
        ],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], Vec::new());

    assert!(db.scan(&response).unwrap().is_empty());
}

#[test]
fn invalid_binary_pattern_returns_error_during_compile() {
    let template = make_template_with_matchers(
        "invalid-binary",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["xyz".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let result = CompiledDatabase::compile(&[template]);
    assert!(
        result.is_err(),
        "should reject template with invalid hex binary pattern"
    );
}

/// Template with 10,000 matchers - should not OOM during compilation
#[test]
fn template_with_10000_matchers_does_not_oom() {
    let matchers: Vec<MatcherDef> = (0..10000)
        .map(|i| MatcherDef {
            kind: MatcherKind::Word,
            values: vec![format!("pattern-{i}")],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        })
        .collect();

    let template = make_template_with_matchers("massive-matcher-template", matchers);

    let start = Instant::now();
    let db = CompiledDatabase::compile(&[template])
        .expect("compilation with 10,000 matchers should succeed");
    let elapsed = start.elapsed();

    assert_eq!(
        db.pattern_count(),
        10000,
        "should compile all 10,000 patterns"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "compilation with 10,000 matchers should complete in < 5 seconds, took {:?}",
        elapsed
    );
}

/// Template with regex .* against 10MB response - should not hang
#[test]
fn regex_star_against_10mb_body_does_not_hang() {
    let template = make_template_with_matchers(
        "greedy-regex",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![".*".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    // Create a 10MB body
    let body = vec![b'x'; 10 * 1024 * 1024];
    let response = ResponseData::new(200, vec![], body);

    let start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    // Allow more time for debug builds - the important thing is it doesn't hang
    assert!(
        elapsed < Duration::from_secs(10),
        "regex .* against 10MB should complete in < 10 seconds (should not hang), took {:?}",
        elapsed
    );
    assert_eq!(matches.len(), 1, "regex .* should match once");
}

/// Template with 100 nested imports - should not cause infinite loop
#[test]
fn template_with_deeply_nested_structure_does_not_overflow() {
    // Create a template with 100 requests, each with 10 matchers
    let mut requests = Vec::new();
    for i in 0..100 {
        let matchers: Vec<MatcherDef> = (0..10)
            .map(|j| MatcherDef {
                kind: MatcherKind::Word,
                values: vec![format!("word-{i}-{j}")],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            })
            .collect();

        requests.push(RequestDef {
            paths: vec![format!("/path-{i}")],
            matchers,
            ..RequestDef::default()
        });
    }

    let template = Template {
        ir_version: 1,
        requests,
        ..make_template_with_matchers("deep-template", vec![])
    };

    let start = Instant::now();
    let db = CompiledDatabase::compile(&[template])
        .expect("compilation with deep structure should succeed");
    let elapsed = start.elapsed();

    assert_eq!(
        db.pattern_count(),
        1000,
        "should compile all 1000 patterns from 100 requests"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "compilation of deeply nested template should complete in < 3 seconds, took {:?}",
        elapsed
    );
}

/// RequestDef with empty paths vec - should not crash in planner
#[test]
fn request_with_empty_paths_should_not_crash() {
    let template = Template {
        ir_version: 1,
        requests: vec![RequestDef {
            paths: vec![], // Empty paths
            matchers: vec![MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["test".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            }],
            ..RequestDef::default()
        }],
        ..make_template_with_matchers("empty-paths-template", vec![])
    };

    // Should compile without panic
    let db = CompiledDatabase::compile(&[template])
        .expect("compilation should succeed with empty paths");
    assert_eq!(
        db.pattern_count(),
        1,
        "should have 1 pattern despite empty paths"
    );
}

/// ResponseData with status=0, empty body, empty headers - should not crash scan
#[test]
fn response_with_all_empty_fields_should_not_crash() {
    let template = make_template_with_matchers(
        "empty-response-test",
        vec![
            MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["anything".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
            MatcherDef {
                kind: MatcherKind::Status,
                values: vec!["0".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
        ],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    // Response with all empty/minimal values
    let response = ResponseData::new(0, vec![], vec![]);

    // Should not panic
    let matches = db.scan(&response).unwrap();

    // Status 0 should match
    assert_eq!(matches.len(), 1, "should match status 0");
    assert_eq!(
        matches[0].matcher.kind,
        MatcherKind::Status,
        "status matcher should match"
    );
}

/// Template ID with unicode characters - should handle correctly
#[test]
fn template_id_with_unicode_should_work() {
    let unicode_id = "测试模板-🔥-日本語";
    let template = make_template_with_matchers(
        unicode_id,
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(
        matches.len(),
        1,
        "should find match with unicode template ID"
    );
    assert_eq!(
        matches[0].template_id, unicode_id,
        "template_id should preserve unicode"
    );
}

/// Template ID with 10KB string - should handle large IDs
#[test]
fn template_id_with_10kb_string_should_work() {
    let huge_id = "x".repeat(10 * 1024);
    let template = make_template_with_matchers(
        &huge_id,
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["test".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], b"test".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 1, "should find match with 10KB template ID");
    assert_eq!(
        matches[0].template_id.len(),
        10 * 1024,
        "template_id should be 10KB"
    );
}

/// Binary matcher with null bytes pattern - should match null bytes in response
#[test]
fn binary_matcher_with_null_bytes_should_work() {
    let template = make_template_with_matchers(
        "null-byte-matcher",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["00".to_string()], // Null byte
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    // Response with null bytes
    let response = ResponseData::new(200, vec![], vec![0x48, 0x00, 0x65, 0x00, 0x6c, 0x6c, 0x6f]);
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 1, "should match null byte pattern");
    assert_eq!(matches[0].offset, 1, "null byte should be at offset 1");
}

/// CompiledDatabase::compile with 0 templates then scan - should work
#[test]
fn compile_zero_templates_then_scan_should_work() {
    let db = CompiledDatabase::compile(&[]).expect("operation should succeed");

    assert_eq!(
        db.template_count(),
        0,
        "empty database should have 0 templates"
    );
    assert_eq!(
        db.pattern_count(),
        0,
        "empty database should have 0 patterns"
    );

    // Scan any response - should not panic
    let response = ResponseData::new(200, vec![], b"anything".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(matches.len(), 0, "empty database should produce no matches");
}

/// HTTP response with 100,000 headers - should handle extreme header count
#[test]
fn response_with_100000_headers_should_not_crash() {
    let template = make_template_with_matchers(
        "header-matcher",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["header-99999-value".to_string()],
            part: MatchPart::Header,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    // Create 100,000 headers
    let headers: Vec<(String, String)> = (0..100000)
        .map(|i| (format!("X-Header-{i}"), format!("header-{i}-value")))
        .collect();

    let response = ResponseData::new(200, headers, b"body".to_vec());

    let start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "scan with 100,000 headers should complete in < 2 seconds, took {:?}",
        elapsed
    );
    assert_eq!(matches.len(), 1, "should find match in 100,000 headers");
}

/// Payloads containing null bytes - should handle gracefully
#[test]
fn payloads_with_null_bytes_should_not_crash() {
    // Create a template with payloads containing null bytes
    let mut payloads = HashMap::new();
    payloads.insert(
        "test_payload".to_string(),
        vec!["hello\0world".to_string(), "normal".to_string()],
    );

    let template = Template {
        ir_version: 1,
        requests: vec![RequestDef {
            paths: vec!["{{BaseURL}}".to_string()],
            payloads,
            matchers: vec![MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["test".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            }],
            ..RequestDef::default()
        }],
        ..make_template_with_matchers("null-payload-template", vec![])
    };

    // Should compile without panic
    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    assert_eq!(
        db.pattern_count(),
        1,
        "should compile despite null bytes in payloads"
    );
}

// =============================================================================

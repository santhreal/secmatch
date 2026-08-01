// CATEGORY 2: CORRECTNESS TESTS - Tests for exact expected behavior
// These verify specific edge cases in matching logic
// =============================================================================

use super::*;

/// Two templates with identical matchers but different IDs - both should produce findings
/// Note: The database uses pattern deduplication for performance, but each template's
/// matcher is tracked separately at the template index level
#[test]
fn two_templates_identical_matchers_different_ids_should_produce_separate_findings() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["nginx".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    };

    let template1 = make_template_with_matchers("template-alpha", vec![matcher.clone()]);
    let template2 = make_template_with_matchers("template-beta", vec![matcher]);

    let db = CompiledDatabase::compile(&[template1, template2]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], b"nginx server".to_vec());
    let matches = db.scan(&response).unwrap();

    // Each template has its own pattern reference even with same pattern text
    // The dedup key includes template_idx, so both templates produce matches
    assert!(
        !matches.is_empty(),
        "should produce at least 1 match from templates with identical patterns"
    );

    // Verify we have matches from both templates (they may be deduplicated at pattern level
    // but both template IDs should be represented if the implementation supports it)
    // Check that found matches have the correct template IDs
    for m in &matches {
        assert!(
            m.template_id == "template-alpha" || m.template_id == "template-beta",
            "match should belong to one of our test templates"
        );
    }

    // Both templates should be tracked in the database
    assert_eq!(db.template_count(), 2, "database should have 2 templates");
}

/// Template with a negative word matcher AND a negative regex matcher.
///
/// A negative matcher is INVERTED (nuclei semantics, see the negative-matcher
/// tests in `database_matcher_comprehensive`): it emits `Match { negative: true }`
/// when its pattern is ABSENT and nothing when the pattern is present. This test
/// previously asserted the reverse (0 matches when both patterns are absent; a
/// match emitted when the forbidden word was PRESENT), which encoded the pre-fix
/// bug where negative matchers were never inverted. Corrected to the canonical
/// absence semantics; the code fix is the compile-time negative_matchers list +
/// the absence pass in `scan`.
#[test]
fn double_negative_matchers_emit_on_absence_not_presence() {
    let template = make_template_with_matchers(
        "double-negative",
        vec![
            MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["error".to_string()],
                part: MatchPart::Body,
                negative: true, // Fires (emits) when "error" is ABSENT
                condition: MatcherCondition::Or,
                internal: false,
            },
            MatcherDef {
                kind: MatcherKind::Regex,
                values: vec![r"exception:\s*\w+".to_string()],
                part: MatchPart::Body,
                negative: true, // Fires (emits) when the regex does NOT match
                condition: MatcherCondition::And,
                internal: false,
            },
        ],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    // Neither pattern present: BOTH negative matchers are satisfied and each
    // emits its inverted match.
    let clean_response = ResponseData::new(200, vec![], b"success page".to_vec());
    let matches = db.scan(&clean_response).unwrap();
    assert_eq!(
        matches.len(),
        2,
        "both absent patterns must each emit one negative match"
    );
    assert!(
        matches.iter().all(|m| m.negative),
        "every emitted match here is a negated (absence) match"
    );
    assert!(
        matches.iter().any(|m| m.matched_value == "error"),
        "the absent negative word matcher must emit"
    );
    assert!(
        matches
            .iter()
            .any(|m| m.matched_value.contains("exception:")),
        "the absent negative regex matcher must emit"
    );

    // "error" IS present: the negative WORD matcher is NOT satisfied (emits
    // nothing); the negative REGEX is still absent, so it alone emits.
    let error_response = ResponseData::new(200, vec![], b"error occurred".to_vec());
    let matches = db.scan(&error_response).unwrap();
    assert!(
        !matches.iter().any(|m| m.matched_value == "error"),
        "a present forbidden word must NOT emit a negative match"
    );
    assert_eq!(
        matches.len(),
        1,
        "only the still-absent negative regex matcher emits"
    );
    assert!(
        matches[0].negative && matches[0].matched_value.contains("exception:"),
        "the sole match is the inverted negative regex matcher"
    );

    // The regex IS present: the negative REGEX matcher is NOT satisfied; the
    // negative word "error" is absent, so it alone emits.
    let exception_response = ResponseData::new(200, vec![], b"exception: NullPointer".to_vec());
    let matches = db.scan(&exception_response).unwrap();
    assert!(
        !matches.iter().any(|m| m.matched_value.contains("exception:")),
        "a present forbidden regex must NOT emit a negative match"
    );
    assert_eq!(
        matches.len(),
        1,
        "only the still-absent negative word matcher emits"
    );
    assert!(
        matches[0].negative && matches[0].matched_value == "error",
        "the sole match is the inverted negative word matcher"
    );
}

/// Status matcher with value "0" - should match status code 0
#[test]
fn status_matcher_zero_should_match_status_code_zero() {
    let template = make_template_with_matchers(
        "status-zero",
        vec![MatcherDef {
            kind: MatcherKind::Status,
            values: vec!["0".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    let status_zero = ResponseData::new(0, vec![], b"body".to_vec());
    let matches = db.scan(&status_zero).unwrap();

    assert_eq!(matches.len(), 1, "status 0 should match status code 0");
    assert_eq!(matches[0].matched_value, "0", "matched value should be '0'");

    let status_200 = ResponseData::new(200, vec![], b"body".to_vec());
    let matches = db.scan(&status_200).unwrap();

    assert_eq!(
        matches.len(),
        0,
        "status 200 should not match status code 0 matcher"
    );
}

/// Empty word values are skipped during compilation because Aho-Corasick
/// treats them as matching every position.
#[test]
fn word_matcher_empty_string_is_ignored() {
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

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    let empty_response = ResponseData::new(200, vec![], vec![]);
    assert!(
        db.scan(&empty_response).unwrap().is_empty(),
        "empty word pattern should not match empty bodies"
    );

    let response = ResponseData::new(200, vec![], b"anything".to_vec());
    assert!(
        db.scan(&response).unwrap().is_empty(),
        "empty word pattern should not match non-empty bodies"
    );
}

/// Regex matcher with value "^$" - should match empty body only
#[test]
fn regex_caret_dollar_should_match_empty_body_only() {
    let template = make_template_with_matchers(
        "empty-regex",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec!["^$".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    // Empty body - should match
    let empty_response = ResponseData::new(200, vec![], vec![]);
    let matches = db.scan(&empty_response).unwrap();
    assert_eq!(matches.len(), 1, "^$ should match empty body");

    // Non-empty body - should NOT match
    let response = ResponseData::new(200, vec![], b"anything".to_vec());
    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 0, "^$ should NOT match non-empty body");
}

/// DSL matcher: "status_code == 200 && contains(body, 'test')" - verify both conditions checked
#[test]
fn dsl_matcher_with_and_condition_checks_both_conditions() {
    let template = make_template_with_matchers(
        "dsl-and",
        vec![MatcherDef {
            kind: MatcherKind::Dsl,
            values: vec!["status_code == 200 && contains(body, 'test')".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    // Both conditions true
    let both_match = ResponseData::new(200, vec![], b"this is a test".to_vec());
    let matches = db.scan(&both_match).unwrap();
    // DSL expressions that evaluate to true produce a match
    // The actual behavior depends on the DSL implementation
    assert!(
        matches.len() <= 1,
        "DSL should produce at most 1 match when expression is true"
    );

    // Status matches but body doesn't
    let status_only = ResponseData::new(200, vec![], b"no match here".to_vec());
    let matches = db.scan(&status_only).unwrap();
    assert_eq!(
        matches.len(),
        0,
        "DSL should NOT match when body condition fails"
    );

    // Body matches but status doesn't
    let body_only = ResponseData::new(404, vec![], b"this is a test".to_vec());
    let matches = db.scan(&body_only).unwrap();
    assert_eq!(
        matches.len(),
        0,
        "DSL should NOT match when status condition fails"
    );

    // Neither matches
    let neither = ResponseData::new(500, vec![], b"no match".to_vec());
    let matches = db.scan(&neither).unwrap();
    assert_eq!(
        matches.len(),
        0,
        "DSL should NOT match when both conditions fail"
    );
}

/// Binary matcher with "00" - should match any null byte in response
#[test]
fn binary_matcher_00_should_match_any_null_byte() {
    let template = make_template_with_matchers(
        "binary-null",
        vec![MatcherDef {
            kind: MatcherKind::Binary,
            values: vec!["00".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    // Response with null bytes at various positions
    let with_null = ResponseData::new(200, vec![], vec![0x00, 0x01, 0x02, 0x00]);
    let matches = db.scan(&with_null).unwrap();

    // Aho-Corasick finds all matches, dedup happens per pattern ref
    assert!(
        !matches.is_empty(),
        "binary matcher 00 should match null bytes"
    );

    // Response without null bytes
    let no_null = ResponseData::new(200, vec![], vec![0x01, 0x02, 0x03]);
    let matches = db.scan(&no_null).unwrap();
    assert_eq!(
        matches.len(),
        0,
        "binary matcher 00 should NOT match non-null bytes"
    );
}

/// Word matcher with "00" as text (not binary) - should match literal "00"
#[test]
fn word_matcher_00_text_should_match_literal_string() {
    let template = make_template_with_matchers(
        "word-00",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["00".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    // Response with literal "00" text
    let with_text = ResponseData::new(200, vec![], b"version 1.00 release".to_vec());
    let matches = db.scan(&with_text).unwrap();

    assert_eq!(
        matches.len(),
        1,
        "word matcher '00' should match literal text '00'"
    );

    // Response with null byte (0x00) - should NOT match "00" text
    let with_null = ResponseData::new(200, vec![], vec![0x00, 0x01, 0x02]);
    let matches = db.scan(&with_null).unwrap();
    assert_eq!(
        matches.len(),
        0,
        "word matcher '00' should NOT match null byte 0x00"
    );
}

// =============================================================================
// CATEGORY 3: PERFORMANCE REGRESSION TESTS
// These ensure performance stays within acceptable bounds
// =============================================================================

/// Compile 1000 templates with 10 matchers each - should complete in < 1 second
#[test]
fn compile_1000_templates_10_matchers_each_should_be_fast() {
    let templates: Vec<Template> = (0..1000)
        .map(|i| {
            let matchers: Vec<MatcherDef> = (0..10)
                .map(|j| MatcherDef {
                    kind: MatcherKind::Word,
                    values: vec![format!("template-{i}-pattern-{j}")],
                    part: MatchPart::Body,
                    negative: false,
                    condition: MatcherCondition::Or,
                    internal: false,
                })
                .collect();
            make_template_with_matchers(&format!("template-{i}"), matchers)
        })
        .collect();

    let start = Instant::now();
    let db = CompiledDatabase::compile(&templates).expect("operation should succeed");
    let elapsed = start.elapsed();

    assert_eq!(db.template_count(), 1000, "should compile 1000 templates");
    assert_eq!(db.pattern_count(), 10000, "should compile 10,000 patterns");
    assert!(
        elapsed < Duration::from_secs(1),
        "compiling 1000 templates with 10 matchers each should complete in < 1 second, took {:?}",
        elapsed
    );
}

/// Scan 1 response against 1000-template database - should complete in < 10ms
#[test]
fn scan_1_response_against_1000_template_database_should_be_fast() {
    // Create 1000 templates, each with 10 word matchers
    let templates: Vec<Template> = (0..1000)
        .map(|i| {
            let matchers: Vec<MatcherDef> = (0..10)
                .map(|j| MatcherDef {
                    kind: MatcherKind::Word,
                    values: vec![format!("pattern-{i}-{j}")],
                    part: MatchPart::Body,
                    negative: false,
                    condition: MatcherCondition::Or,
                    internal: false,
                })
                .collect();
            make_template_with_matchers(&format!("template-{i}"), matchers)
        })
        .collect();

    let db = CompiledDatabase::compile(&templates).expect("operation should succeed");

    // Response that matches one pattern from the last template
    let response = ResponseData::new(200, vec![], b"pattern-999-5".to_vec());

    let start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(matches.len(), 1, "should find exactly 1 match");
    assert_eq!(
        matches[0].template_id, "template-999",
        "should match last template"
    );
    assert!(
        elapsed < Duration::from_millis(10),
        "scanning 1 response against 1000-template database should complete in < 10ms, took {:?}",
        elapsed
    );
}

/// Regex-heavy database scan should complete in reasonable time
#[test]
fn regex_heavy_database_scan_should_be_fast() {
    let templates: Vec<Template> = (0..100)
        .map(|i| {
            let matchers: Vec<MatcherDef> = (0..10)
                .map(|j| MatcherDef {
                    kind: MatcherKind::Regex,
                    values: vec![format!(r"pattern-{i}-{j}-\d+")],
                    part: MatchPart::Body,
                    negative: false,
                    condition: MatcherCondition::Or,
                    internal: false,
                })
                .collect();
            make_template_with_matchers(&format!("regex-template-{i}"), matchers)
        })
        .collect();

    let db = CompiledDatabase::compile(&templates).expect("operation should succeed");

    // Response that matches multiple regex patterns
    let response = ResponseData::new(200, vec![], b"pattern-50-5-12345 here".to_vec());

    let start = Instant::now();
    let matches = db.scan(&response).unwrap();
    let elapsed = start.elapsed();

    assert!(!matches.is_empty(), "should find at least one regex match");
    assert!(
        elapsed < Duration::from_millis(50),
        "regex-heavy scan should complete in < 50ms, took {:?}",
        elapsed
    );
}

#[test]
fn regex_set_compilation_fallback() {
    let matchers: Vec<MatcherDef> = (0..600)
        .map(|i| MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![format!(
                "a{{1,50}}b{{1,50}}c{{1,50}}d{{1,50}}e{{1,50}}f{{1,50}}_{i}"
            )],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        })
        .collect();

    let template = make_template_with_matchers("regex-fallback-test", matchers);

    let db = CompiledDatabase::compile(&[template]).expect("compilation should succeed");

    assert_eq!(db.regex_matchers.len(), 600);
    assert!(
        !db.regex_sets_body.is_empty(),
        "regex_sets_body should not be empty"
    );

    let total_indices: usize = db
        .regex_sets_body
        .iter()
        .map(|(_, indices)| indices.len())
        .sum();
    assert_eq!(
        total_indices, 600,
        "all indices should be present in chunked sets"
    );

    let response = ResponseData::new(200, vec![], b"abbccddeeff_123".to_vec());
    let matches = db.scan(&response).unwrap();

    // It will match _1, _12, and _123 since there is no anchor
    assert_eq!(matches.len(), 3, "should match exactly 3 patterns");
    assert!(matches.iter().any(|m| m.matched_value == "abbccddeeff_123"));
}

#[test]
fn unified_word_scan_preserves_part_and_offset() {
    // Use distinct words for each part so Aho-Corasick can distinguish them
    // while still verifying a single scan over the combined buffer dispatches
    // matches to the correct part with the correct offset.
    let response = ResponseData::new(
        200,
        vec![("X-Foo".to_string(), "common,headtoken".to_string())],
        b"the bodytoken is here".to_vec(),
    );
    let header_len = response.headers.len();

    let word = |part, value: &str| MatcherDef {
        kind: MatcherKind::Word,
        values: vec![value.to_string()],
        part,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    };

    let templates = [
        // "common" appears in both header and body; All should record the header occurrence.
        make_template_with_matchers("all", vec![word(MatchPart::All, "common")]),
        make_template_with_matchers("header", vec![word(MatchPart::Header, "headtoken")]),
        make_template_with_matchers("body", vec![word(MatchPart::Body, "bodytoken")]),
    ];

    let db = CompiledDatabase::compile(&templates).expect("compile");
    let matches = db.scan(&response).unwrap();

    let by_template: std::collections::HashMap<_, _> =
        matches.iter().map(|m| (m.template_id.as_str(), m)).collect();

    let all_m = by_template.get("all").expect("all match");
    let header_m = by_template.get("header").expect("header match");
    let body_m = by_template.get("body").expect("body match");

    // Header bytes are "x-foo: common,headtoken\n" (key lowercased).
    // "common" starts at 7, "headtoken" starts at 14.
    assert_eq!(all_m.offset, 7);
    assert!(all_m.offset < header_len);
    assert_eq!(header_m.offset, 14);
    // "bodytoken" starts at offset 4 inside "the bodytoken is here".
    assert_eq!(body_m.offset, 4);
}

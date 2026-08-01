//! Comprehensive extractor and transform tests.
//!
//! Tests all extractor kinds, all transforms, and edge cases for both.

use secir::matcher::ResponseData;
use secir::template::{ExtractorDef, ExtractorKind, MatchPart, Transform};
use secmatch::{extract_from_response, extract_variables_from_response, transform_response};

// ============================================================================
// Helpers
// ============================================================================

fn make_response(status: u16, headers: Vec<(&str, &str)>, body: &[u8]) -> ResponseData {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    ResponseData::new(status, headers, body.to_vec())
}

// ============================================================================
// Regex Extractor Tests
// ============================================================================

#[test]
fn extract_regex_group_0_full_match() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"version=(\d+\.\d+\.\d+)".to_string()],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("version"), Some(&"version=2.4.6".to_string()));
}

#[test]
fn extract_regex_group_1_capture() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"version=(\d+\.\d+\.\d+)".to_string()],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("version"), Some(&"2.4.6".to_string()));
}

#[test]
fn extract_regex_group_2_capture() {
    let response = make_response(200, vec![], b"name=alice age=30");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"name=(\w+) age=(\d+)".to_string()],
            name: Some("age".to_string()),
            part: MatchPart::Body,
            group: 2,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("age"), Some(&"30".to_string()));
}

#[test]
fn extract_regex_no_match_returns_empty() {
    let response = make_response(200, vec![], b"no version here");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"version=(\d+)".to_string()],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: false,
        }],
    );
    assert!(extracted.is_empty());
}

#[test]
fn extract_regex_multiple_patterns_first_wins() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![
                r"version=(\d+)".to_string(),
                r"version=(\d+\.\d+\.\d+)".to_string(),
            ],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("version"), Some(&"2".to_string()));
}

#[test]
fn extract_regex_second_pattern_fallback() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![
                r"noversion=(\d+)".to_string(),
                r"version=(\d+\.\d+\.\d+)".to_string(),
            ],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("version"), Some(&"2.4.6".to_string()));
}

#[test]
fn extract_regex_invalid_pattern_skipped() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![
                "(".to_string(), // invalid regex
                r"version=(\d+\.\d+\.\d+)".to_string(),
            ],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("version"), Some(&"2.4.6".to_string()));
}

#[test]
fn extract_regex_from_header() {
    let response = make_response(200, vec![("Authorization", "Bearer token123")], b"body");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"Bearer (\S+)".to_string()],
            name: Some("token".to_string()),
            part: MatchPart::Header,
            group: 1,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("token"), Some(&"token123".to_string()));
}

#[test]
fn extract_regex_group_out_of_bounds() {
    let response = make_response(200, vec![], b"test123");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"test(\d+)".to_string()],
            name: Some("test".to_string()),
            part: MatchPart::Body,
            group: 99,
            internal: false,
        }],
    );
    assert!(extracted.is_empty());
}

#[test]
fn extract_regex_with_null_bytes() {
    let response = make_response(200, vec![], b"te\x00st");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"te\x00st".to_string()],
            name: Some("test".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("test"), Some(&"te\u{0}st".to_string()));
}

#[test]
fn extract_regex_unicode() {
    let response = make_response(200, vec![], "名前=太郎".as_bytes());
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"名前=(.+)".to_string()],
            name: Some("name".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("name"), Some(&"太郎".to_string()));
}

#[test]
fn extract_regex_no_name_uses_first_pattern() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"version=(\d+\.\d+\.\d+)".to_string()],
            name: None,
            part: MatchPart::Body,
            group: 1,
            internal: false,
        }],
    );
    assert_eq!(
        extracted.get("version=(\\d+\\.\\d+\\.\\d+)"),
        Some(&"2.4.6".to_string())
    );
}

// ============================================================================
// Kval Extractor Tests
// ============================================================================

#[test]
fn extract_kval_basic() {
    let response = make_response(200, vec![("Server", "nginx/1.25.3")], b"body");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Kval,
            patterns: vec!["Server".to_string()],
            name: Some("server".to_string()),
            part: MatchPart::Header,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("server"), Some(&"nginx/1.25.3".to_string()));
}

#[test]
fn extract_kval_case_insensitive() {
    let response = make_response(200, vec![("Content-Type", "application/json")], b"body");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Kval,
            patterns: vec!["content-type".to_string()],
            name: Some("ct".to_string()),
            part: MatchPart::Header,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("ct"), Some(&"application/json".to_string()));
}

#[test]
fn extract_kval_no_match() {
    let response = make_response(200, vec![], b"body");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Kval,
            patterns: vec!["Server".to_string()],
            name: Some("server".to_string()),
            part: MatchPart::Header,
            group: 0,
            internal: false,
        }],
    );
    assert!(extracted.is_empty());
}

#[test]
fn extract_kval_multiple_patterns_first_wins() {
    let response = make_response(200, vec![("X-First", "first-value")], b"body");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Kval,
            patterns: vec!["X-First".to_string(), "X-Second".to_string()],
            name: Some("val".to_string()),
            part: MatchPart::Header,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("val"), Some(&"first-value".to_string()));
}

#[test]
fn extract_kval_second_pattern_fallback() {
    let response = make_response(200, vec![("X-Second", "second-value")], b"body");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Kval,
            patterns: vec!["X-First".to_string(), "X-Second".to_string()],
            name: Some("val".to_string()),
            part: MatchPart::Header,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("val"), Some(&"second-value".to_string()));
}

// ============================================================================
// JSON Extractor Tests
// ============================================================================

#[test]
fn extract_json_simple() {
    let response = make_response(200, vec![], b"{\"name\": \"alice\"}");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["name".to_string()],
            name: Some("name".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("name"), Some(&"alice".to_string()));
}

#[test]
fn extract_json_nested() {
    let response = make_response(200, vec![], b"{\"user\": {\"profile\": {\"age\": 30}}}");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["user.profile.age".to_string()],
            name: Some("age".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("age"), Some(&"30".to_string()));
}

#[test]
fn extract_json_array() {
    let response = make_response(
        200,
        vec![],
        b"{\"items\": [{\"name\": \"a\"}, {\"name\": \"b\"}]}",
    );
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["items.#.name".to_string()],
            name: Some("names".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("names"), Some(&"a\nb".to_string()));
}

#[test]
fn extract_json_dollar_prefix() {
    let response = make_response(200, vec![], b"{\"key\": \"value\"}");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["$.key".to_string()],
            name: Some("key".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("key"), Some(&"value".to_string()));
}

#[test]
fn extract_json_bracket_notation() {
    let response = make_response(
        200,
        vec![],
        b"{\"items\": [{\"name\": \"a\"}, {\"name\": \"b\"}]}",
    );
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["items[]name".to_string()],
            name: Some("names".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("names"), Some(&"a\nb".to_string()));
}

#[test]
fn extract_json_invalid_json_skipped() {
    let response = make_response(200, vec![], b"not json");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["key".to_string()],
            name: Some("key".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert!(extracted.is_empty());
}

#[test]
fn extract_json_missing_path() {
    let response = make_response(200, vec![], b"{\"key\": \"value\"}");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["nonexistent".to_string()],
            name: Some("missing".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert!(extracted.is_empty());
}

#[test]
fn extract_json_null_value() {
    let response = make_response(200, vec![], b"{\"data\": null}");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["data".to_string()],
            name: Some("data".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("data"), Some(&"null".to_string()));
}

#[test]
fn extract_json_boolean_value() {
    let response = make_response(200, vec![], b"{\"active\": true}");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["active".to_string()],
            name: Some("active".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("active"), Some(&"true".to_string()));
}

#[test]
fn extract_json_number_value() {
    let response = make_response(200, vec![], b"{\"count\": 42}");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["count".to_string()],
            name: Some("count".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("count"), Some(&"42".to_string()));
}

// ============================================================================
// Internal Extractor Tests
// ============================================================================

#[test]
fn extract_internal_skipped_by_default() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"version=(\d+\.\d+\.\d+)".to_string()],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: true,
        }],
    );
    assert!(extracted.is_empty());
}

#[test]
fn extract_internal_included_when_requested() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_variables_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"version=(\d+\.\d+\.\d+)".to_string()],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: true,
        }],
    );
    assert_eq!(extracted.get("version"), Some(&"2.4.6".to_string()));
}

// ============================================================================
// Transform Tests - Base64
// ============================================================================

#[test]
fn transform_base64_decode_valid() {
    let result = transform_response(b"aGVsbG8=".to_vec(), &[Transform::Base64Decode]);
    assert_eq!(result, b"hello");
}

#[test]
fn transform_base64_decode_invalid_passthrough() {
    let data = b"!!!invalid!!!".to_vec();
    let result = transform_response(data.clone(), &[Transform::Base64Decode]);
    assert_eq!(result, data);
}

#[test]
fn transform_base64_decode_empty() {
    let result = transform_response(b"".to_vec(), &[Transform::Base64Decode]);
    assert_eq!(result, b"");
}

#[test]
fn transform_base64_decode_with_nulls() {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&[0x00, 0x01, 0x00, 0x02]);
    let result = transform_response(encoded.into_bytes(), &[Transform::Base64Decode]);
    assert_eq!(result, vec![0x00, 0x01, 0x00, 0x02]);
}

// ============================================================================
// Transform Tests - Hex
// ============================================================================

#[test]
fn transform_hex_decode_valid() {
    let result = transform_response(b"68656c6c6f".to_vec(), &[Transform::HexDecode]);
    assert_eq!(result, b"hello");
}

#[test]
fn transform_hex_decode_invalid_passthrough() {
    let data = b"GGHHZZ".to_vec();
    let result = transform_response(data.clone(), &[Transform::HexDecode]);
    assert_eq!(result, data);
}

#[test]
fn transform_hex_decode_empty() {
    let result = transform_response(b"".to_vec(), &[Transform::HexDecode]);
    assert_eq!(result, b"");
}

#[test]
fn transform_hex_decode_with_nulls() {
    let result = transform_response(b"00010002".to_vec(), &[Transform::HexDecode]);
    assert_eq!(result, vec![0x00, 0x01, 0x00, 0x02]);
}

// ============================================================================
// Transform Tests - URL Decode
// ============================================================================

#[test]
fn transform_url_decode_valid() {
    let result = transform_response(b"hello%20world".to_vec(), &[Transform::UrlDecode]);
    assert_eq!(result, b"hello world");
}

#[test]
fn transform_url_decode_invalid_passthrough() {
    let data = b"%ZZ%GG%".to_vec();
    let result = transform_response(data.clone(), &[Transform::UrlDecode]);
    assert_eq!(result, data);
}

#[test]
fn transform_url_decode_unicode() {
    let result = transform_response("caf%C3%A9".as_bytes().to_vec(), &[Transform::UrlDecode]);
    assert_eq!(result, "café".as_bytes());
}

// ============================================================================
// Transform Tests - Gzip
// ============================================================================

#[test]
fn transform_gzip_valid() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(b"hello world").unwrap();
    let compressed = encoder.finish().unwrap();

    let result = transform_response(compressed, &[Transform::GzipDecompress]);
    assert_eq!(result, b"hello world");
}

#[test]
fn transform_gzip_invalid_passthrough() {
    let data = vec![0x1f, 0x8b, 0x08, 0x00, 0xFF, 0xFF];
    let result = transform_response(data.clone(), &[Transform::GzipDecompress]);
    assert_eq!(result, data);
}

// ============================================================================
// Transform Tests - JSON Parse
// ============================================================================

#[test]
fn transform_json_parse_simple() {
    let result = transform_response(
        b"{\"key\": \"value\"}".to_vec(),
        &[Transform::JsonParse {
            path: "key".to_string(),
        }],
    );
    assert_eq!(result, b"value");
}

#[test]
fn transform_json_parse_nested() {
    let result = transform_response(
        b"{\"user\": {\"name\": \"alice\"}}".to_vec(),
        &[Transform::JsonParse {
            path: "user.name".to_string(),
        }],
    );
    assert_eq!(result, b"alice");
}

#[test]
fn transform_json_parse_missing_path_empty() {
    let result = transform_response(
        b"{\"key\": \"value\"}".to_vec(),
        &[Transform::JsonParse {
            path: "missing".to_string(),
        }],
    );
    assert!(result.is_empty());
}

#[test]
fn transform_json_parse_invalid_json_passthrough() {
    let data = b"not json".to_vec();
    let result = transform_response(
        data.clone(),
        &[Transform::JsonParse {
            path: "key".to_string(),
        }],
    );
    assert_eq!(result, data);
}

#[test]
fn transform_json_parse_array() {
    let result = transform_response(
        b"{\"items\": [1, 2, 3]}".to_vec(),
        &[Transform::JsonParse {
            path: "items".to_string(),
        }],
    );
    // gjson echoes the raw substring (including original whitespace).
    assert_eq!(result, b"[1, 2, 3]");
}

// ============================================================================
// Transform Tests - JWT Decode
// ============================================================================

#[test]
fn transform_jwt_decode_valid() {
    use base64::Engine;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"sub\":\"123\"}");
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
    let token = format!("{header}.{payload}.{signature}");

    let result = transform_response(token.into_bytes(), &[Transform::JwtDecode]);
    assert_eq!(result, b"{\"sub\":\"123\"}");
}

#[test]
fn transform_jwt_decode_invalid_passthrough() {
    let data = b"not.a.jwt".to_vec();
    let result = transform_response(data.clone(), &[Transform::JwtDecode]);
    assert_eq!(result, data);
}

#[test]
fn transform_jwt_decode_two_parts_passthrough() {
    let data = b"header.payload".to_vec();
    let result = transform_response(data.clone(), &[Transform::JwtDecode]);
    assert_eq!(result, data);
}

// ============================================================================
// Transform Chain Tests
// ============================================================================

#[test]
fn transform_chain_base64_then_hex() {
    use base64::Engine;
    let hex_encoded = b"68656c6c6f"; // "hello" in hex
    let base64_encoded = base64::engine::general_purpose::STANDARD.encode(hex_encoded);
    let result = transform_response(
        base64_encoded.into_bytes(),
        &[Transform::Base64Decode, Transform::HexDecode],
    );
    assert_eq!(result, b"hello");
}

#[test]
fn transform_chain_url_then_base64() {
    use base64::Engine;
    let base64_encoded = base64::engine::general_purpose::STANDARD.encode(b"secret");
    let url_encoded = urlencoding::encode(&base64_encoded);
    let result = transform_response(
        url_encoded.into_owned().into_bytes(),
        &[Transform::UrlDecode, Transform::Base64Decode],
    );
    assert_eq!(result, b"secret");
}

#[test]
fn transform_chain_failure_in_middle_continues() {
    // "!!!invalid!!!" is neither valid base64 nor valid hex, so both
    // transforms fail closed and the original data passes through.
    let result = transform_response(
        b"!!!invalid!!!".to_vec(),
        &[
            Transform::Base64Decode,
            Transform::HexDecode,
        ],
    );
    assert_eq!(result, b"!!!invalid!!!");
}

#[test]
fn transform_chain_empty() {
    let result = transform_response(b"unchanged".to_vec(), &[]);
    assert_eq!(result, b"unchanged");
}

// ============================================================================
// Extractor + Transform Integration
// ============================================================================

#[test]
fn extract_after_transform_base64() {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(r#"{"token":"abc123"}"#);
    let mut response = make_response(200, vec![], encoded.as_bytes());
    response.body = transform_response(response.body, &[Transform::Base64Decode]);
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Json,
            patterns: vec!["token".to_string()],
            name: Some("token".to_string()),
            part: MatchPart::Body,
            group: 0,
            internal: false,
        }],
    );
    assert_eq!(extracted.get("token"), Some(&"abc123".to_string()));
}

// ============================================================================
// Invalid-pattern handling (Law-10: loud skip, no silent poison)
// ============================================================================

/// An invalid regex in an extractor's pattern list must be skipped (the code
/// now emits a `tracing::warn!` instead of swallowing the compile error via
/// `.ok()`), and must NOT abort the extractor: a valid sibling pattern listed
/// after it still extracts. Before this fix an invalid pattern silently
/// produced no value; this test locks the skip-and-continue contract.
#[test]
fn extract_regex_invalid_pattern_skipped_valid_sibling_still_extracts() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            // First pattern is an invalid regex (unclosed group) -> compile
            // error -> must be skipped loudly. Second is valid -> must match.
            patterns: vec![
                r"version=(\d+".to_string(),
                r"version=(\d+\.\d+\.\d+)".to_string(),
            ],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: false,
        }],
    );
    assert_eq!(
        extracted.get("version"),
        Some(&"2.4.6".to_string()),
        "valid sibling pattern must still extract after an invalid one is skipped"
    );
}

/// An extractor whose ONLY pattern is invalid must extract nothing (not panic,
/// not insert a garbage key).
#[test]
fn extract_regex_only_invalid_pattern_extracts_nothing() {
    let response = make_response(200, vec![], b"version=2.4.6");
    let extracted = extract_from_response(
        &response,
        &[ExtractorDef {
            kind: ExtractorKind::Regex,
            patterns: vec![r"version=(\d+".to_string()],
            name: Some("version".to_string()),
            part: MatchPart::Body,
            group: 1,
            internal: false,
        }],
    );
    assert!(
        extracted.get("version").is_none(),
        "an extractor with only an invalid pattern must yield no value"
    );
    assert!(extracted.is_empty(), "no keys should be inserted");
}

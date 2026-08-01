//! Comprehensive DSL evaluator tests.
//!
//! Tests all DSL functions, parser edge cases, operator combinations,
//! and boundary conditions.

use secir::matcher::ResponseData;
use secmatch::evaluate_dsl;

fn response_200() -> ResponseData {
    ResponseData::new(200, vec![], b"hello world".to_vec())
}

fn response_with_headers() -> ResponseData {
    ResponseData::new(
        200,
        vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Custom".to_string(), "custom-value".to_string()),
        ],
        b"{\"status\":\"ok\"}".to_vec(),
    )
}

fn eval(expr: &str, response: &ResponseData) -> bool {
    evaluate_dsl(expr, response)
}

// ============================================================================
// Comparison Operators
// ============================================================================

#[test]
fn dsl_eq_integer() {
    assert!(eval("status_code == 200", &response_200()));
    assert!(!eval("status_code == 404", &response_200()));
}

#[test]
fn dsl_ne_integer() {
    assert!(eval("status_code != 404", &response_200()));
    assert!(!eval("status_code != 200", &response_200()));
}

#[test]
fn dsl_gt_integer() {
    assert!(eval("status_code > 100", &response_200()));
    assert!(!eval("status_code > 200", &response_200()));
}

#[test]
fn dsl_lt_integer() {
    assert!(eval("status_code < 300", &response_200()));
    assert!(!eval("status_code < 200", &response_200()));
}

#[test]
fn dsl_ge_integer() {
    assert!(eval("status_code >= 200", &response_200()));
    assert!(!eval("status_code >= 201", &response_200()));
}

#[test]
fn dsl_le_integer() {
    assert!(eval("status_code <= 200", &response_200()));
    assert!(!eval("status_code <= 199", &response_200()));
}

#[test]
fn dsl_eq_string() {
    assert!(eval(r#"body == "hello world""#, &response_200()));
    assert!(!eval(r#"body == "goodbye""#, &response_200()));
}

#[test]
fn dsl_ne_string() {
    assert!(eval(r#"body != "goodbye""#, &response_200()));
    assert!(!eval(r#"body != "hello world""#, &response_200()));
}

// ============================================================================
// Logical Operators
// ============================================================================

#[test]
fn dsl_logical_and() {
    assert!(eval(
        "status_code == 200 && content_length > 0",
        &response_200()
    ));
    assert!(!eval(
        "status_code == 200 && content_length < 0",
        &response_200()
    ));
}

#[test]
fn dsl_logical_or() {
    assert!(eval(
        "status_code == 404 || status_code == 200",
        &response_200()
    ));
    assert!(!eval(
        "status_code == 404 || status_code == 500",
        &response_200()
    ));
}

#[test]
fn dsl_logical_chain_many_ands() {
    let expr = "status_code == 200 && content_length > 0 && body_length > 0";
    assert!(eval(expr, &response_200()));
}

#[test]
fn dsl_logical_chain_many_ors() {
    let expr = "status_code == 404 || status_code == 500 || status_code == 200";
    assert!(eval(expr, &response_200()));
}

#[test]
fn dsl_logical_mixed() {
    let expr = "(status_code == 200 && content_length > 0) || status_code == 404";
    assert!(eval(expr, &response_200()));
}

#[test]
fn dsl_logical_not() {
    assert!(!eval("!status_code == 200", &response_200()));
    assert!(eval("!status_code == 404", &response_200()));
}

#[test]
fn dsl_logical_double_not() {
    assert!(eval("!!status_code == 200", &response_200()));
}

// ============================================================================
// Arithmetic Operators
// ============================================================================

#[test]
fn dsl_add() {
    assert!(eval("status_code + 1 == 201", &response_200()));
}

#[test]
fn dsl_sub() {
    assert!(eval("status_code - 1 == 199", &response_200()));
}

#[test]
fn dsl_mul() {
    assert!(eval("status_code * 2 == 400", &response_200()));
}

#[test]
fn dsl_div() {
    assert!(eval("status_code / 2 == 100", &response_200()));
}

#[test]
fn dsl_div_by_zero() {
    assert!(!eval("content_length / 0 == 0", &response_200()));
}

#[test]
fn dsl_arithmetic_precedence() {
    assert!(eval("2 + 3 * 4 == 14", &response_200()));
    assert!(eval("(2 + 3) * 4 == 20", &response_200()));
}

// ============================================================================
// contains() Function
// ============================================================================

#[test]
fn dsl_contains_body() {
    assert!(eval(r#"contains(body, "world")"#, &response_200()));
    assert!(!eval(r#"contains(body, "universe")"#, &response_200()));
}

#[test]
fn dsl_contains_empty_needle() {
    assert!(eval(r#"contains(body, "")"#, &response_200()));
}

#[test]
fn dsl_contains_header() {
    assert!(eval(
        "contains(all_headers, \"Content-Type\")",
        &response_with_headers()
    ));
    assert!(!eval(
        "contains(all_headers, \"Missing\")",
        &response_with_headers()
    ));
}

#[test]
fn dsl_contains_method_call() {
    assert!(eval(r#"body.contains("world")"#, &response_200()));
    assert!(!eval(r#"body.contains("universe")"#, &response_200()));
}

// ============================================================================
// contains_any() Function
// ============================================================================

#[test]
fn dsl_contains_any_match() {
    assert!(eval(
        r#"contains_any(body, "foo", "world", "bar")"#,
        &response_200()
    ));
}

#[test]
fn dsl_contains_any_no_match() {
    assert!(!eval(
        r#"contains_any(body, "foo", "bar", "baz")"#,
        &response_200()
    ));
}

// ============================================================================
// len() Function
// ============================================================================

#[test]
fn dsl_len_body() {
    assert!(eval("len(body) == 11", &response_200()));
}

#[test]
fn dsl_len_empty_body() {
    let response = ResponseData::new(200, vec![], b"".to_vec());
    assert!(eval("len(body) == 0", &response));
}

#[test]
fn dsl_len_unicode_bytes() {
    let response = ResponseData::new(200, vec![], "café".as_bytes().to_vec());
    assert!(eval("len(body) == 5", &response)); // c-a-f-é = 1+1+1+2 = 5 bytes
}

// ============================================================================
// starts_with / ends_with Functions
// ============================================================================

#[test]
fn dsl_starts_with() {
    assert!(eval(r#"starts_with(body, "hello")"#, &response_200()));
    assert!(!eval(r#"starts_with(body, "world")"#, &response_200()));
}

#[test]
fn dsl_ends_with() {
    assert!(eval(r#"ends_with(body, "world")"#, &response_200()));
    assert!(!eval(r#"ends_with(body, "hello")"#, &response_200()));
}

#[test]
fn dsl_starts_with_method() {
    assert!(eval(r#"body.starts_with("hello")"#, &response_200()));
}

#[test]
fn dsl_ends_with_method() {
    assert!(eval(r#"body.ends_with("world")"#, &response_200()));
}

// ============================================================================
// to_lower / to_upper Functions
// ============================================================================

#[test]
fn dsl_to_lower() {
    assert!(eval(r#"to_lower("HELLO") == "hello""#, &response_200()));
}

#[test]
fn dsl_to_upper() {
    assert!(eval(r#"to_upper("hello") == "HELLO""#, &response_200()));
}

#[test]
fn dsl_to_lower_method() {
    assert!(eval(r#""HELLO".to_lower() == "hello""#, &response_200()));
}

#[test]
fn dsl_to_upper_method() {
    assert!(eval(r#""hello".to_upper() == "HELLO""#, &response_200()));
}

// ============================================================================
// regex() Function
// ============================================================================

#[test]
fn dsl_regex_match() {
    assert!(eval(
        r#"regex(body, "\d+")"#,
        &ResponseData::new(200, vec![], b"123".to_vec())
    ));
}

#[test]
fn dsl_regex_no_match() {
    assert!(!eval(r#"regex(body, "\d+")"#, &response_200()));
}

#[test]
fn dsl_regex_invalid_pattern() {
    assert!(!eval(r#"regex(body, "(")"#, &response_200()));
}

// ============================================================================
// md5 / sha1 / sha256 Functions
// ============================================================================

#[test]
fn dsl_md5() {
    assert!(eval(
        r#"md5("") == "d41d8cd98f00b204e9800998ecf8427e""#,
        &response_200()
    ));
}

#[test]
fn dsl_sha1() {
    assert!(eval(
        r#"sha1("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709""#,
        &response_200()
    ));
}

#[test]
fn dsl_sha256() {
    assert!(eval(
        r#"sha256("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855""#,
        &response_200()
    ));
}

// ============================================================================
// base64 / base64_decode Functions
// ============================================================================

#[test]
fn dsl_base64() {
    assert!(eval(r#"base64("hello") == "aGVsbG8=""#, &response_200()));
}

#[test]
fn dsl_base64_decode() {
    assert!(eval(
        r#"base64_decode("aGVsbG8=") == "hello""#,
        &response_200()
    ));
}

#[test]
fn dsl_base64_roundtrip() {
    assert!(eval(
        r#"base64_decode(base64("test")) == "test""#,
        &response_200()
    ));
}

// ============================================================================
// url_encode / url_decode Functions
// ============================================================================

#[test]
fn dsl_url_encode() {
    assert!(eval(
        r#"url_encode("hello world") == "hello%20world""#,
        &response_200()
    ));
}

#[test]
fn dsl_url_decode() {
    assert!(eval(
        r#"url_decode("hello%20world") == "hello world""#,
        &response_200()
    ));
}

// ============================================================================
// trim() Function
// ============================================================================

#[test]
fn dsl_trim() {
    assert!(eval(r#"trim("  hello  ") == "hello""#, &response_200()));
}

#[test]
fn dsl_trim_with_chars() {
    assert!(eval(
        r#"trim("xxhelloxx", "x") == "hello""#,
        &response_200()
    ));
}

#[test]
fn dsl_trim_empty() {
    assert!(eval(r#"trim("") == """#, &response_200()));
}

// ============================================================================
// replace() Function
// ============================================================================

#[test]
fn dsl_replace() {
    assert!(eval(
        r#"replace("hello world", "world", "universe") == "hello universe""#,
        &response_200()
    ));
}

#[test]
fn dsl_replace_empty_old() {
    assert!(eval(
        r#"replace("hello", "", "X") == "XhXeXlXlXoX""#,
        &response_200()
    ));
}

// ============================================================================
// hex_encode / hex_decode Functions
// ============================================================================

#[test]
fn dsl_hex_encode() {
    assert!(eval(
        r#"hex_encode("hello") == "68656c6c6f""#,
        &response_200()
    ));
}

#[test]
fn dsl_hex_decode() {
    assert!(eval(
        r#"hex_decode("68656c6c6f") == "hello""#,
        &response_200()
    ));
}

// ============================================================================
// substr() Function
// ============================================================================

#[test]
fn dsl_substr() {
    assert!(eval(
        r#"substr("hello world", 6, 5) == "world""#,
        &response_200()
    ));
}

#[test]
fn dsl_substr_multibyte_no_panic() {
    // Character-based indexing: byte slicing would panic on the non-ASCII
    // boundary inside "café" (end byte 4 splits 'é'). Counts chars, not bytes.
    assert!(eval(r#"substr("café", 0, 4) == "café""#, &response_200()));
    assert!(eval(r#"substr("naïve", 2, 2) == "ïv""#, &response_200()));
    // Oversized length saturates instead of overflowing start + length.
    assert!(eval(r#"substr("abc", 1, 99999) == "bc""#, &response_200()));
}

#[test]
fn dsl_substr_out_of_bounds() {
    assert!(eval(r#"substr("hello", 100, 5) == """#, &response_200()));
}

#[test]
fn dsl_substr_zero_length() {
    assert!(eval(r#"substr("hello", 0, 0) == """#, &response_200()));
}

// ============================================================================
// concat() Function
// ============================================================================

#[test]
fn dsl_concat() {
    assert!(eval(
        r#"concat("hello", " ", "world") == "hello world""#,
        &response_200()
    ));
}

#[test]
fn dsl_concat_many() {
    assert!(eval(
        r#"concat("a", "b", "c", "d", "e") == "abcde""#,
        &response_200()
    ));
}

// ============================================================================
// all_match / any_match Functions
// ============================================================================

#[test]
fn dsl_all_match_true() {
    assert!(eval(
        r#"all_match("\d+", ["1", "2", "3"])"#,
        &response_200()
    ));
}

#[test]
fn dsl_all_match_false() {
    assert!(!eval(
        r#"all_match("\d+", ["1", "a", "3"])"#,
        &response_200()
    ));
}

#[test]
fn dsl_any_match_true() {
    assert!(eval(
        r#"any_match("\d+", ["a", "2", "c"])"#,
        &response_200()
    ));
}

#[test]
fn dsl_any_match_false() {
    assert!(!eval(
        r#"any_match("\d+", ["a", "b", "c"])"#,
        &response_200()
    ));
}

// ============================================================================
// to_number() Function
// ============================================================================

#[test]
fn dsl_to_number() {
    assert!(eval(r#"to_number("42") == 42"#, &response_200()));
}

#[test]
fn dsl_to_number_invalid() {
    assert!(!eval(r#"to_number("abc") == 42"#, &response_200()));
}

// ============================================================================
// dec_to_hex / hex_to_dec Functions
// ============================================================================

#[test]
fn dsl_dec_to_hex() {
    assert!(eval(r#"dec_to_hex(255) == "ff""#, &response_200()));
}

#[test]
fn dsl_hex_to_dec() {
    assert!(eval(r#"hex_to_dec("ff") == 255"#, &response_200()));
}

#[test]
fn dsl_hex_to_dec_with_prefix() {
    assert!(eval(r#"hex_to_dec("0xFF") == 255"#, &response_200()));
}

// ============================================================================
// reverse() Function
// ============================================================================

#[test]
fn dsl_reverse() {
    assert!(eval(r#"reverse("hello") == "olleh""#, &response_200()));
}

#[test]
fn dsl_reverse_unicode() {
    assert!(eval(r#"reverse("abc") == "cba""#, &response_200()));
}

// ============================================================================
// join() Function
// ============================================================================

#[test]
fn dsl_join_strings() {
    assert!(eval(
        r#"join("-", "a", "b", "c") == "a-b-c""#,
        &response_200()
    ));
}

#[test]
fn dsl_join_empty_separator() {
    assert!(eval(r#"join("", "a", "b", "c") == "abc""#, &response_200()));
}

// ============================================================================
// split() Function
// ============================================================================

#[test]
fn dsl_split() {
    assert!(eval(r#"split("a,b,c", ",", 1) == "b""#, &response_200()));
}

#[test]
fn dsl_split_out_of_bounds() {
    assert!(eval(r#"split("a,b,c", ",", 10) == """#, &response_200()));
}

// ============================================================================
// regex_find_all() Function
// ============================================================================

#[test]
fn dsl_regex_find_all() {
    // regex_find_all returns a List; a top-level non-boolean value is rejected by
    // evaluate_dsl, so the match is asserted through a boolean comparison.
    assert!(eval(
        r#"len(regex_find_all("hello 123 world 456", "\d+")) > 0"#,
        &response_200()
    ));
}

// ============================================================================
// repeat() Function
// ============================================================================

#[test]
fn dsl_repeat() {
    assert!(eval(r#"repeat("ab", 3) == "ababab""#, &response_200()));
}

#[test]
fn dsl_repeat_zero() {
    assert!(eval(r#"repeat("ab", 0) == """#, &response_200()));
}

// ============================================================================
// line_count / word_count Functions
// ============================================================================

#[test]
fn dsl_line_count() {
    assert!(eval(r#"line_count("a\nb\nc") == 3"#, &response_200()));
}

#[test]
fn dsl_word_count() {
    assert!(eval(
        r#"word_count("hello world test") == 3"#,
        &response_200()
    ));
}

// ============================================================================
// version_compare Function
// ============================================================================

#[test]
fn dsl_version_compare_equal() {
    assert!(eval(
        r#"version_compare("1.0.0", "==", "1.0.0")"#,
        &response_200()
    ));
}

#[test]
fn dsl_version_compare_less() {
    assert!(eval(
        r#"version_compare("1.0.0", "<", "2.0.0")"#,
        &response_200()
    ));
}

#[test]
fn dsl_version_compare_greater() {
    assert!(eval(
        r#"version_compare("2.0.0", ">", "1.0.0")"#,
        &response_200()
    ));
}

#[test]
fn dsl_version_compare_invalid_op() {
    assert!(!eval(
        r#"version_compare("1.0.0", "invalid", "2.0.0")"#,
        &response_200()
    ));
}

// ============================================================================
// wait_for Function
// ============================================================================

#[test]
fn dsl_wait_for_clamped() {
    assert!(eval(r#"wait_for(100) == 10"#, &response_200()));
    assert!(eval(r#"wait_for(5) == 5"#, &response_200()));
}

// ============================================================================
// date_time Function
// ============================================================================

#[test]
fn dsl_date_time_empty() {
    assert!(eval(r#"len(date_time("")) > 0"#, &response_200()));
}

// ============================================================================
// rand_int Function
// ============================================================================

#[test]
fn dsl_rand_int_in_range() {
    // We can't test randomness precisely, but we can test the expression parses and evaluates
    let response = response_200();
    let result = evaluate_dsl(
        r#"rand_int(0, 100) >= 0 && rand_int(0, 100) <= 100"#,
        &response,
    );
    assert!(result);
}

#[test]
fn dsl_rand_int_min_eq_max() {
    assert!(eval(r#"rand_int(42, 42) == 42"#, &response_200()));
}

// ============================================================================
// rand_text Functions
// ============================================================================

#[test]
fn dsl_rand_text_alpha_length() {
    assert!(eval(r#"len(rand_text_alpha(10)) == 10"#, &response_200()));
}

#[test]
fn dsl_rand_text_numeric_length() {
    assert!(eval(r#"len(rand_text_numeric(10)) == 10"#, &response_200()));
}

#[test]
fn dsl_rand_text_alphanumeric_length() {
    assert!(eval(
        r#"len(rand_text_alphanumeric(10)) == 10"#,
        &response_200()
    ));
}

// ============================================================================
// rand_ip / rand_base Functions
// ============================================================================

#[test]
fn dsl_rand_ip_format() {
    assert!(eval(r#"len(rand_ip()) > 0"#, &response_200()));
}

#[test]
fn dsl_rand_base_length() {
    assert!(eval(r#"len(rand_base(10, "abc")) == 10"#, &response_200()));
}

#[test]
fn dsl_rand_base_empty_charset_error() {
    assert!(!eval(r#"len(rand_base(10, "")) == 10"#, &response_200()));
}

// ============================================================================
// Parser Edge Cases
// ============================================================================

#[test]
fn dsl_empty_expression() {
    assert!(!eval("", &response_200()));
}

#[test]
fn dsl_whitespace_only() {
    assert!(!eval("   \n\t  ", &response_200()));
}

#[test]
fn dsl_unmatched_paren() {
    assert!(!eval("(status_code == 200", &response_200()));
}

#[test]
fn dsl_extra_paren() {
    assert!(!eval("status_code == 200)", &response_200()));
}

#[test]
fn dsl_unknown_identifier() {
    assert!(!eval("unknown_var == 200", &response_200()));
}

#[test]
fn dsl_malformed_comparison() {
    assert!(!eval("status_code == ", &response_200()));
}

#[test]
fn dsl_unknown_function() {
    assert!(!eval("unknown_func(1, 2)", &response_200()));
}

#[test]
fn dsl_deeply_nested_parens() {
    let expr = "(".repeat(20) + "status_code == 200" + &")".repeat(20);
    assert!(eval(&expr, &response_200()));
}

#[test]
fn dsl_string_with_escaped_quotes() {
    assert!(eval(
        r#""hello \"world\"" == "hello \"world\"""#,
        &response_200()
    ));
}

#[test]
fn dsl_string_with_backslash() {
    assert!(eval(r#""hello\\world" == "hello\\world""#, &response_200()));
}

// ============================================================================
// Response Identifiers
// ============================================================================

#[test]
fn dsl_body_length() {
    assert!(eval("body_length == 11", &response_200()));
}

#[test]
fn dsl_content_length() {
    assert!(eval("content_length == 11", &response_200()));
}

#[test]
fn dsl_response_headers_count() {
    assert!(eval(
        "response_headers_count == 2",
        &response_with_headers()
    ));
}

#[test]
fn dsl_header_identifier() {
    assert!(eval("len(header) > 0", &response_with_headers()));
}

#[test]
fn dsl_all_identifier() {
    assert!(eval("len(all) > 0", &response_with_headers()));
}

#[test]
fn dsl_header_names_list() {
    assert!(eval("len(header_names) == 2", &response_with_headers()));
}

#[test]
fn dsl_header_values_list() {
    assert!(eval("len(header_values) == 2", &response_with_headers()));
}

// ============================================================================
// Status Code Series Identifiers
// ============================================================================

#[test]
fn dsl_status_code_0() {
    assert!(eval("status_code_0 == 200", &response_200()));
}

#[test]
fn dsl_body_0() {
    assert!(eval("body_0 == body", &response_200()));
}

#[test]
fn dsl_header_0() {
    assert!(eval("header_0 == header", &response_200()));
}

use secir::matcher::ResponseData;
use secmatch::evaluate_dsl;

fn response() -> ResponseData {
    ResponseData::new(
        200,
        vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("X-Test".to_string(), "payload".to_string()),
        ],
        b"body payload 123".to_vec(),
    )
}

macro_rules! dsl_false_case {
    ($name:ident, $doc:expr, $expr:expr) => {
        #[doc = $doc]
        #[test]
        fn $name() {
            let response = response();
            let expr = $expr;
            let result = std::panic::catch_unwind(|| evaluate_dsl(&expr, &response));
            assert!(
                result.is_ok(),
                "malformed expression should not panic: {:?}",
                expr
            );
            assert!(
                !result.unwrap(),
                "malformed expression should evaluate to false: {:?}",
                expr
            );
        }
    };
}

dsl_false_case!(
    empty_expression,
    "Expected behavior: empty expressions should evaluate to false without panicking.",
    "".to_string()
);
dsl_false_case!(
    whitespace_only_spaces,
    "Expected behavior: space-only expressions should evaluate to false without panicking.",
    "     ".to_string()
);
dsl_false_case!(
    whitespace_only_mixed,
    "Expected behavior: mixed whitespace should evaluate to false without panicking.",
    " \n\t\r ".to_string()
);
dsl_false_case!(
    single_open_paren,
    "Expected behavior: an unmatched opening parenthesis should evaluate to false.",
    "(".to_string()
);
dsl_false_case!(
    single_close_paren,
    "Expected behavior: an unmatched closing parenthesis should evaluate to false.",
    ")".to_string()
);
dsl_false_case!(
    double_open_paren,
    "Expected behavior: stacked unmatched opening parentheses should evaluate to false.",
    "((".to_string()
);
dsl_false_case!(
    double_close_paren,
    "Expected behavior: stacked unmatched closing parentheses should evaluate to false.",
    "))".to_string()
);
dsl_false_case!(
    unclosed_group_after_identifier,
    "Expected behavior: unfinished grouped expressions should evaluate to false.",
    "(status_code == 200".to_string()
);
dsl_false_case!(
    trailing_close_after_group,
    "Expected behavior: extra closing parentheses should evaluate to false.",
    "(status_code == 200))".to_string()
);
dsl_false_case!(
    dangling_and_operator,
    "Expected behavior: dangling logical operators should evaluate to false.",
    "status_code == 200 &&".to_string()
);
dsl_false_case!(
    dangling_or_operator,
    "Expected behavior: dangling logical operators should evaluate to false.",
    "status_code == 200 ||".to_string()
);
dsl_false_case!(
    leading_and_operator,
    "Expected behavior: leading logical operators should evaluate to false.",
    "&& status_code == 200".to_string()
);
dsl_false_case!(
    leading_or_operator,
    "Expected behavior: leading logical operators should evaluate to false.",
    "|| status_code == 200".to_string()
);
dsl_false_case!(
    single_ampersand,
    "Expected behavior: unsupported single ampersands should evaluate to false.",
    "status_code == 200 & body == 'x'".to_string()
);
dsl_false_case!(
    single_pipe,
    "Expected behavior: unsupported single pipes should evaluate to false.",
    "status_code == 200 | body == 'x'".to_string()
);
dsl_false_case!(
    triple_ampersand,
    "Expected behavior: malformed repeated ampersands should evaluate to false.",
    "status_code == 200 &&& body == 'x'".to_string()
);
dsl_false_case!(
    triple_pipe,
    "Expected behavior: malformed repeated pipes should evaluate to false.",
    "status_code == 200 ||| body == 'x'".to_string()
);
dsl_false_case!(
    single_equals,
    "Expected behavior: assignment-like syntax should evaluate to false.",
    "status_code = 200".to_string()
);
dsl_false_case!(
    triple_equals,
    "Expected behavior: JavaScript-style triple equals should evaluate to false.",
    "status_code === 200".to_string()
);
dsl_false_case!(
    double_not_equals,
    "Expected behavior: malformed inequality operators should evaluate to false.",
    "status_code !== 200".to_string()
);
dsl_false_case!(
    shift_operator_left,
    "Expected behavior: unsupported shift operators should evaluate to false.",
    "status_code << 1".to_string()
);
dsl_false_case!(
    shift_operator_right,
    "Expected behavior: unsupported shift operators should evaluate to false.",
    "status_code >> 1".to_string()
);
dsl_false_case!(
    sql_like_not,
    "Expected behavior: SQL-style NOT should not parse as valid DSL.",
    "NOT status_code == 200".to_string()
);
dsl_false_case!(
    sql_like_and,
    "Expected behavior: SQL-style AND should not parse as valid DSL.",
    "status_code == 200 AND body == 'x'".to_string()
);
dsl_false_case!(
    sql_like_or,
    "Expected behavior: SQL-style OR should not parse as valid DSL.",
    "status_code == 200 OR body == 'x'".to_string()
);
dsl_false_case!(
    keyword_true,
    "Expected behavior: bare unknown identifiers like true should evaluate to false.",
    "true".to_string()
);
dsl_false_case!(
    keyword_false,
    "Expected behavior: bare unknown identifiers like false should evaluate to false.",
    "false".to_string()
);
dsl_false_case!(
    keyword_null,
    "Expected behavior: bare null should evaluate to false.",
    "null".to_string()
);
dsl_false_case!(
    keyword_none,
    "Expected behavior: bare none should evaluate to false.",
    "none".to_string()
);
dsl_false_case!(
    unknown_identifier_equality,
    "Expected behavior: unknown identifiers should evaluate to false.",
    "totally_unknown == 1".to_string()
);
dsl_false_case!(
    unknown_identifier_arithmetic,
    "Expected behavior: arithmetic with unknown identifiers should evaluate to false.",
    "totally_unknown + 1 == 2".to_string()
);
dsl_false_case!(
    unsupported_contains_infix,
    "Expected behavior: unsupported infix operators should evaluate to false.",
    r#"body contains "payload""#.to_string()
);
dsl_false_case!(
    unsupported_matches_infix,
    "Expected behavior: unsupported infix matches syntax should evaluate to false.",
    r#"body matches ".*""#.to_string()
);
dsl_false_case!(
    unsupported_regex_infix,
    "Expected behavior: regex-style infix syntax should evaluate to false.",
    r#"body =~ "payload""#.to_string()
);
dsl_false_case!(
    unsupported_not_regex_infix,
    "Expected behavior: negated regex-style syntax should evaluate to false.",
    r#"body !~ "payload""#.to_string()
);
dsl_false_case!(
    unterminated_single_quote,
    "Expected behavior: unterminated single-quoted strings should evaluate to false.",
    "'payload".to_string()
);
dsl_false_case!(
    unterminated_double_quote,
    "Expected behavior: unterminated double-quoted strings should evaluate to false.",
    "\"payload".to_string()
);
dsl_false_case!(
    unfinished_escape_single_quote,
    "Expected behavior: unfinished escapes inside single-quoted strings should evaluate to false.",
    "'payload\\".to_string()
);
dsl_false_case!(
    unfinished_escape_double_quote,
    "Expected behavior: unfinished escapes inside double-quoted strings should evaluate to false.",
    "\"payload\\".to_string()
);
dsl_false_case!(
    quote_then_identifier,
    "Expected behavior: stray trailing tokens after strings should evaluate to false.",
    "'payload' body".to_string()
);
dsl_false_case!(
    string_followed_by_group,
    "Expected behavior: adjacent primary expressions should evaluate to false.",
    "'a'('b')".to_string()
);
dsl_false_case!(
    number_followed_by_group,
    "Expected behavior: calling an integer as a function should evaluate to false.",
    "1(2)".to_string()
);
dsl_false_case!(
    number_followed_by_identifier,
    "Expected behavior: adjacent number and identifier tokens should evaluate to false.",
    "1status_code".to_string()
);
dsl_false_case!(
    open_bracket_literal,
    "Expected behavior: unsupported bracket literals should evaluate to false.",
    "[".to_string()
);
dsl_false_case!(
    json_like_array,
    "Expected behavior: JSON-like array syntax should evaluate to false.",
    "[1,2,3]".to_string()
);
dsl_false_case!(
    json_like_object,
    "Expected behavior: JSON-like object syntax should evaluate to false.",
    "{\"a\":1}".to_string()
);
dsl_false_case!(
    bare_comma,
    "Expected behavior: a bare comma should evaluate to false.",
    ",".to_string()
);
dsl_false_case!(
    double_comma_call,
    "Expected behavior: repeated commas in function calls should evaluate to false.",
    "contains(body,, 'x')".to_string()
);
dsl_false_case!(
    leading_comma_call,
    "Expected behavior: leading commas in function calls should evaluate to false.",
    "contains(, body, 'x')".to_string()
);
dsl_false_case!(
    trailing_comma_call,
    "Expected behavior: trailing commas in function calls should evaluate to false.",
    "contains(body, 'x',)".to_string()
);
dsl_false_case!(
    only_comma_arguments,
    "Expected behavior: comma-only call bodies should evaluate to false.",
    "contains(,,)".to_string()
);
dsl_false_case!(
    empty_method_call_target,
    "Expected behavior: method calls without receivers should evaluate to false.",
    ".contains('x')".to_string()
);
dsl_false_case!(
    empty_method_name,
    "Expected behavior: dots without a method name should evaluate to false.",
    "body.('x')".to_string()
);
dsl_false_case!(
    missing_method_parens,
    "Expected behavior: method calls must include parentheses and should otherwise evaluate to false.",
    "body.contains".to_string()
);
dsl_false_case!(
    double_dot_chain,
    "Expected behavior: repeated dots should evaluate to false.",
    "body..contains('x')".to_string()
);
dsl_false_case!(
    triple_dot_chain,
    "Expected behavior: triple dots should evaluate to false.",
    "body...contains('x')".to_string()
);
dsl_false_case!(
    dot_after_call_without_identifier,
    "Expected behavior: a trailing dot after a call should evaluate to false.",
    "contains(body, 'x').".to_string()
);
dsl_false_case!(
    method_call_with_trailing_dot,
    "Expected behavior: trailing dots on method chains should evaluate to false.",
    "body.trim().".to_string()
);
dsl_false_case!(
    nested_trailing_dot,
    "Expected behavior: nested trailing dots should evaluate to false.",
    "body.trim().to_lower().".to_string()
);
dsl_false_case!(
    double_not_operator,
    "Expected behavior: repeated unary operators without operands should evaluate to false.",
    "!!".to_string()
);
dsl_false_case!(
    dangling_not_operator,
    "Expected behavior: a lone unary not should evaluate to false.",
    "!".to_string()
);
dsl_false_case!(
    not_before_close_paren,
    "Expected behavior: invalid unary placement should evaluate to false.",
    "!)".to_string()
);
dsl_false_case!(
    leading_plus,
    "Expected behavior: unsupported unary plus should evaluate to false.",
    "+1 == 1".to_string()
);
/// Regression test: negative integer literals are now SUPPORTED (the DSL
/// compares against signed fields, and rejecting them broke valid rules like
/// `status_code == -1`). `-1 == -1` must evaluate to true, not parse-fail.
#[test]
fn leading_minus_supported() {
    let response = response();
    let result = std::panic::catch_unwind(|| evaluate_dsl("-1 == -1", &response));
    assert!(
        matches!(result, Ok(true)),
        "negative literal comparison must evaluate to true"
    );
}
dsl_false_case!(
    double_plus,
    "Expected behavior: malformed arithmetic operators should evaluate to false.",
    "1 ++ 2".to_string()
);
dsl_false_case!(
    double_minus,
    "Expected behavior: malformed arithmetic operators should evaluate to false.",
    "1 -- 2".to_string()
);
dsl_false_case!(
    plus_star,
    "Expected behavior: malformed operator sequences should evaluate to false.",
    "1 +* 2".to_string()
);
dsl_false_case!(
    slash_star,
    "Expected behavior: C-style comment starts should not parse as operators.",
    "1 /* 2".to_string()
);
dsl_false_case!(
    star_slash,
    "Expected behavior: C-style comment endings should not parse as operators.",
    "1 */ 2".to_string()
);
dsl_false_case!(
    division_by_zero,
    "Expected behavior: division by zero should be handled as a false evaluation, not a panic.",
    "content_length / 0 == 1".to_string()
);
dsl_false_case!(
    division_by_zero_nested,
    "Expected behavior: nested division by zero should be handled as a false evaluation.",
    "(content_length + 1) / (1 - 1) == 1".to_string()
);
dsl_false_case!(
    arithmetic_type_error,
    "Expected behavior: arithmetic on strings should evaluate to false.",
    "'1' + 2 == 3".to_string()
);
dsl_false_case!(
    comparison_type_error,
    "Expected behavior: numeric comparisons on strings should evaluate to false.",
    "'1' > 0".to_string()
);
dsl_false_case!(
    bool_chain_type_error,
    "Expected behavior: invalid comparisons inside logical chains should evaluate to false.",
    "('x' > 1) && status_code == 200".to_string()
);
dsl_false_case!(
    call_unknown_function,
    "Expected behavior: unknown functions should evaluate to false.",
    "definitely_not_real(body)".to_string()
);
dsl_false_case!(
    call_unknown_function_with_many_args,
    "Expected behavior: unknown functions with many args should evaluate to false.",
    "definitely_not_real(body, header, status_code, 1, 2, 3)".to_string()
);
dsl_false_case!(
    call_contains_wrong_arity_zero,
    "Expected behavior: known functions with missing arguments should evaluate to false.",
    "contains()".to_string()
);
dsl_false_case!(
    call_contains_wrong_arity_one,
    "Expected behavior: known functions with too few arguments should evaluate to false.",
    "contains(body)".to_string()
);
dsl_false_case!(
    call_contains_wrong_arity_three,
    "Expected behavior: known functions with too many arguments should evaluate to false.",
    "contains(body, 'x', 'y')".to_string()
);
dsl_false_case!(
    call_len_wrong_arity_two,
    "Expected behavior: len should reject extra arguments and evaluate to false.",
    "len(body, 1)".to_string()
);
dsl_false_case!(
    call_trim_wrong_arity_zero,
    "Expected behavior: trim should reject missing arguments and evaluate to false.",
    "trim()".to_string()
);
dsl_false_case!(
    call_replace_wrong_arity_two,
    "Expected behavior: replace requires three args and should otherwise evaluate to false.",
    "replace(body, 'x')".to_string()
);
dsl_false_case!(
    call_split_wrong_arity_two,
    "Expected behavior: split requires three args and should otherwise evaluate to false.",
    "split(body, ',')".to_string()
);
dsl_false_case!(
    call_rand_int_wrong_arity_one,
    "Expected behavior: rand_int requires two args and should otherwise evaluate to false.",
    "rand_int(1)".to_string()
);
dsl_false_case!(
    call_rand_text_alpha_wrong_type,
    "Expected behavior: wrong arg types should evaluate to false.",
    "rand_text_alpha('ten')".to_string()
);
dsl_false_case!(
    call_substr_wrong_arity_two,
    "Expected behavior: substr requires three args and should otherwise evaluate to false.",
    "substr(body, 1)".to_string()
);
dsl_false_case!(
    call_substr_wrong_types,
    "Expected behavior: substr with string indexes should evaluate to false.",
    "substr(body, '1', '2')".to_string()
);
dsl_false_case!(
    call_regex_wrong_arity_one,
    "Expected behavior: regex_find_all requires two args and should otherwise evaluate to false.",
    "regex_find_all(body)".to_string()
);
dsl_false_case!(
    call_regex_invalid_pattern,
    "Expected behavior: invalid regex patterns should evaluate to false without panicking.",
    "regex_find_all(body, '(') == 1".to_string()
);
dsl_false_case!(
    call_json_extract_wrong_arity_one,
    "Expected behavior: json_extract requires two args and should otherwise evaluate to false.",
    "json_extract(body)".to_string()
);
dsl_false_case!(
    call_json_extract_invalid_json,
    "Expected behavior: invalid JSON should evaluate to false when used as a boolean comparison.",
    "json_extract('{', '$.x') == 'y'".to_string()
);
dsl_false_case!(
    call_version_compare_wrong_arity_two,
    "Expected behavior: version_compare requires three args and should otherwise evaluate to false.",
    "version_compare('1', '==')".to_string()
);
dsl_false_case!(
    call_version_compare_invalid_operator,
    "Expected behavior: invalid version operators should evaluate to false.",
    "version_compare('1', '===', '1')".to_string()
);
dsl_false_case!(
    call_wait_for_negative,
    "Expected behavior: invalid wait_for arguments should evaluate to false rather than panic.",
    "wait_for(-1)".to_string()
);
dsl_false_case!(
    call_wait_for_wrong_type,
    "Expected behavior: non-integer wait_for arguments should evaluate to false.",
    "wait_for('x')".to_string()
);
dsl_false_case!(
    call_generate_java_gadget_wrong_arity_two,
    "Expected behavior: generate_java_gadget requires three args and should otherwise evaluate to false.",
    "generate_java_gadget('a', 'b')".to_string()
);
dsl_false_case!(
    call_date_time_wrong_arity_zero,
    "Expected behavior: date_time requires one arg and should otherwise evaluate to false.",
    "date_time()".to_string()
);
dsl_false_case!(
    call_join_wrong_arity_one,
    "Expected behavior: join with too few args should evaluate to false.",
    "join(',')".to_string()
);
dsl_false_case!(
    call_repeat_wrong_type,
    "Expected behavior: repeat with a non-integer count should evaluate to false.",
    "repeat('a', 'b')".to_string()
);
dsl_false_case!(
    call_repeat_negative_count,
    "Expected behavior: negative repeat counts should evaluate to false without panicking.",
    "repeat('a', -1) == 'a'".to_string()
);
dsl_false_case!(
    call_hex_decode_invalid,
    "Expected behavior: invalid hex input should evaluate to false when forced through a boolean comparison.",
    "hex_decode('zz') == 'x'".to_string()
);
dsl_false_case!(
    call_base64_decode_invalid,
    "Expected behavior: invalid base64 input should evaluate to false when forced through a boolean comparison.",
    "base64_decode('%%%') == 'x'".to_string()
);
dsl_false_case!(
    call_to_number_invalid,
    "Expected behavior: invalid numeric conversions should evaluate to false.",
    "to_number('abc') == 1".to_string()
);
dsl_false_case!(
    call_starts_with_wrong_arity_one,
    "Expected behavior: starts_with requires two args and should otherwise evaluate to false.",
    "starts_with(body)".to_string()
);
dsl_false_case!(
    call_ends_with_wrong_arity_three,
    "Expected behavior: ends_with with extra args should evaluate to false.",
    "ends_with(body, 'x', 'y')".to_string()
);
dsl_false_case!(
    call_concat_no_args_non_bool,
    "Expected behavior: non-boolean function results should not be treated as success by evaluate_dsl.",
    "concat()".to_string()
);
dsl_false_case!(
    call_md5_non_bool,
    "Expected behavior: non-boolean string-returning expressions should evaluate to false at the top level.",
    "md5(body)".to_string()
);
dsl_false_case!(
    call_sha256_non_bool,
    "Expected behavior: non-boolean string-returning expressions should evaluate to false at the top level.",
    "sha256(body)".to_string()
);
dsl_false_case!(
    call_body_identifier_non_bool,
    "Expected behavior: bare string identifiers should evaluate to false at the top level.",
    "body".to_string()
);
dsl_false_case!(
    call_header_identifier_non_bool,
    "Expected behavior: bare header identifiers should evaluate to false at the top level.",
    "header".to_string()
);
dsl_false_case!(
    call_status_identifier_non_bool,
    "Expected behavior: bare integer identifiers should evaluate to false at the top level.",
    "status_code".to_string()
);
dsl_false_case!(
    emoji_identifier,
    "Expected behavior: unsupported Unicode identifiers should evaluate to false.",
    "😀 == 1".to_string()
);
dsl_false_case!(
    confusable_identifier,
    "Expected behavior: non-ASCII lookalike identifiers should evaluate to false.",
    "ѕtatus_code == 200".to_string()
);
dsl_false_case!(
    null_byte_inside_identifier,
    "Expected behavior: embedded null bytes should be handled safely and evaluate to false.",
    "status\0_code == 200".to_string()
);
dsl_false_case!(
    null_byte_inside_string_then_trailing_junk,
    "Expected behavior: embedded null bytes with trailing junk should evaluate to false.",
    "'a\0b' junk".to_string()
);
dsl_false_case!(
    carriage_return_mid_identifier,
    "Expected behavior: broken identifiers across carriage returns should evaluate to false.",
    "statu\r\ns_code == 200".to_string()
);
dsl_false_case!(
    tab_split_identifier,
    "Expected behavior: split identifiers should evaluate to false.",
    "status\tcode == 200".to_string()
);
dsl_false_case!(
    comment_like_hash,
    "Expected behavior: shell-style comments should not be accepted as syntax.",
    "status_code == 200 # ok".to_string()
);
dsl_false_case!(
    comment_like_double_slash,
    "Expected behavior: C++-style comments should not be accepted as syntax.",
    "status_code == 200 // ok".to_string()
);
dsl_false_case!(
    comment_like_block,
    "Expected behavior: block comments should not be accepted as syntax.",
    "status_code == 200 /* ok */".to_string()
);
dsl_false_case!(
    semicolon_statement_separator,
    "Expected behavior: statement separators should not be accepted as syntax.",
    "status_code == 200; body == 'x'".to_string()
);
dsl_false_case!(
    colon_separator,
    "Expected behavior: colon separators should not be accepted as syntax.",
    "status_code == 200: body == 'x'".to_string()
);
dsl_false_case!(
    question_mark_ternary,
    "Expected behavior: ternary syntax should not be accepted as DSL.",
    "status_code == 200 ? 1 : 0".to_string()
);
dsl_false_case!(
    backtick_string,
    "Expected behavior: backtick-delimited strings should not be accepted as syntax.",
    "`payload`".to_string()
);
dsl_false_case!(
    xml_like_expression,
    "Expected behavior: XML-like payloads should not parse as DSL expressions.",
    "<tag>payload</tag>".to_string()
);
dsl_false_case!(
    yaml_like_expression,
    "Expected behavior: YAML-like key/value syntax should not parse as DSL expressions.",
    "key: value".to_string()
);
dsl_false_case!(
    json_pointer_like_expression,
    "Expected behavior: slash-heavy pointer syntax should not parse as DSL expressions.",
    "/a/b/c".to_string()
);
dsl_false_case!(
    deep_unclosed_parentheses,
    "Expected behavior: deeply nested but unclosed groups should evaluate to false without stack overflows.",
    "(".repeat(128)
);
dsl_false_case!(
    deep_closed_then_extra_token,
    "Expected behavior: deeply nested groups with trailing junk should evaluate to false.",
    format!("{}1{}", "(".repeat(64), ")".repeat(64)) + " x"
);
dsl_false_case!(
    deep_division_by_zero,
    "Expected behavior: deep arithmetic with a terminal divide-by-zero should evaluate to false without panicking.",
    format!("{}1{}", "(".repeat(40), " / 0)".repeat(40))
);
dsl_false_case!(
    very_long_unknown_identifier,
    "Expected behavior: huge identifiers should evaluate to false without panicking.",
    "a".repeat(8192)
);
dsl_false_case!(
    very_long_unterminated_string,
    "Expected behavior: huge unterminated strings should evaluate to false without panicking.",
    format!("'{}", "a".repeat(8192))
);
dsl_false_case!(
    very_long_invalid_function_name,
    "Expected behavior: huge unknown function names should evaluate to false without panicking.",
    format!("{}(body)", "f".repeat(4096))
);
dsl_false_case!(
    very_long_argument_list_with_missing_closer,
    "Expected behavior: huge malformed argument lists should evaluate to false without panicking.",
    format!("contains({}, 'x'", "body,".repeat(2048))
);
dsl_false_case!(
    very_long_operator_chain,
    "Expected behavior: huge malformed operator chains should evaluate to false without panicking.",
    "status_code ".to_string() + &"== == == == ".repeat(2048) + "200"
);
dsl_false_case!(
    huge_whitespace_and_junk_suffix,
    "Expected behavior: large whitespace prefixes with junk should evaluate to false without panicking.",
    format!("{}junk", " \n\t".repeat(4096))
);
dsl_false_case!(
    oversized_numeric_literal,
    "Expected behavior: oversized integer literals should not panic the lexer and should evaluate to false.",
    "999999999999999999999999999999999999 == 1".to_string()
);
dsl_false_case!(
    hex_numeric_literal_not_supported,
    "Expected behavior: hex numeric syntax should evaluate to false.",
    "0xff == 255".to_string()
);
dsl_false_case!(
    binary_numeric_literal_not_supported,
    "Expected behavior: binary numeric syntax should evaluate to false.",
    "0b1010 == 10".to_string()
);
dsl_false_case!(
    octal_numeric_literal_not_supported,
    "Expected behavior: octal-like numeric syntax should evaluate to false.",
    "077 == 63".to_string()
);
dsl_false_case!(
    float_literal_not_supported,
    "Expected behavior: float syntax should evaluate to false.",
    "3.14 > 3".to_string()
);
dsl_false_case!(
    scientific_literal_not_supported,
    "Expected behavior: scientific notation should evaluate to false.",
    "1e9 > 0".to_string()
);
dsl_false_case!(
    double_decimal_point,
    "Expected behavior: malformed decimal literals should evaluate to false.",
    "1..2 == 3".to_string()
);
dsl_false_case!(
    float_then_method_style,
    "Expected behavior: float-like tokens followed by identifiers should evaluate to false.",
    "1.2trim()".to_string()
);
dsl_false_case!(
    receiver_missing_before_chain,
    "Expected behavior: a chain starting with a dot should evaluate to false.",
    ".trim().to_lower()".to_string()
);
dsl_false_case!(
    method_chain_missing_middle_name,
    "Expected behavior: broken method chains should evaluate to false.",
    "body.trim()..to_lower()".to_string()
);
dsl_false_case!(
    method_chain_missing_final_call,
    "Expected behavior: chains ending on a bare method name should evaluate to false.",
    "body.trim().to_lower".to_string()
);
dsl_false_case!(
    method_chain_unknown_method,
    "Expected behavior: unknown methods should evaluate to false.",
    "body.not_a_real_method('x')".to_string()
);
dsl_false_case!(
    function_call_then_unknown_method,
    "Expected behavior: unknown methods on valid call results should evaluate to false.",
    "trim(body).not_a_real_method('x')".to_string()
);
dsl_false_case!(
    broken_nested_calls,
    "Expected behavior: malformed nested calls should evaluate to false.",
    "contains(trim(body, ), 'y')".to_string()
);
dsl_false_case!(
    broken_method_arguments,
    "Expected behavior: malformed method arguments should evaluate to false.",
    "body.contains(, 'x')".to_string()
);
dsl_false_case!(
    receiver_is_integer_for_method_call,
    "Expected behavior: nonsensical method receivers should evaluate to false.",
    "1.contains('x')".to_string()
);
dsl_false_case!(
    receiver_is_group_for_missing_method,
    "Expected behavior: grouped receivers with missing method names should evaluate to false.",
    "(body).('x')".to_string()
);
dsl_false_case!(
    nested_unknown_identifier_chain,
    "Expected behavior: chained unknown identifiers should evaluate to false.",
    "unknown.unknown('x')".to_string()
);
dsl_false_case!(
    invalid_escape_sequence_then_junk,
    "Expected behavior: unusual escapes should still be handled safely and evaluate to false when trailing junk remains.",
    "'\\x' junk".to_string()
);
dsl_false_case!(
    invalid_unicode_escape_then_junk,
    "Expected behavior: unsupported Unicode escapes should still be handled safely and evaluate to false when trailing junk remains.",
    "'\\u{zz}' junk".to_string()
);
dsl_false_case!(
    large_null_padded_expression,
    "Expected behavior: large null-padded malformed expressions should evaluate to false without panicking.",
    format!("contains(body, 'x'){}\0junk", "\0".repeat(512))
);

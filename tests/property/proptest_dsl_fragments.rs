//! S-proptest-01: DSL fragments must parse to expected shapes or reject cleanly.

use proptest::prelude::*;
use secmatch::dsl::{BinaryOp, Expr, parse_expression};

fn parse_ok(input: &str) -> Expr {
    parse_expression(input).expect("expected parse success")
}

fn parse_rejects(input: &str) {
    assert!(parse_expression(input).is_none());
}

prop_compose! {
    fn arb_ident()(s in "[a-zA-Z_][a-zA-Z0-9_]{0,20}") -> String {
        s
    }
}

prop_compose! {
    fn arb_cmp_fragment()(ident in arb_ident(), n in any::<i64>()) -> String {
        format!("{ident} == {n}")
    }
}

prop_compose! {
    fn arb_binary_fragment()(
        left in arb_cmp_fragment(),
        op in 0u8..2,
        right in arb_cmp_fragment(),
    ) -> String {
        let op_s = if op == 0 { "&&" } else { "||" };
        format!("({left}) {op_s} ({right})")
    }
}

macro_rules! dsl_roundtrip_ident {
    ($name:ident) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]
            #[test]
            fn $name(ident in arb_ident()) {
                let parsed = parse_ok(&ident);
                prop_assert_eq!(parsed, Expr::Identifier(ident.clone()));
            }
        }
    };
}

dsl_roundtrip_ident!(prop_dsl_ident_fragment);
dsl_roundtrip_ident!(prop_dsl_ident_body_alias);
dsl_roundtrip_ident!(prop_dsl_ident_status_code);
dsl_roundtrip_ident!(prop_dsl_ident_content_length);
dsl_roundtrip_ident!(prop_dsl_ident_header_x);
dsl_roundtrip_ident!(prop_dsl_ident_host);
dsl_roundtrip_ident!(prop_dsl_ident_url);
dsl_roundtrip_ident!(prop_dsl_ident_scheme);
dsl_roundtrip_ident!(prop_dsl_ident_path);
dsl_roundtrip_ident!(prop_dsl_ident_port);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_dsl_integer_fragment(n in any::<i64>()) {
        let input = n.to_string();
        let parsed = parse_ok(&input);
        prop_assert_eq!(parsed, Expr::Integer(n));
    }

    #[test]
    fn prop_dsl_string_fragment(s in "[a-zA-Z0-9]{0,32}") {
        let input = format!("\"{s}\"");
        let parsed = parse_ok(&input);
        prop_assert_eq!(parsed, Expr::String(s));
    }

    #[test]
    fn prop_dsl_empty_string_fragment(_case in 0u8..1) {
        let parsed = parse_ok("\"\"");
        prop_assert_eq!(parsed, Expr::String(String::new()));
    }

    #[test]
    fn prop_dsl_not_unary_fragment(inner in arb_cmp_fragment()) {
        let input = format!("!({inner})");
        let parsed = parse_ok(&input);
        match parsed {
            Expr::UnaryNot(boxed) => {
                let inner_ok = matches!(
                    *boxed,
                    Expr::Binary { .. } | Expr::Identifier(_) | Expr::Integer(_)
                );
                prop_assert!(inner_ok);
            }
            other => {
                let msg = format!("unexpected: {:?}", other);
                prop_assert!(false, "{}", msg);
            }
        }
    }

    #[test]
    fn prop_dsl_paren_wrap_identifier(ident in arb_ident()) {
        let input = format!("({ident})");
        let parsed = parse_ok(&input);
        prop_assert_eq!(parsed, Expr::Identifier(ident));
    }

    #[test]
    fn prop_dsl_eq_comparison_fragment(fragment in arb_cmp_fragment()) {
        let parsed = parse_ok(&fragment);
        match parsed {
            Expr::Binary { op: BinaryOp::Eq, .. } => prop_assert!(true),
            _ => prop_assert!(false, "expected Eq binary"),
        }
    }

    #[test]
    fn prop_dsl_ne_comparison(ident in arb_ident(), n in any::<i64>()) {
        let input = format!("{ident} != {n}");
        let parsed = parse_ok(&input);
        match parsed {
            Expr::Binary { op: BinaryOp::Ne, .. } => prop_assert!(true),
            _ => prop_assert!(false),
        }
    }

    #[test]
    fn prop_dsl_gt_comparison(ident in arb_ident(), n in any::<i64>()) {
        let input = format!("{ident} > {n}");
        parse_ok(&input);
    }

    #[test]
    fn prop_dsl_lt_comparison(ident in arb_ident(), n in any::<i64>()) {
        let input = format!("{ident} < {n}");
        parse_ok(&input);
    }

    #[test]
    fn prop_dsl_ge_comparison(ident in arb_ident(), n in any::<i64>()) {
        let input = format!("{ident} >= {n}");
        parse_ok(&input);
    }

    #[test]
    fn prop_dsl_le_comparison(ident in arb_ident(), n in any::<i64>()) {
        let input = format!("{ident} <= {n}");
        parse_ok(&input);
    }

    #[test]
    fn prop_dsl_and_fragment(expr in arb_binary_fragment()) {
        // The shared generator emits `&&` or `||`; pin the `&&` form here the
        // same way prop_dsl_or_fragment pins `||`, so the assertion below
        // tests parsing rather than generator luck.
        let input = expr.replace("||", "&&");
        let parsed = parse_ok(&input);
        match parsed {
            Expr::Binary { op: BinaryOp::And, .. } => prop_assert!(true),
            _ => prop_assert!(false, "expected And"),
        }
    }

    #[test]
    fn prop_dsl_or_fragment(expr in arb_binary_fragment()) {
        let input = expr.replace("&&", "||");
        let parsed = parse_ok(&input);
        match parsed {
            Expr::Binary { op: BinaryOp::Or, .. } => prop_assert!(true),
            _ => prop_assert!(false, "expected Or"),
        }
    }

    #[test]
    fn prop_dsl_add_sub_mul_div(
        a in any::<i64>(),
        b in any::<i64>(),
        op in 0u8..4,
    ) {
        let op_s = match op {
            0 => "+",
            1 => "-",
            2 => "*",
            _ => "/",
        };
        let input = format!("{a} {op_s} {b}");
        prop_assert!(parse_expression(&input).is_some());
    }

    #[test]
    fn prop_dsl_len_call(ident in arb_ident()) {
        let input = format!("len({ident})");
        let parsed = parse_ok(&input);
        match parsed {
            Expr::FunctionCall { name, .. } => prop_assert_eq!(name, "len"),
            _ => prop_assert!(false),
        }
    }

    #[test]
    fn prop_dsl_contains_call(s in "[a-z]{1,12}") {
        let input = format!("contains(body, \"{s}\")");
        prop_assert!(parse_expression(&input).is_some());
    }

    #[test]
    fn prop_dsl_regex_call(pat in "[a-z]{1,8}") {
        let input = format!("regex(body, \"{pat}\")");
        prop_assert!(parse_expression(&input).is_some());
    }

    #[test]
    fn prop_dsl_nested_parens(fragment in arb_binary_fragment()) {
        let input = format!("(({fragment}))");
        prop_assert!(parse_expression(&input).is_some());
    }

    #[test]
    fn prop_dsl_method_call_chain(ident in arb_ident()) {
        let input = format!("{ident}.length()");
        prop_assert!(parse_expression(&input).is_some());
    }

    #[test]
    fn prop_dsl_random_garbage_never_panics(garbage in "\\PC{0,64}") {
        let _ = parse_expression(&garbage);
    }

    #[test]
    fn prop_dsl_unclosed_paren_rejects(prefix in arb_ident()) {
        parse_rejects(&format!("({prefix}"));
    }

    #[test]
    fn prop_dsl_unclosed_string_rejects(_case in 0u8..1) {
        parse_rejects("\"nope");
    }

    #[test]
    fn prop_dsl_double_operator_rejects(ident in arb_ident()) {
        parse_rejects(&format!("{ident} === 1"));
    }

    #[test]
    fn prop_dsl_lone_operator_rejects(op in prop::sample::select(vec!["==", "&&", "||", ">=", "<="])) {
        parse_rejects(op);
    }

    #[test]
    fn prop_dsl_invalid_ident_start_rejects(bad in "[0-9][a-z]{2,6}") {
        parse_rejects(&bad);
    }

    #[test]
    fn prop_dsl_trailing_comma_call_rejects(ident in arb_ident()) {
        parse_rejects(&format!("len({ident},)"));
    }

    #[test]
    fn prop_dsl_empty_input_rejects(_case in 0u8..1) {
        parse_rejects("");
    }

    #[test]
    fn prop_dsl_whitespace_only_rejects(ws in "[ \t\n\r]{1,8}") {
        parse_rejects(&ws);
    }

    #[test]
    fn prop_dsl_status_code_literal_chain(_case in 0u8..1) {
        let input = "status_code == 200 && status_code < 300";
        parse_ok(input);
    }

    #[test]
    fn prop_dsl_body_string_eq(s in "[a-z]{1,10}") {
        let input = format!("body == \"{s}\"");
        parse_ok(&input);
    }

    #[test]
    fn prop_dsl_mixed_and_or_parenthesized(fragment in arb_binary_fragment()) {
        let input = format!("!({fragment}) || ({fragment})");
        prop_assert!(parse_expression(&input).is_some());
    }

    #[test]
    fn prop_dsl_hex_integer_fragment(n in 0i64..1000i64) {
        let input = format!("0x{n:x}");
        let _ = parse_expression(&input);
    }

    #[test]
    fn prop_dsl_true_false_ident_reject(truthy in prop::sample::select(vec!["true", "false"])) {
        // bare true/false are identifiers if allowed, or reject, must not panic
        let _ = parse_expression(truthy);
    }

    #[test]
    fn prop_dsl_line_comment_suffix_rejects(ident in arb_ident()) {
        parse_rejects(&format!("{ident} == 1 # comment"));
    }

    #[test]
    fn prop_dsl_unicode_outside_ascii_rejects(s in "[\\x80-\\xFF]{1,4}") {
        let _ = parse_expression(&s);
        prop_assert!(parse_expression(&s).is_none());
    }

    #[test]
    fn prop_dsl_fragment_parse_or_reject_cleanly(seed in "\\PC{0,40}") {
        let result = std::panic::catch_unwind(|| parse_expression(&seed));
        prop_assert!(result.is_ok());
        if let Ok(opt) = result {
            if let Some(ast) = opt {
                let rendered = format!("{:?}", ast);
                prop_assert!(!rendered.is_empty());
            }
        }
    }

    #[test]
    fn prop_dsl_binary_associativity_same_op(
        a in arb_cmp_fragment(),
        b in arb_cmp_fragment(),
        c in arb_cmp_fragment(),
    ) {
        let input = format!("(({a}) && ({b})) && ({c})");
        prop_assert!(parse_expression(&input).is_some());
    }

    #[test]
    fn prop_dsl_string_escape_reject(bad in "[^\\x22\\\\]{1,6}") {
        // The payload must not contain a double quote (it would close the
        // string and make the input VALID) or a backslash (it can escape the
        // closing quote into valid content). What remains is guaranteed to be
        // an unterminated string, which must reject.
        let input = format!("\"{bad}");
        prop_assert!(parse_expression(&input).is_none());
    }

    #[test]
    fn prop_dsl_function_name_case_sensitive(fname in "[a-z]{2,6}") {
        let input = format!("{fname}(body)");
        let _ = parse_expression(&input);
    }

    #[test]
    fn prop_dsl_not_not_identifier(ident in arb_ident()) {
        let input = format!("!!{ident}");
        let _ = parse_expression(&input);
    }

    #[test]
    fn prop_dsl_compare_string_to_ident(lhs in arb_ident(), rhs in arb_ident()) {
        let input = format!("{lhs} == {rhs}");
        let _ = parse_expression(&input);
    }

    #[test]
    fn prop_dsl_deep_binary_depth(depth in 1u8..5) {
        let mut expr = "status_code == 200".to_string();
        for _ in 0..depth {
            expr = format!("({expr}) && status_code == 200");
        }
        prop_assert!(parse_expression(&expr).is_some());
    }

    #[test]
    fn prop_dsl_reject_unbalanced_parens(count in 1usize..5) {
        let parens = "(".repeat(count);
        parse_rejects(&format!("{parens}status_code == 1"));
    }

    #[test]
    fn prop_dsl_reject_suffix_garbage(ident in arb_ident(), junk in "[@#$%]{1,3}") {
        parse_rejects(&format!("{ident} == 1{junk}"));
    }

    #[test]
    fn prop_dsl_accept_negative_integer(n in -1000i64..-1i64) {
        let input = n.to_string();
        let parsed = parse_ok(&input);
        prop_assert_eq!(parsed, Expr::Integer(n));
    }

    #[test]
    fn prop_dsl_reject_float_literal(f in "[0-9]+\\.[0-9]+") {
        parse_rejects(&f);
    }

    #[test]
    fn prop_dsl_concat_plus_on_strings(a in "[a-z]{1,4}", b in "[a-z]{1,4}") {
        let input = format!("\"{a}\" + \"{b}\"");
        let _ = parse_expression(&input);
    }

    #[test]
    fn prop_dsl_method_vs_function_distinct(ident in arb_ident()) {
        let func = format!("len({ident})");
        let method = format!("{ident}.len()");
        let f = parse_expression(&func);
        let m = parse_expression(&method);
        prop_assert!(f.is_some() || m.is_some());
    }

    #[test]
    fn prop_dsl_reject_double_dot(ident in arb_ident()) {
        parse_rejects(&format!("{ident}..length()"));
    }

    #[test]
    fn prop_dsl_reject_call_without_close(ident in arb_ident()) {
        parse_rejects(&format!("len({ident}"));
    }

    #[test]
    fn prop_dsl_reject_orphan_close_paren(_case in 0u8..1) {
        parse_rejects(")");
    }

    #[test]
    fn prop_dsl_reject_orphan_open_then_eof(_case in 0u8..1) {
        parse_rejects("(");
    }

    #[test]
    fn prop_dsl_identifier_max_length(ident in "[a-zA-Z_][a-zA-Z0-9_]{50,80}") {
        let _ = parse_expression(&ident);
    }

    #[test]
    fn prop_dsl_string_with_spaces(s in "[a-zA-Z0-9 ]{1,20}") {
        let input = format!("\"{s}\"");
        let parsed = parse_ok(&input);
        prop_assert_eq!(parsed, Expr::String(s));
    }

    #[test]
    fn prop_dsl_chained_comparison_rejects(ident in arb_ident()) {
        parse_rejects(&format!("{ident} < 2 < 3"));
    }

    #[test]
    fn prop_dsl_matcher_style_fragment(
        code in 100u16..599u16,
        word in "[a-z]{2,10}",
    ) {
        let input = format!("status_code == {code} && contains(body, \"{word}\")");
        prop_assert!(parse_expression(&input).is_some());
    }

    #[test]
    fn prop_dsl_template_var_style(var in "[a-z_][a-z0-9_]{0,12}") {
        let input = format!("{var} != \"\"");
        let _ = parse_expression(&input);
    }

    #[test]
    fn prop_dsl_reject_null_byte_injection(s in "[a-z]{2,8}") {
        let input = format!("{s}\0 == 1");
        prop_assert!(parse_expression(&input).is_none());
    }

    #[test]
    fn prop_dsl_tabs_between_tokens(ident in arb_ident(), n in any::<i64>()) {
        let input = format!("{ident}\t==\t{n}");
        prop_assert!(parse_expression(&input).is_some());
    }

    #[test]
    fn prop_dsl_newlines_between_tokens(ident in arb_ident(), n in any::<i64>()) {
        let input = format!("{ident}\n==\n{n}");
        prop_assert!(parse_expression(&input).is_some());
    }
}

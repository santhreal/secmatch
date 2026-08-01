use proptest::prelude::*;
use secmatch::dsl::{Expr, parse_expression};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn prop_parser_does_not_panic_on_random_strings(
        input in ".*"
    ) {
        // Just verify we don't panic on arbitrary garbage
        let _ = parse_expression(&input);
    }

    #[test]
    fn prop_parser_parses_valid_identifiers(
        ident in "[a-zA-Z_][a-zA-Z0-9_]*"
    ) {
        let result = parse_expression(&ident);
        assert!(result.is_some());

        if let Some(Expr::Identifier(name)) = result {
            assert_eq!(name, ident);
        } else {
            panic!("Expected identifier");
        }
    }

    #[test]
    fn prop_parser_parses_integers(
        val in any::<i64>()
    ) {
        let input = format!("{}", val);
        let result = parse_expression(&input);

        if let Some(Expr::Integer(v)) = result {
            assert_eq!(v, val);
        }
    }

    #[test]
    fn prop_parser_roundtrip_simple_strings(
        s in "[a-zA-Z0-9 ]*"
    ) {
        let input = format!("\"{}\"", s);
        let result = parse_expression(&input);

        assert!(result.is_some());
        if let Some(Expr::String(val)) = result {
            assert_eq!(val, s);
        } else {
            panic!("Expected string");
        }
    }
}

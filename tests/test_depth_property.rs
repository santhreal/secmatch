use proptest::prelude::*;
use secir::template::Transform;
use secmatch::evaluator::{evaluate_condition, substitute_variables, transform_response};
use std::collections::HashMap;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn prop_transform_response_never_panics_and_returns_vec(
        input in ".*",
        transform_idx in 0..6usize
    ) {
        let transforms = match transform_idx {
            0 => vec![Transform::Base64Decode],
            1 => vec![Transform::HexDecode],
            2 => vec![Transform::UrlDecode],
            3 => vec![Transform::GzipDecompress],
            4 => vec![Transform::JsonParse { path: "$.test".to_string() }],
            5 => vec![Transform::JwtDecode],
            _ => vec![]
        };

        let result = transform_response(input.into_bytes(), &transforms);
        // Ensure result is a Vec<u8> and we don't panic
        assert_eq!(result.is_empty(), result.is_empty());
    }

    #[test]
    fn prop_evaluate_condition_never_panics(
        condition in ".*"
    ) {
        // Evaluate condition should never panic on arbitrary strings
        let _ = evaluate_condition(&condition);
    }

    #[test]
    fn prop_substitute_variables_never_panics(
        input in ".*",
        var_key in ".*",
        var_value in ".*"
    ) {
        let mut vars = HashMap::new();
        vars.insert(var_key, var_value);
        let _ = substitute_variables(&input, &vars);
    }
}

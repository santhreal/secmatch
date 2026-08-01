use secmatch::evaluator::{evaluate_condition, substitute_variables};
use std::collections::HashMap;

#[test]
fn test_evaluate_condition_gap_no_spaces() {
    // Gap: Should be able to evaluate equality even if there are no spaces around `==`
    // Implementation currently looks for `" == "` exclusively.
    assert_eq!(
        evaluate_condition("\"foo\"==\"foo\""),
        true,
        "Should handle missing spaces in == operator"
    );
    assert_eq!(
        evaluate_condition("'foo'=='foo'"),
        true,
        "Should handle missing spaces in == operator"
    );
    assert_eq!(
        evaluate_condition("1==1"),
        true,
        "Should handle missing spaces in == operator"
    );
}

#[test]
fn test_evaluate_condition_gap_no_spaces_not_eq() {
    // Gap: Should be able to evaluate inequality even if there are no spaces around `!=`
    assert_eq!(
        evaluate_condition("\"foo\"!=\"bar\""),
        true,
        "Should handle missing spaces in != operator"
    );
    assert_eq!(
        evaluate_condition("1!=2"),
        true,
        "Should handle missing spaces in != operator"
    );
}

#[test]
fn test_substitute_variables_gap_missing_brackets() {
    let mut vars = HashMap::new();
    vars.insert("user".to_string(), "admin".to_string());

    let result = substitute_variables("Hello {user}", &vars);
    assert_eq!(
        result, "Hello {user}",
        "Should not replace variables missing double brackets"
    );
}

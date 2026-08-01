use secir::template::{MatchPart, MatcherCondition, MatcherDef, MatcherKind, Transform};
use secmatch::evaluator::{
    evaluate_condition, matcher_satisfied, substitute_variables, transform_response,
};
use std::collections::{HashMap, HashSet};

#[test]
fn test_evaluate_condition_basic_operators() {
    assert_eq!(evaluate_condition("1 == 1"), true);
    assert_eq!(evaluate_condition("1 != 2"), true);
    assert_eq!(evaluate_condition("1 == 2"), false);
    assert_eq!(evaluate_condition("\"abc\" contains \"b\""), true);
    assert_eq!(evaluate_condition("\"abc\" contains \"d\""), false);
    assert_eq!(evaluate_condition("not_empty"), true);
    assert_eq!(evaluate_condition(""), false);
}

#[test]
fn test_substitute_variables_basic() {
    let mut vars = HashMap::new();
    vars.insert("user".to_string(), "admin".to_string());
    vars.insert("id".to_string(), "1".to_string());

    let result = substitute_variables("Hello {{user}}, your id is {{id}}", &vars);
    assert_eq!(result, "Hello admin, your id is 1");
}

#[test]
fn test_transform_response_base64() {
    let input = b"aGVsbG8=".to_vec();
    let result = transform_response(input, &[Transform::Base64Decode]);
    assert_eq!(result, b"hello");
}

#[test]
fn test_transform_response_hex() {
    let input = b"68656c6c6f".to_vec();
    let result = transform_response(input, &[Transform::HexDecode]);
    assert_eq!(result, b"hello");
}

#[test]
fn test_transform_response_url() {
    let input = b"hello%20world".to_vec();
    let result = transform_response(input, &[Transform::UrlDecode]);
    assert_eq!(result, b"hello world");
}

#[test]
fn test_matcher_satisfied_and() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["a".to_string(), "b".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::And,
        internal: false,
    };

    let partial_set = HashSet::from([0usize]);
    let complete_set = HashSet::from([0usize, 1usize]);
    let partial: Option<&HashSet<usize>> = Some(&partial_set);
    let complete: Option<&HashSet<usize>> = Some(&complete_set);

    assert_eq!(matcher_satisfied(&matcher, partial), false);
    assert_eq!(matcher_satisfied(&matcher, complete), true);
}

#[test]
fn test_matcher_satisfied_or() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["a".to_string(), "b".to_string()],
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    };

    let empty_set = HashSet::new();
    let partial_set = HashSet::from([0usize]);
    let empty: Option<&HashSet<usize>> = Some(&empty_set);
    let partial: Option<&HashSet<usize>> = Some(&partial_set);

    assert_eq!(matcher_satisfied(&matcher, empty), false);
    assert_eq!(matcher_satisfied(&matcher, partial), true);
}

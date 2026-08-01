use secir::template::Transform;
use secmatch::evaluator::{evaluate_condition, substitute_variables, transform_response};
use std::collections::HashMap;

#[test]
fn test_substitute_variables_adversarial_null_bytes() {
    let mut vars = HashMap::new();
    vars.insert("inject\0".to_string(), "malicious\0".to_string());

    let result = substitute_variables("test {{\0}} and {{inject\0}}", &vars);
    assert_eq!(result, "test {{\0}} and malicious\0");
}

#[test]
fn test_substitute_variables_adversarial_huge() {
    let mut vars = HashMap::new();
    let huge_str = "A".repeat(1024 * 1024);
    vars.insert("huge".to_string(), huge_str.clone());

    let result = substitute_variables("test {{huge}}", &vars);
    assert_eq!(result, format!("test {}", huge_str));
}

#[test]
fn test_substitute_variables_adversarial_unicode() {
    let mut vars = HashMap::new();
    vars.insert("🚀".to_string(), "💥".to_string());

    let result = substitute_variables("test {{🚀}}", &vars);
    assert_eq!(result, "test 💥");
}

#[test]
fn test_transform_response_adversarial_huge() {
    let huge_str = "A".repeat(1024 * 1024);
    let result = transform_response(huge_str.into_bytes(), &[Transform::Base64Decode]);

    // As "A" is not a valid base64 with padding of this length, it won't decode and will just return the same
    // We mainly care that it doesn't panic
    assert!(result.len() > 0);
}

#[test]
fn test_transform_response_adversarial_null_bytes() {
    let input = b"\0\0\0\0".to_vec();
    let result = transform_response(input.clone(), &[Transform::HexDecode]);
    assert_eq!(result, input); // Doesn't decode because invalid hex length/format, returns input
}

#[test]
fn test_transform_response_adversarial_0xff() {
    let input = vec![0xff, 0xff, 0xff, 0xff];
    let result = transform_response(input.clone(), &[Transform::UrlDecode]);
    assert_eq!(result, input); // Returns input if it fails to decode lossy string
}

#[test]
fn test_evaluate_condition_adversarial() {
    assert_eq!(evaluate_condition("\0 == \0"), true);
    assert_eq!(evaluate_condition("\u{FFFD} == \u{FFFD}"), true);
    assert_eq!(evaluate_condition("A".repeat(1024 * 1024).as_str()), true); // not empty string returns true in fallback
}

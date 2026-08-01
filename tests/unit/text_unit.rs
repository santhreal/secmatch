use secir::template::{MatchPart, MatcherCondition, MatcherDef, MatcherKind, RequestDef};
use secmatch::text::request_matches_text;

fn create_request(matchers: Vec<MatcherDef>, condition: MatcherCondition) -> RequestDef {
    let mut req = RequestDef::default();
    req.matchers = matchers;
    req.matchers_condition = condition;
    req
}

#[test]
fn test_request_matches_text_empty_matchers() {
    let req = create_request(vec![], MatcherCondition::Or);
    assert!(!request_matches_text(&req, "any text"));
}

#[test]
fn test_request_matches_text_and_condition() {
    let m1 = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["alpha".to_string()],
        part: MatchPart::Body,
        condition: MatcherCondition::Or,
        negative: false,
        internal: false,
    };
    let m2 = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["beta".to_string()],
        part: MatchPart::Body,
        condition: MatcherCondition::Or,
        negative: false,
        internal: false,
    };

    let req = create_request(vec![m1, m2], MatcherCondition::And);

    // Both missing
    assert!(!request_matches_text(&req, "gamma"));
    // One present
    assert!(!request_matches_text(&req, "alpha gamma"));
    // Both present
    assert!(request_matches_text(&req, "alpha beta"));
}

#[test]
fn test_request_matches_text_or_condition() {
    let m1 = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["alpha".to_string()],
        part: MatchPart::Body,
        condition: MatcherCondition::Or,
        negative: false,
        internal: false,
    };
    let m2 = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["beta".to_string()],
        part: MatchPart::Body,
        condition: MatcherCondition::Or,
        negative: false,
        internal: false,
    };

    let req = create_request(vec![m1, m2], MatcherCondition::Or);

    // Both missing
    assert!(!request_matches_text(&req, "gamma"));
    // One present
    assert!(request_matches_text(&req, "alpha gamma"));
    // Both present
    assert!(request_matches_text(&req, "alpha beta"));
}

#[test]
fn test_request_matches_text_negative_matcher() {
    let m1 = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["alpha".to_string()],
        part: MatchPart::Body,
        condition: MatcherCondition::Or,
        negative: true, // Should NOT contain "alpha"
        internal: false,
    };

    let req = create_request(vec![m1], MatcherCondition::Or);

    // Does not contain alpha -> matches the negative condition
    assert!(request_matches_text(&req, "gamma"));
    // Contains alpha -> fails the negative condition
    assert!(!request_matches_text(&req, "alpha gamma"));
}

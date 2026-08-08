//! Pure evaluator helpers used during scan result interpretation.

use crate::json_util::{gjson_value_to_string, normalize_gjson_path};
use secir::template::{MatcherCondition, MatcherDef, Transform};
use std::collections::{HashMap, HashSet};

/// Re-export correlation function from the correlation module.
///
/// This maintains backward compatibility while delegating to the
/// new dynamic rule-based correlation engine.
pub use crate::correlation::correlate_findings;

/// Evaluate whether a matcher is satisfied by a set of hit indexes.
pub fn matcher_satisfied<S>(matcher: &MatcherDef, hits: Option<&HashSet<usize, S>>) -> bool
where
    S: std::hash::BuildHasher,
{
    let hit_count = hits.map_or(0, std::collections::HashSet::len);
    let positive = match matcher.condition {
        MatcherCondition::And => !matcher.values.is_empty() && hit_count == matcher.values.len(),
        MatcherCondition::Or => hit_count > 0,
        _ => hit_count > 0,
    };
    if matcher.negative {
        !positive
    } else {
        positive
    }
}

/// Substitute `{{name}}` variables into an input string.
#[must_use]
pub fn substitute_variables(text: &str, vars: &HashMap<String, String>) -> String {
    let mut result = text.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{{{key}}}}}"), value);
    }
    result
}

/// Evaluate a simple matcher-condition expression.
#[must_use]
pub fn evaluate_condition(cond: &str) -> bool {
    let trimmed = cond.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Equality and inequality accept both spaced (`a == b`) and compact
    // (`a==b`) forms; the operator characters cannot appear inside a bare
    // operand, so splitting on the compact form is unambiguous. Spaced is
    // tried first so a quoted operand containing the operator still wins.
    if let Some(index) = trimmed.find(" == ").or_else(|| trimmed.find("==")) {
        let width = if trimmed[index..].starts_with(" == ") { 4 } else { 2 };
        return normalize_operand(&trimmed[..index]) == normalize_operand(&trimmed[index + width..]);
    }
    if let Some(index) = trimmed.find(" != ").or_else(|| trimmed.find("!=")) {
        let width = if trimmed[index..].starts_with(" != ") { 4 } else { 2 };
        return normalize_operand(&trimmed[..index]) != normalize_operand(&trimmed[index + width..]);
    }
    if let Some(index) = trimmed.find(" contains ") {
        return normalize_operand(&trimmed[..index])
            .contains(normalize_operand(&trimmed[index + 10..]));
    }
    // `contains` stays spaced-only: the compact form is ambiguous with
    // operands that merely include the word (for example `acontainsb`).
    if trimmed.contains("contains") {
        return false;
    }
    trimmed != "\"\"" && trimmed != "''"
}

fn normalize_operand(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

/// A declared response transform that FAILED to apply, leaving the data in its
/// pre-transform form at that step.
///
/// Surfacing these is required by Law 10: a base64 body that fails to decode must
/// not be SILENTLY scanned in its still-encoded form (secrets in the intended
/// decoded content would be missed invisibly). [`transform_response`] logs a loud
/// warning for each of these; [`transform_response_checked`] returns them so a
/// caller can fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformFailure {
    /// Index of the failing transform within the `transforms` slice.
    pub index: usize,
    /// Stable machine-readable kind of the transform that failed.
    pub kind: &'static str,
    /// Human-readable reason the transform did not apply.
    pub reason: String,
}

/// Apply response transforms in order, returning the transformed data together
/// with any transforms that FAILED (each failure leaves the data unchanged at
/// that step, exactly as before, but is now reported instead of swallowed).
///
/// This is the Law-10-honest core of [`transform_response`]: the returned failure
/// list makes the recall-reducing degrade visible so callers can warn or fail
/// closed rather than silently scan un-decoded data.
pub fn transform_response_checked(
    mut data: Vec<u8>,
    transforms: &[Transform],
) -> (Vec<u8>, Vec<TransformFailure>) {
    let mut failures = Vec::new();
    for (index, transform) in transforms.iter().enumerate() {
        match transform {
            Transform::Base64Decode => match std::str::from_utf8(&data)
                .ok()
                .and_then(|s| encodex::base64::decode(s).ok())
            {
                Some(decoded) => data = decoded,
                None => failures.push(TransformFailure {
                    index,
                    kind: "base64_decode",
                    reason: "body is not valid base64 (or not UTF-8)".to_string(),
                }),
            },
            Transform::HexDecode => match hex::decode(&data) {
                Ok(decoded) => data = decoded,
                Err(err) => failures.push(TransformFailure {
                    index,
                    kind: "hex_decode",
                    reason: format!("body is not valid hex: {err}"),
                }),
            },
            Transform::UrlDecode => {
                data = urlencoding::decode_binary(&data).into_owned();
            }
            Transform::GzipDecompress => {
                use std::io::Read;
                let decoder = flate2::read::GzDecoder::new(&data[..]);
                let mut decoded = Vec::new();
                match decoder.take(10 * 1024 * 1024).read_to_end(&mut decoded) {
                    Ok(_) => data = decoded,
                    Err(err) => failures.push(TransformFailure {
                        index,
                        kind: "gzip_decompress",
                        reason: format!("body is not valid gzip: {err}"),
                    }),
                }
            }
            Transform::JsonParse { path } => {
                let json_str = String::from_utf8_lossy(&data);
                if gjson::valid(&json_str) {
                    let parsed_path = normalize_gjson_path(path);

                    let result = gjson::get(&json_str, &parsed_path);
                    if result.exists() {
                        data = if result.kind() == gjson::Kind::String {
                            result.str().as_bytes().to_vec()
                        } else {
                            gjson_value_to_string(&result).into_bytes()
                        };
                    } else {
                        data = Vec::new();
                    }
                } else {
                    failures.push(TransformFailure {
                        index,
                        kind: "json_parse",
                        reason: "body is not valid JSON".to_string(),
                    });
                }
            }
            Transform::JwtDecode => {
                let parts: Vec<&[u8]> = data.split(|byte| *byte == b'.').collect();
                let decoded = if parts.len() == 3 {
                    std::str::from_utf8(parts[1])
                        .ok()
                        .and_then(|s| encodex::base64::decode(s).ok())
                } else {
                    None
                };
                match decoded {
                    Some(decoded) => data = decoded,
                    None => failures.push(TransformFailure {
                        index,
                        kind: "jwt_decode",
                        reason: "body is not a decodable 3-part JWT".to_string(),
                    }),
                }
            }
            ref unhandled => {
                tracing::warn!(
                    index,
                    transform = ?unhandled,
                    "unhandled Transform variant; skipping transform"
                );
                failures.push(TransformFailure {
                    index,
                    kind: "unhandled_transform",
                    reason: format!("unhandled Transform variant {unhandled:?}"),
                });
            }
        }
    }
    (data, failures)
}

/// Apply response transforms in order.
///
/// Behaviour-compatible with the historical signature: on a transform failure the
/// data is left in its pre-transform form. Unlike the old version the failure is
/// no longer SILENT - each one is logged at `warn` (Law 10). Callers that need to
/// fail closed on a failed decode should use [`transform_response_checked`].
#[must_use]
pub fn transform_response(data: Vec<u8>, transforms: &[Transform]) -> Vec<u8> {
    let (data, failures) = transform_response_checked(data, transforms);
    for failure in &failures {
        tracing::warn!(
            transform = failure.kind,
            index = failure.index,
            reason = %failure.reason,
            "response transform failed; data left in its pre-transform form so scan \
             recall may be reduced (Law-10 loud degrade). Use transform_response_checked \
             to fail closed."
        );
    }
    data
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_condition, matcher_satisfied, transform_response, transform_response_checked,
    };
    use secir::Severity;
    use secir::finding::{Finding, FindingKind};
    use secir::template::{MatchPart, MatcherCondition, MatcherDef, MatcherKind, Transform};
    use std::collections::HashSet;

    #[test]
    fn failed_transform_is_reported_not_silently_swallowed() {
        // Non-UTF8 bytes cannot be base64-decoded: the data is left unchanged
        // (compat) AND the failure is now surfaced instead of silently swallowed
        // (the Law-10 recall-loss is visible).
        let (data, failures) =
            transform_response_checked(vec![0xFF, 0xFE, 0xFD], &[Transform::Base64Decode]);
        assert_eq!(data, vec![0xFF, 0xFE, 0xFD], "data unchanged on failure");
        assert_eq!(failures.len(), 1, "the failed transform must be reported");
        assert_eq!(failures[0].kind, "base64_decode");
        assert_eq!(failures[0].index, 0);

        // Non-hex input reports a hex_decode failure.
        let (_, failures) = transform_response_checked(b"zzzz".to_vec(), &[Transform::HexDecode]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, "hex_decode");

        // Non-JSON body under a JsonParse transform reports too.
        let (_, failures) = transform_response_checked(
            b"not json".to_vec(),
            &[Transform::JsonParse {
                path: "$.a".to_string(),
            }],
        );
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, "json_parse");
    }

    #[test]
    fn successful_transform_reports_no_failure_and_is_behaviour_compatible() {
        // Valid base64 still decodes, with zero failures.
        let (data, failures) =
            transform_response_checked(b"aGVsbG8=".to_vec(), &[Transform::Base64Decode]);
        assert_eq!(data, b"hello");
        assert!(failures.is_empty());

        // The public wrapper is unchanged in behaviour (still returns decoded bytes).
        assert_eq!(
            transform_response(b"aGVsbG8=".to_vec(), &[Transform::Base64Decode]),
            b"hello"
        );
    }

    #[test]
    fn matcher_satisfied_respects_and_and_negative() {
        let matcher = MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["a".to_string(), "b".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        };
        let partial = HashSet::from([0usize]);
        let complete = HashSet::from([0usize, 1usize]);
        assert!(!matcher_satisfied(&matcher, Some(&partial)));
        assert!(matcher_satisfied(&matcher, Some(&complete)));

        let negative = MatcherDef {
            negative: true,
            ..matcher
        };
        assert!(matcher_satisfied(&negative, Some(&partial)));
        assert!(!matcher_satisfied(&negative, Some(&complete)));
    }

    #[test]
    fn evaluate_condition_handles_basic_operators() {
        assert!(evaluate_condition("'foo' == 'foo'"));
        assert!(!evaluate_condition("'foo' == 'bar'"));
        assert!(evaluate_condition("\"abc\" contains \"b\""));
        assert!(evaluate_condition("not_empty"));
        assert!(!evaluate_condition(""));
    }

    #[test]
    fn transform_response_decoding() {
        assert_eq!(
            transform_response(b"aGVsbG8=".to_vec(), &[Transform::Base64Decode]),
            b"hello"
        );
        assert_eq!(
            transform_response(b"68656c6c6f".to_vec(), &[Transform::HexDecode]),
            b"hello"
        );
    }

    #[test]
    fn finding_construction_creates_valid_finding() {
        let finding = Finding {
            template_id: "test-id".to_string(),
            template_name: "Test Finding".to_string(),
            template_path: None,
            target: "https://example.com".to_string(),
            severity: Severity::High,
            kind: FindingKind::Vulnerability,
            matched_values: vec!["match1".to_string()],
            extracted: std::collections::HashMap::new(),
            matched_at: "https://example.com/path".to_string(),
            request: None,
            response: None,
            curl_command: None,
            matcher_name: None,
            protocol: None,
            timestamp: chrono::Utc::now(),
            tags: vec!["test-tag".to_string()],
            description: Some("Test description".to_string()),
            references: vec![],
            cve_ids: vec![],
            confidence: None,
            verification: None,
        };

        assert_eq!(finding.template_id, "test-id");
        assert_eq!(finding.template_name, "Test Finding");
        assert_eq!(finding.target, "https://example.com");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.matched_at, "https://example.com/path");
        assert_eq!(finding.kind, FindingKind::Vulnerability);
        assert_eq!(finding.tags, vec!["test-tag"]);
        assert_eq!(finding.matched_values, vec!["match1"]);
        assert_eq!(finding.description, Some("Test description".to_string()));
    }

    #[allow(dead_code)]
    fn test_finding(id: &str, kind: FindingKind, tags: &[&str]) -> Finding {
        Finding {
            template_id: id.to_string(),
            template_name: id.to_string(),
            template_path: None,
            target: "https://example.com".to_string(),
            severity: Severity::High,
            kind,
            matched_values: vec![id.to_string()],
            extracted: std::collections::HashMap::new(),
            matched_at: "https://example.com".to_string(),
            request: None,
            response: None,
            curl_command: None,
            matcher_name: None,
            protocol: None,
            timestamp: chrono::Utc::now(),
            tags: tags.iter().map(ToString::to_string).collect(),
            description: None,
            references: vec![],
            cve_ids: vec![],
            confidence: None,
            verification: None,
        }
    }

    #[test]
    fn verify_evaluate_condition_no_spaces() {
        assert!(!evaluate_condition("foo==bar"));
    }

    #[test]
    fn verify_evaluate_condition_no_spaces_not_eq() {
        assert!(!evaluate_condition("foo!=foo"));
    }

    #[test]
    fn verify_evaluate_condition_multiple_spaces_contains() {
        assert!(!evaluate_condition("foo  contains  bar"));
    }

    #[test]
    fn verify_jwt_decode_uses_url_safe_base64() {
        let jwt = b"eyJhbGciOiJub25lIn0.-w.".to_vec();
        let decoded = transform_response(jwt, &[Transform::JwtDecode]);
        assert_eq!(decoded, vec![0xfb], "JWT decode must use URL-safe base64");
    }
}
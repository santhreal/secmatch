//! Response data extraction using regex capture groups and key-value header lookups.
//!
//! Extractors pull named values out of HTTP responses for use in subsequent
//! requests (variable chaining) or for inclusion in scan findings.

use secir::matcher::{ResponseData, select_response_part};
use secir::template::{ExtractorDef, ExtractorKind};
use crate::json_util::{gjson_value_to_string, normalize_gjson_path};
use std::collections::HashMap;

/// Extracts user-facing values from a response, excluding internal extractors.
pub fn extract_from_response(
    response: &ResponseData,
    extractors: &[ExtractorDef],
) -> HashMap<String, String> {
    extract_impl(response, extractors, false)
}

/// Extracts all response variables, including internal extractors for later requests.
pub fn extract_variables_from_response(
    response: &ResponseData,
    extractors: &[ExtractorDef],
) -> HashMap<String, String> {
    extract_impl(response, extractors, true)
}

fn extract_impl(
    response: &ResponseData,
    extractors: &[ExtractorDef],
    include_internal: bool,
) -> HashMap<String, String> {
    let mut extracted = HashMap::new();

    for extractor in extractors {
        if extractor.internal && !include_internal {
            continue;
        }

        let Some(key) = extractor_key(extractor) else {
            continue;
        };

        match extractor.kind {
            ExtractorKind::Regex => {
                let haystack = select_response_part(response, &extractor.part);
                for pattern in &extractor.patterns {
                    let regex = match crate::dsl::cache::cached_regex(pattern) {
                        Ok(regex) => regex,
                        Err(error) => {
                            // Law-10: an invalid extractor pattern silently
                            // extracting nothing breaks variable chaining
                            // invisibly. Surface the compile failure loudly.
                            tracing::warn!(
                                extractor = %key,
                                pattern = %pattern,
                                %error,
                                "extractor regex failed to compile; skipping this pattern"
                            );
                            continue;
                        }
                    };

                    let Some(captures) = regex.captures(haystack) else {
                        continue;
                    };

                    let Some(value) = captures.get(extractor.group).map(|m| m.as_str()) else {
                        continue;
                    };

                    extracted.insert(key.clone(), value.to_string());
                    break;
                }
            }
            ExtractorKind::Kval => {
                for pattern in &extractor.patterns {
                    let Some(value) = response
                        .header_map
                        .iter()
                        .find(|(header, _)| header.eq_ignore_ascii_case(pattern))
                        .map(|(_, value)| value.clone())
                    else {
                        continue;
                    };

                    extracted.insert(key.clone(), value);
                    break;
                }
            }
            ExtractorKind::Json => {
                let haystack = select_response_part(response, &extractor.part);
                if !gjson::valid(haystack) {
                    continue;
                }

                for pattern in &extractor.patterns {
                    let path = normalize_gjson_path(pattern.trim());

                    let result = gjson::get(haystack, &path);
                    if !result.exists() {
                        continue;
                    }

                    let extracted_str = match result.kind() {
                        gjson::Kind::Array => {
                            let mut vals = Vec::new();
                            result.each(|_, value| {
                                vals.push(if value.kind() == gjson::Kind::String {
                                    value.str().to_string()
                                } else {
                                    gjson_value_to_string(&value)
                                });
                                true
                            });
                            vals.join("\n")
                        }
                        gjson::Kind::String => result.str().to_string(),
                        _ => gjson_value_to_string(&result),
                    };

                    extracted.insert(key.clone(), extracted_str);
                    break;
                }
            }
            _ => {}
        }
    }

    extracted
}

fn extractor_key(extractor: &ExtractorDef) -> Option<String> {
    extractor
        .name
        .clone()
        .or_else(|| extractor.patterns.first().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secir::template::MatchPart;

    fn sample_response() -> ResponseData {
        ResponseData::new(
            200,
            vec![
                ("Server".to_string(), "nginx/1.25.3".to_string()),
                ("X-Trace".to_string(), "trace-123".to_string()),
            ],
            b"version=2.4.6".to_vec(),
        )
    }

    #[test]
    fn extracts_regex_group_from_body() {
        let extracted = extract_from_response(
            &sample_response(),
            &[ExtractorDef {
                kind: ExtractorKind::Regex,
                patterns: vec![r"version=(\d+\.\d+\.\d+)".to_string()],
                name: Some("version".to_string()),
                part: MatchPart::Body,
                group: 1,
                internal: false,
            }],
        );

        assert_eq!(extracted.get("version"), Some(&"2.4.6".to_string()));
    }

    #[test]
    fn extracts_kval_header_case_insensitively() {
        let extracted = extract_from_response(
            &sample_response(),
            &[ExtractorDef {
                kind: ExtractorKind::Kval,
                patterns: vec!["server".to_string()],
                name: Some("server".to_string()),
                part: MatchPart::Header,
                group: 0,
                internal: false,
            }],
        );

        assert_eq!(extracted.get("server"), Some(&"nginx/1.25.3".to_string()));
    }

    #[test]
    fn skips_internal_and_invalid_extractors() {
        let extracted = extract_from_response(
            &sample_response(),
            &[
                ExtractorDef {
                    kind: ExtractorKind::Regex,
                    patterns: vec!["(".to_string()],
                    name: Some("broken".to_string()),
                    part: MatchPart::Body,
                    group: 0,
                    internal: false,
                },
                ExtractorDef {
                    kind: ExtractorKind::Regex,
                    patterns: vec![r"trace-(\d+)".to_string()],
                    name: Some("trace".to_string()),
                    part: MatchPart::Header,
                    group: 1,
                    internal: true,
                },
            ],
        );

        assert_eq!(
            extracted.len(),
            0,
            "extractor with regex for header should return no values when matching against body"
        );
    }

    #[test]
    fn extracts_json_path_from_body() {
        let response = ResponseData::new(
            200,
            vec![],
            b"{\"user\": {\"id\": 42, \"email\": \"admin@localhost\", \"roles\": [\"user\", \"admin\"]}}".to_vec(),
        );

        let extracted = extract_from_response(
            &response,
            &[ExtractorDef {
                kind: ExtractorKind::Json,
                patterns: vec!["user.email".to_string()],
                name: Some("email".to_string()),
                part: MatchPart::Body,
                group: 0,
                internal: false,
            }],
        );

        assert_eq!(
            extracted.get("email").map(|s| s.as_str()),
            Some("admin@localhost")
        );
    }

    #[test]
    fn extracts_json_array_from_body() {
        let response = ResponseData::new(
            200,
            vec![],
            b"{\"items\": [{\"name\": \"a\"}, {\"name\": \"b\"}]}".to_vec(),
        );

        let extracted = extract_from_response(
            &response,
            &[ExtractorDef {
                kind: ExtractorKind::Json,
                patterns: vec!["items.#.name".to_string()],
                name: Some("names".to_string()),
                part: MatchPart::Body,
                group: 0,
                internal: false,
            }],
        );

        // gjson array results are joined by newline in our extractor
        assert_eq!(extracted.get("names").map(|s| s.as_str()), Some("a\nb"));
    }
}

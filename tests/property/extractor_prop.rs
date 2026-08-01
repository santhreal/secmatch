use proptest::prelude::*;
use secir::matcher::ResponseData;
use secir::template::{ExtractorDef, ExtractorKind, MatchPart};
use secmatch::extractor::{extract_from_response, extract_variables_from_response};

fn mock_response(body: Vec<u8>, headers_str: Vec<(String, String)>) -> ResponseData {
    ResponseData::new(200, headers_str, body)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn prop_extractor_regex_does_not_panic(
        body in ".*",
        pattern in ".*",
        group in 0..10usize,
    ) {
        let response = mock_response(body.into_bytes(), vec![]);

        let extractor = ExtractorDef {
            name: Some("test_val".to_string()),
            kind: ExtractorKind::Regex,
            patterns: vec![pattern],
            group: group,
            part: MatchPart::Body,
            internal: false,
        };

        let _ = extract_from_response(&response, &[extractor]);
    }

    #[test]
    fn prop_extractor_kval_does_not_panic(
        header_key in "[a-zA-Z0-9_-]+",
        header_val in ".*",
        kval_key in ".*",
    ) {
        let response = mock_response(vec![], vec![(header_key, header_val)]);

        let extractor = ExtractorDef {
            name: Some("test_val".to_string()),
            kind: ExtractorKind::Kval,
            patterns: vec![kval_key.to_lowercase()],
            group: 0,
            part: MatchPart::Header,
            internal: false,
        };

        let _ = extract_from_response(&response, &[extractor]);
    }

    #[test]
    fn prop_extractor_json_does_not_panic(
        body in ".*",
        json_path in ".*",
    ) {
        let response = mock_response(body.into_bytes(), vec![]);

        let extractor = ExtractorDef {
            name: Some("test_val".to_string()),
            kind: ExtractorKind::Json,
            patterns: vec![json_path],
            group: 0,
            part: MatchPart::Body,
            internal: false,
        };

        let _ = extract_from_response(&response, &[extractor]);
    }

    #[test]
    fn prop_internal_extraction_respects_flag(
        internal_flag in any::<bool>(),
        body in ".*"
    ) {
        let response = mock_response(body.into_bytes(), vec![]);

        let extractor = ExtractorDef {
            name: Some("test_val".to_string()),
            kind: ExtractorKind::Regex,
            patterns: vec![".*".to_string()],
            group: 0,
            part: MatchPart::Body,
            internal: internal_flag,
        };

        let extracted_normal = extract_from_response(&response, &[extractor.clone()]);
        let extracted_all = extract_variables_from_response(&response, &[extractor.clone()]);

        if internal_flag {
            assert!(extracted_normal.is_empty());
            assert!(extracted_all.contains_key("test_val"));
        } else {
            assert!(extracted_normal.contains_key("test_val"));
            assert!(extracted_all.contains_key("test_val"));
        }
    }
}

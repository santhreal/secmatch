use secir::MatchDatabase;
use secir::matcher::ResponseData;
use secir::severity::Severity;
use secir::template::{
    MatchPart, MatcherCondition, MatcherDef, MatcherKind, RequestDef, Template, TemplateInfo,
    TemplateMeta,
};
use secmatch::database::CompiledDatabase;
use std::collections::HashMap;

fn create_test_template(id: &str, matchers: Vec<MatcherDef>) -> Template {
    Template {
        depends_on: vec![],
        id: id.to_string(),
        ir_version: 1,
        extends: None,
        imports: vec![],
        info: TemplateInfo {
            name: id.to_string(),
            author: vec!["test".to_string()],
            severity: Severity::Info,
            description: None,
            reference: vec![],
            tags: vec![],
            metadata: TemplateMeta::default(),
        },
        protocol: secir::template::Protocol::Http,
        self_contained: false,
        variables: HashMap::new(),
        cli_variables: HashMap::new(),
        source_path: None,
        flow: None,
        extensions: HashMap::new(),
        parallel_groups: vec![],
        exports: vec![],
        workflows: vec![],
        requests: vec![RequestDef {
            call: None,
            compute: vec![],
            method: "GET".to_string(),
            raw: None,
            paths: vec!["{{BaseURL}}".to_string()],
            headers: HashMap::new(),
            body: None,
            port: None,
            inputs: vec![],
            payloads: HashMap::new(),
            attack: secir::AttackType::BatteringRam,
            matchers,
            matchers_condition: MatcherCondition::Or,
            extractors: vec![],
            redirects: true,
            max_redirects: 10,
            stop_at_first_match: false,
            encoding: None,
            differential: false,
            max_response_time_ms: None,
            cookie_reuse: false,
            condition: None,
            iterate: None,
            transforms: vec![],
            label: None,
            goto: None,
            headless_actions: vec![],
        }],
    }
}

#[test]
fn test_adversarial_memory_exhaustion_huge_payload() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: vec!["trigger_word".to_string()],
        part: MatchPart::Body,
        condition: MatcherCondition::Or,
        negative: false,
        internal: false,
    };

    let template = create_test_template("memory_exhaustion_test", vec![matcher]);
    let db = CompiledDatabase::compile(&[template]).expect("Failed to compile database");

    // Construct a 50MB payload
    let mut huge_body = vec![b'A'; 50 * 1024 * 1024];
    // Put trigger word near the very end to ensure it evaluates the entire payload
    huge_body.extend_from_slice(b"trigger_word");

    let response = ResponseData::new(200, vec![], huge_body);

    // This should not OOM or panic
    let matches = db.scan(&response).unwrap();

    assert_eq!(
        matches.len(),
        1,
        "Should find exactly 1 match in huge payload"
    );
}

#[test]
fn test_adversarial_catastrophic_regex_payload() {
    // A catastrophic backtracking regex usually looks like (a+)+$
    // We want to ensure PCRE matching doesn't hang indefinitely or panic
    // though rust's `regex` crate is linear time, but let's test it heavily
    let matcher = MatcherDef {
        kind: MatcherKind::Regex,
        values: vec!["(a+)+$".to_string()],
        part: MatchPart::Body,
        condition: MatcherCondition::Or,
        negative: false,
        internal: false,
    };

    let template = create_test_template("catastrophic_regex_test", vec![matcher]);
    let db = CompiledDatabase::compile(&[template]).expect("Failed to compile database");

    // 1MB string of 'a's followed by a 'b', which will cause backtracking in engines that aren't linear
    let mut huge_body = vec![b'a'; 1024 * 1024];
    huge_body.push(b'b');

    let response = ResponseData::new(200, vec![], huge_body);

    let matches = db.scan(&response).unwrap();

    assert_eq!(
        matches.len(),
        0,
        "Should gracefully fail to match without hanging"
    );
}

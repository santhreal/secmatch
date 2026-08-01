use secir::MatchDatabase;
use secir::Severity;
use secir::matcher::ResponseData;
use secir::template::{
    MatchPart, MatcherCondition, MatcherDef, MatcherKind, RequestDef, Template, TemplateInfo,
    TemplateMeta,
};
use secmatch::database::CompiledDatabase;
use std::collections::HashMap;
use std::sync::{Arc, Barrier};
use std::thread;

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
fn test_concurrent_scan_load() {
    let mut templates = Vec::new();
    for i in 0..100 {
        let matcher = MatcherDef {
            kind: MatcherKind::Word,
            values: vec![format!("secret_pattern_{}", i)],
            part: MatchPart::Body,
            condition: MatcherCondition::Or,
            negative: false,
            internal: false,
        };
        templates.push(create_test_template(
            &format!("template_{}", i),
            vec![matcher],
        ));
    }

    let db = Arc::new(CompiledDatabase::compile(&templates).expect("Compilation failed"));
    let thread_count = 50;
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();

    for i in 0..thread_count {
        let db_clone = Arc::clone(&db);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Wait for all threads to be ready
            barrier_clone.wait();

            // Create a custom response for this thread
            let body = format!(
                "This response contains secret_pattern_{} hidden inside",
                i % 100
            )
            .into_bytes();
            let response = ResponseData::new(200, vec![], body);

            // Perform 1000 scans
            for _ in 0..1000 {
                let matches = db_clone.scan(&response).unwrap();
                assert!(!matches.is_empty(), "Thread {} failed to find match", i);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

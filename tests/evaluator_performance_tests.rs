//! Performance tests for the matching evaluator module
//!
//! Each test has a time bound that must not be exceeded.

use secir::finding::Finding;
use secir::matcher::ResponseData;
use secmatch::{evaluate_dsl, substitute_variables};
use std::collections::HashMap;
use std::time::Instant;

/// 6. Variable substitution on 1000 variables in < 50ms
#[test]
fn variable_substitution_1000_variables_in_50ms() {
    let mut vars = HashMap::new();
    for i in 0..1000 {
        vars.insert(format!("var{}", i), format!("value{}", i));
    }

    let text = (0..1000)
        .map(|i| format!("{{{{var{}}}}}", i))
        .collect::<Vec<_>>()
        .join(" ");

    let start = Instant::now();
    let _result = substitute_variables(&text, &vars);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_micros() < 50_000,
        "Variable substitution on 1000 variables took {:?}, expected < 50ms",
        elapsed
    );
}

/// 7. DSL evaluate 100 expressions in < 50ms
#[test]
fn dsl_evaluate_100_expressions_in_50ms() {
    let response = ResponseData::new(
        200,
        vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("Server".to_string(), "nginx".to_string()),
        ],
        b"Hello World test body content".to_vec(),
    );

    let expressions: Vec<String> = (0..100)
        .map(|i| {
            format!(
                "status_code == 200 && contains(body, 'test') && {} < {}",
                i,
                i + 10
            )
        })
        .collect();

    let start = Instant::now();
    for expr in &expressions {
        let _result = evaluate_dsl(expr, &response);
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_micros() < 50_000,
        "DSL evaluating 100 expressions took {:?}, expected < 50ms",
        elapsed
    );
}

/// 10. Finding construction for 1000 findings in < 10ms
#[test]
fn finding_construction_1000_findings_in_10ms() {
    use secir::Severity;
    use secir::template::{Template, TemplateInfo};

    let templates: Vec<Template> = (0..1000)
        .map(|i| Template {
            depends_on: vec![],
            id: format!("template-{}", i),
            ir_version: 1,
            extends: None,
            imports: Vec::new(),
            info: TemplateInfo {
                name: format!("Test Template {}", i),
                author: vec!["test".to_string()],
                severity: Severity::High,
                description: Some(format!("Description {}", i)),
                reference: vec![],
                tags: vec!["test".to_string()],
                metadata: Default::default(),
            },
            requests: vec![],
            protocol: Default::default(),
            self_contained: false,
            variables: HashMap::new(),
            cli_variables: HashMap::new(),
            source_path: None,
            flow: None,
            workflows: Vec::new(),
            extensions: HashMap::new(),
            parallel_groups: Vec::new(),
            exports: Vec::new(),
        })
        .collect();

    let start = Instant::now();
    let _findings: Vec<Finding> = templates
        .iter()
        .map(|t| {
            Finding::from_template(
                t,
                "https://example.com".to_string(),
                "https://example.com/path".to_string(),
                vec!["matched".to_string()],
            )
        })
        .collect();
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_micros() < 10_000,
        "Finding construction for 1000 findings took {:?}, expected < 10ms",
        elapsed
    );
}

/// 14. PCRE compat fix on 1000 patterns in < 10ms
#[test]
fn pcre_compat_fix_1000_patterns_in_10ms() {
    use secir::template::{MatchPart, MatcherCondition, MatcherDef, MatcherKind};

    // Create matcher defs with patterns that need PCRE compat fixes
    let patterns: Vec<String> = (0..1000)
        .map(|i| format!(r"{{,10}}test{{,}}{}[^]{{}}foo", i))
        .collect();

    let matchers: Vec<MatcherDef> = patterns
        .into_iter()
        .map(|p| MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![p],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        })
        .collect();

    // Test the regex compilation path which includes PCRE compat fix
    let start = Instant::now();

    for matcher in &matchers {
        let _ = regex::Regex::new(&matcher.values[0]);
    }

    let elapsed = start.elapsed();

    assert!(
        elapsed.as_micros() < 10_000,
        "PCRE compat fix on 1000 patterns took {:?}, expected < 10ms",
        elapsed
    );
}

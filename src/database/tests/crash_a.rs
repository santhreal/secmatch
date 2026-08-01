use super::*;

#[test]
fn compile_never_panics_for_random_template_counts() {
    let mut rng = StdRng::seed_from_u64(0xC0DEC0DE);

    for iteration in 0..PROPERTY_TEST_ITERATIONS {
        let template_count = rng.gen_range(0..=24);
        let templates = (0..template_count)
            .map(|index| random_template(&mut rng, &format!("compile-{iteration}-{index}"), true))
            .collect::<Vec<_>>();

        let result = catch_unwind(AssertUnwindSafe(|| CompiledDatabase::compile(&templates)));
        assert!(
            result.is_ok(),
            "compile panicked on iteration {iteration} with {template_count} templates: {}",
            panic_message(result.err().unwrap())
        );
    }
}

#[test]
fn scan_never_panics_for_random_templates_and_responses() {
    let mut rng = StdRng::seed_from_u64(0x5CA1_BEEF);

    for iteration in 0..PROPERTY_TEST_ITERATIONS {
        let template_count = rng.gen_range(0..=12);
        let templates = (0..template_count)
            .map(|index| random_template(&mut rng, &format!("scan-{iteration}-{index}"), false))
            .collect::<Vec<_>>();
        let db = CompiledDatabase::compile(&templates)
            .expect("safe random templates should compile without error");
        let response = random_response(&mut rng);

        let result = catch_unwind(AssertUnwindSafe(|| db.scan(&response).unwrap()));
        assert!(
            result.is_ok(),
            "scan panicked on iteration {iteration} with {template_count} templates: {}",
            panic_message(result.err().unwrap())
        );
    }
}

#[test]
fn word_matches_are_emitted_per_value() {
    let template = make_template_with_matchers(
        "multi-word",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string(), "php".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        }],
    );
    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], b"nginx php".to_vec());

    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].value_index, 0);
    assert_eq!(matches[1].value_index, 1);
}

#[test]
fn named_header_word_only_matches_target_header() {
    let template = make_template_with_matchers(
        "server-only",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string()],
            part: MatchPart::Named("Server".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );
    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(
        200,
        vec![
            ("X-Server".to_string(), "nginx".to_string()),
            ("Server".to_string(), "apache".to_string()),
        ],
        b"ok".to_vec(),
    );

    assert_eq!(
        db.scan(&response).unwrap().len(),
        0,
        "response with no matching headers should produce no matches"
    );
}

#[test]
fn named_header_regex_uses_selected_header_value() {
    let template = make_template_with_matchers(
        "etag",
        vec![MatcherDef {
            kind: MatcherKind::Regex,
            values: vec![r#"^[A-Z]{3}-\d+$"#.to_string()],
            part: MatchPart::Named("X-Trace".to_string()),
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );
    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(
        200,
        vec![("X-Trace".to_string(), "ABC-123".to_string())],
        b"ok".to_vec(),
    );

    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "ABC-123");
}

#[test]
fn dsl_matches_are_emitted_per_expression() {
    let template = make_template_with_matchers(
        "dsl",
        vec![MatcherDef {
            kind: MatcherKind::Dsl,
            values: vec![
                "status_code == 200".to_string(),
                r#"contains(body, "nginx")"#.to_string(),
            ],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::And,
            internal: false,
        }],
    );
    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], b"nginx".to_vec());

    let matches = db.scan(&response).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn compile_empty_templates() {
    let db = CompiledDatabase::compile(&[]).expect("operation should succeed");
    assert_eq!(db.pattern_count(), 0);
    assert_eq!(db.template_count(), 0);
}

#[test]
fn compile_empty_templates_returns_empty_database() {
    let db = CompiledDatabase::compile(&[]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], b"ok".to_vec());

    assert_eq!(db.pattern_count(), 0);
    assert_eq!(db.template_count(), 0);
    assert_eq!(
        db.scan(&response).unwrap().len(),
        0,
        "empty database should produce no matches for any response"
    );
}

#[test]
fn status_matcher_matches_correct_code() {
    let template = make_template_with_matchers(
        "status",
        vec![MatcherDef {
            kind: MatcherKind::Status,
            values: vec!["404".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );
    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");

    assert_eq!(
        db.scan(&ResponseData::new(404, vec![], b"missing".to_vec()))
            .unwrap()
            .len(),
        1
    );
    assert!(
        db.scan(&ResponseData::new(200, vec![], b"ok".to_vec()))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn word_matcher_is_case_insensitive() {
    let template = make_template_with_matchers(
        "word-case",
        vec![MatcherDef {
            kind: MatcherKind::Word,
            values: vec!["nginx".to_string()],
            part: MatchPart::Body,
            negative: false,
            condition: MatcherCondition::Or,
            internal: false,
        }],
    );
    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let matches = db
        .scan(&ResponseData::new(200, vec![], b"Server: NGINX".to_vec()))
        .unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "nginx");
}

#[test]
fn byte_regex_scans_non_utf8_body_alongside_binary_matchers() {
    // A non-UTF-8 body must NOT abort the regex set scan. `regex_set_scan` uses a
    // byte-oriented RegexSet, so the `PNG` regex matches the ASCII bytes inside
    // the raw body AND the binary matcher matches the PNG magic: both fire.
    // The old code gated on `from_utf8` and silently skipped the ENTIRE regex
    // set on any non-UTF-8 segment, an invisible recall loss (Law-10). This
    // test guards against that regression: no skip, no skip-log.
    let template = make_template_with_matchers(
        "binary-and-regex",
        vec![
            MatcherDef {
                kind: MatcherKind::Regex,
                values: vec![r"PNG".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
            MatcherDef {
                kind: MatcherKind::Binary,
                values: vec!["89504E47".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            },
        ],
    );
    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], vec![0x89, b'P', b'N', b'G', 0x0d])
        .with_url("https://example.com/binary");
    let output = SharedWriter::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(output.clone())
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
    );

    let matches = tracing::subscriber::with_default(subscriber, || db.scan(&response).unwrap());

    // Both matchers fire on the non-UTF-8 body: byte-regex `PNG` and binary magic.
    assert_eq!(
        matches.len(),
        2,
        "byte-regex must scan the non-UTF-8 body instead of skipping it: {matches:?}"
    );
    assert!(
        matches.iter().any(|m| m.matcher.kind == MatcherKind::Regex),
        "regex matcher must fire on the byte body"
    );
    assert!(
        matches.iter().any(|m| m.matcher.kind == MatcherKind::Binary),
        "binary matcher must fire"
    );
    let logs = output.display_string();
    assert!(
        !logs.contains("skipping regex set scan"),
        "the recall-losing non-UTF-8 regex skip must not happen: {logs}"
    );
}

#[test]
fn aho_corasick_builder_falls_back_to_nfa_when_dfa_build_fails() {
    let patterns = vec!["nginx".to_string(), "apache".to_string()];
    let automaton = CompiledDatabase::build_word_automaton_with(
        || Err("forced dfa failure"),
        || {
            let mut builder = AhoCorasick::builder();
            builder
                .ascii_case_insensitive(true)
                .kind(Some(AhoCorasickKind::ContiguousNFA));
            builder.build(&patterns)
        },
    )
    .expect("operation should succeed");

    assert_eq!(automaton.kind(), AhoCorasickKind::ContiguousNFA);
    assert_eq!(
        automaton
            .find("Apache")
            .expect("operation should succeed")
            .start(),
        0
    );
}

#[test]
fn compile_database_with_1000_word_patterns() {
    let matcher = MatcherDef {
        kind: MatcherKind::Word,
        values: (0..1000).map(|i| format!("pattern-{i:04}")).collect(),
        part: MatchPart::Body,
        negative: false,
        condition: MatcherCondition::Or,
        internal: false,
    };
    let template = make_template_with_matchers("large-word-db", vec![matcher]);

    let db = CompiledDatabase::compile(&[template]).expect("operation should succeed");
    let response = ResponseData::new(200, vec![], b"pattern-0999".to_vec());
    let matches = db.scan(&response).unwrap();

    assert_eq!(db.pattern_count(), 1000);
    assert_eq!(db.template_count(), 1);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_value, "pattern-0999");
    assert_eq!(matches[0].value_index, 999);
}

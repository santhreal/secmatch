use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use secir::{
    MatchDatabase, MatchPart, MatcherCondition, MatcherDef, MatcherKind, Protocol, RequestDef,
    ResponseData, Severity, Template, TemplateInfo, TemplateMeta,
};
use secmatch::CompiledDatabase;
use std::collections::HashMap;

const STACKS: &[(&str, &str, &str)] = &[
    ("nginx", "php", "wordpress"),
    ("apache", "tomcat", "jsp"),
    ("iis", "asp.net", "mssql"),
    ("cloudflare", "rails", "puma"),
    ("caddy", "laravel", "redis"),
    ("haproxy", "node.js", "express"),
    ("openresty", "lua", "kong"),
    ("envoy", "grpc", "istio"),
    ("varnish", "drupal", "memcached"),
    ("traefik", "grafana", "prometheus"),
];

fn build_template(id: &str, matchers: Vec<MatcherDef>) -> Template {
    Template {
        ir_version: 1,
        id: id.to_string(),
        extends: None,
        imports: Vec::new(),
        parallel_groups: Vec::new(),
        exports: Vec::new(),
        info: TemplateInfo {
            name: format!("Technology fingerprint for {id}"),
            author: vec!["benchmark".to_string()],
            severity: Severity::Info,
            description: Some("Synthetic but realistic benchmark template".to_string()),
            reference: vec![],
            tags: vec!["tech".to_string(), "benchmark".to_string()],
            metadata: TemplateMeta::default(),
        },
        protocol: Protocol::Http,
        requests: vec![RequestDef {
            call: None,
            compute: vec![],
            condition: None,
            goto: None,
            headless_actions: Vec::new(),
            iterate: None,
            label: None,
            transforms: Vec::new(),
            method: "GET".to_string(),
            raw: None,
            paths: vec!["{{BaseURL}}/".to_string()],
            headers: HashMap::new(),
            body: None,
            port: None,
            inputs: Vec::new(),
            payloads: HashMap::new(),
            attack: secir::AttackType::BatteringRam,
            matchers,
            matchers_condition: MatcherCondition::And,
            extractors: Vec::new(),
            redirects: true,
            max_redirects: 10,
            stop_at_first_match: false,
            encoding: None,
            differential: false,
            max_response_time_ms: None,
            cookie_reuse: false,
        }],
        self_contained: false,
        variables: HashMap::new(),
        cli_variables: HashMap::new(),
        source_path: None,
        flow: None,
        depends_on: Vec::new(),
        workflows: Vec::new(),
        extensions: HashMap::new(),
    }
}

fn generate_templates(count: usize) -> Vec<Template> {
    (0..count)
        .map(|i| {
            let a = STACKS[i % STACKS.len()];
            let b = STACKS[(i + 3) % STACKS.len()];
            let c = STACKS[(i + 6) % STACKS.len()];

            build_template(
                &format!("stack-{i:04}"),
                vec![
                    MatcherDef {
                        kind: MatcherKind::Word,
                        values: vec![a.0.to_string()],
                        part: MatchPart::Header,
                        negative: false,
                        condition: MatcherCondition::Or,
                        internal: false,
                    },
                    MatcherDef {
                        kind: MatcherKind::Word,
                        values: vec![format!("{}-marker-{i:04}", b.1)],
                        part: MatchPart::Body,
                        negative: false,
                        condition: MatcherCondition::Or,
                        internal: false,
                    },
                    MatcherDef {
                        kind: MatcherKind::Word,
                        values: vec![format!("{}-asset-{i:04}", c.2)],
                        part: MatchPart::All,
                        negative: false,
                        condition: MatcherCondition::Or,
                        internal: false,
                    },
                ],
            )
        })
        .collect()
}

fn generate_regex_templates(count: usize) -> Vec<Template> {
    (0..count)
        .map(|i| {
            let stack = STACKS[i % STACKS.len()];
            build_template(
                &format!("regex-stack-{i:04}"),
                vec![MatcherDef {
                    kind: MatcherKind::Regex,
                    values: vec![format!(
                        r#"{}\s+[0-9]+\.[0-9]+|{}-marker-{:04}|{}-asset-{:04}"#,
                        regex::escape(stack.0),
                        regex::escape(stack.1),
                        i,
                        regex::escape(stack.2),
                        i
                    )],
                    part: MatchPart::All,
                    negative: false,
                    condition: MatcherCondition::Or,
                    internal: false,
                }],
            )
        })
        .collect()
}

fn generate_response(size_bytes: usize) -> ResponseData {
    let headers = vec![
        (
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        ),
        ("Server".to_string(), "nginx 1.25.3".to_string()),
        ("X-Powered-By".to_string(), "php-marker-0001".to_string()),
        ("X-Generator".to_string(), "wordpress 6.6".to_string()),
        (
            "Cache-Control".to_string(),
            "public, max-age=600".to_string(),
        ),
        ("X-Frame-Options".to_string(), "SAMEORIGIN".to_string()),
    ];

    let mut body = String::from(
        "<!doctype html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"generator\" content=\"wordpress 6.6\">\n\
         <title>Karyx Benchmark Portal</title>\n\
         <link rel=\"stylesheet\" href=\"/static/css/site.css\">\n\
         <script src=\"/static/js/app.js\"></script>\n\
         </head>\n\
         <body>\n\
         <header>\n\
         <nav>Products Pricing Docs Status Login</nav>\n\
         </header>\n\
         <main>\n\
         <section class=\"hero\">Fast HTTP scanning for modern stacks.</section>\n\
         <section id=\"tech-markers\">nginx php-marker-0001 wordpress-asset-0002</section>\n",
    );

    let snippets = [
        "<article><h2>Release notes</h2><p>Apache reverse proxy fallback enabled for legacy endpoints.</p></article>\n",
        "<article><h2>Integration</h2><p>Rails services emit JSON into Envoy with grpc backends and Prometheus metrics.</p></article>\n",
        "<article><h2>Support</h2><p>Caddy, HAProxy, Varnish, and Traefik examples are available in the admin guide.</p></article>\n",
        "<article><h2>Telemetry</h2><p>node.js-marker-0005 dashboards feed grafana-asset-0009 for the operations team.</p></article>\n",
        "<article><h2>Footer</h2><p>Static assets, marketing copy, and unrelated lorem ipsum reduce match density.</p></article>\n",
    ];

    let mut idx = 0;
    while body.len() < size_bytes {
        body.push_str(snippets[idx % snippets.len()]);
        idx += 1;
    }

    body.push_str("</main><footer>Generated for benchmark coverage.</footer></body></html>\n");
    body.truncate(size_bytes);

    ResponseData::new(200, headers, body.into_bytes()).with_url("https://bench.karyx.local/")
}

fn compile_bench(c: &mut Criterion, templates: usize) {
    let templates_list = generate_templates(templates);
    c.bench_function(
        &format!("compile_{templates}_templates"),
        |b: &mut criterion::Bencher| {
            b.iter(|| {
                black_box(CompiledDatabase::compile(&templates_list.clone()).unwrap());
            });
        },
    );

    // We don't want to include compilation time in the scan benchmark
    let db = CompiledDatabase::compile(&templates_list).unwrap();

    let mut group = c.benchmark_group("scanning_workload");

    group.bench_function(
        format!("scan_against_{templates}_patterns"),
        |b: &mut criterion::Bencher| {
            b.iter(|| {
                let response =
                    ResponseData::new(200, vec![], b"password=admin&username=admin".to_vec());
                let _ = black_box(db.scan(black_box(&response)).expect("scan"));
            });
        },
    );
    group.finish();
}

fn scan_bench(c: &mut Criterion, templates: usize) {
    let data = generate_templates(templates);
    let compiled = CompiledDatabase::compile(&data).unwrap();
    let response = generate_response(4 * 1024);

    c.bench_function(&format!("scan_against_{templates}_patterns"), |b| {
        b.iter(|| {
            let matches = black_box(&compiled)
                .scan(black_box(&response))
                .expect("scan");
            black_box(matches);
        })
    });
}

fn compile_10_templates(c: &mut Criterion) {
    compile_bench(c, 10);
}

fn compile_100_templates(c: &mut Criterion) {
    compile_bench(c, 100);
}

fn compile_1000_templates(c: &mut Criterion) {
    compile_bench(c, 1000);
}

fn scan_against_10_patterns(c: &mut Criterion) {
    scan_bench(c, 10);
}

fn scan_against_100_patterns(c: &mut Criterion) {
    scan_bench(c, 100);
}

fn scan_against_1000_patterns(c: &mut Criterion) {
    scan_bench(c, 1000);
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let dataset = generate_templates(200); // Changed from generate_test_templates to generate_templates

    // Warmup the compiler cache (simulate real-world usage where regexes are hot)
    let db = CompiledDatabase::compile(&dataset).unwrap();

    let text_payloads = vec![
        "var token = \"eyJh...\"",
        "username=admin&password=Password123",
        "<h1>Welcome to Admin Panel</h1>",
        "x-api-key: ak_live_123456789",
    ];

    let mut group = c.benchmark_group("matcher_throughput");
    group.throughput(criterion::Throughput::Bytes(
        text_payloads.iter().map(|s| s.len() as u64).sum(),
    ));

    group.bench_with_input(
        BenchmarkId::new("text_search", "mixed_payloads"),
        &text_payloads,
        |b: &mut criterion::Bencher, payloads| {
            b.iter(|| {
                for payload in payloads {
                    let response = ResponseData::new(200, vec![], payload.as_bytes().to_vec());
                    black_box(db.scan(black_box(&response)).expect("scan"));
                }
            });
        },
    );
    group.finish();
}

fn scan_response_sizes(c: &mut Criterion) {
    let templates = generate_templates(100);
    let compiled = CompiledDatabase::compile(&templates).unwrap();
    let mut group = c.benchmark_group("scan_response_sizes");

    for size in [1024usize, 10 * 1024, 100 * 1024] {
        let response = generate_response(size);
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &response,
            |b, response| {
                b.iter(|| {
                    let matches = black_box(&compiled)
                        .scan(black_box(response))
                        .expect("scan");
                    black_box(matches);
                })
            },
        );
    }

    group.finish();
}

fn word_vs_regex_matching(c: &mut Criterion) {
    let response = generate_response(4 * 1024);
    let word_templates = generate_templates(100);
    let regex_templates = generate_regex_templates(100);
    let word_db = CompiledDatabase::compile(&word_templates).unwrap();
    let regex_db = CompiledDatabase::compile(&regex_templates).unwrap();
    let mut group = c.benchmark_group("word_vs_regex_matching");

    group.bench_function(BenchmarkId::new("matcher_set", "word"), |b| {
        b.iter(|| {
            let matches = black_box(&word_db)
                .scan(black_box(&response))
                .expect("scan");
            black_box(matches);
        })
    });

    group.bench_function(BenchmarkId::new("matcher_set", "regex"), |b| {
        b.iter(|| {
            let matches = black_box(&regex_db)
                .scan(black_box(&response))
                .expect("scan");
            black_box(matches);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    compile_10_templates,
    compile_100_templates,
    compile_1000_templates,
    scan_against_10_patterns,
    scan_against_100_patterns,
    scan_against_1000_patterns,
    scan_response_sizes,
    word_vs_regex_matching
);
criterion_main!(benches);

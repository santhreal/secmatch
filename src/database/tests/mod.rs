use super::*;
use aho_corasick::{AhoCorasick, AhoCorasickKind};
use rand::{Rng, SeedableRng, distributions::Alphanumeric, rngs::StdRng};
use secir::Severity;
use secir::matcher::{MatchDatabase, ResponseData};
use secir::template::*;
use std::collections::HashMap;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing_subscriber::prelude::*;

mod adversarial;
mod correctness_perf;
mod crash_a;
mod crash_b;
mod destruction_a;
mod destruction_b;
mod matching_gaps;

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl SharedWriter {
    fn display_string(&self) -> String {
        String::from_utf8(
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
        )
        .expect("operation should succeed")
    }
}

struct SharedWriterGuard(Arc<Mutex<Vec<u8>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedWriter {
    type Writer = SharedWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedWriterGuard(self.0.clone())
    }
}

impl io::Write for SharedWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn make_template_with_matchers(id: &str, matchers: Vec<MatcherDef>) -> Template {
    Template {
        depends_on: vec![],
        id: id.to_string(),
        ir_version: 1,
        extends: None,
        imports: Vec::new(),
        parallel_groups: Vec::new(),
        info: TemplateInfo {
            name: id.to_string(),
            author: vec!["test".to_string()],
            severity: Severity::Info,
            description: None,
            reference: vec![],
            tags: vec![],
            metadata: TemplateMeta::default(),
        },
        protocol: Protocol::Http,
        requests: vec![RequestDef {
            call: None,
            condition: None,
            goto: None,
            headless_actions: Vec::new(),
            iterate: None,
            label: None,
            transforms: Vec::new(),
            method: "GET".to_string(),
            raw: None,
            paths: vec!["{{BaseURL}}".to_string()],
            headers: HashMap::new(),
            body: None,
            port: None,
            inputs: Vec::new(),
            payloads: HashMap::new(),
            attack: AttackType::BatteringRam,
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
            compute: vec![],
        }],
        self_contained: false,
        variables: HashMap::new(),
        cli_variables: HashMap::new(),
        source_path: None,
        flow: None,
        workflows: Vec::new(),
        extensions: HashMap::new(),
        exports: Vec::new(),
    }
}

const PROPERTY_TEST_ITERATIONS: usize = 100;

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

fn random_ascii_string(rng: &mut impl Rng, max_len: usize) -> String {
    let len = rng.gen_range(0..=max_len);
    (0..len)
        .map(|_| rng.sample(Alphanumeric))
        .map(char::from)
        .collect()
}

fn random_header_name(rng: &mut impl Rng) -> String {
    let suffix = random_ascii_string(rng, 8);
    if suffix.is_empty() {
        "x-karyx".to_string()
    } else {
        format!("x-{suffix}")
    }
}

fn random_match_part(rng: &mut impl Rng) -> MatchPart {
    match rng.gen_range(0..4) {
        0 => MatchPart::Body,
        1 => MatchPart::Header,
        2 => MatchPart::All,
        _ => MatchPart::Named(random_header_name(rng)),
    }
}

fn random_safe_matcher(rng: &mut impl Rng) -> MatcherDef {
    let kind = match rng.gen_range(0..6) {
        0 => MatcherKind::Word,
        1 => MatcherKind::Regex,
        2 => MatcherKind::Status,
        3 => MatcherKind::Size,
        4 => MatcherKind::Binary,
        _ => MatcherKind::Dsl,
    };

    let values = match kind {
        MatcherKind::Word => vec![random_ascii_string(rng, 16), random_ascii_string(rng, 8)],
        MatcherKind::Regex => vec![
            regex::escape(&random_ascii_string(rng, 16)),
            regex::escape(&random_ascii_string(rng, 8)),
        ],
        MatcherKind::Status => vec![rng.gen_range(0..=999).to_string()],
        MatcherKind::Size => vec![rng.gen_range(0..=4096).to_string()],
        MatcherKind::Binary => {
            let byte_len = rng.gen_range(0..=8);
            let hex = (0..byte_len)
                .map(|_| format!("{:02x}", rng.gen_range(0..=255)))
                .collect::<String>();
            vec![hex]
        }
        MatcherKind::Dsl => {
            let header = random_header_name(rng);
            let expected = random_ascii_string(rng, 12);
            vec![
                format!("status_code == {}", rng.gen_range(0..=999)),
                format!("contains(body, \"{}\")", random_ascii_string(rng, 12)),
                format!("contains(all_headers, \"{header}\")"),
                format!(
                    "contains(header_{}, \"{expected}\")",
                    header.replace('-', "_")
                ),
            ]
        }
        _ => vec![random_ascii_string(rng, 16)],
    };

    MatcherDef {
        kind,
        values,
        part: random_match_part(rng),
        negative: rng.gen_bool(0.5),
        condition: if rng.gen_bool(0.5) {
            MatcherCondition::And
        } else {
            MatcherCondition::Or
        },
        internal: rng.gen_bool(0.2),
    }
}

fn random_chaotic_matcher(rng: &mut impl Rng) -> MatcherDef {
    let kind = match rng.gen_range(0..6) {
        0 => MatcherKind::Word,
        1 => MatcherKind::Regex,
        2 => MatcherKind::Status,
        3 => MatcherKind::Size,
        4 => MatcherKind::Binary,
        _ => MatcherKind::Dsl,
    };

    let value_count = rng.gen_range(0..=4);
    let values = (0..value_count)
        .map(|_| {
            if rng.gen_bool(0.3) {
                let bytes = (0..rng.gen_range(0..=12))
                    .map(|_| rng.gen_range(0..=255))
                    .collect::<Vec<u8>>();
                String::from_utf8_lossy(&bytes).into_owned()
            } else {
                random_ascii_string(rng, 20)
            }
        })
        .collect();

    MatcherDef {
        kind,
        values,
        part: random_match_part(rng),
        negative: rng.gen_bool(0.5),
        condition: if rng.gen_bool(0.5) {
            MatcherCondition::And
        } else {
            MatcherCondition::Or
        },
        internal: rng.gen_bool(0.2),
    }
}

fn random_template(rng: &mut impl Rng, id: &str, chaotic: bool) -> Template {
    let matcher_count = rng.gen_range(0..=6);
    let matchers = (0..matcher_count)
        .map(|_| {
            if chaotic {
                random_chaotic_matcher(rng)
            } else {
                random_safe_matcher(rng)
            }
        })
        .collect();
    make_template_with_matchers(id, matchers)
}

fn random_response(rng: &mut impl Rng) -> ResponseData {
    let header_count = rng.gen_range(0..=6);
    let headers = (0..header_count)
        .map(|_| (random_header_name(rng), random_ascii_string(rng, 32)))
        .collect();
    let body_len = rng.gen_range(0..=128);
    let body = (0..body_len)
        .map(|_| rng.gen_range(0..=255))
        .collect::<Vec<u8>>();

    ResponseData::new(rng.gen_range(0..=999), headers, body)
}

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]
//! Pure-computation pattern matching engine for Karyx.
//!
//! This crate is the architectural crown jewel: zero I/O, zero network
//! dependencies. It takes compiled templates and responses, produces matches
//! and findings through Aho-Corasick + `RegexSet` fusion.
//!
//! # Design invariants
//!
//! - **No I/O.** This crate never touches the network or filesystem.
//! - **No protocol knowledge.** It operates on `ResponseData`, not HTTP/DNS/TCP.
//! - **Independently testable.** Every function is pure computation.
//! - **Independently benchmarkable.** No mocks needed.

pub mod correlation;
pub mod database;
pub mod dsl;
pub mod evaluator;
pub mod extractor;
pub(crate) mod json_util;
pub mod inter_template;
pub mod streaming;
pub mod text;

pub use correlation::{
    CorrelationEngine, CorrelationRule, correlate_findings, correlate_findings_with_rules_dir,
};
pub use database::CompiledDatabase;
pub use dsl::{evaluate_dsl, evaluate_dsl_with_variables};
pub use evaluator::{
    evaluate_condition, matcher_satisfied, substitute_variables, transform_response,
    transform_response_checked, TransformFailure,
};
pub use extractor::{extract_from_response, extract_variables_from_response};
pub use inter_template::{
    InterTemplateState, resolve_variable_reference, substitute_variables_with_imports,
};
pub use streaming::{StreamChunkResult, StreamingMatcher};

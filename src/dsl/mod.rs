//! Nuclei-style DSL parsing and evaluation used by matcher conditions.

use secir::matcher::ResponseData;
use std::collections::HashMap;

/// Cache module for compiled regexes and ASTs.
pub mod cache;
mod evaluator;
mod functions;
mod parser;

#[cfg(test)]
mod tests;

pub use self::cache::cached_regex;
pub use self::evaluator::DslError;
pub use self::functions::Value;
pub use self::parser::{BinaryOp, Expr, parse_expression};

use self::cache::ast_cache;
use self::evaluator::Evaluator;

/// Evaluate a Nuclei-style DSL expression against a response payload.
pub fn evaluate_dsl(expression: &str, response: &ResponseData) -> bool {
    evaluate_dsl_with_variables(expression, response, &HashMap::new())
}

/// Evaluate a DSL expression with additional template/extraction variables.
///
/// Variables are resolved in this priority order:
/// 1. Built-in response identifiers (body, `status_code`, etc.)
/// 2. User-provided variables (extracted values, template variables)
///
/// This enables conditional execution: `condition: '{{token}} != ""'`
/// where `token` was extracted by a previous request.
pub fn evaluate_dsl_with_variables(
    expression: &str,
    response: &ResponseData,
    variables: &HashMap<String, String>,
) -> bool {
    let expression = expression.trim();
    ast_cache(|cache| {
        let Some(ast) = cache.get_or_parse(expression) else {
            log_evaluation_failure(
                expression,
                &DslError::Parse("invalid expression".to_string()),
            );
            return false;
        };

        let evaluator = Evaluator::with_variables(response, variables);
        evaluator.reset();

        match evaluator.eval(ast) {
            Ok(Value::Bool(result)) => result,
            Ok(value) => {
                log_evaluation_failure(
                    expression,
                    &DslError::Evaluation(format!(
                        "expression returned {} instead of a boolean",
                        value.kind()
                    )),
                );
                false
            }
            Err(error) => {
                log_evaluation_failure(expression, &error);
                false
            }
        }
    })
}

fn log_evaluation_failure(expression: &str, error: &DslError) {
    tracing::debug!(
        expression = expression,
        error = %error,
        "failed to evaluate DSL expression"
    );
}

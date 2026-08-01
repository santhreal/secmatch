use crate::dsl::parser::Expr;

pub(crate) fn select_regex_pattern_and_input<'a>(
    left_expr: &Expr,
    right_expr: &Expr,
    left_value: &'a str,
    right_value: &'a str,
) -> (&'a str, &'a str) {
    match (expr_likely_input(left_expr), expr_likely_input(right_expr)) {
        (false, true) => (left_value, right_value),
        (true, false) => (right_value, left_value),
        _ => {
            let left_looks_like_pattern = looks_like_regex_pattern(left_value);
            let right_looks_like_pattern = looks_like_regex_pattern(right_value);
            match (left_looks_like_pattern, right_looks_like_pattern) {
                (true, false) => (left_value, right_value),
                (false, true) => (right_value, left_value),
                _ => (right_value, left_value),
            }
        }
    }
}

pub(crate) fn expr_likely_input(expr: &Expr) -> bool {
    match expr {
        Expr::Identifier(_) | Expr::MethodCall { .. } | Expr::FunctionCall { .. } => true,
        Expr::UnaryNot(inner) => expr_likely_input(inner),
        Expr::Binary { .. } => true,
        Expr::List(_) => false,
        Expr::Integer(_) | Expr::String(_) => false,
    }
}

pub(crate) fn looks_like_regex_pattern(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '*' | '+' | '?' | '^' | '$' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '\\'
        )
    })
}

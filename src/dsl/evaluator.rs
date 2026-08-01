use super::functions::Value;
use super::parser::{BinaryOp, Expr};
use rand::rngs::ThreadRng;
use secir::matcher::ResponseData;
use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;

pub(super) const DEFAULT_MAX_DEPTH: u32 = 32;
pub(super) const DEFAULT_MAX_OPERATIONS: u32 = 10_000;
pub(super) const DEFAULT_MAX_STRING_BYTES: usize = 1_048_576;

#[derive(Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum DslError {
    Parse(String),
    Evaluation(String),
}

impl std::fmt::Display for DslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DslError::Parse(message) => write!(f, "parse error: {message}"),
            DslError::Evaluation(message) => write!(f, "evaluation error: {message}"),
        }
    }
}

pub(super) struct Evaluator<'a> {
    pub(super) response: &'a ResponseData,
    pub(super) variables: &'a HashMap<String, String>,
    pub(super) max_depth: u32,
    pub(super) max_operations: u32,
    pub(super) depth: Cell<u32>,
    pub(super) ops: Cell<u32>,
    pub(super) rng: RefCell<ThreadRng>,
    /// Lazily-decoded UTF-8 views of the response byte regions. A single rule
    /// can reference `body`/`header`/`all` many times; decoding on every
    /// reference re-runs a full `from_utf8_lossy` validation scan over the
    /// whole region. These caches collapse N whole-region scans to one.
    body_str: OnceCell<String>,
    header_str: OnceCell<String>,
    all_str: OnceCell<String>,
}

impl<'a> Evaluator<'a> {
    #[cfg(test)]
    pub(super) fn new(response: &'a ResponseData) -> Self {
        static EMPTY: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
        Self {
            response,
            variables: EMPTY.get_or_init(HashMap::new),
            max_depth: DEFAULT_MAX_DEPTH,
            max_operations: DEFAULT_MAX_OPERATIONS,
            depth: Cell::new(0),
            ops: Cell::new(0),
            rng: RefCell::new(rand::thread_rng()),
            body_str: OnceCell::new(),
            header_str: OnceCell::new(),
            all_str: OnceCell::new(),
        }
    }

    pub(super) fn with_variables(
        response: &'a ResponseData,
        variables: &'a HashMap<String, String>,
    ) -> Self {
        Self {
            response,
            variables,
            max_depth: DEFAULT_MAX_DEPTH,
            max_operations: DEFAULT_MAX_OPERATIONS,
            depth: Cell::new(0),
            ops: Cell::new(0),
            rng: RefCell::new(rand::thread_rng()),
            body_str: OnceCell::new(),
            header_str: OnceCell::new(),
            all_str: OnceCell::new(),
        }
    }

    pub(super) fn body_str(&self) -> &str {
        self.body_str
            .get_or_init(|| String::from_utf8_lossy(&self.response.body).into_owned())
    }

    pub(super) fn header_str(&self) -> &str {
        self.header_str.get_or_init(|| {
            // Reconstruct the header block from header_map to preserve ORIGINAL
            // header-name case: nuclei's `header`/`all_headers` is case
            // preserving, but response.headers lowercases keys for
            // case-insensitive Named lookups, which would make a case-sensitive
            // contains(all_headers, "Content-Type") wrongly fail.
            let mut out = String::new();
            for (key, value) in &self.response.header_map {
                out.push_str(key);
                out.push_str(": ");
                out.push_str(value);
                out.push('\n');
            }
            out
        })
    }

    pub(super) fn all_str(&self) -> &str {
        self.all_str
            .get_or_init(|| String::from_utf8_lossy(self.response.all_bytes()).into_owned())
    }

    pub(super) fn reset(&self) {
        self.depth.set(0);
        self.ops.set(0);
    }

    pub(super) fn eval(&self, expr: &Expr) -> Result<Value, DslError> {
        let depth = self.depth.get().saturating_add(1);
        self.depth.set(depth);
        if depth > self.max_depth {
            self.depth.set(depth.saturating_sub(1));
            return Err(DslError::Evaluation(format!(
                "maximum evaluation depth of {} exceeded",
                self.max_depth
            )));
        }

        let result = match expr {
            Expr::Integer(value) => Ok(Value::Int(*value)),
            Expr::String(value) => Ok(Value::Str(value.clone())),
            Expr::List(items) => Ok(Value::List(
                items.iter().map(|item| self.eval(item)).collect::<Result<Vec<_>, _>>()?,
            )),
            Expr::Identifier(name) => self.resolve_identifier(name),
            Expr::UnaryNot(inner) => Ok(Value::Bool(!self.eval(inner)?.to_bool())),
            Expr::Binary { left, op, right } => self.eval_binary(left, *op, right),
            Expr::FunctionCall { name, args } => self.eval_call(name, None, args),
            Expr::MethodCall {
                receiver,
                name,
                args,
            } => {
                let receiver = self.eval(receiver)?;
                self.eval_call(name, Some(receiver), args)
            }
        };
        self.depth.set(depth - 1);
        result
    }

    fn eval_binary(&self, left: &Expr, op: BinaryOp, right: &Expr) -> Result<Value, DslError> {
        match op {
            BinaryOp::And => Ok(Value::Bool(self.eval_logical_chain(left, op, right)?)),
            BinaryOp::Or => Ok(Value::Bool(self.eval_logical_chain(left, op, right)?)),
            BinaryOp::Add => self.eval_int_arithmetic(left, right, |a, b| Ok(a + b)),
            BinaryOp::Sub => self.eval_int_arithmetic(left, right, |a, b| Ok(a - b)),
            BinaryOp::Mul => self.eval_int_arithmetic(left, right, |a, b| Ok(a * b)),
            BinaryOp::Div => self.eval_int_arithmetic(left, right, |a, b| {
                if b == 0 {
                    Err(DslError::Evaluation("division by zero".to_string()))
                } else {
                    Ok(a / b)
                }
            }),
            BinaryOp::Eq => {
                self.increment_operations()?;
                Ok(Value::Bool(self.eval(left)? == self.eval(right)?))
            }
            BinaryOp::Ne => {
                self.increment_operations()?;
                Ok(Value::Bool(self.eval(left)? != self.eval(right)?))
            }
            BinaryOp::Gt => self.compare_ints(left, right, |a, b| a > b),
            BinaryOp::Lt => self.compare_ints(left, right, |a, b| a < b),
            BinaryOp::Ge => self.compare_ints(left, right, |a, b| a >= b),
            BinaryOp::Le => self.compare_ints(left, right, |a, b| a <= b),
        }
    }

    fn eval_int_arithmetic(
        &self,
        left: &Expr,
        right: &Expr,
        op: impl FnOnce(i64, i64) -> Result<i64, DslError>,
    ) -> Result<Value, DslError> {
        self.increment_operations()?;
        let left = self.eval(left)?;
        let right = self.eval(right)?;
        match (left.as_int(), right.as_int()) {
            (Some(a), Some(b)) => op(a, b).map(Value::Int),
            _ => Err(DslError::Evaluation(
                "arithmetic requires integer operands".to_string(),
            )),
        }
    }

    fn eval_logical_chain(
        &self,
        left: &Expr,
        op: BinaryOp,
        right: &Expr,
    ) -> Result<bool, DslError> {
        self.increment_operations()?;
        let mut pending = vec![right, left];

        while let Some(expr) = pending.pop() {
            match expr {
                Expr::Binary {
                    left,
                    op: nested_op,
                    right,
                } if *nested_op == op => {
                    self.increment_operations()?;
                    pending.push(right);
                    pending.push(left);
                }
                _ => {
                    let value = self.eval(expr)?.to_bool();
                    match op {
                        BinaryOp::And if !value => return Ok(false),
                        BinaryOp::Or if value => return Ok(true),
                        _ => {}
                    }
                }
            }
        }

        Ok(matches!(op, BinaryOp::And))
    }

    fn compare_ints(
        &self,
        left: &Expr,
        right: &Expr,
        predicate: impl FnOnce(i64, i64) -> bool,
    ) -> Result<Value, DslError> {
        self.increment_operations()?;
        let left = self.eval(left)?;
        let right = self.eval(right)?;
        match (left.as_int(), right.as_int()) {
            (Some(a), Some(b)) => Ok(Value::Bool(predicate(a, b))),
            _ => Err(DslError::Evaluation(
                "numeric comparison requires integer operands".to_string(),
            )),
        }
    }

    fn resolve_identifier(&self, name: &str) -> Result<Value, DslError> {
        match name {
            "status_code" => Ok(Value::Int(i64::from(self.response.status))),
            "content_length" => Ok(Value::Int(self.response.content_length as i64)),
            "body_length" => Ok(Value::Int(self.response.body.len() as i64)),
            "response_headers_count" => Ok(Value::Int(self.response.header_map.len() as i64)),
            "body" => Ok(Value::Str(self.body_str().to_owned())),
            // `header` and `all_headers` are aliases for the raw response header
            // block (nuclei exposes it as `all_headers`); both resolve to the
            // same cached decode.
            "header" | "all_headers" => Ok(Value::Str(self.header_str().to_owned())),
            "all" => Ok(Value::Str(self.all_str().to_owned())),
            "header_names" => Ok(Value::List(
                self.response
                    .header_map
                    .iter()
                    .map(|(k, _)| Value::Str(k.clone()))
                    .collect(),
            )),
            "header_values" => Ok(Value::List(
                self.response
                    .header_map
                    .iter()
                    .map(|(_, v)| Value::Str(v.clone()))
                    .collect(),
            )),
            _ => {
                if let Some(value) = self.variables.get(name) {
                    if let Ok(n) = value.parse::<i64>() {
                        Ok(Value::Int(n))
                    } else {
                        Ok(Value::Str(value.clone()))
                    }
                } else if let Some(value) = self.resolve_built_in_series_identifier(name) {
                    Ok(value)
                } else {
                    Err(DslError::Evaluation(format!("unknown identifier `{name}`")))
                }
            }
        }
    }

    pub(super) fn increment_operations(&self) -> Result<(), DslError> {
        let next = self.ops.get().saturating_add(1);
        self.ops.set(next);
        if next > self.max_operations {
            tracing::debug!(
                operations = next,
                max_operations = self.max_operations,
                "dsl evaluation exceeded operation budget"
            );
            return Err(DslError::Evaluation(format!(
                "maximum operation count of {} exceeded",
                self.max_operations
            )));
        }
        Ok(())
    }

    pub(super) fn validate_output_len(&self, len: i64, function: &str) -> Result<usize, DslError> {
        let len = usize::try_from(len)
            .map_err(|_| DslError::Evaluation(format!("{function} length must be non-negative")))?;
        self.ensure_output_budget(len, function)?;
        Ok(len)
    }

    pub(super) fn ensure_output_budget(&self, len: usize, function: &str) -> Result<(), DslError> {
        if len > DEFAULT_MAX_STRING_BYTES {
            return Err(DslError::Evaluation(format!(
                "{function} output exceeds configured budget of {DEFAULT_MAX_STRING_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn resolve_built_in_series_identifier(&self, name: &str) -> Option<Value> {
        // Indexed response fields (status_code_1, body_2, ...) require a multi-response
        // chain; only the _0 suffix aliases the current response.
        if let Some(suffix) = name.strip_prefix("status_code_") {
            if suffix == "0" {
                return Some(Value::Int(i64::from(self.response.status)));
            }
            return None;
        }
        if let Some(suffix) = name.strip_prefix("body_") {
            if suffix == "0" {
                return Some(Value::Str(self.body_str().to_owned()));
            }
            return None;
        }
        if let Some(suffix) = name.strip_prefix("header_") {
            if suffix == "0" {
                return Some(Value::Str(self.header_str().to_owned()));
            }
            return None;
        }
        None
    }
}

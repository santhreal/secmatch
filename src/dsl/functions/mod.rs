pub mod crypto;
pub mod encoding;
pub mod gadget;
pub mod json;
pub mod random;
pub mod regex_utils;
pub mod types;
pub mod version;

#[cfg(test)]
mod tests;

use super::DslError;
use super::cache::cached_regex;
use super::evaluator::Evaluator;
use super::parser::Expr;
use crate::dsl::functions::crypto::*;
use crate::dsl::functions::encoding::*;
use crate::dsl::functions::gadget::*;
use crate::dsl::functions::json::*;
use crate::dsl::functions::random::*;
use crate::dsl::functions::regex_utils::*;
pub use crate::dsl::functions::types::Value;
use crate::dsl::functions::version::*;
use chrono::format::{Item, StrftimeItems};
use chrono::{Local, Utc};

impl Evaluator<'_> {
    pub(super) fn eval_call(
        &self,
        name: &str,
        receiver: Option<Value>,
        args: &[Expr],
    ) -> Result<Value, DslError> {
        // Each match arm calls increment_operations() individually.
        // No outer increment  -  avoids double-counting.
        match (name, receiver) {
            ("header", None) if args.len() == 1 => {
                self.increment_operations()?;
                let name = self.eval(&args[0])?.to_display_string();
                let lower = name.to_ascii_lowercase();
                let value = self
                    .response
                    .header_index
                    .get(&lower)
                    .and_then(|index| self.response.header_map.get(*index))
                    .map(|(_, value)| value.as_str())
                    .unwrap_or("");
                Ok(Value::Str(value.to_string()))
            }
            ("contains", None) if args.len() == 2 => {
                self.increment_operations()?;
                let haystack = self.eval(&args[0])?.to_display_string();
                let needle = self.eval(&args[1])?.to_display_string();
                Ok(Value::Bool(haystack.contains(&needle)))
            }
            ("contains", Some(receiver)) if args.len() == 1 => {
                self.increment_operations()?;
                let haystack = receiver.to_display_string();
                let needle = self.eval(&args[0])?.to_display_string();
                Ok(Value::Bool(haystack.contains(&needle)))
            }
            ("contains_any", None) if args.len() >= 2 => {
                self.increment_operations()?;
                let haystack = self.eval(&args[0])?.to_display_string();
                let needles = args[1..]
                    .iter()
                    .map(|arg| self.eval(arg).map(Value::to_display_string))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Value::Bool(
                    needles.iter().any(|needle| haystack.contains(needle)),
                ))
            }
            ("len", None) if args.len() == 1 => {
                self.increment_operations()?;
                let val = self.eval(&args[0])?;
                match val {
                    Value::List(list) => Ok(Value::Int(list.len() as i64)),
                    other => Ok(Value::Int(other.to_display_string().len() as i64)),
                }
            }
            ("starts_with", None) if args.len() == 2 => {
                self.increment_operations()?;
                let value = self.eval(&args[0])?.to_display_string();
                let prefix = self.eval(&args[1])?.to_display_string();
                Ok(Value::Bool(value.starts_with(&prefix)))
            }
            ("starts_with", Some(receiver)) if args.len() == 1 => {
                self.increment_operations()?;
                let value = receiver.to_display_string();
                let prefix = self.eval(&args[0])?.to_display_string();
                Ok(Value::Bool(value.starts_with(&prefix)))
            }
            ("ends_with", None) if args.len() == 2 => {
                self.increment_operations()?;
                let value = self.eval(&args[0])?.to_display_string();
                let suffix = self.eval(&args[1])?.to_display_string();
                Ok(Value::Bool(value.ends_with(&suffix)))
            }
            ("ends_with", Some(receiver)) if args.len() == 1 => {
                self.increment_operations()?;
                let value = receiver.to_display_string();
                let suffix = self.eval(&args[0])?.to_display_string();
                Ok(Value::Bool(value.ends_with(&suffix)))
            }
            ("to_lower", None) if args.len() == 1 => {
                self.increment_operations()?;
                let value = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(value.to_lowercase()))
            }
            ("to_lower", Some(receiver)) if args.is_empty() => {
                self.increment_operations()?;
                Ok(Value::Str(receiver.to_display_string().to_lowercase()))
            }
            ("to_upper", None) if args.len() == 1 => {
                self.increment_operations()?;
                let value = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(value.to_uppercase()))
            }
            ("to_upper", Some(receiver)) if args.is_empty() => {
                self.increment_operations()?;
                Ok(Value::Str(receiver.to_display_string().to_uppercase()))
            }
            ("regex", None) if args.len() == 2 => {
                self.increment_operations()?;
                let left = self.eval(&args[0])?.to_display_string();
                let right = self.eval(&args[1])?.to_display_string();
                let (pattern, input) =
                    select_regex_pattern_and_input(&args[0], &args[1], &left, &right);
                let regex = cached_regex(pattern).map_err(|error| {
                    DslError::Evaluation(format!("invalid regex `{pattern}`: {error}"))
                })?;
                Ok(Value::Bool(regex.is_match(input)))
            }
            ("md5", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(md5_hex(s.as_bytes())))
            }
            ("sha1", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(sha1_hex(s.as_bytes())))
            }
            ("sha256", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(sha256_hex(s.as_bytes())))
            }
            ("base64", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(encodex::base64::encode(s.as_bytes())))
            }
            ("base64_decode", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                match encodex::base64::decode(&s) {
                    Ok(decoded) => Ok(Value::Str(String::from_utf8_lossy(&decoded).into_owned())),
                    Err(_) => Err(DslError::Evaluation("base64 decode failed".to_string())),
                }
            }
            ("url_encode", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(url_encode(&s)))
            }
            ("url_decode", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                match url_decode(&s) {
                    Ok(decoded) => Ok(Value::Str(decoded)),
                    Err(()) => Err(DslError::Evaluation("url decode failed".to_string())),
                }
            }
            ("trim", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(s.trim().to_string()))
            }
            ("trim", None) if args.len() == 2 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                let chars = self.eval(&args[1])?.to_display_string();
                Ok(Value::Str(
                    s.trim_matches(|c| chars.contains(c)).to_string(),
                ))
            }
            ("replace", None) if args.len() == 3 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                let old = self.eval(&args[1])?.to_display_string();
                let new = self.eval(&args[2])?.to_display_string();
                if old.is_empty() {
                    // Rust inserts `new` between every UTF-8 scalar; bound before allocating.
                    const REPLACE_EMPTY_OLD_MAX: usize = 10_000;
                    let est = s
                        .chars()
                        .count()
                        .saturating_mul(new.len())
                        .saturating_add(new.len());
                    if est > REPLACE_EMPTY_OLD_MAX {
                        return Err(DslError::Evaluation(format!(
                            "replace with empty pattern would produce {est} bytes (max {REPLACE_EMPTY_OLD_MAX})"
                        )));
                    }
                    self.ensure_output_budget(est, "replace")?;
                } else {
                    let est = s
                        .len()
                        .saturating_add(s.matches(old.as_str()).count().saturating_mul(new.len()));
                    self.ensure_output_budget(est, "replace")?;
                }
                Ok(Value::Str(s.replace(&old, &new)))
            }
            ("hex_encode", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(hex_encode(s.as_bytes())))
            }
            ("hex_decode", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                match hex_decode(&s) {
                    Ok(decoded) => Ok(Value::Str(String::from_utf8_lossy(&decoded).into_owned())),
                    Err(()) => Err(DslError::Evaluation("hex decode failed".to_string())),
                }
            }
            ("concat", None) if !args.is_empty() => {
                self.increment_operations()?;
                let mut res = String::new();
                for arg in args {
                    res.push_str(&self.eval(arg)?.to_display_string());
                }
                Ok(Value::Str(res))
            }
            ("substr", None) if args.len() == 3 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                let start = self.eval(&args[1])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("substr start index must be an integer".to_string())
                })?;
                let length = self.eval(&args[2])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("substr length must be an integer".to_string())
                })?;
                // Index by CHARACTERS, not bytes: byte slicing s[start..end]
                // panics on a non-ASCII char boundary, and `as usize` casts /
                // start+length could wrap. skip/take saturate safely; a
                // negative start or length clamps to 0.
                let start = usize::try_from(start).unwrap_or(0);
                let length = usize::try_from(length).unwrap_or(0);
                let result: String = s.chars().skip(start).take(length).collect();
                Ok(Value::Str(result))
            }
            ("all_match", None) if args.len() == 2 => {
                self.increment_operations()?;
                let pattern = self.eval(&args[0])?.to_display_string();
                let list = self.eval(&args[1])?;
                let regex = cached_regex(&pattern).map_err(|error| {
                    DslError::Evaluation(format!("invalid regex `{pattern}`: {error}"))
                })?;
                match list {
                    Value::List(items) => {
                        Ok(Value::Bool(items.iter().all(|item| {
                            regex.is_match(&item.clone().to_display_string())
                        })))
                    }
                    _ => Err(DslError::Evaluation(
                        "all_match requires a list as its second argument".to_string(),
                    )),
                }
            }
            ("any_match", None) if args.len() == 2 => {
                self.increment_operations()?;
                let pattern = self.eval(&args[0])?.to_display_string();
                let list = self.eval(&args[1])?;
                let regex = cached_regex(&pattern).map_err(|error| {
                    DslError::Evaluation(format!("invalid regex `{pattern}`: {error}"))
                })?;
                match list {
                    Value::List(items) => {
                        Ok(Value::Bool(items.iter().any(|item| {
                            regex.is_match(&item.clone().to_display_string())
                        })))
                    }
                    _ => Err(DslError::Evaluation(
                        "any_match requires a list as its second argument".to_string(),
                    )),
                }
            }
            ("rand_int", None) if args.len() == 2 => {
                self.increment_operations()?;
                let min = self.eval(&args[0])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("rand_int min must be an integer".to_string())
                })?;
                let max = self.eval(&args[1])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("rand_int max must be an integer".to_string())
                })?;
                Ok(Value::Int(random_int(&mut self.rng.borrow_mut(), min, max)))
            }
            ("rand_text_alpha", None) if args.len() == 1 => {
                self.increment_operations()?;
                let len = self.eval(&args[0])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("rand_text_alpha length must be an integer".to_string())
                })?;
                // Clamp negative values to 0
                let len = if len < 0 { 0 } else { len };
                let len = self.validate_output_len(len, "rand_text_alpha")?;
                let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                Ok(Value::Str(random_string(
                    &mut self.rng.borrow_mut(),
                    len,
                    charset,
                )))
            }
            ("rand_text_numeric", None) if args.len() == 1 => {
                self.increment_operations()?;
                let len = self.eval(&args[0])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("rand_text_numeric length must be an integer".to_string())
                })?;
                // Clamp negative values to 0
                let len = if len < 0 { 0 } else { len };
                let len = self.validate_output_len(len, "rand_text_numeric")?;
                Ok(Value::Str(random_string(
                    &mut self.rng.borrow_mut(),
                    len,
                    b"0123456789",
                )))
            }
            ("rand_text_alphanumeric", None) if args.len() == 1 => {
                self.increment_operations()?;
                let len = self.eval(&args[0])?.as_int().ok_or_else(|| {
                    DslError::Evaluation(
                        "rand_text_alphanumeric length must be an integer".to_string(),
                    )
                })?;
                // Clamp negative values to 0
                let len = if len < 0 { 0 } else { len };
                let len = self.validate_output_len(len, "rand_text_alphanumeric")?;
                let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                Ok(Value::Str(random_string(
                    &mut self.rng.borrow_mut(),
                    len,
                    charset,
                )))
            }
            ("rand_ip", None) if args.is_empty() => {
                self.increment_operations()?;
                let mut rng = self.rng.borrow_mut();
                Ok(Value::Str(format!(
                    "{}.{}.{}.{}",
                    random_int(&mut rng, 1, 254),
                    random_int(&mut rng, 0, 255),
                    random_int(&mut rng, 0, 255),
                    random_int(&mut rng, 1, 254)
                )))
            }
            ("rand_base", None) if args.len() == 2 => {
                self.increment_operations()?;
                let len = self.eval(&args[0])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("rand_base length must be an integer".to_string())
                })?;
                // Clamp negative values to 0
                let len = if len < 0 { 0 } else { len };
                let len = self.validate_output_len(len, "rand_base")?;
                let charset = self.eval(&args[1])?.to_display_string();
                if charset.is_empty() {
                    return Err(DslError::Evaluation(
                        "rand_base charset must not be empty".to_string(),
                    ));
                }
                Ok(Value::Str(random_string(
                    &mut self.rng.borrow_mut(),
                    len,
                    charset.as_bytes(),
                )))
            }
            ("to_number", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                match s.parse::<i64>() {
                    Ok(n) => Ok(Value::Int(n)),
                    Err(_) => Err(DslError::Evaluation(format!(
                        "failed to parse `{s}` as integer"
                    ))),
                }
            }
            ("dec_to_hex", None) if args.len() == 1 => {
                self.increment_operations()?;
                let n = self.eval(&args[0])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("dec_to_hex argument must be an integer".to_string())
                })?;
                Ok(Value::Str(format!("{n:x}")))
            }
            ("hex_to_dec", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                match i64::from_str_radix(s.trim_start_matches("0x"), 16) {
                    Ok(n) => Ok(Value::Int(n)),
                    Err(_) => Err(DslError::Evaluation(format!(
                        "failed to parse `{s}` as hex"
                    ))),
                }
            }
            ("reverse", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Str(s.chars().rev().collect()))
            }
            ("join", None) if args.len() >= 2 => {
                self.increment_operations()?;
                let values = args
                    .iter()
                    .map(|arg| self.eval(arg))
                    .collect::<Result<Vec<_>, _>>()?;
                let (sep, items) = match values.as_slice() {
                    [Value::List(list), sep] => (
                        sep.clone().to_display_string(),
                        list.iter()
                            .cloned()
                            .map(Value::to_display_string)
                            .collect::<Vec<_>>(),
                    ),
                    [sep, rest @ ..] => {
                        let mut items = Vec::new();
                        for value in rest {
                            match value {
                                Value::List(list) => {
                                    items
                                        .extend(list.iter().cloned().map(Value::to_display_string));
                                }
                                other => items.push(other.clone().to_display_string()),
                            }
                        }
                        (sep.clone().to_display_string(), items)
                    }
                    [] => unreachable!(),
                };
                Ok(Value::Str(items.join(&sep)))
            }
            ("split", None) if args.len() == 3 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                let sep = self.eval(&args[1])?.to_display_string();
                let idx = self.eval(&args[2])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("split index must be an integer".to_string())
                })? as usize;
                let parts: Vec<&str> = s.split(&sep).collect();
                Ok(Value::Str(
                    parts.get(idx).map(|&p| p.to_string()).unwrap_or_default(),
                ))
            }
            ("regex_find_all", None) if args.len() == 2 => {
                self.increment_operations()?;
                let left = self.eval(&args[0])?.to_display_string();
                let right = self.eval(&args[1])?.to_display_string();
                let (pattern, input) =
                    select_regex_pattern_and_input(&args[0], &args[1], &left, &right);
                let regex = cached_regex(pattern).map_err(|error| {
                    DslError::Evaluation(format!("invalid regex `{pattern}`: {error}"))
                })?;
                const MAX_REGEX_FIND_ALL: usize = 999;
                let matches: Vec<Value> = regex
                    .find_iter(input)
                    .take(MAX_REGEX_FIND_ALL)
                    .map(|m| Value::Str(m.as_str().to_string()))
                    .collect();
                Ok(Value::List(matches))
            }
            ("repeat", None) if args.len() == 2 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                let count = self.eval(&args[1])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("repeat count must be an integer".to_string())
                })?;
                let count = self.validate_output_len(count, "repeat")?;
                let total_len = s.len().checked_mul(count).ok_or_else(|| {
                    DslError::Evaluation("repeat output exceeds configured budget".to_string())
                })?;
                self.ensure_output_budget(total_len, "repeat")?;
                Ok(Value::Str(s.repeat(count)))
            }
            ("line_count", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Int(s.lines().count() as i64))
            }
            ("word_count", None) if args.len() == 1 => {
                self.increment_operations()?;
                let s = self.eval(&args[0])?.to_display_string();
                Ok(Value::Int(s.split_whitespace().count() as i64))
            }
            ("json_extract", None) if args.len() == 2 => {
                self.increment_operations()?;
                let input = self.eval(&args[0])?.to_display_string();
                let path = self.eval(&args[1])?.to_display_string();
                Ok(Value::Str(json_extract(&input, &path)?))
            }
            ("compare_versions", None) if args.len() == 3 => {
                self.increment_operations()?;
                let left = self.eval(&args[0])?.to_display_string();
                let op = self.eval(&args[1])?.to_display_string();
                let right = self.eval(&args[2])?.to_display_string();
                Ok(Value::Bool(compare_versions(&left, &op, &right)?))
            }
            ("version_compare", None) if args.len() == 3 => {
                self.increment_operations()?;
                let left = self.eval(&args[0])?.to_display_string();
                let op = self.eval(&args[1])?.to_display_string();
                let right = self.eval(&args[2])?.to_display_string();
                Ok(Value::Bool(compare_versions(&left, &op, &right)?))
            }
            ("wait_for", None) if args.len() == 1 => {
                self.increment_operations()?;
                let seconds = self.eval(&args[0])?.as_int().ok_or_else(|| {
                    DslError::Evaluation("wait_for seconds must be an integer".to_string())
                })?;
                let seconds = seconds.clamp(0, 10) as u64;
                Ok(Value::Int(seconds as i64))
            }
            ("date_time", None) if args.len() == 1 => {
                self.increment_operations()?;
                let format = self.eval(&args[0])?.to_display_string();
                if format.is_empty() {
                    Ok(Value::Str(Utc::now().to_rfc3339()))
                } else {
                    // chrono's `format(&fmt).to_string()` PANICS on an invalid
                    // strftime specifier, and `fmt` is template-controlled.
                    // Parse the items first and fail with a DSL error on any
                    // Item::Error so a bad format cannot crash the evaluator.
                    let items: Vec<Item> = StrftimeItems::new(&format).collect();
                    if items.iter().any(|item| matches!(item, Item::Error)) {
                        return Err(DslError::Evaluation(format!(
                            "date_time: invalid strftime format string: {format:?}"
                        )));
                    }
                    Ok(Value::Str(
                        Local::now().format_with_items(items.iter()).to_string(),
                    ))
                }
            }
            ("generate_java_gadget", None) if args.len() == 2 => {
                self.increment_operations()?;
                let class = self.eval(&args[0])?.to_display_string();
                let command = self.eval(&args[1])?.to_display_string();
                let payload = build_java_gadget_payload(&class, &command)
                    .map_err(DslError::Evaluation)?;
                Ok(Value::Str(encode_java_gadget_payload(&payload, "raw")))
            }
            ("generate_java_gadget", None) if args.len() == 3 => {
                self.increment_operations()?;
                let gadget_type = self.eval(&args[0])?.to_display_string();
                let command = self.eval(&args[1])?.to_display_string();
                let encoding = self.eval(&args[2])?.to_display_string();
                let payload = build_java_gadget_payload(&gadget_type, &command)
                    .map_err(DslError::Evaluation)?;
                Ok(Value::Str(encode_java_gadget_payload(&payload, &encoding)))
            }
            ("print_debug", None) if !args.is_empty() => {
                self.increment_operations()?;
                let rendered = args
                    .iter()
                    .map(|arg| self.eval(arg).map(Value::to_display_string))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(" ");
                println!("{rendered}");
                Ok(Value::Str(String::new()))
            }
            _ => Err(DslError::Evaluation(format!(
                "unsupported call `{name}` with {} argument(s)",
                args.len()
            ))),
        }
    }
}

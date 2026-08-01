use crate::dsl::DslError;
use serde_json::Value as JsonValue;

pub(crate) fn json_extract(input: &str, path: &str) -> Result<String, DslError> {
    let value: JsonValue = serde_json::from_str(input)
        .map_err(|error| DslError::Evaluation(format!("json_extract parse failed: {error}")))?;
    let mut current = &value;

    for segment in path
        .trim_start_matches('$')
        .trim_start_matches('.')
        .split('.')
        .filter(|segment| !segment.is_empty())
    {
        if let Ok(index) = segment.parse::<usize>() {
            current = current.get(index).ok_or_else(|| {
                DslError::Evaluation(format!("json_extract path not found: {path}"))
            })?;
        } else {
            current = current.get(segment).ok_or_else(|| {
                DslError::Evaluation(format!("json_extract path not found: {path}"))
            })?;
        }
    }

    Ok(match current {
        JsonValue::Null => String::new(),
        JsonValue::String(text) => text.clone(),
        other => other.to_string(),
    })
}

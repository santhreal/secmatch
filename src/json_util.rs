//! Shared helpers for `gjson` path normalization and value rendering.

/// Normalize a Nuclei-style JSON path into a `gjson` path.
///
/// - Strips a leading `$.`, `$`, or `.`.
/// - Converts `[]` (empty brackets) into the `gjson` wildcard `.#` and,
///   when followed by another key, inserts the required dot so that
///   `items[]name` becomes `items.#.name`.
pub(crate) fn normalize_gjson_path(path: &str) -> String {
    let path = path
        .strip_prefix("$.")
        .or_else(|| path.strip_prefix('$'))
        .or_else(|| path.strip_prefix('.'))
        .unwrap_or(path);

    let mut out = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '[' && chars.peek() == Some(&']') {
            chars.next(); // consume ']'
            out.push_str(".#");
            // gjson needs a dot before a following key: items[]name -> items.#.name
            if let Some(&next) = chars.peek() {
                if next != '.' {
                    out.push('.');
                }
            }
        } else {
            out.push(ch);
        }
    }

    out
}

/// Render a `gjson` scalar as the string a downstream extractor expects.
///
/// `gjson::Value::to_string()` (and `str()`) returns an empty string for
/// `null`, which is unhelpful for matching; we map it to `"null"` so the
/// extracted value is observable and distinct from a missing value.
pub(crate) fn gjson_value_to_string(value: &gjson::Value<'_>) -> String {
    if value.kind() == gjson::Kind::Null {
        "null".to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_leading_dollar_dot() {
        assert_eq!(normalize_gjson_path("$.key"), "key");
        assert_eq!(normalize_gjson_path("$key"), "key");
        assert_eq!(normalize_gjson_path(".key"), "key");
    }

    #[test]
    fn normalize_converts_bracket_notation() {
        assert_eq!(normalize_gjson_path("items[]name"), "items.#.name");
        assert_eq!(normalize_gjson_path("items[].name"), "items.#.name");
        assert_eq!(normalize_gjson_path("data[].value"), "data.#.value");
    }

    #[test]
    fn normalize_leaves_already_gjson_paths() {
        assert_eq!(normalize_gjson_path("items.#.name"), "items.#.name");
    }
}

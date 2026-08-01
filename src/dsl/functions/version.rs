use crate::dsl::DslError;
use std::cmp::Ordering;

pub(crate) fn compare_versions(left: &str, op: &str, right: &str) -> Result<bool, DslError> {
    let ordering = version_cmp(left, right);
    match op {
        "==" | "=" | "eq" => Ok(ordering == Ordering::Equal),
        "!=" | "<>" | "ne" => Ok(ordering != Ordering::Equal),
        ">" | "gt" => Ok(ordering == Ordering::Greater),
        ">=" | "ge" => Ok(matches!(ordering, Ordering::Greater | Ordering::Equal)),
        "<" | "lt" => Ok(ordering == Ordering::Less),
        "<=" | "le" => Ok(matches!(ordering, Ordering::Less | Ordering::Equal)),
        _ => Err(DslError::Evaluation(format!(
            "unsupported compare_versions operator `{op}`"
        ))),
    }
}

pub(crate) fn version_cmp(left: &str, right: &str) -> Ordering {
    let left_parts = version_parts(left);
    let right_parts = version_parts(right);
    let max_len = left_parts.len().max(right_parts.len());

    for idx in 0..max_len {
        let left_part = left_parts.get(idx);
        let right_part = right_parts.get(idx);
        let cmp = match (left_part, right_part) {
            (Some(VersionPart::Num(a)), Some(VersionPart::Num(b))) => a.cmp(b),
            (Some(VersionPart::Text(a)), Some(VersionPart::Text(b))) => a.cmp(b),
            (Some(VersionPart::Num(_)), Some(VersionPart::Text(_))) => Ordering::Greater,
            (Some(VersionPart::Text(_)), Some(VersionPart::Num(_))) => Ordering::Less,
            (Some(VersionPart::Num(a)), None) => a.cmp(&0),
            (None, Some(VersionPart::Num(b))) => 0.cmp(b),
            (Some(VersionPart::Text(a)), None) => {
                if a.is_empty() {
                    Ordering::Equal
                } else {
                    Ordering::Less
                }
            }
            (None, Some(VersionPart::Text(b))) => {
                if b.is_empty() {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                }
            }
            (None, None) => Ordering::Equal,
        };

        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    Ordering::Equal
}

#[derive(Debug)]
pub(crate) enum VersionPart {
    Num(i64),
    Text(String),
}

pub(crate) fn version_parts(version: &str) -> Vec<VersionPart> {
    // Strip v prefix: v1.0.0 → 1.0.0
    let version = version
        .strip_prefix('v')
        .or(version.strip_prefix('V'))
        .unwrap_or(version);
    // Strip build metadata per semver: 1.0.0+build123 → 1.0.0
    let version = version.split('+').next().unwrap_or(version);
    version
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| match part.parse::<i64>() {
            Ok(num) => VersionPart::Num(num),
            Err(_) => VersionPart::Text(part.to_ascii_lowercase()),
        })
        .collect()
}

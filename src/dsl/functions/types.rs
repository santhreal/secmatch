#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<Value>),
}

impl Value {
    pub(crate) fn to_bool(&self) -> bool {
        match self {
            Value::Bool(value) => *value,
            Value::Int(value) => *value != 0,
            Value::Str(value) => !value.is_empty(),
            Value::List(value) => !value.is_empty(),
        }
    }

    pub(crate) fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(value) => Some(*value),
            _ => None,
        }
    }

    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_display_string(self) -> String {
        match self {
            Value::Bool(value) => value.to_string(),
            Value::Int(value) => value.to_string(),
            Value::Str(value) => value,
            Value::List(values) => {
                let mut s = String::from("[");
                for (i, v) in values.into_iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    s.push_str(&v.to_display_string());
                }
                s.push(']');
                s
            }
        }
    }

    #[must_use]
    #[allow(missing_docs)]
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Bool(_) => "boolean",
            Value::Int(_) => "integer",
            Value::Str(_) => "string",
            Value::List(_) => "list",
        }
    }
}

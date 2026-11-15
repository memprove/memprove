//! A small JSON writer and readers over [`memprove_protocol::strict_json`],
//! so that the crate needs no serialization dependency.

use std::fmt::Write as _;

pub use memprove_protocol::strict_json::JsonValue;

/// `value` as a JSON string literal.
#[must_use]
pub fn string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\t' => encoded.push_str("\\t"),
            '\r' => encoded.push_str("\\r"),
            control if u32::from(control) < 0x20 => {
                write!(encoded, "\\u{:04x}", u32::from(control))
                    .expect("writing to a String cannot fail");
            }
            other => encoded.push(other),
        }
    }
    encoded.push('"');
    encoded
}

/// An object on one line from members whose values are already encoded.
#[must_use]
pub fn object(members: &[(&str, String)]) -> String {
    let body: Vec<String> = members
        .iter()
        .map(|(name, value)| format!("{}:{value}", string(name)))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// The string at `name` of `value`.
#[must_use]
pub fn str_at<'a>(value: &'a JsonValue, name: &str) -> Option<&'a str> {
    value.get(name)?.as_str()
}

/// The first string among the members `names` of `value`.
#[must_use]
pub fn first_str<'a>(value: &'a JsonValue, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| str_at(value, name))
}

/// `value` as JSON indented by two spaces per level.
pub fn pretty(value: &JsonValue, indent: usize, out: &mut String) {
    let pad = |out: &mut String, depth: usize| out.push_str(&" ".repeat(depth));
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        JsonValue::Number(number) => out.push_str(number),
        JsonValue::String(text) => out.push_str(&string(text)),
        JsonValue::Array(items) if items.is_empty() => out.push_str("[]"),
        JsonValue::Object(members) if members.is_empty() => out.push_str("{}"),
        JsonValue::Array(items) => {
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                pad(out, indent + 2);
                pretty(item, indent + 2, out);
                out.push_str(if index + 1 < items.len() { ",\n" } else { "\n" });
            }
            pad(out, indent);
            out.push(']');
        }
        JsonValue::Object(members) => {
            out.push_str("{\n");
            for (index, (name, member)) in members.iter().enumerate() {
                pad(out, indent + 2);
                out.push_str(&string(name));
                out.push_str(": ");
                pretty(member, indent + 2, out);
                out.push_str(if index + 1 < members.len() {
                    ",\n"
                } else {
                    "\n"
                });
            }
            pad(out, indent);
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_strings_and_objects() {
        assert_eq!(string("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\u0001\"");
        assert_eq!(
            object(&[("a", string("x")), ("b", "1".to_owned())]),
            "{\"a\":\"x\",\"b\":1}"
        );
    }
}

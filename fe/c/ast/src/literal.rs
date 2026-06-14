//! Shared C literal parsing helpers.

use crate::alloc_prelude::*;

/// Parses a C integer constant, returning its value and whether it carries an unsigned suffix.
#[inline(never)]
#[must_use]
pub fn parse_integer(raw: &str) -> Option<(i128, bool)> {
    let digits = raw.trim_end_matches(['u', 'U', 'l', 'L']);
    if digits.is_empty() {
        return None;
    }
    let unsigned = raw.contains('u') || raw.contains('U');
    let value = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i128::from_str_radix(hex, 16).ok()?
    } else if digits.len() > 1 && digits.starts_with('0') {
        i128::from_str_radix(&digits[1..], 8).ok()?
    } else {
        digits.parse::<i128>().ok()?
    };
    Some((value, unsigned))
}

/// Decodes a C character constant such as `'A'` or `'\n'`.
#[inline(never)]
#[must_use]
pub fn decode_char_literal(raw: &str) -> Option<u32> {
    if let Ok(value) = raw.parse::<u32>() {
        return Some(value);
    }
    let body = literal_body(raw, '\'', '\'')?;
    let mut chars = body.chars();
    let first = chars.next()?;
    if first == '\\' {
        decode_escape(&mut chars)
    } else {
        Some(first as u32)
    }
}

/// Decodes a C string literal's contents, stripping prefixes and quotes.
#[inline(never)]
#[must_use]
pub fn decode_string_literal(raw: &str) -> Option<String> {
    let body = literal_body(raw, '"', '"').unwrap_or(raw);
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let value = decode_escape(&mut chars)?;
            out.push(char::from_u32(value)?);
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

#[inline(never)]
fn literal_body(raw: &str, open: char, close: char) -> Option<&str> {
    let body = raw.trim_start_matches(['L', 'u', 'U', '8']);
    body.strip_prefix(open)?.strip_suffix(close)
}

#[inline(never)]
fn decode_escape(chars: &mut core::str::Chars<'_>) -> Option<u32> {
    let escape = chars.next()?;
    let value = match escape {
        'n' => u32::from(b'\n'),
        't' => u32::from(b'\t'),
        'r' => u32::from(b'\r'),
        '\\' => u32::from(b'\\'),
        '\'' => u32::from(b'\''),
        '"' => u32::from(b'"'),
        '?' => u32::from(b'?'),
        'a' => 0x07,
        'b' => 0x08,
        'f' => 0x0C,
        'v' => 0x0B,
        'x' => decode_hex_escape(chars)?,
        '0'..='7' => decode_octal_escape(escape, chars),
        _ => return None,
    };
    Some(value)
}

#[inline(never)]
fn decode_hex_escape(chars: &mut core::str::Chars<'_>) -> Option<u32> {
    let mut digits = String::new();
    while let Some(ch) = chars.clone().next() {
        if !ch.is_ascii_hexdigit() {
            break;
        }
        digits.push(ch);
        let _ = chars.next();
    }
    if digits.is_empty() {
        return None;
    }
    u32::from_str_radix(&digits, 16).ok()
}

#[inline(never)]
fn decode_octal_escape(first: char, chars: &mut core::str::Chars<'_>) -> u32 {
    let mut digits = String::new();
    digits.push(first);
    for _ in 0..2 {
        let Some(ch) = chars.clone().next() else {
            break;
        };
        if !matches!(ch, '0'..='7') {
            break;
        }
        digits.push(ch);
        let _ = chars.next();
    }
    digits
        .bytes()
        .fold(0, |value, digit| value * 8 + u32::from(digit - b'0'))
}

#[cfg(test)]
mod tests {
    use super::{decode_char_literal, decode_string_literal, parse_integer};

    #[test]
    fn integer_parser_covers_bases_suffixes_and_invalid_digits() {
        assert_eq!(parse_integer(""), None);
        assert_eq!(parse_integer("0x10ul"), Some((16, true)));
        assert_eq!(parse_integer("0xzz"), None);
        assert_eq!(parse_integer("0Xzz"), None);
        assert_eq!(parse_integer("010"), Some((8, false)));
        assert_eq!(parse_integer("42"), Some((42, false)));
        assert_eq!(parse_integer("09"), None);
        assert_eq!(parse_integer("bad"), None);
    }

    #[test]
    fn char_parser_covers_simple_hex_octal_and_invalid_escapes() {
        assert_eq!(decode_char_literal("65"), Some(65));
        assert_eq!(decode_char_literal("'A'"), Some(65));
        assert_eq!(decode_char_literal("'\\n'"), Some(u32::from(b'\n')));
        assert_eq!(decode_char_literal("'\\t'"), Some(u32::from(b'\t')));
        assert_eq!(decode_char_literal("'\\r'"), Some(u32::from(b'\r')));
        assert_eq!(decode_char_literal("'\\\\'"), Some(u32::from(b'\\')));
        assert_eq!(decode_char_literal("'\\''"), Some(u32::from(b'\'')));
        assert_eq!(decode_char_literal("'\\\"'"), Some(u32::from(b'"')));
        assert_eq!(decode_char_literal("'\\?'"), Some(u32::from(b'?')));
        assert_eq!(decode_char_literal("'\\a'"), Some(0x07));
        assert_eq!(decode_char_literal("'\\b'"), Some(0x08));
        assert_eq!(decode_char_literal("'\\f'"), Some(0x0c));
        assert_eq!(decode_char_literal("'\\v'"), Some(0x0b));
        assert_eq!(decode_char_literal("'\\x41'"), Some(65));
        assert_eq!(decode_char_literal("'\\101'"), Some(65));
        assert_eq!(decode_char_literal("'\\12x'"), Some(u32::from(b'\n')));
        assert_eq!(decode_char_literal("'\\z'"), None);
        assert_eq!(decode_char_literal("''"), None);
    }

    #[test]
    fn string_parser_stops_hex_at_first_non_hex_and_handles_octal() {
        assert_eq!(
            decode_string_literal("\"a\\n\\x21\"").as_deref(),
            Some("a\n!")
        );
        assert_eq!(decode_string_literal("\"\\x41Z\"").as_deref(), Some("AZ"));
        assert_eq!(decode_string_literal("\"\\x110000\""), None);
        assert_eq!(decode_string_literal("\"\\101\"").as_deref(), Some("A"));
        assert_eq!(decode_string_literal("\"\\12x\"").as_deref(), Some("\nx"));
        assert_eq!(decode_string_literal("\"\\x\""), None);
    }
}

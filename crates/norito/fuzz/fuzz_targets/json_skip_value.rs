#![no_main]
use libfuzzer_sys::fuzz_target;
// JSON-safe string content from arbitrary bytes (without surrounding quotes).
fn esc_str(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    for &b in data {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x00..=0x1F => {
                out.push_str("\\u00");
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push(HEX[((b >> 4) & 0x0F) as usize] as char);
                out.push(HEX[(b & 0x0F) as usize] as char);
            }
            0x20..=0x7E => out.push(b as char),
            _ => {
                out.push_str("\\u00");
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push(HEX[((b >> 4) & 0x0F) as usize] as char);
                out.push(HEX[(b & 0x0F) as usize] as char);
            }
        }
    }
    out
}
// Simple recursive generator for nested JSON from bytes; depth and size limited.
fn derive_limits(data: &[u8]) -> (usize, usize) {
    // Derive max depth in [4..12] and a token budget in [256..4096]
    let b0 = *data.first().unwrap_or(&7);
    let b1 = *data.get(1).unwrap_or(&128);
    let max_depth = 4 + (b0 as usize % 9); // 4..12
    let budget = 256 + ((b1 as usize) * 16).min(3840); // up to 4096
    (max_depth, budget)
}
fn take_slice<'a>(data: &'a [u8], idx: &mut usize, max_len: usize) -> &'a [u8] {
    if *idx >= data.len() {
        return &data[0..0];
    }
    let len = 1 + (data[*idx] as usize % max_len.max(1));
    *idx += 1;
    let end = (*idx + len).min(data.len());
    let s = &data[*idx..end];
    *idx = end;
    s
}
fn gen_key(data: &[u8], idx: &mut usize) -> String {
    // Build a JSON key content that includes escaped characters.
    // Returned string is already escaped for use inside quotes.
    let bytes = take_slice(data, idx, 16);
    if bytes.is_empty() {
        return "k".to_string();
    }
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    s.push('k');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        match b % 12 {
            0 => s.push_str("\\\""), // escaped quote
            1 => s.push_str("\\\\"), // backslash
            2 => s.push_str("\\n"),
            3 => s.push_str("\\r"),
            4 => s.push_str("\\t"),
            5 => s.push_str("\\/"),
            6 => {
                // \u00XX form
                s.push_str("\\u00");
                s.push(HEX[((b >> 4) & 0x0F) as usize] as char);
                s.push(HEX[(b & 0x0F) as usize] as char);
            }
            7 => {
                // surrogate pair for 😀 to exercise pair handling
                s.push_str("\\uD83D\\uDE03");
            }
            _ => {
                // printable ascii or hex nibble fallback
                if (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\' {
                    s.push(b as char);
                } else {
                    s.push_str("\\u00");
                    s.push(HEX[((b >> 4) & 0x0F) as usize] as char);
                    s.push(HEX[(b & 0x0F) as usize] as char);
                }
            }
        }
        i += 1;
    }
    s
}
fn gen_number(data: &[u8], idx: &mut usize, tag: u8) -> String {
    // Integers or simple floats
    if (tag & 1) == 0 {
        let sign = if (tag & 0x80) != 0 { -1i64 } else { 1i64 };
        let mag = (tag as i64) & 0x7F;
        format!("{}", sign * mag)
    } else {
        let int = (tag as u32) % 1000;
        let frac_b = *data.get(*idx).unwrap_or(&0);
        *idx = (*idx).saturating_add(1);
        let frac = (frac_b as u32) % 1000;
        let exp_b = *data.get(*idx).unwrap_or(&0);
        *idx = (*idx).saturating_add(1);
        let exp = (exp_b as u32) % 10;
        format!(
            "{}.{}e{}{}",
            int,
            frac,
            if (tag & 0x40) != 0 { '-' } else { '+' },
            exp
        )
    }
}
fn gen_json(
    data: &[u8],
    depth: usize,
    max_depth: usize,
    budget: &mut usize,
    idx: &mut usize,
) -> String {
    if *budget == 0 {
        return String::from("null");
    }
    if *idx >= data.len() || depth >= max_depth {
        *budget = budget.saturating_sub(1);
        let leaf = take_slice(data, idx, 32);
        return format!("\"{}\"", esc_str(leaf));
    }
    let tag = data[*idx];
    *idx += 1;
    *budget = budget.saturating_sub(1);
    match tag % 8 {
        0 => {
            // string
            let leaf = take_slice(data, idx, 32);
            format!("\"{}\"", esc_str(leaf))
        }
        1 => gen_number(data, idx, tag),
        2 => String::from("true"),
        3 => String::from("false"),
        4 => String::from("null"),
        5 => {
            // array (1..=4 elements)
            let mut out = String::from("[");
            let count = 1 + (tag as usize % 4);
            for i in 0..count {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&gen_json(data, depth + 1, max_depth, budget, idx));
                if *budget == 0 {
                    break;
                }
            }
            out.push(']');
            out
        }
        _ => {
            // object (1..=4 fields) with variable keys
            let mut out = String::from("{");
            let count = 1 + (tag as usize % 4);
            for i in 0..count {
                if i > 0 {
                    out.push(',');
                }
                let key = gen_key(data, idx);
                out.push('"');
                out.push_str(&key);
                out.push('"');
                out.push(':');
                out.push_str(&gen_json(data, depth + 1, max_depth, budget, idx));
                if *budget == 0 {
                    break;
                }
            }
            out.push('}');
            out
        }
    }
}
// Build a JSON array: [<nested_value>, "needle"]
fn json_nested_with_tail_str(data: &[u8]) -> String {
    let (max_depth, mut budget) = derive_limits(data);
    let mut idx = 0usize;
    let first = gen_json(data, 0, max_depth, &mut budget, &mut idx);
    let tail_bytes = take_slice(data, &mut idx, 24);
    let tail = esc_str(tail_bytes);
    format!("[{},\"{}\"]", first, tail)
}
fuzz_target!(|data: &[u8]| {
    // Exercise both Parser and TapeWalker skip_value across nested structures.
    let s = json_nested_with_tail_str(data);
    // Parser::skip_value
    let mut p = norito::json::Parser::new(&s);
    if p.consume_char(b'[').is_ok() {
        let _ = p.skip_value();
        let _ = p.consume_comma_if_present();
        let _ = p.parse_string();
    }
    // TapeWalker::skip_value
    let mut w = norito::json::TapeWalker::new(&s);
    if let Some((off, ch)) = w.peek_struct()
        && ch == b'['
    {
        let _ = w.next_struct();
        w.sync_to_raw(off + 1);
    }
    let _ = w.skip_value();
    let _ = w.consume_comma_if_present();
    let mut arena = norito::json::Arena::new();
    let _ = w.parse_string_ref_inline(&mut arena);
});

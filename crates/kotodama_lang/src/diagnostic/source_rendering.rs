//! Bounded source excerpts and terminal-cell underlines from immutable snapshots.
mod widths;

use super::SourceSpan;
use crate::source::SourceFile;
use std::fmt::Write as _;

const MAX_EXCERPT_LINES: usize = 4;
const MAX_LINE_CHARACTERS: usize = 180;
const CONTEXT_CHARACTERS: usize = 60;
const TAB_WIDTH: usize = 4;

/// Render plain source and underlines using fixed Unicode widths and four-cell tab stops.
/// Display escapes prevent terminal controls from changing the excerpt's layout. Source
/// byte ranges, scalar columns, source identity, and machine-readable diagnostics are untouched.
pub(super) fn render(output: &mut String, source: &SourceFile, span: &SourceSpan) {
    let Some(range) = span.byte_range else { return };
    if source.slice(range).is_none() {
        return;
    }
    let start = range.start as usize;
    let end = range.end as usize;
    let mut offset = 0;
    let mut shown = 0;
    for (index, raw_line) in source.text().split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let line_end = offset + line.len();
        let intersects = start <= line_end && (end > offset || start == end && start == offset);
        if intersects {
            if shown == MAX_EXCERPT_LINES {
                output.push_str("\n      | ...");
                break;
            }
            let mut local_start = start.saturating_sub(offset).min(line.len());
            let local_end = end.saturating_sub(offset).min(line.len());
            // Continuation lines of a multi-line span underline their code,
            // not their indentation.
            if start < offset {
                let indentation = line.len() - line.trim_start_matches([' ', '\t']).len();
                if indentation < local_end {
                    local_start = local_start.max(indentation);
                }
            }
            render_line(output, index + 1, line, local_start, local_end);
            shown += 1;
        }
        offset += raw_line.len() + 1;
        if offset > end {
            break;
        }
    }
}

fn display_character(character: char, column: usize, at_left_edge: bool) -> (String, usize) {
    if character == '\t' {
        let width = TAB_WIDTH - column % TAB_WIDTH;
        return (" ".repeat(width), width);
    }
    let width = widths::width(character);
    // Joining, direction, and variation controls must not reinterpret neighbouring cells.
    // Unicode line separators and non-ASCII spaces other than the
    // ideographic space are shown escaped too: they are rejected source
    // characters that would otherwise look like ordinary spacing.
    let changes_layout = matches!(character,
        '\u{00ad}' | '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{206f}' | '\u{fe00}'..='\u{fe0f}' | '\u{feff}'
        | '\u{e0000}'..='\u{e0fff}')
        || (character.is_whitespace() && !character.is_ascii() && character != '\u{3000}');
    if character.is_control() || changes_layout || at_left_edge && width == 0 {
        let escaped = character.escape_unicode().to_string();
        let width = escaped.len();
        return (escaped, width);
    }
    (character.to_string(), width)
}

fn render_line(output: &mut String, number: usize, line: &str, start: usize, end: usize) {
    let first = line[..start]
        .chars()
        .count()
        .saturating_sub(CONTEXT_CHARACTERS);
    let mut excerpt = String::new();
    let mut column = 0;
    let mut origin = 0;
    let mut last_ink = 0;
    let mut mark_start = None;
    let mut mark_end = 0;
    let mut truncated = false;
    for (index, (byte, character)) in line.char_indices().enumerate() {
        if index == first + MAX_LINE_CHARACTERS {
            truncated = true;
            break;
        }
        let visible = index >= first;
        if index == first {
            origin = column;
        }
        let (display, width) = display_character(character, column, index == first);
        if visible {
            excerpt.push_str(&display);
            let selected = if start == end {
                byte == start
            } else {
                byte < end && byte + character.len_utf8() > start
            };
            if selected {
                // A selected combining mark underlines its base cell, even when the
                // base itself lies just outside the source byte selection.
                mark_start.get_or_insert(if width == 0 {
                    last_ink.max(origin)
                } else {
                    column
                });
                mark_end = column + width;
            }
        }
        if width > 0 {
            last_ink = column;
        }
        column += width;
    }
    let prefix_width = if first == 0 { 0 } else { 3 };
    let caret = mark_start.unwrap_or(column).saturating_sub(origin) + prefix_width;
    let underline_width = if start == end {
        1
    } else {
        mark_end.saturating_sub(mark_start.unwrap_or(column)).max(1)
    };
    let gutter = number.to_string().len().max(4);
    let _ = write!(
        output,
        "\n {number:>gutter$} | {}{excerpt}{}\n {:gutter$} | {}{}",
        if first == 0 { "" } else { "..." },
        if truncated { "..." } else { "" },
        "",
        " ".repeat(caret),
        "^".repeat(underline_width)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{SourceId, TextRange};

    fn excerpt(text: &str, start: usize, end: usize) -> String {
        let source = SourceFile::new(SourceId(0), "example.ko", text);
        let span = SourceSpan::from_range(&source, TextRange::new(start as u32, end as u32));
        let mut output = String::new();
        render(&mut output, &source, &span);
        output
    }

    #[test]
    fn underlines_use_japanese_width_and_expanded_tab_stops() {
        let text = "\tlet 日本 = e\u{301};\n";
        let start = text.find("日本").unwrap();
        assert_eq!(
            excerpt(text, start, start + 6),
            "\n    1 |     let 日本 = e\u{301};\n      |         ^^^^"
        );
        let text = "日本\tx";
        assert_eq!(
            excerpt(text, text.len() - 1, text.len()),
            "\n    1 | 日本    x\n      |         ^"
        );
    }

    #[test]
    fn combining_marks_do_not_shift_following_underlines() {
        let text = "e\u{301} 日本";
        let start = text.find("日本").unwrap();
        assert_eq!(
            excerpt(text, start, text.len()),
            "\n    1 | e\u{301} 日本\n      |   ^^^^"
        );
        assert_eq!(excerpt(text, 1, 3), "\n    1 | e\u{301} 日本\n      | ^");
        assert_eq!(widths::width('\u{3099}'), 0);
        assert_eq!(widths::width('日'), 2);
        assert_eq!(widths::width('a'), 1);
    }

    #[test]
    fn empty_ranges_and_crlf_line_boundaries_are_exact() {
        assert_eq!(excerpt("a\r\nb\r\n", 0, 3), "\n    1 | a\n      | ^");
        assert_eq!(excerpt("a\n", 2, 2), "\n    2 | \n      | ^");
        assert_eq!(excerpt("a", 1, 1), "\n    1 | a\n      |  ^");
        assert_eq!(excerpt("", 0, 0), "\n    1 | \n      | ^");
    }

    #[test]
    fn line_and_character_bounds_keep_the_selected_location_visible() {
        let text = "a\nb\nc\nd\ne\nf\n";
        let output = excerpt(text, 0, text.len());
        assert_eq!(output.matches('^').count(), MAX_EXCERPT_LINES);
        assert!(output.ends_with("| ..."));
        let text = format!("{}日本{}", "x".repeat(400), "z".repeat(400));
        let output = excerpt(&text, 400, 406);
        let lines: Vec<_> = output.lines().collect();
        assert!(lines[1].starts_with("    1 | ..."));
        assert!(lines[1].ends_with("..."));
        assert_eq!(lines[1].chars().count(), 8 + 3 + MAX_LINE_CHARACTERS + 3);
        assert_eq!(
            lines[2],
            format!("      | {}^^^^", " ".repeat(CONTEXT_CHARACTERS + 3))
        );
    }

    #[test]
    fn continuation_lines_do_not_underline_indentation() {
        let text = "call(\n    first,\n)";
        assert_eq!(
            excerpt(text, 0, text.len()),
            "\n    1 | call(\n      | ^^^^^\n    2 |     first,\n      |     ^^^^^^\n    3 | )\n      | ^"
        );
    }
    #[test]
    fn rejected_unicode_spacing_is_shown_escaped_but_ideographic_space_is_not() {
        assert_eq!(
            excerpt("a\u{2028}b", 0, 1),
            "\n    1 | a\\u{2028}b\n      | ^"
        );
        assert_eq!(excerpt("a\u{a0}b", 0, 1), "\n    1 | a\\u{a0}b\n      | ^");
        assert_eq!(
            excerpt("a\u{3000}b", 0, 1),
            "\n    1 | a\u{3000}b\n      | ^"
        );
    }
    #[test]
    fn terminal_controls_are_visible_and_cannot_move_underlines() {
        let text = "\u{1b}[31m日本";
        let start = text.find("日本").unwrap();
        assert_eq!(
            excerpt(text, start, text.len()),
            "\n    1 | \\u{1b}[31m日本\n      |           ^^^^"
        );
        assert!(!excerpt(text, start, text.len()).contains('\u{1b}'));
    }
}

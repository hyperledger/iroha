//! Completion-only repair of an incomplete buffer.
//!
//! A repaired buffer is analyzed in a temporary snapshot only to recover receiver types and
//! lexical scope at the cursor. It is never returned to a build API, and callers consume
//! completion candidates only.
use super::{SourceFile, Token, TokenKind};

const fn closer(kind: &TokenKind) -> Option<char> {
    match kind {
        TokenKind::LParen => Some(')'),
        TokenKind::LBracket => Some(']'),
        TokenKind::LBrace => Some('}'),
        _ => None,
    }
}

/// Whether an expression operand must follow this token.
const fn expects_operand(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Equal
            | TokenKind::PlusEqual
            | TokenKind::MinusEqual
            | TokenKind::StarEqual
            | TokenKind::SlashEqual
            | TokenKind::PercentEqual
            | TokenKind::Plus
            | TokenKind::Minus
            | TokenKind::Star
            | TokenKind::Slash
            | TokenKind::Percent
            | TokenKind::EqualEqual
            | TokenKind::BangEqual
            | TokenKind::Less
            | TokenKind::LessEqual
            | TokenKind::Greater
            | TokenKind::GreaterEqual
            | TokenKind::AndAnd
            | TokenKind::OrOr
            | TokenKind::Bang
            | TokenKind::LParen
            | TokenKind::LBracket
            | TokenKind::Comma
            | TokenKind::Colon
            | TokenKind::FatArrow
            | TokenKind::Question
            | TokenKind::Return
    )
}

/// Append the closing delimiters every still-open delimiter needs at the end of the buffer.
fn close_at_end(mut text: String) -> Option<String> {
    let tokens = crate::lexer::lex(&text).ok()?;
    let mut closing = Vec::new();
    for token in tokens {
        if let Some(close) = closer(&token.kind) {
            closing.push(close);
        } else if matches!(
            token.kind,
            TokenKind::RParen | TokenKind::RBrace | TokenKind::RBracket
        ) {
            closing.pop();
        }
    }
    text.extend(closing.into_iter().rev());
    Some(text)
}

/// Ordered candidate repairs for completion at `offset`, most conservative first.
///
/// The active member or identifier becomes a parseable placeholder. Because the cursor is
/// usually inside an unfinished statement (`let x = Scores.`, `require(Scores.`,
/// `return Scores.`), later candidates also close the statement's open parentheses and
/// brackets, terminate it with `;`, or give an `if`/`for` header an empty block.
pub(super) fn completion_repairs(file: &SourceFile, tokens: &[Token], offset: u32) -> Vec<String> {
    let text = file.text();
    let before = tokens
        .iter()
        .filter(|token| token.range.start < offset && token.kind != TokenKind::EOF)
        .collect::<Vec<_>>();
    let Some(last) = before.last() else {
        return Vec::new();
    };
    let (start, end, placeholder) = if last.kind == TokenKind::Dot {
        if tokens
            .iter()
            .any(|token| token.range.start == offset && matches!(token.kind, TokenKind::Ident(_)))
        {
            return Vec::new();
        }
        (offset, offset, "len()".to_owned())
    } else if matches!(last.kind, TokenKind::Ident(_)) {
        if last.range.end != offset {
            return Vec::new();
        }
        let member = before
            .len()
            .checked_sub(2)
            .and_then(|index| before.get(index))
            .is_some_and(|token| token.kind == TokenKind::Dot);
        let placeholder = if member {
            "len()".to_owned()
        } else {
            format!(
                "0{}",
                " ".repeat(last.range.end.saturating_sub(last.range.start + 1) as usize)
            )
        };
        (last.range.start, last.range.end, placeholder)
    } else if expects_operand(&last.kind) {
        (offset, offset, "0".to_owned())
    } else {
        return Vec::new();
    };
    let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
        return Vec::new();
    };
    if end > text.len() || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return Vec::new();
    }
    // Parentheses and brackets opened by the current statement and still unclosed.
    let mut open = Vec::new();
    for token in &before {
        match token.kind {
            TokenKind::LBrace | TokenKind::Semicolon => open.clear(),
            TokenKind::LParen | TokenKind::LBracket => open.push(&token.kind),
            TokenKind::RParen | TokenKind::RBracket => {
                open.pop();
            }
            _ => {}
        }
    }
    // Delimiters the editor already auto-closed right after the cursor.
    let mut following = tokens
        .iter()
        .filter(|token| token.range.start >= offset && token.kind != TokenKind::EOF)
        .peekable();
    let mut closed_after = offset;
    while let Some(token) = following.peek() {
        let matches_open = open.last().is_some_and(|kind| {
            matches!(
                (kind, &token.kind),
                (TokenKind::LParen, TokenKind::RParen) | (TokenKind::LBracket, TokenKind::RBracket)
            )
        });
        if !matches_open {
            break;
        }
        closed_after = token.range.end;
        open.pop();
        following.next();
    }
    let closers = open
        .iter()
        .rev()
        .filter_map(|kind| closer(kind))
        .collect::<String>();
    let mut candidates = Vec::new();
    let mut push = |insert_at_cursor: &str, after_closed: &str| {
        let mut repaired = String::with_capacity(text.len() + 16);
        repaired.push_str(&text[..start]);
        repaired.push_str(&placeholder);
        repaired.push_str(insert_at_cursor);
        let closed_after = usize::try_from(closed_after).unwrap_or(end).max(end);
        repaired.push_str(&text[end..closed_after]);
        repaired.push_str(after_closed);
        repaired.push_str(&text[closed_after..]);
        if let Some(repaired) = close_at_end(repaired)
            && repaired != text
            && !candidates.contains(&repaired)
        {
            candidates.push(repaired);
        }
    };
    push("", "");
    push(&closers, ";");
    push(&closers, "");
    push(&closers, " {}");
    // A surrounding call that does not type-check (a builtin missing required arguments,
    // for example) can hide the receiver's type. As a last resort, isolate the receiver
    // chain as its own statement by blanking the statement text before it.
    if placeholder == "len()"
        && let Some(isolated) =
            isolated_receiver(text, &before, start, end, closed_after, &placeholder)
        && !candidates.contains(&isolated)
    {
        candidates.push(isolated);
    }
    candidates
}

/// Replace every character of `range` with spaces, preserving byte offsets and newlines.
fn blank(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character == '\n' {
                "\n".to_owned()
            } else {
                " ".repeat(character.len_utf8())
            }
        })
        .collect()
}

/// The buffer with the member receiver's chain as a standalone `receiver.len();` statement.
fn isolated_receiver(
    text: &str,
    before: &[&Token],
    start: usize,
    end: usize,
    closed_after: u32,
    placeholder: &str,
) -> Option<String> {
    let dot = before
        .iter()
        .rposition(|token| token.kind == TokenKind::Dot)?;
    let mut first = dot;
    let mut depth = 0_usize;
    for index in (0..dot).rev() {
        match before[index].kind {
            TokenKind::RParen | TokenKind::RBracket => depth += 1,
            TokenKind::LParen | TokenKind::LBracket if depth > 0 => depth -= 1,
            TokenKind::LParen | TokenKind::LBracket => break,
            _ if depth > 0 => {}
            TokenKind::Ident(_) | TokenKind::Dot | TokenKind::ColonColon => {}
            _ => break,
        }
        first = index;
    }
    if first == dot {
        return None;
    }
    let receiver = usize::try_from(before[first].range.start).ok()?;
    let statement = before[..first]
        .iter()
        .rev()
        .find(|token| {
            matches!(
                token.kind,
                TokenKind::Semicolon | TokenKind::LBrace | TokenKind::RBrace
            )
        })
        .map_or(Some(0), |token| usize::try_from(token.range.end).ok())?;
    let closed_after = usize::try_from(closed_after).ok()?.max(end);
    let mut repaired = String::with_capacity(text.len() + 8);
    repaired.push_str(&text[..statement]);
    repaired.push_str(&blank(&text[statement..receiver]));
    repaired.push_str(&text[receiver..start]);
    repaired.push_str(placeholder);
    if !text[closed_after..].trim_start().starts_with(';') {
        repaired.push(';');
    }
    repaired.push_str(&blank(&text[end..closed_after]));
    repaired.push_str(&text[closed_after..]);
    close_at_end(repaired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{FrontendBudget, SourceId};

    fn repairs(source: &str) -> Vec<String> {
        let offset = u32::try_from(source.find('|').expect("cursor")).expect("short source");
        let text = source.replacen('|', "", 1);
        let file = SourceFile::new(SourceId(0), "repair.ko", &text);
        let budget = FrontendBudget::v1();
        let (tokens, _) =
            crate::lexer::lower_lexed_recovering(&file, budget, crate::syntax::lex(&file, budget));
        completion_repairs(&file, &tokens, offset)
    }

    #[test]
    fn repairs_terminate_and_close_the_active_statement() {
        let candidates = repairs("seiyaku A { fn f() { let x = Scores.|\n return; } }");
        assert!(
            candidates
                .iter()
                .any(|text| text.contains("let x = Scores.len();\n return; } }")),
            "{candidates:#?}"
        );
        let candidates = repairs("seiyaku A { fn f() { require(Scores.| } }");
        assert!(
            candidates
                .iter()
                .any(|text| text.contains("require(Scores.len()); } }")),
            "{candidates:#?}"
        );
        let candidates = repairs("seiyaku A { fn f() { require(Scores.|) } }");
        assert!(
            candidates
                .iter()
                .any(|text| text.contains("require(Scores.len()); } }")),
            "{candidates:#?}"
        );
        let candidates = repairs("seiyaku A { fn f() { if (Scores.g| } }");
        assert!(
            candidates
                .iter()
                .any(|text| text.contains("if (Scores.len()) {} } }")),
            "{candidates:#?}"
        );
        let candidates = repairs("seiyaku A { fn f() { require(Scores.get(who).| } }");
        assert!(
            candidates
                .iter()
                .any(|text| text == "seiyaku A { fn f() {         Scores.get(who).len(); } }"),
            "{candidates:#?}"
        );
        let candidates = repairs("seiyaku A { fn f() { Values.get(1).| } }");
        assert_eq!(
            candidates[0],
            "seiyaku A { fn f() { Values.get(1).len() } }"
        );
    }

    #[test]
    fn complete_members_and_non_word_positions_need_no_repair() {
        assert!(repairs("seiyaku A { fn f() { Scores.|len() } }").is_empty());
        assert!(repairs("seiyaku A { fn f() { let |").is_empty());
        assert!(repairs("|").is_empty());
        let operand = repairs("seiyaku A { fn f(int a) { let x = 1 +| } }");
        assert!(
            operand
                .iter()
                .any(|text| text.contains("let x = 1 +0; } }")),
            "{operand:#?}"
        );
    }
}

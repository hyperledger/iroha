//! Lossless, recovering Kotodama lexer.
use super::{cst::GreenToken, kind::SyntaxKind};
use crate::{
    diagnostic::{Diagnostic, DiagnosticFix, DiagnosticPhase, SourcePosition, SourceSpan},
    lexer::{TokenKind, V1_PUNCTUATION_KINDS, v1_keyword_kind},
    source::{FrontendBudget, SourceFile, TextRange},
};
/// Lossless lexer output.
#[derive(Clone, Debug)]
pub struct Lexed {
    /// Tokens in source order, including trivia and end-of-file.
    pub tokens: Vec<GreenToken>,
    /// Bounded lexical and budget diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Lexical diagnostics discarded after reaching the fixed V1 cap.
    pub(crate) omitted_diagnostics: usize,
}
fn diagnostic(
    source: &SourceFile,
    code: &'static str,
    message: impl Into<String>,
    range: TextRange,
) -> Diagnostic {
    let start = source.line_column(range.start);
    let end = source.line_column(range.end);
    Diagnostic::error(
        code,
        DiagnosticPhase::Lex,
        message,
        Some(SourceSpan {
            package_identity: source.package_identity().map(str::to_owned),
            source: Some(source.name().to_owned()),
            start: SourcePosition {
                line: start.line,
                column: start.column,
            },
            end: SourcePosition {
                line: end.line,
                column: end.column,
            },
            byte_range: Some(range),
        }),
    )
    .with_source(source)
}
fn keyword_kind(text: &str) -> SyntaxKind {
    match v1_keyword_kind(text) {
        Some(TokenKind::Fn) => SyntaxKind::KwFn,
        Some(TokenKind::Let) => SyntaxKind::KwLet,
        Some(TokenKind::Var) => SyntaxKind::KwVar,
        Some(TokenKind::Const) => SyntaxKind::KwConst,
        Some(TokenKind::Return) => SyntaxKind::KwReturn,
        Some(TokenKind::Break) => SyntaxKind::KwBreak,
        Some(TokenKind::Continue) => SyntaxKind::KwContinue,
        Some(TokenKind::State) => SyntaxKind::KwState,
        Some(TokenKind::Struct) => SyntaxKind::KwStruct,
        Some(TokenKind::Event) => SyntaxKind::KwEvent,
        Some(TokenKind::Emit) => SyntaxKind::KwEmit,
        Some(TokenKind::Error) => SyntaxKind::KwError,
        Some(TokenKind::Enum) => SyntaxKind::KwEnum,
        Some(TokenKind::Authorize) => SyntaxKind::KwAuthorize,
        Some(TokenKind::Permission) => SyntaxKind::KwPermission,
        Some(TokenKind::Trigger) => SyntaxKind::KwTrigger,
        Some(TokenKind::If) => SyntaxKind::KwIf,
        Some(TokenKind::Match) => SyntaxKind::KwMatch,
        Some(TokenKind::Else) => SyntaxKind::KwElse,
        Some(TokenKind::For) => SyntaxKind::KwFor,
        Some(TokenKind::In) => SyntaxKind::KwIn,
        Some(TokenKind::Seiyaku) => SyntaxKind::KwSeiyaku,
        Some(TokenKind::Module) => SyntaxKind::KwModule,
        Some(TokenKind::Include) => SyntaxKind::KwInclude,
        Some(TokenKind::Import) => SyntaxKind::KwImport,
        Some(TokenKind::As) => SyntaxKind::KwAs,
        Some(TokenKind::Export) => SyntaxKind::KwExport,
        Some(TokenKind::Kotoage) => SyntaxKind::KwKotoage,
        Some(TokenKind::Hajimari) => SyntaxKind::KwHajimari,
        Some(TokenKind::Kaizen) => SyntaxKind::KwKaizen,
        Some(TokenKind::View) => SyntaxKind::KwView,
        Some(TokenKind::True) => SyntaxKind::KwTrue,
        Some(TokenKind::False) => SyntaxKind::KwFalse,
        Some(other) => unreachable!("non-keyword token in V1 keyword table: {other:?}"),
        None => SyntaxKind::Ident,
    }
}
struct Scanner<'source> {
    text: &'source str,
    pos: usize,
    previous_significant: Option<SyntaxKind>,
}
/// One lexical error with site-specific help and exact fixes.
#[derive(Clone)]
struct LexicalError {
    code: &'static str,
    message: String,
    help: Option<String>,
    /// Absolute replacement ranges, preferred first.
    fixes: Vec<(TextRange, String)>,
    strip_numeric_suffix: bool,
}
impl LexicalError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            help: None,
            fixes: Vec::new(),
            strip_numeric_suffix: false,
        }
    }
    fn help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
    fn fix(mut self, range: TextRange, replacement: impl Into<String>) -> Self {
        self.fixes.push((range, replacement.into()));
        self
    }
    fn retired_numeric_suffix(suffix: &str) -> Self {
        Self {
            strip_numeric_suffix: matches!(suffix, "amt" | "qty"),
            ..Self::new(
                "E_RETIRED_NUMERIC_SUFFIX",
                "numeric literal suffixes are not part of Kotodama V1; use an unsuffixed literal in an int, decimal, or quantity context",
            )
        }
    }
}
/// Characters that make reviewed text differ from what compiles: bidirectional
/// controls reorder the display, and Unicode line separators end a line in
/// many viewers but not in the lexer. They are rejected everywhere, including
/// comments and string literals.
fn deceptive_character(character: char) -> Option<(&'static str, &'static str)> {
    Some(match character {
        '\u{202a}' => ("E_BIDI_CONTROL_CHARACTER", "LEFT-TO-RIGHT EMBEDDING"),
        '\u{202b}' => ("E_BIDI_CONTROL_CHARACTER", "RIGHT-TO-LEFT EMBEDDING"),
        '\u{202c}' => ("E_BIDI_CONTROL_CHARACTER", "POP DIRECTIONAL FORMATTING"),
        '\u{202d}' => ("E_BIDI_CONTROL_CHARACTER", "LEFT-TO-RIGHT OVERRIDE"),
        '\u{202e}' => ("E_BIDI_CONTROL_CHARACTER", "RIGHT-TO-LEFT OVERRIDE"),
        '\u{2066}' => ("E_BIDI_CONTROL_CHARACTER", "LEFT-TO-RIGHT ISOLATE"),
        '\u{2067}' => ("E_BIDI_CONTROL_CHARACTER", "RIGHT-TO-LEFT ISOLATE"),
        '\u{2068}' => ("E_BIDI_CONTROL_CHARACTER", "FIRST STRONG ISOLATE"),
        '\u{2069}' => ("E_BIDI_CONTROL_CHARACTER", "POP DIRECTIONAL ISOLATE"),
        '\u{200e}' => ("E_BIDI_CONTROL_CHARACTER", "LEFT-TO-RIGHT MARK"),
        '\u{200f}' => ("E_BIDI_CONTROL_CHARACTER", "RIGHT-TO-LEFT MARK"),
        '\u{061c}' => ("E_BIDI_CONTROL_CHARACTER", "ARABIC LETTER MARK"),
        '\u{2028}' => ("E_UNICODE_LINE_SEPARATOR", "LINE SEPARATOR"),
        '\u{2029}' => ("E_UNICODE_LINE_SEPARATOR", "PARAGRAPH SEPARATOR"),
        '\u{0085}' => ("E_UNICODE_LINE_SEPARATOR", "NEXT LINE"),
        _ => return None,
    })
}
/// Whitespace that separates tokens: ASCII whitespace and the ideographic
/// space U+3000 that Japanese input methods insert. `koto fmt` rewrites U+3000
/// to an ASCII space.
const fn is_token_separator(character: char) -> bool {
    matches!(
        character,
        ' ' | '\t' | '\n' | '\r' | '\u{000b}' | '\u{000c}' | '\u{3000}'
    )
}
/// ASCII character for a full-width form (U+FF01..=U+FF5E).
fn fullwidth_ascii(character: char) -> Option<char> {
    let code = u32::from(character);
    (0xff01..=0xff5e)
        .contains(&code)
        .then(|| char::from_u32(code - 0xfee0))
        .flatten()
}
/// Whether `character` is written in a Japanese or Chinese script.
fn is_cjk(character: char) -> bool {
    matches!(u32::from(character),
        0x3040..=0x30ff | 0x31f0..=0x31ff | 0x3400..=0x4dbf | 0x4e00..=0x9fff
        | 0xf900..=0xfaff | 0xff66..=0xff9f | 0x20000..=0x2fa1f)
}
/// Diagnose a non-ASCII identifier, distinguishing input-method slips around
/// the branded keywords from genuinely non-ASCII names.
fn non_ascii_identifier_error(text: &str, start: usize) -> LexicalError {
    let range = TextRange::new(start as u32, (start + text.len()) as u32);
    // `言挙げfn`: a kanji keyword glued to the next ASCII word. A name such as
    // `誓約_x` or `誓約2` is an attempted identifier, not a missing space.
    for keyword in &crate::glossary::BRANDED_KEYWORDS {
        if let Some(rest) = text.strip_prefix(keyword.kanji)
            && rest
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_alphabetic())
            && rest
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            let boundary = (start + keyword.kanji.len()) as u32;
            return LexicalError::new(
                "E_KEYWORD_SPACING",
                format!("`{}` and `{rest}` need a space between them", keyword.kanji),
            )
            .help(format!(
                "`{}` is a keyword (also spelled `{}`); separate it from the next word with a space",
                keyword.kanji, keyword.romaji
            ))
            .fix(TextRange::empty(boundary), " ");
        }
    }
    if text
        .chars()
        .any(|character| fullwidth_ascii(character).is_some())
    {
        return fullwidth_error(text, start);
    }
    let keyword = crate::glossary::suggestion_for(text).or_else(|| {
        let length = text.chars().count();
        (text.chars().any(is_cjk) && (2..=4).contains(&length))
            .then(|| {
                // A keyword followed by more characters (`誓約名`) is an attempted
                // identifier, not a misspelling of the keyword.
                crate::glossary::BRANDED_KEYWORDS.iter().find(|keyword| {
                    !text.starts_with(keyword.kanji)
                        && crate::diagnostic::suggest::edit_distance(text, keyword.kanji, 1)
                            .is_some()
                })
            })
            .flatten()
    });
    if let Some(keyword) = keyword {
        return LexicalError::new(
            "E_CONFUSABLE_KEYWORD",
            format!(
                "`{text}` is not a Kotodama keyword; did you mean `{}`/`{}`?",
                keyword.kanji, keyword.romaji
            ),
        )
        .help(format!(
            "`{}` ({}, \u{201c}{}\u{201d}) is spelled exactly `{}` or `{}`; both spellings are the same keyword",
            keyword.kanji, keyword.reading, keyword.literal, keyword.kanji, keyword.romaji
        ))
        .fix(range, keyword.kanji)
        .fix(range, keyword.romaji);
    }
    if text.chars().any(is_cjk) {
        LexicalError::new(
            "K0100",
            format!("non-ASCII identifier `{text}`: identifiers are ASCII"),
        )
        .help("the only Japanese words in Kotodama source are the keywords 誓約, 言挙げ, 始まり and 改善 (also spelled seiyaku, kotoage, hajimari and kaizen); name declarations with ASCII letters, digits and `_`, and keep Japanese text in strings and comments")
    } else {
        LexicalError::new(
            "K0100",
            format!("non-ASCII identifier `{text}`: identifiers are ASCII"),
        )
        .help("name declarations with ASCII letters, digits and `_`; non-ASCII text belongs in string literals and comments")
    }
}
/// `E_FULLWIDTH_ASCII` for text containing full-width forms of ASCII
/// characters, typically typed with a Japanese input method still active.
fn fullwidth_error(text: &str, start: usize) -> LexicalError {
    let ascii = text
        .chars()
        .map(|character| fullwidth_ascii(character).unwrap_or(character))
        .collect::<String>();
    let first = text
        .chars()
        .find(|character| fullwidth_ascii(*character).is_some())
        .unwrap_or('\u{ff01}');
    LexicalError::new(
        "E_FULLWIDTH_ASCII",
        format!(
            "full-width `{text}` (U+{:04X}) is not Kotodama syntax; write `{ascii}`",
            u32::from(first)
        ),
    )
    .help("punctuation, letters and digits outside string literals are ASCII; switch the input method to half-width (direct input) for code")
    .fix(TextRange::new(start as u32, (start + text.len()) as u32), ascii)
}
#[derive(Clone)]
enum ScannedNumber {
    Integer,
    Decimal,
    Invalid(LexicalError),
}
impl<'source> Scanner<'source> {
    fn new(source: &'source SourceFile) -> Self {
        Self {
            text: source.text(),
            pos: 0,
            previous_significant: None,
        }
    }
    fn rest(&self) -> &'source str {
        &self.text[self.pos..]
    }
    fn current(&self) -> Option<char> {
        self.rest().chars().next()
    }
    fn bump(&mut self) -> Option<char> {
        let character = self.current()?;
        self.pos += character.len_utf8();
        Some(character)
    }
    fn starts_with(&self, pattern: &str) -> bool {
        self.rest().starts_with(pattern)
    }
    fn scan_whitespace(&mut self) {
        while self.current().is_some_and(|character| {
            is_token_separator(character)
                || deceptive_character(character)
                    .is_some_and(|(code, _)| code == "E_UNICODE_LINE_SEPARATOR")
        }) {
            self.bump();
        }
    }
    fn scan_line_comment(&mut self) {
        self.pos += 2;
        while let Some(character) = self.bump() {
            if character == '\n' {
                break;
            }
        }
    }
    fn scan_block_comment(&mut self) -> bool {
        self.pos += 2;
        while self.pos < self.text.len() {
            if self.starts_with("*/") {
                self.pos += 2;
                return true;
            }
            self.bump();
        }
        false
    }
    fn scan_identifier(&mut self) {
        while self.current().is_some_and(|character| {
            character.is_alphanumeric()
                || character == '_'
                || fullwidth_ascii(character).is_some_and(|ascii| ascii == '_')
        }) {
            self.bump();
        }
    }
    /// Scan an unsuffixed integer or exact base-10 decimal token.
    fn scan_number(&mut self, tuple_index: bool) -> ScannedNumber {
        if self.starts_with("0x") || self.starts_with("0X") {
            self.pos += 2;
            while self
                .current()
                .is_some_and(|character| character.is_ascii_hexdigit() || character == '_')
            {
                self.bump();
            }
            return self.finish_integer();
        }
        if self.starts_with("0b") || self.starts_with("0B") {
            self.pos += 2;
            while self
                .current()
                .is_some_and(|character| matches!(character, '0' | '1' | '_'))
            {
                self.bump();
            }
            return self.finish_integer();
        }
        while self
            .current()
            .is_some_and(|character| character.is_ascii_digit() || character == '_')
        {
            self.bump();
        }
        let mut has_fraction = false;
        // `0..10` is an integer followed by `..`; the parser explains ranges.
        if self.starts_with(".") && !tuple_index && !self.starts_with("..") {
            let after_dot = self.rest()[1..].chars().next();
            if after_dot.is_some_and(|character| character.is_ascii_digit() || character == '_') {
                has_fraction = true;
            } else if !tuple_index {
                self.bump();
                return ScannedNumber::Invalid(LexicalError::new(
                    "E_DECIMAL_MALFORMED",
                    "decimal literals require at least one digit after `.`",
                ));
            }
        }
        if has_fraction {
            self.bump();
            while self
                .current()
                .is_some_and(|character| character.is_ascii_digit() || character == '_')
            {
                self.bump();
            }
        }
        let mut has_exponent = false;
        if matches!(self.current(), Some('e' | 'E')) {
            has_exponent = true;
            self.bump();
            if matches!(self.current(), Some('+' | '-')) {
                self.bump();
            }
            let exponent_start = self.pos;
            while self
                .current()
                .is_some_and(|character| character.is_ascii_digit() || character == '_')
            {
                self.bump();
            }
            if self.pos == exponent_start {
                return ScannedNumber::Invalid(LexicalError::new(
                    "E_DECIMAL_EXPONENT",
                    "decimal exponent requires at least one digit",
                ));
            }
        }
        if self
            .current()
            .is_some_and(|character| character.is_ascii_alphabetic())
        {
            let suffix_start = self.pos;
            self.scan_identifier();
            return ScannedNumber::Invalid(LexicalError::retired_numeric_suffix(
                &self.text[suffix_start..self.pos],
            ));
        }
        if has_fraction || has_exponent {
            ScannedNumber::Decimal
        } else {
            ScannedNumber::Integer
        }
    }
    fn finish_integer(&mut self) -> ScannedNumber {
        if self
            .current()
            .is_some_and(|character| character.is_ascii_alphabetic())
        {
            let suffix_start = self.pos;
            self.scan_identifier();
            ScannedNumber::Invalid(LexicalError::retired_numeric_suffix(
                &self.text[suffix_start..self.pos],
            ))
        } else {
            ScannedNumber::Integer
        }
    }
    fn scan_quoted(&mut self, prefix_bytes: usize) -> bool {
        self.pos += prefix_bytes;
        let Some('"') = self.bump() else {
            return false;
        };
        let mut escaped = false;
        while let Some(character) = self.current() {
            if character == '\n' || character == '\r' {
                return false;
            }
            self.bump();
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                return true;
            }
        }
        false
    }
    fn raw_prefix(&self) -> Option<(bool, usize, usize)> {
        let bytes = self.text.as_bytes();
        let mut cursor = self.pos;
        let is_bytes = if (bytes.get(cursor) == Some(&b'b') && bytes.get(cursor + 1) == Some(&b'r'))
            || (bytes.get(cursor) == Some(&b'r') && bytes.get(cursor + 1) == Some(&b'b'))
        {
            cursor += 2;
            true
        } else if bytes.get(cursor) == Some(&b'r') {
            cursor += 1;
            false
        } else {
            return None;
        };
        let mut hashes = 0_usize;
        while bytes.get(cursor) == Some(&b'#') {
            cursor += 1;
            hashes += 1;
        }
        (bytes.get(cursor) == Some(&b'"')).then_some((is_bytes, cursor + 1, hashes))
    }
    fn scan_raw(&mut self, content_start: usize, hashes: usize) -> bool {
        self.pos = content_start;
        let bytes = self.text.as_bytes();
        while self.pos < bytes.len() {
            if bytes[self.pos] == b'"' {
                let hashes_start = self.pos + 1;
                let hashes_end = hashes_start.saturating_add(hashes);
                if hashes_end <= bytes.len()
                    && bytes[hashes_start..hashes_end]
                        .iter()
                        .all(|byte| *byte == b'#')
                {
                    self.pos = hashes_end;
                    return true;
                }
            }
            self.bump();
        }
        false
    }
    /// Whether the previous significant token ends an operand, so a binary
    /// operator may follow it.
    fn previous_ends_operand(&self) -> bool {
        matches!(
            self.previous_significant,
            Some(
                SyntaxKind::Ident
                    | SyntaxKind::Number
                    | SyntaxKind::Decimal
                    | SyntaxKind::String
                    | SyntaxKind::Bytes
                    | SyntaxKind::KwTrue
                    | SyntaxKind::KwFalse
                    | SyntaxKind::RParen
                    | SyntaxKind::RBracket
            )
        )
    }
    /// After a `|` consumed in operand position, whether the text reads as
    /// a closure parameter list `name, name|` on the same line.
    fn closure_parameters_follow(&self) -> bool {
        if self.previous_ends_operand() {
            return false;
        }
        let rest = self.rest();
        let Some(end) = rest.find(['|', '\n']) else {
            return false;
        };
        rest.as_bytes().get(end) == Some(&b'|')
            && rest[..end].bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b',' | b' ' | b':')
            })
    }
    fn punctuation(&mut self) -> Option<SyntaxKind> {
        for &(spelling, kind) in V1_PUNCTUATION_KINDS {
            if self.starts_with(spelling) {
                self.pos += spelling.len();
                return Some(kind);
            }
        }
        // Preserve the scanner's progress guarantee for invalid input.
        self.bump();
        None
    }
    fn next_token(&mut self) -> (GreenToken, Option<LexicalError>) {
        let start = self.pos;
        let Some(character) = self.current() else {
            return (
                GreenToken::source(
                    SyntaxKind::Eof,
                    TextRange::empty(self.text.len().min(u32::MAX as usize) as u32),
                ),
                None,
            );
        };
        let (kind, mut error) = if is_token_separator(character)
            || deceptive_character(character)
                .is_some_and(|(code, _)| code == "E_UNICODE_LINE_SEPARATOR")
        {
            self.scan_whitespace();
            (SyntaxKind::Whitespace, None)
        } else if character.is_whitespace() {
            self.bump();
            let replaced = TextRange::new(start as u32, self.pos as u32);
            (
                SyntaxKind::ErrorToken,
                Some(
                    LexicalError::new(
                        "E_NON_ASCII_WHITESPACE",
                        format!(
                            "U+{:04X} is not a token separator; use an ASCII space",
                            u32::from(character)
                        ),
                    )
                    .help("tokens are separated by ASCII spaces, tabs and line breaks, or the ideographic space U+3000; other Unicode spaces look identical but are rejected")
                    .fix(replaced, " "),
                ),
            )
        } else if deceptive_character(character).is_some() {
            // Reported once by the whole-source scan in `lex`.
            self.bump();
            (SyntaxKind::ErrorToken, None)
        } else if self.starts_with("//") {
            let kind = if self.starts_with("///") && !self.starts_with("////") {
                SyntaxKind::DocComment
            } else {
                SyntaxKind::LineComment
            };
            self.scan_line_comment();
            (kind, None)
        } else if self.starts_with("/*") {
            let terminated = self.scan_block_comment();
            (
                if terminated {
                    SyntaxKind::BlockComment
                } else {
                    SyntaxKind::ErrorToken
                },
                (!terminated).then(|| {
                    LexicalError::new("K0100", "unterminated block comment")
                        .help("close the comment with `*/`; block comments do not nest")
                }),
            )
        } else if let Some((is_bytes, content_start, hashes)) = self.raw_prefix() {
            let terminated = self.scan_raw(content_start, hashes);
            (
                if terminated {
                    if is_bytes {
                        SyntaxKind::Bytes
                    } else {
                        SyntaxKind::String
                    }
                } else {
                    SyntaxKind::ErrorToken
                },
                (!terminated).then(|| {
                    LexicalError::new("K0100", "unterminated raw string literal")
                        .help(format!("close the literal with `\"{}`", "#".repeat(hashes)))
                }),
            )
        } else if self.starts_with("b\"") {
            let terminated = self.scan_quoted(1);
            (
                if terminated {
                    SyntaxKind::Bytes
                } else {
                    SyntaxKind::ErrorToken
                },
                (!terminated).then(|| {
                    LexicalError::new("K0100", "unterminated byte string literal").help(
                        "close the literal with `\"` on the same line; write a line break as `\\n`",
                    )
                }),
            )
        } else if character == '"' {
            let terminated = self.scan_quoted(0);
            (
                if terminated {
                    SyntaxKind::String
                } else {
                    SyntaxKind::ErrorToken
                },
                (!terminated).then(|| {
                    LexicalError::new("K0100", "unterminated string literal").help(
                        "close the string with `\"` on the same line; write a line break as `\\n`",
                    )
                }),
            )
        } else if character.is_alphabetic()
            || character == '_'
            || fullwidth_ascii(character).is_some_and(|ascii| ascii.is_ascii_alphanumeric())
        {
            self.scan_identifier();
            let text = &self.text[start..self.pos];
            let kind = keyword_kind(text);
            if kind == SyntaxKind::Ident && !text.is_ascii() {
                (
                    SyntaxKind::ErrorToken,
                    Some(non_ascii_identifier_error(text, start)),
                )
            } else {
                (kind, None)
            }
        } else if character.is_ascii_digit() {
            let tuple_index = self.previous_significant == Some(SyntaxKind::Dot);
            match self.scan_number(tuple_index) {
                ScannedNumber::Integer => (SyntaxKind::Number, None),
                ScannedNumber::Decimal => (SyntaxKind::Decimal, None),
                ScannedNumber::Invalid(error) => (SyntaxKind::ErrorToken, Some(error)),
            }
        } else if self.starts_with("++") {
            self.pos += 2;
            let operator = TextRange::new(start as u32, self.pos as u32);
            let mut error =
                LexicalError::new("E_UNSUPPORTED_OPERATOR", "`++` is not a Kotodama operator")
                    .help("increment with a compound assignment: `count += 1;`");
            if matches!(
                self.previous_significant,
                Some(SyntaxKind::Ident | SyntaxKind::RParen | SyntaxKind::RBracket)
            ) {
                error = error.fix(operator, " += 1");
            }
            (SyntaxKind::ErrorToken, Some(error))
        } else if let Some(kind) = self.punctuation() {
            (kind, None)
        } else {
            // `punctuation` consumed exactly one Unicode scalar before
            // reporting failure.
            let consumed = TextRange::new(start as u32, self.pos as u32);
            let error = match character {
                '|' if self.closure_parameters_follow() => {
                    // `|x| x + 1`: absorb the parameter list up to the closing
                    // `|` so the closure is reported once.
                    while self.current().is_some_and(|next| next != '|') {
                        self.bump();
                    }
                    self.bump();
                    LexicalError::new(
                        "E_UNSUPPORTED_OPERATOR",
                        "closures are not part of Kotodama",
                    )
                    .help("write a named `fn` helper and call it; transform lists with comprehensions such as `[x + 1 for x in values]`")
                }
                '&' | '|' if !self.previous_ends_operand() => LexicalError::new(
                    "E_UNSUPPORTED_OPERATOR",
                    format!("`{character}` is not a Kotodama operator"),
                )
                .help("Kotodama has no references, bitwise operators or closures; boolean AND and OR are `&&` and `||`"),
                '&' | '|' => {
                    let doubled = if character == '&' { "&&" } else { "||" };
                    let meaning = if character == '&' { "AND" } else { "OR" };
                    LexicalError::new(
                        "E_UNSUPPORTED_OPERATOR",
                        format!("`{character}` is not a Kotodama operator; boolean {meaning} is `{doubled}`"),
                    )
                    .help("Kotodama has no bitwise operators or closures; combine `bool` conditions with `&&` and `||`")
                    .fix(consumed, doubled)
                }
                _ if fullwidth_ascii(character).is_some() => {
                    // Absorb the whole run of full-width forms so `（）` is
                    // one error with one fix.
                    while self.current().and_then(fullwidth_ascii).is_some() {
                        self.bump();
                    }
                    fullwidth_error(&self.text[start..self.pos], start)
                }
                _ if character.is_ascii() => LexicalError::new(
                    "K0100",
                    format!("`{}` is not valid Kotodama source", character.escape_default()),
                )
                .help("this character has no meaning outside string literals and comments; remove it"),
                _ if is_cjk(character) => LexicalError::new(
                    "K0100",
                    format!("Japanese character `{character}` outside a string or comment"),
                )
                .help("outside string literals and comments Kotodama uses ASCII, except the keywords 誓約, 言挙げ, 始まり and 改善 (also spelled seiyaku, kotoage, hajimari and kaizen)"),
                _ => LexicalError::new(
                    "K0100",
                    format!(
                        "non-ASCII character U+{:04X} outside a string or comment",
                        u32::from(character)
                    ),
                )
                .help("outside string literals and comments Kotodama source is ASCII; remove the character or move it into a string"),
            };
            (SyntaxKind::ErrorToken, Some(error))
        };
        if let Some(error) = error.as_mut()
            && error.strip_numeric_suffix
        {
            let literal = &self.text[start..self.pos];
            if let Some(replacement) = literal
                .strip_suffix("amt")
                .or_else(|| literal.strip_suffix("qty"))
            {
                error.fixes.push((
                    TextRange::new(start as u32, self.pos as u32),
                    replacement.to_owned(),
                ));
            }
        }
        let end = self.pos;
        if !kind.is_trivia() && kind != SyntaxKind::Eof {
            self.previous_significant = Some(kind);
        }
        (
            GreenToken::source(
                kind,
                TextRange::new(
                    start.min(u32::MAX as usize) as u32,
                    end.min(u32::MAX as usize) as u32,
                ),
            ),
            error,
        )
    }
}
fn record_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    omitted_diagnostics: &mut usize,
    budget: FrontendBudget,
    diagnostic: Diagnostic,
) {
    if diagnostics.len() < budget.max_diagnostics() {
        diagnostics.push(diagnostic);
    } else {
        *omitted_diagnostics = omitted_diagnostics.saturating_add(1);
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DelimiterKind {
    Brace,
    Bracket,
    Parenthesis,
}
impl DelimiterKind {
    fn opening(kind: SyntaxKind) -> Option<Self> {
        match kind {
            SyntaxKind::LBrace => Some(Self::Brace),
            SyntaxKind::LBracket => Some(Self::Bracket),
            SyntaxKind::LParen => Some(Self::Parenthesis),
            _ => None,
        }
    }
    fn closing(kind: SyntaxKind) -> Option<Self> {
        match kind {
            SyntaxKind::RBrace => Some(Self::Brace),
            SyntaxKind::RBracket => Some(Self::Bracket),
            SyntaxKind::RParen => Some(Self::Parenthesis),
            _ => None,
        }
    }
}
/// Lex one source file without discarding trivia or malformed text.
#[must_use]
pub fn lex(source: &SourceFile, budget: FrontendBudget) -> Lexed {
    if source.original_len() > budget.max_source_bytes() {
        let range = source.full_range();
        return Lexed {
            tokens: vec![
                GreenToken::source(SyntaxKind::ErrorToken, range),
                GreenToken::source(SyntaxKind::Eof, TextRange::empty(range.end)),
            ],
            diagnostics: vec![diagnostic(
                source,
                "K0001",
                format!(
                    "source contains {} bytes and exceeds the {}-byte compiler limit",
                    source.original_len(),
                    budget.max_source_bytes(),
                ),
                range,
            )],
            omitted_diagnostics: 0,
        };
    }
    let mut scanner = Scanner::new(source);
    let mut tokens = Vec::new();
    let mut diagnostics = Vec::new();
    let mut omitted_diagnostics = 0_usize;
    let mut significant_tokens = 0_usize;
    let mut delimiter_stack = Vec::new();
    let mut nesting_reported = false;
    loop {
        let (token, lexical_error) = scanner.next_token();
        if !token.kind.is_trivia() && token.kind != SyntaxKind::Eof {
            if significant_tokens >= budget.max_tokens().saturating_sub(1) {
                let collapsed = TextRange::new(token.range.start, source.full_range().end);
                tokens.push(GreenToken::source(SyntaxKind::ErrorToken, collapsed));
                tokens.push(GreenToken::source(
                    SyntaxKind::Eof,
                    TextRange::empty(collapsed.end),
                ));
                record_diagnostic(
                    &mut diagnostics,
                    &mut omitted_diagnostics,
                    budget,
                    diagnostic(
                        source,
                        "K0002",
                        format!(
                            "source exceeds the {}-token compiler limit",
                            budget.max_tokens()
                        ),
                        collapsed,
                    ),
                );
                break;
            }
            significant_tokens = significant_tokens.saturating_add(1);
        }
        if let Some(delimiter) = DelimiterKind::opening(token.kind) {
            delimiter_stack.push(delimiter);
            if delimiter_stack.len() > budget.max_nesting() && !nesting_reported {
                nesting_reported = true;
                record_diagnostic(
                    &mut diagnostics,
                    &mut omitted_diagnostics,
                    budget,
                    diagnostic(
                        source,
                        "K0003",
                        format!(
                            "source exceeds the {}-level nesting limit",
                            budget.max_nesting()
                        ),
                        token.range,
                    ),
                );
            }
        } else if let Some(delimiter) = DelimiterKind::closing(token.kind)
            && delimiter_stack.last() == Some(&delimiter)
        {
            delimiter_stack.pop();
        }
        if let Some(error) = lexical_error {
            // Resolving a span's column is linear in the line length, so past
            // the cap only the count is kept; a long line of errors stays
            // linear overall.
            if diagnostics.len() < budget.max_diagnostics() {
                diagnostics.push(lexical_error_diagnostic(source, error, token.range));
            } else {
                omitted_diagnostics = omitted_diagnostics.saturating_add(1);
            }
        }
        let end = token.kind == SyntaxKind::Eof;
        tokens.push(token);
        if end {
            break;
        }
    }
    let capacity = budget.max_diagnostics().saturating_sub(diagnostics.len());
    let (deceptive, omitted) = deceptive_character_diagnostics(source, &tokens, capacity);
    diagnostics.extend(deceptive);
    omitted_diagnostics = omitted_diagnostics.saturating_add(omitted);
    Lexed {
        tokens,
        diagnostics,
        omitted_diagnostics,
    }
}
fn lexical_error_diagnostic(
    source: &SourceFile,
    error: LexicalError,
    range: TextRange,
) -> Diagnostic {
    let mut emitted = diagnostic(source, error.code, error.message, range);
    if let Some(help) = error.help {
        emitted.help = Some(help);
    }
    let mut fixes = error
        .fixes
        .into_iter()
        .map(|(range, replacement)| DiagnosticFix {
            span: SourceSpan::from_range(source, range),
            replacement,
        });
    emitted.fix = fixes.next();
    emitted.alternative_fixes = fixes.collect();
    emitted
}
/// Report every bidirectional control and Unicode line separator in the
/// source, including inside comments and string literals.
///
/// Inside a string literal the fix spells the character as a `\u{...}`
/// escape, keeping the string's value; elsewhere it deletes the character.
/// At most `capacity` diagnostics are built; the number of further
/// occurrences is returned alongside them.
fn deceptive_character_diagnostics(
    source: &SourceFile,
    tokens: &[GreenToken],
    capacity: usize,
) -> (Vec<Diagnostic>, usize) {
    let text = source.text();
    let mut diagnostics = Vec::new();
    let mut omitted = 0_usize;
    for (offset, character) in text.char_indices() {
        let Some((code, name)) = deceptive_character(character) else {
            continue;
        };
        if diagnostics.len() >= capacity {
            omitted = omitted.saturating_add(1);
            continue;
        }
        let range = TextRange::new(offset as u32, (offset + character.len_utf8()) as u32);
        let owner = tokens
            .partition_point(|token| token.range.end <= range.start)
            .min(tokens.len().saturating_sub(1));
        let in_string = tokens.get(owner).is_some_and(|token| {
            matches!(token.kind, SyntaxKind::String | SyntaxKind::Bytes)
                && token.range.start <= range.start
                && range.end <= token.range.end
        });
        let escape = format!("\\u{{{:x}}}", u32::from(character));
        let what = if code == "E_BIDI_CONTROL_CHARACTER" {
            "bidirectional control character"
        } else {
            "line separator"
        };
        let mut emitted = diagnostic(
            source,
            code,
            format!(
                "source contains the invisible {what} U+{:04X} ({name})",
                u32::from(character)
            ),
            range,
        )
        .with_help(if in_string {
            format!("it can make reviewed code read differently from what compiles; write it as the escape `{escape}` if the string really needs it")
        } else {
            "it can make reviewed code read differently from what compiles; delete it (inside a string literal, write it as a `\\u{...}` escape)".to_owned()
        });
        emitted.fix = Some(DiagnosticFix {
            span: SourceSpan::from_range(source, range),
            replacement: if in_string { escape } else { String::new() },
        });
        diagnostics.push(emitted);
    }
    (diagnostics, omitted)
}
#[cfg(test)]
mod tests {
    use super::lex;
    use crate::{
        lexer::{V1_OPERATORS, V1_PUNCTUATION_KINDS},
        source::{FrontendBudget, SourceFile, SourceId},
        syntax::SyntaxKind,
    };
    #[test]
    fn branded_keywords_are_accepted_in_both_scripts() {
        let source = SourceFile::new(
            SourceId(0),
            "branded-keywords.ko",
            "誓約 Demo { permission Run;  始まり() {} 言挙げ fn run() authorize(Run) {} 改善() {} }",
        );
        let lexed = lex(&source, FrontendBudget::v1());
        assert!(lexed.diagnostics.is_empty(), "{:?}", lexed.diagnostics);
        for expected in [
            SyntaxKind::KwSeiyaku,
            SyntaxKind::KwHajimari,
            SyntaxKind::KwKotoage,
            SyntaxKind::KwKaizen,
        ] {
            assert!(lexed.tokens.iter().any(|token| token.kind == expected));
        }
    }
    #[test]
    fn branded_keywords_do_not_enable_unicode_identifiers() {
        for text in ["利用者", "誓約名", "始まり名", "改善版", "言挙げrun"] {
            let source = SourceFile::new(SourceId(0), "invalid.ko", text);
            let lexed = lex(&source, FrontendBudget::v1());
            assert!(
                !lexed.diagnostics.is_empty(),
                "invalid Unicode identifier `{text}` was accepted"
            );
            assert_eq!(lexed.tokens[0].kind, SyntaxKind::ErrorToken);
        }
    }
    #[test]
    fn retired_words_are_plain_identifiers_and_retired_operators_are_errors() {
        for text in [
            "contract", "entry", "init", "meta", "this", "upgrade", "while",
        ] {
            let source = SourceFile::new(SourceId(0), "retired-word.ko", text);
            let lexed = lex(&source, FrontendBudget::v1());
            assert!(
                lexed.diagnostics.is_empty(),
                "{text}: {:?}",
                lexed.diagnostics
            );
            assert_eq!(lexed.tokens[0].kind, SyntaxKind::Ident, "{text}");
        }
        for text in ["++", "&", "|"] {
            let source = SourceFile::new(SourceId(0), "retired-operator.ko", text);
            let lexed = lex(&source, FrontendBudget::v1());
            assert!(!lexed.diagnostics.is_empty(), "{text} must be rejected");
            assert_eq!(lexed.tokens[0].kind, SyntaxKind::ErrorToken, "{text}");
        }
    }
    fn diagnostics_for(text: &str) -> Vec<crate::diagnostic::Diagnostic> {
        let source = SourceFile::new(SourceId(0), "unicode.ko", text);
        let mut diagnostics = lex(&source, FrontendBudget::v1()).diagnostics;
        diagnostics.sort_by_key(|diagnostic| {
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.byte_range)
                .map(|range| range.start)
        });
        diagnostics
    }
    fn fixes(diagnostic: &crate::diagnostic::Diagnostic) -> Vec<(u32, u32, String)> {
        diagnostic
            .fixes()
            .map(|fix| {
                let range = fix.span.byte_range.expect("fix range");
                (range.start, range.end, fix.replacement.clone())
            })
            .collect()
    }
    #[test]
    fn deceptive_characters_are_rejected_in_code_comments_and_strings() {
        for (text, code) in [
            ("// note \u{202e} hidden", "E_BIDI_CONTROL_CHARACTER"),
            ("/* \u{2066} */", "E_BIDI_CONTROL_CHARACTER"),
            ("x\u{200f}", "E_BIDI_CONTROL_CHARACTER"),
            ("// reset\u{2028}code();", "E_UNICODE_LINE_SEPARATOR"),
            ("// note\u{0085}v = 0;", "E_UNICODE_LINE_SEPARATOR"),
            ("let a = 1;\u{2029}", "E_UNICODE_LINE_SEPARATOR"),
        ] {
            let diagnostics = diagnostics_for(text);
            assert_eq!(
                diagnostics
                    .iter()
                    .map(|d| d.code.as_str())
                    .collect::<Vec<_>>(),
                [code],
                "{text:?}: {diagnostics:?}"
            );
            assert!(diagnostics[0].message.contains("invisible"));
            assert_eq!(fixes(&diagnostics[0])[0].2, "", "{text:?}");
        }
        let text = "\"admin\u{202e} user\"";
        let diagnostics = diagnostics_for(text);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(fixes(&diagnostics[0]), [(6, 9, "\\u{202e}".to_owned())]);
        assert!(
            diagnostics[0]
                .message
                .contains("U+202E (RIGHT-TO-LEFT OVERRIDE)")
        );
    }
    #[test]
    fn ideographic_space_separates_tokens_but_other_unicode_spaces_do_not() {
        let source = SourceFile::new(SourceId(0), "ime.ko", "誓約\u{3000}Demo\u{3000}{}");
        let lexed = lex(&source, FrontendBudget::v1());
        assert!(lexed.diagnostics.is_empty(), "{:?}", lexed.diagnostics);
        assert_eq!(lexed.tokens[1].kind, SyntaxKind::Whitespace);
        for space in ['\u{00a0}', '\u{2003}', '\u{202f}'] {
            let text = format!("state{space}int x;");
            let diagnostics = diagnostics_for(&text);
            assert_eq!(diagnostics[0].code, "E_NON_ASCII_WHITESPACE", "{text:?}");
            let end = 5 + space.len_utf8() as u32;
            assert_eq!(fixes(&diagnostics[0]), [(5, end, " ".to_owned())]);
        }
    }
    #[test]
    fn full_width_forms_get_one_error_with_an_ascii_fix() {
        let text = "始まり（） {}";
        let diagnostics = diagnostics_for(text);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(diagnostics[0].code, "E_FULLWIDTH_ASCII");
        assert!(
            diagnostics[0]
                .message
                .contains("full-width `（）` (U+FF08)")
        );
        let start = "始まり".len() as u32;
        assert_eq!(
            fixes(&diagnostics[0]),
            [(start, start + 6, "()".to_owned())]
        );
        let diagnostics = diagnostics_for("return 1；");
        assert_eq!(diagnostics[0].code, "E_FULLWIDTH_ASCII");
        assert_eq!(fixes(&diagnostics[0])[0].2, ";");
        let diagnostics = diagnostics_for("ｓｅｉｙａｋｕ");
        assert_eq!(diagnostics[0].code, "E_FULLWIDTH_ASCII");
        assert_eq!(fixes(&diagnostics[0])[0].2, "seiyaku");
    }
    #[test]
    fn input_method_slips_around_branded_keywords_get_targeted_fixes() {
        let diagnostics = diagnostics_for("言挙げfn bump()");
        assert_eq!(diagnostics[0].code, "E_KEYWORD_SPACING");
        let boundary = "言挙げ".len() as u32;
        assert_eq!(
            fixes(&diagnostics[0]),
            [(boundary, boundary, " ".to_owned())]
        );
        for (text, kanji, romaji) in [
            ("契約", "誓約", "seiyaku"),
            ("制約", "誓約", "seiyaku"),
            ("事挙げ", "言挙げ", "kotoage"),
            ("言上げ", "言挙げ", "kotoage"),
            ("始り", "始まり", "hajimari"),
            ("カイゼン", "改善", "kaizen"),
            ("ことあげ", "言挙げ", "kotoage"),
        ] {
            let diagnostics = diagnostics_for(text);
            assert_eq!(diagnostics[0].code, "E_CONFUSABLE_KEYWORD", "{text}");
            assert!(
                diagnostics[0]
                    .message
                    .contains(&format!("did you mean `{kanji}`/`{romaji}`?")),
                "{text}: {}",
                diagnostics[0].message
            );
            let replacements = fixes(&diagnostics[0])
                .into_iter()
                .map(|(_, _, replacement)| replacement)
                .collect::<Vec<_>>();
            assert_eq!(replacements, [kanji, romaji], "{text}");
        }
        // Near-miss suggestions never make the confusable spellings valid.
        assert_eq!(diagnostics_for("利用者")[0].code, "K0100");
        // A keyword prefix followed by `_` or a digit is an attempted name,
        // so no space is suggested.
        for text in ["誓約_x", "言挙げ2"] {
            let diagnostics = diagnostics_for(text);
            assert_eq!(diagnostics[0].code, "K0100", "{text}: {diagnostics:?}");
            assert!(diagnostics[0].fix.is_none(), "{text}");
        }
    }
    #[test]
    fn foreign_operators_get_targeted_replacements() {
        let diagnostics = diagnostics_for("a & b");
        assert_eq!(diagnostics[0].code, "E_UNSUPPORTED_OPERATOR");
        assert_eq!(fixes(&diagnostics[0]), [(2, 3, "&&".to_owned())]);
        let diagnostics = diagnostics_for("a | b");
        assert_eq!(fixes(&diagnostics[0]), [(2, 3, "||".to_owned())]);
        // Closures are one error without a misleading `||` fix.
        let diagnostics = diagnostics_for("let f = |x, y| x + y;");
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(diagnostics[0].message, "closures are not part of Kotodama");
        assert!(diagnostics[0].fix.is_none());
        // `&x` is not an AND, so `&&` is not offered.
        assert!(diagnostics_for("let r = &x;")[0].fix.is_none());
        let diagnostics = diagnostics_for("i++;");
        assert_eq!(fixes(&diagnostics[0]), [(1, 3, " += 1".to_owned())]);
        assert!(fixes(&diagnostics_for("++i;")[0]).is_empty());
        let diagnostics = diagnostics_for("a @ b");
        assert_eq!(diagnostics[0].code, "K0100");
        assert!(
            !diagnostics[0]
                .help
                .as_deref()
                .unwrap_or("")
                .contains("誓約")
        );
    }
    #[test]
    fn specification_glossary_rows_match_the_shared_glossary() {
        let specification = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/kotodama_grammar.md"),
        )
        .expect("read normative Kotodama grammar");
        for keyword in &crate::glossary::BRANDED_KEYWORDS {
            let row = format!(
                "| `{}` / `{}` | {} | {} | {} |",
                keyword.romaji, keyword.kanji, keyword.reading, keyword.literal, keyword.role
            );
            assert!(
                specification.contains(&row),
                "specs/kotodama_grammar.md lacks the glossary row {row}"
            );
        }
    }
    #[test]
    fn integer_range_is_not_a_malformed_decimal() {
        let source = SourceFile::new(SourceId(0), "range.ko", "0..10");
        let lexed = lex(&source, FrontendBudget::v1());
        assert!(lexed.diagnostics.is_empty(), "{:?}", lexed.diagnostics);
        let kinds = lexed
            .tokens
            .iter()
            .map(|token| token.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                SyntaxKind::Number,
                SyntaxKind::DotDot,
                SyntaxKind::Number,
                SyntaxKind::Eof
            ]
        );
    }
    #[test]
    fn unterminated_literals_explain_how_to_close_them() {
        let diagnostics = diagnostics_for("\"open");
        assert_eq!(diagnostics[0].code, "K0100");
        assert!(
            diagnostics[0]
                .help
                .as_deref()
                .unwrap_or("")
                .contains("close the string")
        );
        let diagnostics = diagnostics_for("/* open");
        assert!(
            diagnostics[0]
                .help
                .as_deref()
                .unwrap_or("")
                .contains("`*/`")
        );
    }
    #[test]
    fn normative_operator_table_drives_the_lossless_scanner() {
        assert_eq!(V1_OPERATORS.len(), V1_PUNCTUATION_KINDS.len());
        for &spelling in V1_OPERATORS {
            let expected = V1_PUNCTUATION_KINDS
                .iter()
                .find_map(|(candidate, kind)| (*candidate == spelling).then_some(*kind))
                .expect("every documented operator has a generated scanner kind");
            let source = SourceFile::new(SourceId(0), "operator.ko", spelling);
            let lexed = lex(&source, FrontendBudget::v1());
            assert!(
                lexed.diagnostics.is_empty(),
                "{spelling}: {:?}",
                lexed.diagnostics
            );
            assert_eq!(lexed.tokens[0].kind, expected, "{spelling}");
            assert_eq!(source.slice(lexed.tokens[0].range), Some(spelling));
            assert_eq!(lexed.tokens[1].kind, SyntaxKind::Eof, "{spelling}");
        }
    }
    #[test]
    fn decimal_is_one_lossless_token_with_exact_range() {
        let source = SourceFile::new(SourceId(0), "decimal.ko", "  1.250_0 // exact\n");
        let lexed = lex(&source, FrontendBudget::v1());
        assert!(lexed.diagnostics.is_empty(), "{:?}", lexed.diagnostics);
        let decimal = lexed
            .tokens
            .iter()
            .find(|token| token.kind == SyntaxKind::Decimal)
            .expect("decimal token");
        assert_eq!(source.slice(decimal.range), Some("1.250_0"));
        assert_eq!(decimal.range.start, 2);
        assert_eq!(decimal.range.end, 9);
    }
    #[test]
    fn chained_tuple_projection_keeps_following_dots_as_punctuation() {
        let source = SourceFile::new(SourceId(0), "tuple-projection.ko", "value.0.1.field");
        let lexed = lex(&source, FrontendBudget::v1());
        assert!(lexed.diagnostics.is_empty(), "{:?}", lexed.diagnostics);
        let kinds = lexed
            .tokens
            .iter()
            .map(|token| token.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                SyntaxKind::Ident,
                SyntaxKind::Dot,
                SyntaxKind::Number,
                SyntaxKind::Dot,
                SyntaxKind::Number,
                SyntaxKind::Dot,
                SyntaxKind::Ident,
                SyntaxKind::Eof,
            ]
        );
    }
    #[test]
    fn comment_period_does_not_turn_a_following_decimal_into_a_tuple_index() {
        let source = SourceFile::new(
            SourceId(0),
            "comment-decimal.ko",
            "let value = // exact.\n  1.25;",
        );
        let lexed = lex(&source, FrontendBudget::v1());
        assert!(lexed.diagnostics.is_empty(), "{:?}", lexed.diagnostics);
        assert!(
            lexed
                .tokens
                .iter()
                .any(|token| token.kind == SyntaxKind::Decimal
                    && source.slice(token.range) == Some("1.25"))
        );
    }
    #[test]
    fn decimal_and_retired_suffix_failures_have_dedicated_codes() {
        for (spelling, code) in [
            ("1.amt", "E_DECIMAL_MALFORMED"),
            ("1e", "E_DECIMAL_EXPONENT"),
            ("1.25amt", "E_RETIRED_NUMERIC_SUFFIX"),
            ("1.25qty", "E_RETIRED_NUMERIC_SUFFIX"),
            ("0x10amt", "E_RETIRED_NUMERIC_SUFFIX"),
            ("0x10qty", "E_RETIRED_NUMERIC_SUFFIX"),
        ] {
            let source = SourceFile::new(SourceId(0), "invalid-decimal.ko", spelling);
            let lexed = lex(&source, FrontendBudget::v1());
            assert_eq!(lexed.diagnostics[0].code, code, "`{spelling}`");
            assert_eq!(lexed.tokens[0].kind, SyntaxKind::ErrorToken, "`{spelling}`");
        }
    }
    #[test]
    fn amount_and_quantity_suffixes_offer_unsuffixed_literal_fixes() {
        for (spelling, replacement) in [
            ("1amt", "1"),
            ("1.25amt", "1.25"),
            ("1qty", "1"),
            ("1.25qty", "1.25"),
        ] {
            let source = SourceFile::new(SourceId(0), "retired-suffix.ko", spelling);
            let lexed = lex(&source, FrontendBudget::v1());
            assert_eq!(lexed.diagnostics[0].code, "E_RETIRED_NUMERIC_SUFFIX");
            let fix = lexed.diagnostics[0]
                .fix
                .as_ref()
                .expect("amt and qty suffixes have a safe removal fix");
            assert_eq!(fix.span.byte_range, Some(lexed.tokens[0].range));
            assert_eq!(fix.replacement, replacement);
        }
        for spelling in ["1i64", "1u128"] {
            let source = SourceFile::new(SourceId(0), "retired-suffix.ko", spelling);
            let lexed = lex(&source, FrontendBudget::v1());
            assert_eq!(lexed.diagnostics[0].code, "E_RETIRED_NUMERIC_SUFFIX");
            assert!(lexed.diagnostics[0].fix.is_none());
        }
    }
}

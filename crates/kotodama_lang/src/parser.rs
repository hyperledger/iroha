//! Canonical grammar parser for the Kotodama compiler AST and lossless CST.
//!
//! One grammar pass consumes the significant view of the lossless lexer tape,
//! constructs the spanned AST, and records the completed syntax-node outline.
//! The CST sink later merges that outline with the original trivia-bearing
//! tape; there is no second structural parser or CST-to-token reparse.
use super::{
    ast::*,
    diagnostic::{
        Diagnostic, DiagnosticBundle, DiagnosticFix, DiagnosticLabel, DiagnosticPhase,
        MAX_DIAGNOSTICS, SourcePosition, SourceSpan,
    },
    lexer::{Token, TokenKind},
    source::{FrontendBudget, SourceFile, SourceId, SourceRange, TextRange},
    spanned_ast::{
        AstFacts, AstNodeKind, BindingFact, BindingFactKind, CallFact, DeclarationFact,
        DeclarationKind, NodeId, SpannedProgram, TypeUseFact,
    },
    syntax::{
        SyntaxKind,
        cst::{MissingSyntax, SyntaxOutline, SyntaxOutlineBuilder, SyntaxOutlineCheckpoint},
    },
};
use iroha_primitives::{bigint::BigInt, numeric_abi::IntValueV1};

mod expressions;
/// One syntax error produced by the grammar parser.
///
/// The parser reports structured data only. Messages never embed internal
/// token names; source text is echoed exactly as the user wrote it.
#[derive(Clone, Debug, PartialEq)]
pub struct ParseError {
    /// Stable machine-readable diagnostic code, independent of message text.
    pub code: &'static str,
    /// Canonical English message.
    pub message: String,
    /// One-based line of the unexpected token.
    pub line: usize,
    /// One-based column of the unexpected token.
    pub column: usize,
    /// Exact half-open UTF-8 range of the unexpected token. Recovery and the
    /// lossless CST anchor at this range.
    pub range: TextRange,
    /// Range reported to the user when it differs from `range`, such as the
    /// insertion point just after the previous token for a missing `;`.
    pub report_range: Option<TextRange>,
    /// Site-specific remediation. The registry help for `code` is used only
    /// when this is absent.
    pub help: Option<String>,
    /// Machine-applicable replacements, preferred first. Later entries are
    /// equally valid alternatives, such as the other branded spelling.
    pub fixes: Vec<ParseFix>,
    /// Secondary source labels.
    pub labels: Vec<ParseLabel>,
    /// Exact zero-width CST token expected at this failure, when recovery can
    /// insert one without guessing from diagnostic prose.
    pub expected: Option<SyntaxKind>,
    /// Syntax-outline node that owned `expected` at the failure boundary.
    pub(crate) expected_owner: Option<usize>,
}
/// Machine-applicable source replacement attached to a [`ParseError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseFix {
    /// Exact UTF-8 range to replace; empty for an insertion.
    pub range: TextRange,
    /// Replacement text.
    pub replacement: String,
}
/// Secondary labelled range attached to a [`ParseError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseLabel {
    /// Labelled UTF-8 range.
    pub range: TextRange,
    /// What the range contributes to the error.
    pub message: String,
}
impl ParseError {
    /// Construct an error anchored at `token` with no help, fixes or labels.
    fn at(token: &Token, code: &'static str, message: impl Into<String>) -> Box<Self> {
        Self::at_range(token.range, token.line, token.column, code, message)
    }
    /// Construct an error anchored at an explicit range.
    fn at_range(
        range: TextRange,
        line: usize,
        column: usize,
        code: &'static str,
        message: impl Into<String>,
    ) -> Box<Self> {
        Box::new(Self {
            code,
            message: message.into(),
            line,
            column,
            range,
            report_range: None,
            help: None,
            fixes: Vec::new(),
            labels: Vec::new(),
            expected: None,
            expected_owner: None,
        })
    }
    /// Attach site-specific help.
    fn with_help(mut self: Box<Self>, help: impl Into<String>) -> Box<Self> {
        self.help = Some(help.into());
        self
    }
    /// Append a machine-applicable fix; the first fix is the preferred one.
    fn with_fix(
        mut self: Box<Self>,
        range: TextRange,
        replacement: impl Into<String>,
    ) -> Box<Self> {
        self.fixes.push(ParseFix {
            range,
            replacement: replacement.into(),
        });
        self
    }
    /// Append a secondary label.
    fn with_label(mut self: Box<Self>, range: TextRange, message: impl Into<String>) -> Box<Self> {
        self.labels.push(ParseLabel {
            range,
            message: message.into(),
        });
        self
    }
    /// Report the error at `range` instead of the recovery anchor.
    fn reported_at(mut self: Box<Self>, range: TextRange) -> Box<Self> {
        self.report_range = Some(range);
        self
    }
}
/// Exact source text of `token`, so diagnostics echo the user's spelling.
fn token_text<'source>(source: &'source str, token: &Token) -> &'source str {
    source
        .get(token.range.start as usize..token.range.end as usize)
        .unwrap_or("")
}
/// Prose description of a found token for "expected X, found Y" messages.
///
/// Punctuation and keywords appear exactly as written (`言挙げ` stays kanji);
/// names and literals are prefixed with their category.
fn describe_found(source: &str, token: &Token) -> String {
    let text = token_text(source, token);
    let quoted = |text: &str| {
        const MAX: usize = 32;
        if text.chars().count() > MAX {
            format!("`{}...`", text.chars().take(MAX).collect::<String>())
        } else {
            format!("`{text}`")
        }
    };
    match &token.kind {
        TokenKind::EOF => "end of file".to_owned(),
        TokenKind::Ident(_) => format!("identifier {}", quoted(text)),
        TokenKind::Number(_) => format!("integer literal {}", quoted(text)),
        TokenKind::DecimalLiteral(_) => format!("decimal literal {}", quoted(text)),
        TokenKind::String(_) => format!("string literal {}", quoted(text)),
        TokenKind::Bytes(_) => format!("byte-string literal {}", quoted(text)),
        kind if crate::lexer::v1_keyword_spelling(kind).is_some() => {
            format!("keyword {}", quoted(text))
        }
        _ => quoted(text),
    }
}
/// Canonical spelling of an expected token for diagnostics. Branded keywords
/// list both accepted spellings, for example "`kotoage`/`言挙げ`".
fn expected_token_spelling(kind: &TokenKind) -> String {
    match kind {
        TokenKind::EOF => return "end of file".to_owned(),
        TokenKind::Ident(_) => return "identifier".to_owned(),
        TokenKind::Number(_) => return "integer literal".to_owned(),
        TokenKind::DecimalLiteral(_) => return "decimal literal".to_owned(),
        TokenKind::String(_) => return "string literal".to_owned(),
        TokenKind::Bytes(_) => return "byte-string literal".to_owned(),
        _ => {}
    }
    if let Some(spelling) = crate::lexer::v1_keyword_spelling(kind) {
        return crate::glossary::by_spelling(spelling).map_or_else(
            || format!("`{spelling}`"),
            |keyword| format!("`{}`/`{}`", keyword.romaji, keyword.kanji),
        );
    }
    expected_syntax_kind(kind)
        .and_then(|syntax| {
            crate::lexer::V1_PUNCTUATION_KINDS
                .iter()
                .find_map(|(spelling, candidate)| (*candidate == syntax).then_some(*spelling))
        })
        .map_or_else(|| "token".to_owned(), |spelling| format!("`{spelling}`"))
}
/// `text` with its first character lowercased, for embedding a glossary
/// sentence after a colon.
fn lowercase_first(text: &str) -> String {
    let mut characters = text.chars();
    characters.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(characters).collect()
    })
}
type ParseResult<T> = Result<T, Box<ParseError>>;
type ForEachMapBinding = (NodeId, Pattern, Expr);
fn integer_digits(spelling: &str) -> (&str, u32) {
    if let Some(digits) = spelling
        .strip_prefix("0x")
        .or_else(|| spelling.strip_prefix("0X"))
    {
        (digits, 16)
    } else if let Some(digits) = spelling
        .strip_prefix("0b")
        .or_else(|| spelling.strip_prefix("0B"))
    {
        (digits, 2)
    } else {
        (spelling, 10)
    }
}
fn parse_integer_value(spelling: &str, negative: bool) -> Result<BigInt, ()> {
    let (digits, radix_value) = integer_digits(spelling);
    let radix = BigInt::from(radix_value);
    let mut value = BigInt::zero();
    for character in digits.chars().filter(|character| *character != '_') {
        let digit = character.to_digit(radix_value).ok_or(())?;
        value = value.checked_mul(&radix).map_err(|_| ())?;
        value = if negative {
            value.checked_sub(&BigInt::from(digit)).map_err(|_| ())?
        } else {
            value.checked_add(&BigInt::from(digit)).map_err(|_| ())?
        };
    }
    IntValueV1::try_new(value.clone()).map_err(|_| ())?;
    Ok(value)
}
fn parse_bounded_unsigned(spelling: &str, maximum: u64) -> Result<u64, ()> {
    let (digits, radix) = integer_digits(spelling);
    let compact = digits
        .chars()
        .filter(|character| *character != '_')
        .collect::<String>();
    let value = u64::from_str_radix(&compact, radix).map_err(|_| ())?;
    (value <= maximum).then_some(value).ok_or(())
}
fn bigint_literal_expr(value: BigInt) -> Expr {
    Expr::IntLiteral(value)
}
fn retired_numeric_type_replacement(name: &str) -> Option<Option<&'static str>> {
    match name {
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128"
        | "usize" | "num" | "Int" | "Integer" => Some(Some("int")),
        "float" | "f32" | "f64" | "Decimal" | "Fixed" | "FixedPoint" => Some(Some("decimal")),
        "Amount" | "amount" | "money" | "Quantity" => Some(Some("quantity")),
        "number" => Some(None),
        _ => None,
    }
}
fn expected_syntax_kind(kind: &TokenKind) -> Option<SyntaxKind> {
    Some(match kind {
        TokenKind::Fn => SyntaxKind::KwFn,
        TokenKind::Let => SyntaxKind::KwLet,
        TokenKind::Var => SyntaxKind::KwVar,
        TokenKind::Const => SyntaxKind::KwConst,
        TokenKind::Return => SyntaxKind::KwReturn,
        TokenKind::Break => SyntaxKind::KwBreak,
        TokenKind::Continue => SyntaxKind::KwContinue,
        TokenKind::State => SyntaxKind::KwState,
        TokenKind::Struct => SyntaxKind::KwStruct,
        TokenKind::Event => SyntaxKind::KwEvent,
        TokenKind::Emit => SyntaxKind::KwEmit,
        TokenKind::Error => SyntaxKind::KwError,
        TokenKind::Enum => SyntaxKind::KwEnum,
        TokenKind::Authorize => SyntaxKind::KwAuthorize,
        TokenKind::Permission => SyntaxKind::KwPermission,
        TokenKind::Trigger => SyntaxKind::KwTrigger,
        TokenKind::If => SyntaxKind::KwIf,
        TokenKind::Match => SyntaxKind::KwMatch,
        TokenKind::Else => SyntaxKind::KwElse,
        TokenKind::For => SyntaxKind::KwFor,
        TokenKind::In => SyntaxKind::KwIn,
        TokenKind::Seiyaku => SyntaxKind::KwSeiyaku,
        TokenKind::Module => SyntaxKind::KwModule,
        TokenKind::Include => SyntaxKind::KwInclude,
        TokenKind::Import => SyntaxKind::KwImport,
        TokenKind::As => SyntaxKind::KwAs,
        TokenKind::Export => SyntaxKind::KwExport,
        TokenKind::Kotoage => SyntaxKind::KwKotoage,
        TokenKind::Hajimari => SyntaxKind::KwHajimari,
        TokenKind::Kaizen => SyntaxKind::KwKaizen,
        TokenKind::View => SyntaxKind::KwView,
        TokenKind::True => SyntaxKind::KwTrue,
        TokenKind::False => SyntaxKind::KwFalse,
        TokenKind::Ident(_) => SyntaxKind::Ident,
        TokenKind::Number(_) => SyntaxKind::Number,
        TokenKind::DecimalLiteral(_) => SyntaxKind::Decimal,
        TokenKind::String(_) => SyntaxKind::String,
        TokenKind::Bytes(_) => SyntaxKind::Bytes,
        TokenKind::Plus => SyntaxKind::Plus,
        TokenKind::PlusEqual => SyntaxKind::PlusEqual,
        TokenKind::Minus => SyntaxKind::Minus,
        TokenKind::MinusEqual => SyntaxKind::MinusEqual,
        TokenKind::Arrow => SyntaxKind::Arrow,
        TokenKind::FatArrow => SyntaxKind::FatArrow,
        TokenKind::Star => SyntaxKind::Star,
        TokenKind::StarEqual => SyntaxKind::StarEqual,
        TokenKind::Slash => SyntaxKind::Slash,
        TokenKind::SlashEqual => SyntaxKind::SlashEqual,
        TokenKind::Percent => SyntaxKind::Percent,
        TokenKind::PercentEqual => SyntaxKind::PercentEqual,
        TokenKind::Bang => SyntaxKind::Bang,
        TokenKind::BangEqual => SyntaxKind::BangEqual,
        TokenKind::Equal => SyntaxKind::Equal,
        TokenKind::EqualEqual => SyntaxKind::EqualEqual,
        TokenKind::Less => SyntaxKind::Less,
        TokenKind::LessEqual => SyntaxKind::LessEqual,
        TokenKind::Greater => SyntaxKind::Greater,
        TokenKind::GreaterEqual => SyntaxKind::GreaterEqual,
        TokenKind::AndAnd => SyntaxKind::AndAnd,
        TokenKind::OrOr => SyntaxKind::OrOr,
        TokenKind::LParen => SyntaxKind::LParen,
        TokenKind::RParen => SyntaxKind::RParen,
        TokenKind::LBrace => SyntaxKind::LBrace,
        TokenKind::RBrace => SyntaxKind::RBrace,
        TokenKind::LBracket => SyntaxKind::LBracket,
        TokenKind::RBracket => SyntaxKind::RBracket,
        TokenKind::Semicolon => SyntaxKind::Semicolon,
        TokenKind::Comma => SyntaxKind::Comma,
        TokenKind::Colon => SyntaxKind::Colon,
        TokenKind::ColonColon => SyntaxKind::ColonColon,
        TokenKind::Dot => SyntaxKind::Dot,
        TokenKind::DotDot => SyntaxKind::DotDot,
        TokenKind::Question => SyntaxKind::Question,
        TokenKind::Hash => SyntaxKind::Hash,
        TokenKind::EOF => SyntaxKind::Eof,
    })
}
struct PendingExpr(Option<Expr>);
impl PendingExpr {
    fn new(expression: Expr) -> Self {
        Self(Some(expression))
    }
    fn as_ref(&self) -> &Expr {
        self.0.as_ref().expect("pending expression must be present")
    }
    fn take(&mut self) -> Expr {
        self.0.take().expect("pending expression must be present")
    }
    fn replace(&mut self, expression: Expr) {
        assert!(
            self.0.replace(expression).is_none(),
            "pending expression must be empty before replacement"
        );
    }
    fn into_inner(mut self) -> Expr {
        self.take()
    }
}
impl Drop for PendingExpr {
    fn drop(&mut self) {
        if let Some(expression) = self.0.take() {
            crate::ast::drop_expression_iterative(expression);
        }
    }
}
struct PendingType(Option<TypeExpr>);
impl PendingType {
    fn new(ty: TypeExpr) -> Self {
        Self(Some(ty))
    }
    fn take(&mut self) -> TypeExpr {
        self.0.take().expect("pending type must be present")
    }
    fn replace(&mut self, ty: TypeExpr) {
        assert!(
            self.0.replace(ty).is_none(),
            "pending type must be empty before replacement"
        );
    }
    fn into_inner(mut self) -> TypeExpr {
        self.take()
    }
}
impl Drop for PendingType {
    fn drop(&mut self) {
        if let Some(ty) = self.0.take() {
            crate::ast::drop_type_iterative(ty);
        }
    }
}
struct PendingStatement(Option<Statement>);
impl PendingStatement {
    fn new(statement: Statement) -> Self {
        Self(Some(statement))
    }
    fn take(&mut self) -> Statement {
        self.0.take().expect("pending statement must be present")
    }
}
impl Drop for PendingStatement {
    fn drop(&mut self) {
        if let Some(statement) = self.0.take() {
            crate::ast::drop_block_iterative(Block {
                statements: vec![statement],
                tail: None,
            });
        }
    }
}
struct PendingExprs(Vec<Expr>);
impl PendingExprs {
    fn new(expressions: Vec<Expr>) -> Self {
        Self(expressions)
    }
    fn push(&mut self, expression: Expr) {
        self.0.push(expression);
    }
    fn pop(&mut self) -> Option<Expr> {
        self.0.pop()
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn into_inner(mut self) -> Vec<Expr> {
        std::mem::take(&mut self.0)
    }
}
impl Drop for PendingExprs {
    fn drop(&mut self) {
        for expression in std::mem::take(&mut self.0) {
            crate::ast::drop_expression_iterative(expression);
        }
    }
}
struct PendingBlock {
    statements: Vec<Statement>,
    tail: Option<Box<Expr>>,
}
impl PendingBlock {
    fn new() -> Self {
        Self {
            statements: Vec::new(),
            tail: None,
        }
    }
    fn from_block(block: Block) -> Self {
        Self {
            statements: block.statements,
            tail: block.tail,
        }
    }
    fn push_statement(&mut self, statement: Statement) {
        self.statements.push(statement);
    }
    fn set_tail(&mut self, expression: Expr) {
        assert!(
            self.tail.replace(Box::new(expression)).is_none(),
            "one parsed block may have only one tail expression"
        );
    }
    fn into_inner(mut self) -> Block {
        Block {
            statements: std::mem::take(&mut self.statements),
            tail: self.tail.take(),
        }
    }
}
struct PendingValues<T> {
    values: Vec<T>,
    drop_value: fn(T),
}
impl<T> PendingValues<T> {
    fn new(drop_value: fn(T)) -> Self {
        Self {
            values: Vec::new(),
            drop_value,
        }
    }
    fn push(&mut self, value: T) {
        self.values.push(value);
    }
    fn iter(&self) -> std::slice::Iter<'_, T> {
        self.values.iter()
    }
    fn len(&self) -> usize {
        self.values.len()
    }
    fn into_inner(mut self) -> Vec<T> {
        std::mem::take(&mut self.values)
    }
}
impl<T> Drop for PendingValues<T> {
    fn drop(&mut self) {
        for value in std::mem::take(&mut self.values) {
            (self.drop_value)(value);
        }
    }
}
impl Drop for PendingBlock {
    fn drop(&mut self) {
        if self.statements.is_empty() && self.tail.is_none() {
            return;
        }
        crate::ast::drop_block_iterative(Block {
            statements: std::mem::take(&mut self.statements),
            tail: self.tail.take(),
        });
    }
}
struct PendingIfFrame {
    start: u32,
    owner: NodeId,
    syntax: usize,
    pattern: Option<SumPattern>,
    value: Option<PendingExpr>,
    condition: Option<PendingExpr>,
    then_branch: PendingBlock,
}
type ProgramParts = (
    Vec<Item>,
    Vec<FixtureDecl>,
    Vec<SourceDirective>,
    Vec<ExportDecl>,
    Vec<crate::ast::PermissionDecl>,
);
struct PendingProgramParts {
    items: Vec<Item>,
    fixtures: Vec<FixtureDecl>,
    directives: Vec<SourceDirective>,
    exports: Vec<ExportDecl>,
    permissions: Vec<crate::ast::PermissionDecl>,
}
impl PendingProgramParts {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            fixtures: Vec::new(),
            directives: Vec::new(),
            exports: Vec::new(),
            permissions: Vec::new(),
        }
    }
    fn push_item(&mut self, item: Item) {
        self.items.push(item);
    }
    fn push_fixture(&mut self, fixture: FixtureDecl) {
        self.fixtures.push(fixture);
    }
    fn into_inner(mut self) -> ProgramParts {
        (
            std::mem::take(&mut self.items),
            std::mem::take(&mut self.fixtures),
            std::mem::take(&mut self.directives),
            std::mem::take(&mut self.exports),
            std::mem::take(&mut self.permissions),
        )
    }
}
impl Drop for PendingProgramParts {
    fn drop(&mut self) {
        if self.items.is_empty() && self.fixtures.is_empty() {
            return;
        }
        crate::ast::drop_program_iterative(Program {
            unit: SourceUnit {
                kind: SourceUnitKind::Module,
                name: String::new(),
            },
            items: std::mem::take(&mut self.items),
            test_target: None,
            fixtures: std::mem::take(&mut self.fixtures),
            directives: std::mem::take(&mut self.directives),
            exports: std::mem::take(&mut self.exports),
            permissions: std::mem::take(&mut self.permissions),
        });
    }
}
enum ParsedBlockElement {
    Statement(Statement),
    Tail(Expr),
}
fn block_element_syntax_kind(element: &ParsedBlockElement) -> SyntaxKind {
    match element {
        ParsedBlockElement::Tail(_) => SyntaxKind::TailExpr,
        ParsedBlockElement::Statement(statement) => match statement.kind() {
            Statement::Let { .. } => SyntaxKind::LetStmt,
            Statement::Return(_) => SyntaxKind::ReturnStmt,
            Statement::Break => SyntaxKind::BreakStmt,
            Statement::Continue => SyntaxKind::ContinueStmt,
            Statement::If { .. } | Statement::IfLet { .. } => SyntaxKind::IfStmt,
            Statement::For { .. } | Statement::ForEachMap { .. } => SyntaxKind::ForStmt,
            _ => SyntaxKind::ExprStmt,
        },
    }
}
/// Site help for a missing token, describing the construct it belongs to.
fn expected_token_help(kind: &TokenKind) -> Option<&'static str> {
    Some(match kind {
        TokenKind::RParen => "every `(` needs a matching `)`; check the argument or parameter list",
        TokenKind::RBracket => "every `[` needs a matching `]`; list elements are separated by `,`",
        TokenKind::RBrace => "every `{` needs a matching `}`",
        TokenKind::LBrace => {
            "blocks, declaration bodies and struct or JSON literals start with `{`"
        }
        TokenKind::LParen => {
            "parameter and argument lists are written in parentheses, even when empty: `name()`"
        }
        TokenKind::Equal => {
            "`let`, `var` and `const` bindings are always initialized: `let int total = 0;`"
        }
        TokenKind::FatArrow => "match arms are written `Pattern => value`",
        TokenKind::Colon => "fields and JSON entries are written `name: value`",
        TokenKind::ColonColon => "namespaced paths use `::`, for example `Option::some(value)`",
        TokenKind::Greater => "type arguments are closed with `>`, for example `Option<int>`",
        TokenKind::Comma => "separate list items, arguments and fields with `,`",
        TokenKind::In => "loops are written `for item in collection` or `for i in range(N)`",
        TokenKind::As => "an import names its alias: `import \"math.ko\" as math;`",
        TokenKind::Arrow => {
            "a trigger names the function it calls: `trigger name -> function { ... }`"
        }
        TokenKind::EOF => "nothing may follow the closing `}` of the source unit",
        TokenKind::Ident(_) => "a name goes here; keywords cannot be used as names",
        _ => return None,
    })
}
/// Canonical spelling of an `Option`/`Result` constructor or pattern path
/// written with any letter case, such as `option::Some` or `Result::Ok`.
fn canonical_sum_path(namespace: &str, variant: &str) -> Option<&'static str> {
    Some(
        match (
            namespace.to_ascii_lowercase().as_str(),
            variant.to_ascii_lowercase().as_str(),
        ) {
            ("option", "some") => "Option::some",
            ("option", "none") => "Option::none",
            ("result", "ok") => "Result::ok",
            ("result", "err") => "Result::err",
            _ => return None,
        },
    )
}
/// Canonical path for a bare `Some`/`None`/`Ok`/`Err` constructor name.
fn foreign_sum_constructor(name: &str) -> Option<&'static str> {
    Some(match name {
        "Some" => "Option::some",
        "None" => "Option::none",
        "Ok" => "Result::ok",
        "Err" => "Result::err",
        _ => return None,
    })
}
/// Help shared by every `Option`/`Result` spelling diagnostic.
fn sum_constructor_help() -> &'static str {
    "optional and fallible values are built and matched as `Option::some(value)`, `Option::none`, `Result::ok(value)` and `Result::err(error)`"
}
/// Declaration sites that share the type-first `Type name` order.
#[derive(Clone, Copy)]
enum DeclarationSite {
    Parameter,
    StructField,
    State,
    Const,
    Local,
}
/// Help shared by every type-first declaration diagnostic.
fn declaration_order_help() -> &'static str {
    "Kotodama declarations name the type first: `fn add(int lhs)`, `state int total;`, `const int limit = 1;`, `let int count = 0;`, struct field `quantity balance;`"
}
/// How the source-item loop continues after a recognisable stand-in for a
/// declaration keyword (an English word or a typo) has been reported.
enum ItemRecovery {
    /// Parse the rest as a function with this role.
    Function(FunctionKind),
    /// Parse the rest as the lifecycle hook with this keyword token kind.
    Hook(TokenKind),
}
/// Help text stating the shape of a lifecycle hook declaration.
fn lifecycle_hook_help(kind: &TokenKind) -> String {
    let romaji = if matches!(kind, TokenKind::Kaizen) {
        "kaizen"
    } else {
        "hajimari"
    };
    crate::glossary::by_spelling(romaji).map_or_else(String::new, |keyword| {
        format!(
            "`{}`/`{}` {}; it is written `{}() {{ ... }}` with no `fn`, no name and no `authorize(...)`",
            keyword.romaji,
            keyword.kanji,
            lowercase_first(keyword.role),
            keyword.romaji
        )
    })
}
#[derive(Default)]
struct FunctionAttributes {
    is_test: bool,
    test_fixture: Option<String>,
}
impl FunctionAttributes {
    fn is_empty(&self) -> bool {
        !self.is_test && self.test_fixture.is_none()
    }
}
/// Parse a KOTODAMA source string into a [`Program`].
pub fn parse(src: &str) -> Result<Program, String> {
    if src.len() > crate::source::MAX_SOURCE_BYTES {
        return Err(format!(
            "K0001: source contains {} bytes and exceeds the {}-byte Kotodama V1 limit",
            src.len(),
            crate::source::MAX_SOURCE_BYTES
        ));
    }
    let source = SourceFile::new(SourceId(0), "<source>", src);
    parse_source(&source, FrontendBudget::v1()).map_err(|bundle| bundle.render_human())
}
/// Parse one named source file through the canonical V1 token stream.
///
/// The lossless lexer runs exactly once. Its significant tokens feed this AST
/// parser directly, so compilation cannot accept a spelling or token boundary
/// that formatter and CST tooling reject (or vice versa).
pub fn parse_source(
    source: &SourceFile,
    budget: FrontendBudget,
) -> Result<Program, DiagnosticBundle> {
    let output = crate::syntax::parse_program(source, budget);
    output.program.ok_or(output.diagnostics)
}
/// Parse a bare declaration fragment without inventing a source-unit wrapper.
///
/// Fragments retain their original byte ranges. The compiler graph assigns the
/// enclosing unit and enforces its seiyaku or module declaration restrictions.
pub fn parse_fragment_source(
    source: &SourceFile,
    budget: FrontendBudget,
) -> Result<Program, DiagnosticBundle> {
    let (spanned, _) = parse_fragment_source_spanned(source, budget)?;
    let mut program = spanned.program;
    crate::ast::strip_program_provenance(&mut program);
    Ok(program)
}
/// Parse once and retain the exact significant token stream for later resolution/type diagnostics.
pub(crate) fn parse_source_spanned(
    source: &SourceFile,
    budget: FrontendBudget,
) -> Result<(SpannedProgram, Vec<Token>), DiagnosticBundle> {
    crate::syntax::parser::parse_spanned_program(source, budget)
}
/// Parse a declaration fragment with the same source facts as named source units.
pub(crate) fn parse_fragment_source_spanned(
    source: &SourceFile,
    budget: FrontendBudget,
) -> Result<(SpannedProgram, Vec<Token>), DiagnosticBundle> {
    crate::syntax::parser::parse_spanned_fragment_program(source, budget)
}
/// Editor-only declaration facts from an incomplete buffer. No recovered AST escapes this boundary.
pub(crate) fn editor_source_facts(
    source: &SourceFile,
    tokens: &[Token],
) -> crate::spanned_ast::AstFacts {
    let mut parser = CstAstLowerer::new(tokens, source, true, FrontendBudget::v1());
    if let Ok(program) = parser.parse_program() {
        crate::ast::drop_program_iterative(program);
    }
    parser.facts
}
pub(crate) struct GrammarParseOutput {
    pub(crate) spanned: Option<SpannedProgram>,
    pub(crate) diagnostics: DiagnosticBundle,
    pub(crate) outline: SyntaxOutline,
    pub(crate) missing: Vec<MissingSyntax>,
}
/// Parse the canonical significant token view once while recording the CST
/// structure chosen by those exact grammar decisions.
pub(crate) fn parse_with_syntax(
    source: &SourceFile,
    budget: FrontendBudget,
    tokens: &[Token],
) -> GrammarParseOutput {
    parse_with_syntax_mode(source, budget, tokens, false)
}
pub(crate) fn parse_with_syntax_mode(
    source: &SourceFile,
    budget: FrontendBudget,
    tokens: &[Token],
    fragment: bool,
) -> GrammarParseOutput {
    let mut parser = CstAstLowerer::new(tokens, source, true, budget);
    let parsed = if fragment {
        parser.parse_fragment_program()
    } else {
        parser.parse_program()
    };
    let mut errors = std::mem::take(&mut parser.errors);
    if let Err(error) = parsed.as_ref() {
        errors.push(error.as_ref().clone());
    }
    if let Ok(program) = parsed.as_ref()
        && let Some(range) = crate::ast::expression_depth_violation(
            program,
            budget.max_nesting(),
            &parser.expression_syntax_depths,
        )
    {
        let location = source.line_column(range.start);
        errors.push(*ParseError::at_range(
            range,
            location.line,
            location.column,
            "K0003",
            format!(
                "source exceeds the {}-level syntactic nesting limit",
                budget.max_nesting()
            ),
        ));
    }
    append_forbidden_source_identifier_errors(&parser, tokens, &mut errors);
    errors.sort_by(|left, right| {
        left.range
            .cmp(&right.range)
            .then_with(|| left.code.cmp(right.code))
            .then_with(|| left.message.cmp(&right.message))
    });
    parser.syntax.finish_open_nodes(source.text().len() as u32);
    let outline = std::mem::take(&mut parser.syntax).into_outline();
    let mut missing = errors
        .iter()
        .filter_map(|error| {
            error.expected.map(|expected| MissingSyntax {
                offset: error.range.start,
                expected,
                owner: error.expected_owner,
            })
        })
        .collect::<Vec<_>>();
    missing.sort_unstable_by_key(|missing| {
        (
            missing.offset,
            missing.expected as usize,
            missing.owner.unwrap_or(usize::MAX),
        )
    });
    missing.dedup_by(|right, left| right.offset == left.offset && right.expected == left.expected);
    let diagnostics = parse_diagnostic_bundle(source, errors);
    let spanned = match parsed {
        Ok(program) if diagnostics.diagnostics.is_empty() => Some(SpannedProgram {
            program,
            facts: parser.facts,
        }),
        Ok(program) => {
            crate::ast::drop_program_iterative(program);
            None
        }
        Err(_) => None,
    };
    GrammarParseOutput {
        spanned,
        diagnostics,
        outline,
        missing,
    }
}
fn append_forbidden_source_identifier_errors(
    parser: &CstAstLowerer<'_>,
    tokens: &[Token],
    errors: &mut Vec<ParseError>,
) {
    let retired_type_ranges = errors
        .iter()
        .filter(|error| error.code == "E_RETIRED_NUMERIC_TYPE")
        .map(|error| error.range)
        .collect::<std::collections::BTreeSet<_>>();
    for token in tokens {
        let TokenKind::Ident(name) = &token.kind else {
            continue;
        };
        if !kotodama_surface::source_policy::V1_FORBIDDEN_SOURCE_IDENTIFIERS
            .contains(&name.as_str())
            || retired_type_ranges.contains(&token.range)
        {
            continue;
        }
        errors.push(*parser.coded_error(
            token.clone(),
            "E_FORBIDDEN_SOURCE_IDENTIFIER",
            format!(
                "source identifier `{name}` is not part of Kotodama V1; choose a different identifier (lowercase `amount` remains available)"
            ),
        ));
    }
}
#[cfg(test)]
thread_local! {
    static CANONICAL_GRAMMAR_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(crate) fn reset_direct_cst_lowering_count() {
    CANONICAL_GRAMMAR_PARSES.with(|count| count.set(0));
}
#[cfg(test)]
pub(crate) fn record_direct_cst_lowering() {
    CANONICAL_GRAMMAR_PARSES.with(|count| count.set(count.get().saturating_add(1)));
}
#[cfg(test)]
pub(crate) fn direct_cst_lowering_count() -> usize {
    CANONICAL_GRAMMAR_PARSES.with(std::cell::Cell::get)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DelimiterKind {
    Brace,
    Bracket,
    Parenthesis,
}
impl DelimiterKind {
    fn opening(token: &TokenKind) -> Option<Self> {
        match token {
            TokenKind::LBrace => Some(Self::Brace),
            TokenKind::LBracket => Some(Self::Bracket),
            TokenKind::LParen => Some(Self::Parenthesis),
            _ => None,
        }
    }
    fn closing(token: &TokenKind) -> Option<Self> {
        match token {
            TokenKind::RBrace => Some(Self::Brace),
            TokenKind::RBracket => Some(Self::Bracket),
            TokenKind::RParen => Some(Self::Parenthesis),
            _ => None,
        }
    }
}
fn update_delimiter_stack(stack: &mut Vec<DelimiterKind>, token: &TokenKind) {
    if let Some(delimiter) = DelimiterKind::opening(token) {
        stack.push(delimiter);
    } else if let Some(delimiter) = DelimiterKind::closing(token)
        && stack.last() == Some(&delimiter)
    {
        stack.pop();
    }
}
pub(crate) fn validate_nesting(
    source: &SourceFile,
    budget: FrontendBudget,
    tokens: &[Token],
) -> Result<(), DiagnosticBundle> {
    let mut delimiter_stack = Vec::new();
    let mut prefix_depth = 0_usize;
    for token in tokens {
        match &token.kind {
            TokenKind::LBrace
            | TokenKind::LParen
            | TokenKind::LBracket
            | TokenKind::RBrace
            | TokenKind::RParen
            | TokenKind::RBracket => {
                prefix_depth = 0;
            }
            TokenKind::Bang | TokenKind::Minus | TokenKind::Plus => {
                prefix_depth = prefix_depth.saturating_add(1);
            }
            TokenKind::Comma | TokenKind::Semicolon => {
                prefix_depth = 0;
            }
            _ => prefix_depth = 0,
        }
        update_delimiter_stack(&mut delimiter_stack, &token.kind);
        // `<` and `?` are context-sensitive operators, so counting every one
        // until a statement delimiter conflates sibling AST branches. Generic
        // frames and conditional frames enforce their active path below; the
        // completed-expression validator covers comparison and mixed paths.
        if delimiter_stack.len().saturating_add(prefix_depth) > budget.max_nesting() {
            let start = source.line_column(token.range.start);
            let end = source.line_column(token.range.end);
            return Err(DiagnosticBundle::single(Diagnostic::error(
                "K0003",
                DiagnosticPhase::Parse,
                format!(
                    "source exceeds the {}-level syntactic nesting limit",
                    budget.max_nesting()
                ),
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
                    byte_range: Some(token.range),
                }),
            )));
        }
    }
    Ok(())
}
fn parse_diagnostic_bundle(source: &SourceFile, mut errors: Vec<ParseError>) -> DiagnosticBundle {
    let nesting_error = errors.iter().find(|error| error.code == "K0003").cloned();
    let omitted = errors.len().saturating_sub(MAX_DIAGNOSTICS - 1);
    errors.truncate(MAX_DIAGNOSTICS - 1);
    if let Some(nesting_error) = nesting_error
        && !errors.iter().any(|error| error.code == "K0003")
    {
        errors.pop();
        errors.push(nesting_error);
        errors.sort_by(|left, right| {
            left.range
                .cmp(&right.range)
                .then_with(|| left.code.cmp(right.code))
                .then_with(|| left.message.cmp(&right.message))
        });
    }
    let mut diagnostics = errors
        .into_iter()
        .map(|error| parse_error_diagnostic(source, error))
        .collect::<Vec<_>>();
    if omitted != 0 {
        diagnostics.push(Diagnostic::error(
            "K0004",
            DiagnosticPhase::Parse,
            format!("diagnostic limit reached; {omitted} additional syntax error(s) were omitted"),
            None,
        ));
    }
    let mut bundle = DiagnosticBundle::new(diagnostics);
    bundle.capture_source(source);
    bundle
}
/// Project one structured parse error onto the shared diagnostic model.
///
/// Site-specific help replaces the registry fallback; every fix keeps its own
/// exact range, and the first fix is the preferred one.
fn parse_error_diagnostic(source: &SourceFile, error: ParseError) -> Diagnostic {
    let ParseError {
        code,
        message,
        range,
        report_range,
        help,
        fixes,
        labels,
        ..
    } = error;
    let mut diagnostic = Diagnostic::error(
        code,
        DiagnosticPhase::Parse,
        message,
        Some(SourceSpan::from_range(
            source,
            report_range.unwrap_or(range),
        )),
    );
    if let Some(help) = help {
        diagnostic.help = Some(help);
    }
    let mut fixes = fixes.into_iter().map(|fix| DiagnosticFix {
        span: SourceSpan::from_range(source, fix.range),
        replacement: fix.replacement,
    });
    diagnostic.fix = fixes.next();
    diagnostic.alternative_fixes = fixes.collect();
    diagnostic.labels = labels
        .into_iter()
        .map(|label| DiagnosticLabel {
            span: SourceSpan::from_range(source, label.range),
            message: label.message,
        })
        .collect();
    diagnostic
}
/// Wrap a unit-test fragment in a canonical `seiyaku`/`誓約` container before parsing.
#[cfg(test)]
pub(crate) fn parse_test_fragment(src: &str) -> Result<Program, String> {
    let trimmed = src.trim_start();
    if trimmed.starts_with("seiyaku ")
        || trimmed.starts_with("誓約 ")
        || trimmed.starts_with("module ")
    {
        parse(src)
    } else {
        parse(&format!("seiyaku TestContract {{\n{src}\n}}"))
    }
}
struct CstAstLowerer<'a> {
    tokens: &'a [Token],
    pos: usize,
    source: &'a str,
    facts: AstFacts,
    current_function: Option<NodeId>,
    test_target: Option<TestTargetDecl>,
    recover: bool,
    errors: Vec<ParseError>,
    allow_struct_literals: bool,
    allow_statement_if_expression: bool,
    max_nesting: usize,
    delimiter_depths: Vec<usize>,
    expression_syntax_depths: Vec<usize>,
    recursive_expression_entry_depths: Vec<usize>,
    statement_if_condition_depths: Vec<usize>,
    declared_function_parameters: std::collections::BTreeMap<String, Option<Vec<String>>>,
    syntax: SyntaxOutlineBuilder,
    /// Start of the declaration token already reported as following a body
    /// whose `}` is missing, so enclosing blocks do not report it again.
    missing_close_reported: Option<u32>,
}
impl<'a> CstAstLowerer<'a> {
    fn new(
        tokens: &'a [Token],
        source: &'a SourceFile,
        recover: bool,
        budget: FrontendBudget,
    ) -> Self {
        let mut syntax = SyntaxOutlineBuilder::default();
        syntax.start(SyntaxKind::Root, 0);
        let mut delimiter_stack = Vec::new();
        let delimiter_depths = tokens
            .iter()
            .map(|token| {
                let depth_before = delimiter_stack.len();
                update_delimiter_stack(&mut delimiter_stack, &token.kind);
                depth_before
            })
            .collect();
        Self {
            tokens,
            pos: 0,
            source: source.text(),
            facts: AstFacts::new(source.id()),
            current_function: None,
            test_target: None,
            recover,
            errors: Vec::new(),
            allow_struct_literals: true,
            allow_statement_if_expression: false,
            max_nesting: budget.max_nesting(),
            delimiter_depths,
            expression_syntax_depths: Vec::new(),
            recursive_expression_entry_depths: Vec::new(),
            statement_if_condition_depths: Vec::new(),
            declared_function_parameters: std::collections::BTreeMap::new(),
            syntax,
            missing_close_reported: None,
        }
    }
    fn current_start(&self) -> u32 {
        self.tokens
            .get(self.pos)
            .or_else(|| self.tokens.last())
            .map_or(0, |token| token.range.start)
    }
    fn previous_end(&self, fallback: u32) -> u32 {
        self.tokens
            .get(self.pos.saturating_sub(1))
            .map_or(fallback, |token| token.range.end)
    }
    fn begin_node(&mut self, kind: AstNodeKind, start: u32) -> NodeId {
        self.facts
            .source_map
            .begin_owned(kind, start, self.current_function)
    }
    fn finish_node(&mut self, node: NodeId) {
        let start = self
            .facts
            .source_map
            .node(node)
            .map_or(0, |entry| entry.range.start);
        let end = self.previous_end(start);
        self.facts.source_map.finish(node, end);
    }
    fn syntax_start(&mut self, kind: SyntaxKind, start: u32) -> usize {
        self.syntax.start(kind, start)
    }
    fn syntax_finish(&mut self, node: usize, fallback: u32) {
        self.syntax.finish(node, self.previous_end(fallback));
    }
    fn syntax_finish_at(&mut self, node: usize, end: u32) {
        self.syntax.finish(node, end);
    }
    fn syntax_set_kind(&mut self, node: usize, kind: SyntaxKind) {
        self.syntax.set_kind(node, kind);
    }
    fn syntax_checkpoint(&self) -> SyntaxOutlineCheckpoint {
        self.syntax.checkpoint()
    }
    fn syntax_rollback(&mut self, checkpoint: SyntaxOutlineCheckpoint) {
        self.syntax.rollback(checkpoint);
    }
    fn with_syntax<T>(
        &mut self,
        kind: SyntaxKind,
        start: u32,
        parse: impl FnOnce(&mut Self) -> ParseResult<T>,
    ) -> ParseResult<T> {
        let node = self.syntax_start(kind, start);
        let result = parse(self);
        self.syntax_finish(node, start);
        result
    }
    fn syntax_item_kind(&self, start: usize) -> SyntaxKind {
        let mut cursor = start;
        while matches!(
            self.tokens.get(cursor).map(|token| &token.kind),
            Some(TokenKind::Hash)
        ) {
            let mut bracket_depth = 0_usize;
            while let Some(token) = self.tokens.get(cursor) {
                if bracket_depth != 0
                    && matches!(
                        token.kind,
                        TokenKind::Fn
                            | TokenKind::Kotoage
                            | TokenKind::View
                            | TokenKind::Hajimari
                            | TokenKind::Kaizen
                            | TokenKind::Struct
                            | TokenKind::Event
                            | TokenKind::Error
                            | TokenKind::Enum
                            | TokenKind::Const
                            | TokenKind::State
                            | TokenKind::Trigger
                    )
                {
                    break;
                }
                cursor = cursor.saturating_add(1);
                match token.kind {
                    TokenKind::LBracket => bracket_depth = bracket_depth.saturating_add(1),
                    TokenKind::RBracket => {
                        bracket_depth = bracket_depth.saturating_sub(1);
                        if bracket_depth == 0 {
                            break;
                        }
                    }
                    TokenKind::EOF | TokenKind::RBrace => break,
                    _ => {}
                }
            }
        }
        if matches!(
            self.tokens.get(cursor).map(|token| &token.kind),
            Some(TokenKind::Export)
        ) {
            cursor = cursor.saturating_add(1);
        }
        match self.tokens.get(cursor).map(|token| &token.kind) {
            Some(
                TokenKind::Fn
                | TokenKind::Kotoage
                | TokenKind::View
                | TokenKind::Hajimari
                | TokenKind::Kaizen,
            ) => SyntaxKind::FunctionItem,
            Some(TokenKind::Struct) => SyntaxKind::StructItem,
            Some(TokenKind::Event) => SyntaxKind::EventItem,
            Some(TokenKind::Error | TokenKind::Enum) => SyntaxKind::EnumItem,
            Some(TokenKind::Const) => SyntaxKind::ConstItem,
            Some(TokenKind::State) => SyntaxKind::StateItem,
            Some(TokenKind::Trigger) => SyntaxKind::TriggerItem,
            Some(TokenKind::Include) => SyntaxKind::IncludeItem,
            Some(TokenKind::Import)
                if self
                    .tokens
                    .get(cursor + 1)
                    .is_some_and(|token| token.kind == TokenKind::Permission) =>
            {
                SyntaxKind::PermissionItem
            }
            Some(TokenKind::Permission) => SyntaxKind::PermissionItem,
            Some(TokenKind::Import) => SyntaxKind::ImportItem,
            Some(TokenKind::Ident(name)) if name == "fixture" => SyntaxKind::FixtureItem,
            Some(TokenKind::Ident(name)) if name == "koto_test" => SyntaxKind::TestTargetItem,
            _ => SyntaxKind::ErrorNode,
        }
    }
    fn syntax_statement_kind(&self, start: usize) -> SyntaxKind {
        match self.tokens.get(start).map(|token| &token.kind) {
            Some(TokenKind::Let | TokenKind::Var) => SyntaxKind::LetStmt,
            Some(TokenKind::Return) => SyntaxKind::ReturnStmt,
            Some(TokenKind::Break) => SyntaxKind::BreakStmt,
            Some(TokenKind::Continue) => SyntaxKind::ContinueStmt,
            Some(TokenKind::If) => SyntaxKind::IfStmt,
            Some(TokenKind::For) => SyntaxKind::ForStmt,
            _ => SyntaxKind::ExprStmt,
        }
    }
    fn record_declaration(
        &mut self,
        node: NodeId,
        name: String,
        name_range: TextRange,
        kind: DeclarationKind,
        owner: Option<NodeId>,
    ) {
        let name_node = self
            .facts
            .source_map
            .allocate_owned(AstNodeKind::Name, name_range, owner);
        self.facts.declarations.push(DeclarationFact {
            node,
            name_node,
            owner,
            name,
            kind,
            documentation: String::new(),
        });
    }
    fn record_type_use(&mut self, name: String, range: TextRange) {
        let node =
            self.facts
                .source_map
                .allocate_owned(AstNodeKind::Type, range, self.current_function);
        self.facts.type_uses.push(TypeUseFact {
            node,
            owner: self.current_function,
            name,
        });
    }
    fn current_delimiter_depth(&self) -> usize {
        self.delimiter_depths.get(self.pos).copied().unwrap_or(0)
    }
    fn enter_recursive_expression(&mut self) -> ParseResult<()> {
        let delimiter_depth = self.current_delimiter_depth();
        let unrepresented_depth = self
            .recursive_expression_entry_depths
            .iter()
            .filter(|entry_depth| **entry_depth >= delimiter_depth)
            .count()
            .saturating_add(1);
        // A parsed `if` may be committed as a statement, where its condition
        // shares the enclosing block depth. Use that most-permissive shape
        // here; the final AST validation applies the exact committed context.
        if delimiter_depth.saturating_add(unrepresented_depth.saturating_sub(1)) > self.max_nesting
        {
            let range = self
                .tokens
                .get(self.pos)
                .map_or(TextRange::empty(self.current_start()), |token| token.range);
            return Err(self.nesting_error(range));
        }
        self.recursive_expression_entry_depths.push(delimiter_depth);
        Ok(())
    }
    fn leave_recursive_expression(&mut self) {
        self.recursive_expression_entry_depths
            .pop()
            .expect("recursive expression entry must be balanced");
    }
    fn nesting_error(&self, range: TextRange) -> Box<ParseError> {
        let token = self
            .tokens
            .iter()
            .find(|token| token.range.start <= range.start && range.start < token.range.end)
            .or_else(|| {
                self.tokens
                    .iter()
                    .find(|token| token.range.start == range.start)
            })
            .cloned()
            .unwrap_or_else(|| {
                self.tokens
                    .last()
                    .cloned()
                    .unwrap_or_else(|| self.bump_token())
            });
        let mut error = self.coded_error(
            token,
            "K0003",
            format!(
                "source exceeds the {}-level syntactic nesting limit",
                self.max_nesting
            ),
        );
        error.range = range;
        error
    }
    fn bump_token(&self) -> Token {
        Token {
            kind: TokenKind::EOF,
            line: 1,
            column: 1,
            range: TextRange::empty(0),
        }
    }
    fn guard_expression_depth(&mut self, expression: Expr) -> Expr {
        let root_depth = if self.allow_statement_if_expression
            && matches!(expression.kind(), Expr::If { .. } | Expr::IfLet { .. })
        {
            self.current_delimiter_depth().saturating_sub(1)
        } else {
            self.current_delimiter_depth()
        };
        self.guard_expression_depth_at(expression, root_depth)
    }
    fn guard_expression_depth_at(&mut self, expression: Expr, root_depth: usize) -> Expr {
        let violation = crate::ast::expression_depth_violation_in_expression(
            &expression,
            root_depth,
            self.max_nesting,
            &self.expression_syntax_depths,
        );
        let Some(range) = violation else {
            return expression;
        };
        if !self.errors.iter().any(|error| error.code == "K0003") {
            let error = self.nesting_error(range);
            self.errors.push(*error);
        }
        let source = match &expression {
            Expr::Source { node, source, .. } => Some((*node, *source)),
            _ => None,
        };
        crate::ast::drop_expression_iterative(expression);
        source.map_or(Expr::Bool(false), |(node, source)| Expr::Source {
            node,
            source,
            expression: Box::new(Expr::Bool(false)),
        })
    }
    fn sourced_expression(&mut self, node: NodeId, source: SourceRange, expression: Expr) -> Expr {
        self.guard_expression_depth(Expr::Source {
            node,
            source,
            expression: Box::new(expression),
        })
    }
    fn add_expression_syntax_depth(&mut self, expression: Expr, depth: usize) -> Expr {
        if depth == 0 {
            return expression;
        }
        if let Some(node) = expression.source_node() {
            let required = node.index().saturating_add(1);
            if self.expression_syntax_depths.len() < required {
                self.expression_syntax_depths.resize(required, 0);
            }
            self.expression_syntax_depths[node.index()] =
                self.expression_syntax_depths[node.index()].saturating_add(depth);
        }
        self.guard_expression_depth(expression)
    }
    fn source_expression(&mut self, kind: AstNodeKind, range: TextRange, expression: Expr) -> Expr {
        let node = self
            .facts
            .source_map
            .allocate_owned(kind, range, self.current_function);
        self.sourced_expression(
            node,
            SourceRange::new(self.facts.source_map.source(), range),
            expression,
        )
    }
    fn source_expression_from(&mut self, start: u32, expression: Expr) -> Expr {
        let range = TextRange::new(start, self.previous_end(start));
        if expression
            .source()
            .is_some_and(|source| source.range == range)
        {
            expression
        } else {
            self.source_expression(AstNodeKind::Expression, range, expression)
        }
    }
    fn source_statement(&mut self, range: TextRange, statement: Statement) -> Statement {
        let node = self.facts.source_map.allocate_owned(
            AstNodeKind::Statement,
            range,
            self.current_function,
        );
        Statement::Source {
            node,
            source: SourceRange::new(self.facts.source_map.source(), range),
            statement: Box::new(statement),
        }
    }
    fn finish_owned_expression(
        &mut self,
        owner: NodeId,
        kind: AstNodeKind,
        range: TextRange,
        expression: Expr,
    ) -> Expr {
        self.finish_owned_expression_at_depth(
            owner,
            kind,
            range,
            expression,
            self.current_delimiter_depth(),
        )
    }
    fn finish_owned_expression_at_depth(
        &mut self,
        owner: NodeId,
        kind: AstNodeKind,
        range: TextRange,
        expression: Expr,
        root_depth: usize,
    ) -> Expr {
        self.facts.source_map.set_kind(owner, kind);
        self.facts.source_map.finish(owner, range.end);
        self.guard_expression_depth_at(
            Expr::Source {
                node: owner,
                source: SourceRange::new(self.facts.source_map.source(), range),
                expression: Box::new(expression),
            },
            root_depth,
        )
    }
    fn finish_owned_statement(
        &mut self,
        owner: NodeId,
        range: TextRange,
        statement: Statement,
    ) -> Statement {
        self.facts
            .source_map
            .set_kind(owner, AstNodeKind::Statement);
        self.facts.source_map.finish(owner, range.end);
        Statement::Source {
            node: owner,
            source: SourceRange::new(self.facts.source_map.source(), range),
            statement: Box::new(statement),
        }
    }
    fn record_binding(
        &mut self,
        owner: NodeId,
        ordinal: usize,
        name: String,
        range: TextRange,
        kind: BindingFactKind,
    ) {
        let ordinal = u16::try_from(ordinal).expect("one node's binding budget fits u16");
        let name_node =
            self.facts
                .source_map
                .allocate_owned(AstNodeKind::Name, range, self.current_function);
        self.facts.bindings.push(BindingFact {
            owner,
            ordinal,
            name_node,
            name,
            kind,
        });
    }
    fn source_type(&mut self, range: TextRange, ty: TypeExpr) -> TypeExpr {
        let node =
            self.facts
                .source_map
                .allocate_owned(AstNodeKind::Type, range, self.current_function);
        TypeExpr::Source {
            node,
            source: SourceRange::new(self.facts.source_map.source(), range),
            ty: Box::new(ty),
        }
    }
    fn record_call(
        &mut self,
        name: String,
        name_range: TextRange,
        call_range: TextRange,
        implicit_receiver: bool,
        argument_name_nodes: Vec<Option<NodeId>>,
    ) -> (NodeId, SourceRange) {
        let node = self.facts.source_map.allocate_owned(
            AstNodeKind::Call,
            call_range,
            self.current_function,
        );
        let name_node = self.facts.source_map.allocate_owned(
            AstNodeKind::Name,
            name_range,
            self.current_function,
        );
        self.facts.calls.push(CallFact {
            node,
            name_node,
            owner: self.current_function,
            name,
            implicit_receiver,
            argument_name_nodes,
        });
        (
            node,
            SourceRange::new(self.facts.source_map.source(), call_range),
        )
    }
    fn parse_program(&mut self) -> ParseResult<Program> {
        let kind = if self.peek(TokenKind::Seiyaku) {
            SourceUnitKind::Seiyaku
        } else if self.peek(TokenKind::Module) {
            SourceUnitKind::Module
        } else {
            let token = self.current_token();
            let (error, recovered) = self.source_unit_error(&token);
            // A recognisable misspelling of the unit keyword is reported once
            // and parsing continues as that unit, so the body is still checked
            // without cascading errors.
            match recovered {
                Some(kind) if self.recover => {
                    self.errors.push(*error);
                    kind
                }
                _ => {
                    self.bump();
                    return Err(error);
                }
            }
        };
        let errors_before_unit = self.errors.len();
        let (unit, parts) = self.parse_source_unit(kind)?;
        // After an earlier error inside the unit, leftover tokens are the
        // consequence of that error's recovery, not a second problem.
        if !self.peek(TokenKind::EOF) && self.errors.len() == errors_before_unit {
            let token = self.bump();
            let unit_name = unit.name.clone();
            drop(parts);
            return Err(self.trailing_source_error(token, &unit_name));
        }
        let (items, fixtures, directives, exports, permissions) = parts.into_inner();
        Ok(Program {
            unit,
            items,
            permissions,
            directives,
            exports,
            test_target: self.test_target.take(),
            fixtures,
        })
    }
    /// Diagnose a file that does not start with `seiyaku`/`誓約` or `module`.
    ///
    /// Returns the error and, when the token is a recognisable stand-in for
    /// the unit keyword (an English word or a typo), the unit kind recovery
    /// should continue with.
    fn source_unit_error(&self, token: &Token) -> (Box<ParseError>, Option<SourceUnitKind>) {
        let help = "a source file contains exactly one `seiyaku Name { ... }` (deployable; also spelled `誓約`) or one `module Name { ... }` (reusable library)";
        if let TokenKind::Ident(word) = &token.kind
            && self.peek_n_ident(1)
            && self.peek_n(2, TokenKind::LBrace)
        {
            if let Some(keyword) = crate::glossary::suggestion_for(word)
                && keyword.romaji == "seiyaku"
            {
                let error = self
                    .english_word_error(token, keyword, "a deployable unit")
                    .with_help(help);
                return (error, Some(SourceUnitKind::Seiyaku));
            }
            if let Some(suggestion) =
                crate::diagnostic::suggest::closest(word, ["seiyaku", "module"])
            {
                let kind = if suggestion == "module" {
                    SourceUnitKind::Module
                } else {
                    SourceUnitKind::Seiyaku
                };
                return (self.keyword_typo_error(token, suggestion), Some(kind));
            }
        }
        let error = self
            .expected_error(token.clone(), "a `seiyaku`/`誓約` or `module` source unit")
            .with_help(help);
        (error, None)
    }
    /// Diagnose tokens after the closing brace of the source unit.
    fn trailing_source_error(&self, token: Token, unit_name: &str) -> Box<ParseError> {
        match token.kind {
            TokenKind::Seiyaku | TokenKind::Module => {
                let spelling = self.spelling(&token).to_owned();
                self.coded_error(
                    token,
                    "K1001",
                    format!(
                        "a source file contains exactly one seiyaku or module, but `{spelling}` starts a second one after `{unit_name}`"
                    ),
                )
                .with_help(
                    "move the second unit into its own `.ko` file and connect them with `import`",
                )
            }
            TokenKind::RBrace => self
                .coded_error(
                    token,
                    "K1001",
                    format!("unmatched `}}` after the end of `{unit_name}`"),
                )
                .with_help(
                    "remove the extra `}`, or check that every `{` inside the unit is closed exactly once",
                ),
            _ => {
                let found = describe_found(self.source, &token);
                self.coded_error(
                    token,
                    "K1001",
                    format!("{found} appears after the end of `{unit_name}`"),
                )
                .with_help(format!(
                    "declarations belong inside the braces of `{unit_name}`; move this text before its closing `}}`"
                ))
            }
        }
    }
    /// Whether the token at `offset` is an identifier.
    fn peek_n_ident(&self, offset: usize) -> bool {
        matches!(
            self.tokens.get(self.pos + offset).map(|token| &token.kind),
            Some(TokenKind::Ident(_) | TokenKind::Permission)
        )
    }
    /// Whether the function head starting at the cursor declares
    /// `authorize(...)` before its body `{`.
    fn function_head_authorizes(&self) -> bool {
        self.tokens[self.pos.min(self.tokens.len())..]
            .iter()
            .take_while(|token| {
                !matches!(
                    token.kind,
                    TokenKind::LBrace | TokenKind::RBrace | TokenKind::Semicolon | TokenKind::EOF
                )
            })
            .any(|token| token.kind == TokenKind::Authorize)
    }
    /// `E_ENGLISH_DECLARATION_WORD`: an English concept word written where a
    /// branded keyword declares the concept. Offers both spellings.
    fn english_word_error(
        &self,
        token: &Token,
        keyword: &'static crate::glossary::BrandedKeyword,
        concept: &str,
    ) -> Box<ParseError> {
        let word = self.spelling(token);
        ParseError::at(
            token,
            "E_ENGLISH_DECLARATION_WORD",
            format!(
                "`{word}` is not a Kotodama keyword; {concept} is declared with `{}` or `{}`",
                keyword.romaji, keyword.kanji
            ),
        )
        .with_help(format!(
            "`{}`/`{}` ({}, \u{201c}{}\u{201d}) {}; both spellings are the same keyword",
            keyword.romaji,
            keyword.kanji,
            keyword.reading,
            keyword.literal,
            lowercase_first(keyword.role)
        ))
        .with_fix(token.range, keyword.romaji)
        .with_fix(token.range, keyword.kanji)
    }
    /// `E_KEYWORD_TYPO`: a near-miss spelling of a keyword. Branded keywords
    /// offer both spellings.
    fn keyword_typo_error(&self, token: &Token, suggestion: &str) -> Box<ParseError> {
        let word = self.spelling(token);
        let branded = crate::glossary::by_spelling(suggestion);
        let message = match branded {
            Some(keyword) => format!(
                "unknown keyword `{word}`; did you mean `{}`/`{}`?",
                keyword.romaji, keyword.kanji
            ),
            None => format!("unknown keyword `{word}`; did you mean `{suggestion}`?"),
        };
        let mut error = ParseError::at(token, "E_KEYWORD_TYPO", message)
            .with_help("keywords are case-sensitive and spelled exactly as in the V1 keyword table")
            .with_fix(token.range, suggestion);
        if let Some(keyword) = branded {
            error = error.with_fix(token.range, keyword.kanji);
        }
        error
    }
    /// Diagnose a token that cannot start a declaration inside a source unit.
    ///
    /// English concept words and keyword typos get targeted errors with
    /// fixes; when their shape is unambiguous the item loop continues as the
    /// intended declaration.
    fn source_item_error(
        &self,
        token: &Token,
        unit: SourceUnitKind,
    ) -> (Box<ParseError>, Option<ItemRecovery>) {
        const ITEMS: &str = "`fn`, `kotoage fn`/`言挙げ fn`, `view fn`, `hajimari`/`始まり`, `kaizen`/`改善`, `trigger`, `struct`, `enum`, `error enum`, `const` or `state`";
        let next = self.tokens.get(self.pos + 1).map(|token| &token.kind);
        let in_module = unit == SourceUnitKind::Module;
        if let TokenKind::Ident(word) = &token.kind {
            if let Some(keyword) = crate::glossary::suggestion_for(word) {
                match keyword.romaji {
                    "kotoage" if next == Some(&TokenKind::Fn) && in_module => {
                        // Modules have no kotoage or view functions; their
                        // public surface is `export`.
                        let error = ParseError::at(
                            token,
                            "E_ENGLISH_DECLARATION_WORD",
                            format!(
                                "`{}` is not a Kotodama keyword; a module makes a function public with `export`",
                                self.spelling(token)
                            ),
                        )
                        .with_help("a module shares functions, structs, enums and constants with `export`; public `kotoage fn` (also `言挙げ fn`) and `view fn` functions belong to a seiyaku")
                        .with_fix(token.range, "export");
                        return (error, Some(ItemRecovery::Function(FunctionKind::Private)));
                    }
                    "kotoage" if next == Some(&TokenKind::Fn) => {
                        let mut error = self
                            .english_word_error(token, keyword, "a public state-changing function")
                            .with_help(
                                "public functions are `kotoage fn` (also `言挙げ fn`; submitted in a transaction, may write state, requires an explicit `authorize(...)`) or `view fn` (read-only); plain `fn` is private to the unit",
                            );
                        let view = ParseFix {
                            range: token.range,
                            replacement: "view".to_owned(),
                        };
                        // Without a permission clause `kotoage` would fail to
                        // compile, so the read-only `view` is preferred.
                        if self.function_head_authorizes() {
                            error.fixes.push(view);
                        } else {
                            error.fixes.insert(0, view);
                        }
                        return (error, Some(ItemRecovery::Function(FunctionKind::Kotoage)));
                    }
                    "hajimari" | "kaizen" if next == Some(&TokenKind::LParen) && in_module => {
                        let mut error = self
                            .english_word_error(token, keyword, "a lifecycle hook of a seiyaku")
                            .with_help("modules have no lifecycle hooks; a seiyaku declares them, and a module function needs `fn`: `fn name(...) { ... }`");
                        error.fixes.clear();
                        return (error, None);
                    }
                    "hajimari" | "kaizen" if next == Some(&TokenKind::LParen) => {
                        let (concept, kind) = if keyword.romaji == "hajimari" {
                            ("the activation hook", TokenKind::Hajimari)
                        } else {
                            ("the in-place code replacement hook", TokenKind::Kaizen)
                        };
                        let error = self.english_word_error(token, keyword, concept);
                        return (error, Some(ItemRecovery::Hook(kind)));
                    }
                    "seiyaku" => {
                        // Renaming the word would still declare a unit inside
                        // another, so no fix is offered.
                        let mut error = self
                            .english_word_error(token, keyword, "a deployable unit")
                            .with_help("a source file contains exactly one seiyaku or module, so a unit cannot be declared inside another; put it in its own `.ko` file and connect the files with `import`");
                        error.fixes.clear();
                        return (error, None);
                    }
                    _ => {}
                }
            }
            let candidates = [
                "fn", "kotoage", "view", "hajimari", "kaizen", "trigger", "struct", "error",
                "const", "state", "include", "import", "export",
            ];
            if let Some(suggestion) = crate::diagnostic::suggest::closest(word, candidates) {
                let recovery = match suggestion {
                    "kotoage" if next == Some(&TokenKind::Fn) => {
                        Some(ItemRecovery::Function(FunctionKind::Kotoage))
                    }
                    "view" if next == Some(&TokenKind::Fn) => {
                        Some(ItemRecovery::Function(FunctionKind::View))
                    }
                    "hajimari" if next == Some(&TokenKind::LParen) => {
                        Some(ItemRecovery::Hook(TokenKind::Hajimari))
                    }
                    "kaizen" if next == Some(&TokenKind::LParen) => {
                        Some(ItemRecovery::Hook(TokenKind::Kaizen))
                    }
                    _ => None,
                };
                return (self.keyword_typo_error(token, suggestion), recovery);
            }
        }
        let error = self
            .expected_error(token.clone(), &format!("a declaration ({ITEMS})"))
            .with_help("a seiyaku contains state, functions, lifecycle hooks, triggers, structs, enums and constants; statements belong inside a function body");
        (error, None)
    }
    /// `E_DECLARATION_SHAPE` for `kotoage view fn` / `view kotoage fn`.
    fn mixed_role_error(&self, first: &Token, second: &Token) -> Box<ParseError> {
        let first_text = self.spelling(first);
        let second_text = self.spelling(second);
        self.coded_error(
            second.clone(),
            "E_DECLARATION_SHAPE",
            format!(
                "a function is either `{}` or `{}`, not both: `{first_text}` and `{second_text}` cannot be combined",
                if first.kind == TokenKind::Kotoage { format!("{first_text} fn") } else { format!("{second_text} fn") },
                if first.kind == TokenKind::View { format!("{first_text} fn") } else { format!("{second_text} fn") },
            ),
        )
        .with_help("`kotoage fn` (also `言挙げ fn`) is submitted in a transaction and may change state; `view fn` only reads state")
        .with_fix(TextRange::new(first.range.end, second.range.end), "")
        .with_fix(TextRange::new(first.range.start, second.range.start), "")
    }
    /// Parse a `hajimari`/`kaizen` hook whose keyword token was consumed.
    fn parse_lifecycle_hook(
        &mut self,
        hook: &Token,
        attrs: &FunctionAttributes,
        declaration_start: u32,
    ) -> ParseResult<Item> {
        let (name, kind) = if matches!(hook.kind, TokenKind::Kaizen) {
            ("kaizen", FunctionKind::Kaizen)
        } else {
            ("hajimari", FunctionKind::Hajimari)
        };
        self.parse_fn_loose(
            Some(name.to_owned()),
            FunctionModifiers {
                kind,
                authorization: None,
                is_test: attrs.is_test,
                test_fixture: attrs.test_fixture.clone(),
            },
            declaration_start,
            Some(hook.clone()),
        )
    }
    /// Consume a `keyword(...)` clause whose keyword was just consumed and
    /// return its full range. Stops before `{` or the end of the file when the
    /// parentheses are unbalanced.
    fn skip_balanced_clause(&mut self, keyword: &Token) -> TextRange {
        let mut end = keyword.range.end;
        if !self.peek(TokenKind::LParen) {
            return keyword.range;
        }
        let mut depth = 0_usize;
        while let Some(token) = self.tokens.get(self.pos) {
            match token.kind {
                TokenKind::LParen => depth += 1,
                TokenKind::RParen => depth = depth.saturating_sub(1),
                TokenKind::LBrace | TokenKind::EOF => break,
                _ => {}
            }
            end = token.range.end;
            self.pos += 1;
            if depth == 0 {
                break;
            }
        }
        TextRange::new(keyword.range.start, end)
    }
    /// Leading spaces and tabs of the line containing `offset`.
    fn line_indentation(&self, offset: u32) -> &'a str {
        let source: &'a str = self.source;
        let before = source.get(..offset as usize).unwrap_or("");
        let line_start = before.rfind('\n').map_or(0, |newline| newline + 1);
        let line = &source[line_start..];
        let width = line
            .bytes()
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count();
        &line[..width]
    }
    /// Extend `range` backwards over spaces and tabs on the same line, so a
    /// deletion fix also removes the separating whitespace.
    fn leading_space_range(&self, range: TextRange) -> TextRange {
        let prefix = &self.source.as_bytes()[..range.start as usize];
        let spaces = prefix
            .iter()
            .rev()
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count();
        TextRange::new(range.start - spaces as u32, range.end)
    }
    /// Parse `name: Type` at a declaration site, report it once as
    /// `E_RETIRED_DECLARATION_ORDER` and continue as the type-first
    /// declaration `Type name`.
    ///
    /// The cursor is at `name`, followed by `:`. The fix rewrites the text with
    /// the user's own names, and parsing continues so later declarations in
    /// the same list are still checked. Returns the parsed type and the name
    /// token.
    fn colon_declaration(&mut self, site: DeclarationSite) -> ParseResult<(TypeExpr, Token)> {
        let name_token = self.current_token();
        let (error, ty) = self.colon_declaration_error(site)?;
        let mut ty = PendingType::new(ty);
        self.report(error)?;
        Ok((ty.take(), name_token))
    }
    /// Build the `E_RETIRED_DECLARATION_ORDER` error for `name: Type`,
    /// consuming the name, the colon and the type.
    fn colon_declaration_error(
        &mut self,
        site: DeclarationSite,
    ) -> ParseResult<(Box<ParseError>, TypeExpr)> {
        let name_token = self.bump();
        let colon = self.bump();
        let type_start = self.current_start();
        let parsed_type = self.parse_type_expr()?;
        let type_end = self.previous_end(type_start);
        let name = self.spelling(&name_token).to_owned();
        let ty = self
            .source
            .get(type_start as usize..type_end as usize)
            .unwrap_or("")
            .to_owned();
        let (what, example) = match site {
            DeclarationSite::Parameter => ("parameters", format!("`{ty} {name}`")),
            DeclarationSite::StructField => ("struct fields", format!("`{ty} {name};`")),
            DeclarationSite::State => ("state declarations", format!("`state {ty} {name};`")),
            DeclarationSite::Const => ("constants", format!("`const {ty} {name} = ...;`")),
            DeclarationSite::Local => ("typed locals", format!("`let {ty} {name} = ...;`")),
        };
        let written = TextRange::new(name_token.range.start, type_end);
        let error = ParseError::at(
            &colon,
            "E_RETIRED_DECLARATION_ORDER",
            format!("{what} are type-first: write {example}, not `{name}: {ty}`"),
        )
        .reported_at(written)
        .with_help(declaration_order_help())
        .with_fix(written, format!("{ty} {name}"));
        Ok((error, parsed_type))
    }
    /// `E_RETIRED_DECLARATION_ORDER` when a complex type is followed by `:`,
    /// a shape the `name: Type` lookahead cannot rewrite exactly.
    fn type_then_colon_error(&mut self, message: &str) -> Box<ParseError> {
        let colon = self.bump();
        self.coded_error(colon, "E_RETIRED_DECLARATION_ORDER", message)
            .with_help(declaration_order_help())
    }
    /// Whether the current identifier reads as a type (a scalar type name or
    /// a capitalized nominal type) rather than a declared name, so `fn f(int)`
    /// is a missing name while `fn f(value)` is a missing type.
    fn current_names_a_type(&self) -> bool {
        matches!(
            self.tokens.get(self.pos).map(|token| &token.kind),
            Some(TokenKind::Ident(name))
                if matches!(name.as_str(), "int" | "decimal" | "quantity" | "bool" | "string" | "bytes")
                    || name.starts_with(|character: char| character.is_ascii_uppercase())
        )
    }
    /// `E_MISSING_DECLARATION_TYPE` for a declaration that names no type.
    fn missing_type_error(&mut self, site: DeclarationSite) -> Box<ParseError> {
        let name_token = self.bump();
        let name = self.spelling(&name_token).to_owned();
        let (what, example) = match site {
            DeclarationSite::Parameter => ("parameter", format!("`int {name}`")),
            DeclarationSite::StructField => ("struct field", format!("`int {name};`")),
            DeclarationSite::State => ("state declaration", format!("`state int {name};`")),
            DeclarationSite::Const => ("constant", format!("`const int {name} = ...;`")),
            DeclarationSite::Local => ("local", format!("`let int {name} = ...;`")),
        };
        ParseError::at(
            &name_token,
            "E_MISSING_DECLARATION_TYPE",
            format!("{what} `{name}` needs a type before its name, for example {example}"),
        )
        .with_help("declarations name the type first; the type is never inferred for parameters, fields, state or constants")
    }
    /// `for (item in xs)`: Kotodama loop headers are not parenthesized.
    fn report_parenthesized_for_header(&mut self) -> ParseResult<()> {
        let opening = self.current_token();
        let mut depth = 0_usize;
        let mut closing = None;
        for token in &self.tokens[self.pos..] {
            match token.kind {
                TokenKind::LParen => depth += 1,
                TokenKind::RParen => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        closing = Some(token.clone());
                        break;
                    }
                }
                TokenKind::LBrace | TokenKind::EOF => break,
                _ => {}
            }
        }
        let mut error = self
            .coded_error(
                opening.clone(),
                "K1001",
                "`for` loop headers are not parenthesized",
            )
            .with_help("write `for item in collection { ... }` or `for i in range(N) { ... }`");
        if let Some(closing) = closing {
            let inner = self
                .source
                .get(opening.range.end as usize..closing.range.start as usize)
                .unwrap_or("")
                .trim()
                .to_owned();
            let header = TextRange::new(opening.range.start, closing.range.end);
            error = error.reported_at(header).with_fix(header, inner);
        }
        Err(error)
    }
    /// `E_UNSUPPORTED_LOOP` for a three-clause `for (init; condition; step)`
    /// header at the cursor, or `None` when the parentheses hold no `;`.
    ///
    /// The canonical counting shape `(i = 0; i < N; i += 1)` (optionally
    /// declaring `i` with `var`, `let` or `int`, and with `<=` or
    /// `i = i + 1`) gets an exact `i in range(N)` fix.
    fn three_clause_for_error(&self) -> Option<Box<ParseError>> {
        let opening = self.tokens.get(self.pos)?;
        let mut depth = 0_usize;
        let mut separators = Vec::new();
        let mut closing = None;
        for (index, token) in self.tokens.iter().enumerate().skip(self.pos) {
            match token.kind {
                TokenKind::LParen | TokenKind::LBracket => depth += 1,
                TokenKind::RParen | TokenKind::RBracket => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        closing = Some(index);
                        break;
                    }
                }
                TokenKind::Semicolon if depth == 1 => separators.push(index),
                TokenKind::LBrace | TokenKind::RBrace | TokenKind::EOF => break,
                _ => {}
            }
        }
        if separators.is_empty() {
            return None;
        }
        let closing_index = closing?;
        let header = TextRange::new(opening.range.start, self.tokens[closing_index].range.end);
        let mut error = self
            .coded_error(
                opening.clone(),
                "E_UNSUPPORTED_LOOP",
                "`for (init; condition; step)` loops are not part of Kotodama; every loop is a `for` loop with a compiler-proven bound",
            )
            .reported_at(header)
            .with_help("count with `for i in range(N) { ... }`, which runs i = 0 up to N - 1; `N` must be a compile-time integer expression");
        if let [first, second] = separators[..]
            && let Some(replacement) =
                self.counted_range_header(self.pos + 1, first, second, closing_index)
        {
            error = error.with_fix(header, replacement);
        }
        Some(error)
    }
    /// `i in range(N)` for the token ranges `i = 0`, `i < N` and `i += 1`
    /// between the given separator indices, when they have exactly that shape.
    fn counted_range_header(
        &self,
        start: usize,
        first: usize,
        second: usize,
        closing: usize,
    ) -> Option<String> {
        let kinds = |range: std::ops::Range<usize>| self.tokens.get(range);
        let mut init = kinds(start..first)?;
        if let [
            Token {
                kind: TokenKind::Var | TokenKind::Let,
                ..
            },
            rest @ ..,
        ] = init
        {
            init = rest;
        }
        if let [
            Token {
                kind: TokenKind::Ident(ty),
                ..
            },
            rest @ ..,
        ] = init
            && ty == "int"
            && rest.len() == 3
        {
            init = rest;
        }
        let name = match init {
            [
                Token {
                    kind: TokenKind::Ident(name),
                    ..
                },
                Token {
                    kind: TokenKind::Equal,
                    ..
                },
                zero,
            ] if self.spelling(zero) == "0" => name,
            _ => return None,
        };
        let condition = kinds(first + 1..second)?;
        let (inclusive, bound) = match condition {
            [
                Token {
                    kind: TokenKind::Ident(left),
                    ..
                },
                operator,
                bound @ ..,
            ] if left == name
                && matches!(operator.kind, TokenKind::Less | TokenKind::LessEqual)
                && !bound.is_empty()
                // Only an arithmetic bound moves into `range(...)` unchanged.
                && !bound.iter().any(|token| {
                    matches!(
                        token.kind,
                        TokenKind::AndAnd
                            | TokenKind::OrOr
                            | TokenKind::Question
                            | TokenKind::EqualEqual
                            | TokenKind::BangEqual
                            | TokenKind::Less
                            | TokenKind::LessEqual
                            | TokenKind::Greater
                            | TokenKind::GreaterEqual
                    )
                }) =>
            {
                (operator.kind == TokenKind::LessEqual, bound)
            }
            _ => return None,
        };
        let step = kinds(second + 1..closing)?;
        let steps_by_one = match step {
            [
                Token {
                    kind: TokenKind::Ident(target),
                    ..
                },
                Token {
                    kind: TokenKind::PlusEqual,
                    ..
                },
                one,
            ] => target == name && self.spelling(one) == "1",
            [
                Token {
                    kind: TokenKind::Ident(target),
                    ..
                },
                Token {
                    kind: TokenKind::Equal,
                    ..
                },
                Token {
                    kind: TokenKind::Ident(left),
                    ..
                },
                Token {
                    kind: TokenKind::Plus,
                    ..
                },
                one,
            ] => target == name && left == name && self.spelling(one) == "1",
            _ => false,
        };
        if !steps_by_one {
            return None;
        }
        let first_bound = bound.first()?;
        let last_bound = bound.last()?;
        let bound_text = self
            .source
            .get(first_bound.range.start as usize..last_bound.range.end as usize)?;
        Some(if inclusive {
            format!("{name} in range({bound_text} + 1)")
        } else {
            format!("{name} in range({bound_text})")
        })
    }
    /// `for i in a..b`: ranges are written `range(N)`.
    ///
    /// The cursor is at `..`; the start bound has been parsed as `start`.
    /// The end bound is consumed so the loop body still parses.
    fn report_range_operator(&mut self, start: &Expr) -> ParseResult<()> {
        let dots = self.bump();
        let inclusive = self.peek(TokenKind::Equal);
        if inclusive {
            self.bump();
        }
        let start_range = start.source().map_or(dots.range, |source| source.range);
        let start_text = self
            .source
            .get(start_range.start as usize..dots.range.start as usize)
            .unwrap_or("")
            .trim()
            .to_owned();
        let end_start = self.current_start();
        let end = self.parse_expr_before_block()?;
        crate::ast::drop_expression_iterative(end);
        let end_end = self.previous_end(end_start);
        let end_text = self
            .source
            .get(end_start as usize..end_end as usize)
            .unwrap_or("")
            .to_owned();
        let written = TextRange::new(start_range.start, end_end);
        let bound = if inclusive {
            format!("{end_text} + 1")
        } else {
            end_text.clone()
        };
        let mut error = self
            .coded_error(
                dots,
                "E_RANGE_SYNTAX",
                format!(
                    "Kotodama has no `{}` range operator; counted loops use `range(N)`, which counts from 0 up to N - 1",
                    if inclusive { "..=" } else { ".." }
                ),
            )
            .reported_at(written);
        if start_text == "0" {
            error = error
                .with_help("the loop bound must be a compile-time integer expression")
                .with_fix(written, format!("range({bound})"));
        } else {
            error = error.with_help(format!(
                "count from 0 and offset the index: `for k in range({bound} - {start_text}) {{ let i = {start_text} + k; ... }}`; the bound must be a compile-time integer expression"
            ));
        }
        self.report(error)
    }
    /// A match pattern without a `Namespace::` prefix: `_`, `Some(x)`,
    /// `None`, or another bare name.
    fn bare_pattern_error(&self, token: &Token, name: &str) -> Box<ParseError> {
        if name == "_" {
            return self
                .coded_error(
                    token.clone(),
                    "E_MATCH_WILDCARD",
                    "`match` has no wildcard arm; name every variant",
                )
                .with_help("a match over `Option` lists `Option::some(value)` and `Option::none`; over `Result`, `Result::ok(value)` and `Result::err(error)`; payloads you do not use bind `_`");
        }
        if let Some(canonical) = foreign_sum_constructor(name) {
            return self
                .coded_error(
                    token.clone(),
                    "E_LEGACY_SUM_CONSTRUCTOR",
                    format!("`{name}` is spelled `{canonical}` in Kotodama patterns"),
                )
                .with_help(sum_constructor_help())
                .with_fix(token.range, canonical);
        }
        self.expected_error(self.current_token(), "`::` and a variant name")
            .with_help("`match` arms name the variants of an `Option`, `Result`, `enum` or `error enum`, for example `Option::some(value)` or `MyError::Unauthorized`")
    }
    /// Skip to the end of the current match arm: the next `,` or the match's
    /// closing `}` at the arm's own nesting level.
    fn synchronize_match_arm(&mut self, arm_start: usize) {
        let mut stack = Vec::new();
        let mut index = arm_start;
        while let Some(token) = self.tokens.get(index) {
            let closer = DelimiterKind::closing(&token.kind);
            let closes_outer = closer.is_some() && stack.last() != closer.as_ref();
            if matches!(token.kind, TokenKind::EOF)
                || closes_outer
                || (stack.is_empty() && index >= self.pos && token.kind == TokenKind::Comma)
            {
                break;
            }
            update_delimiter_stack(&mut stack, &token.kind);
            index += 1;
        }
        // Always make progress past the failing token.
        self.pos = index.max(self.pos);
    }
    /// A trigger field written twice.
    fn duplicate_trigger_field(&self, field: Token) -> Box<ParseError> {
        let name = self.spelling(&field).to_owned();
        self.coded_error(
            field,
            "K1001",
            format!("trigger field `{name}` is declared more than once"),
        )
        .with_help("each trigger field appears at most once")
    }
    /// Record a recoverable error and continue, or fail when recovery is off.
    fn report(&mut self, error: Box<ParseError>) -> ParseResult<()> {
        if self.recover {
            self.errors.push(*error);
            Ok(())
        } else {
            Err(error)
        }
    }
    fn parse_fragment_program(&mut self) -> ParseResult<Program> {
        let (unit, parts) = self.parse_source_unit(SourceUnitKind::Fragment)?;
        self.expect(TokenKind::EOF)?;
        let (items, fixtures, directives, exports, permissions) = parts.into_inner();
        Ok(Program {
            unit,
            items,
            permissions,
            directives,
            exports,
            test_target: self.test_target.take(),
            fixtures,
        })
    }
    fn parse_source_unit(
        &mut self,
        kind: SourceUnitKind,
    ) -> ParseResult<(SourceUnit, PendingProgramParts)> {
        let start = self.current_start();
        let syntax_unit = self.syntax_start(SyntaxKind::SourceUnit, start);
        let node = self.begin_node(AstNodeKind::SourceUnit, start);
        let name = if kind == SourceUnitKind::Fragment {
            String::new()
        } else {
            self.bump(); // `seiyaku`/`誓約` or `module`
            let (name, name_token) = self.expect_ident_token()?;
            self.record_declaration(
                node,
                name.clone(),
                name_token.range,
                DeclarationKind::SourceUnit,
                None,
            );
            self.expect(TokenKind::LBrace)?;
            name
        };
        let syntax_items = self.syntax_start(SyntaxKind::ItemList, self.previous_end(start));
        let mut parts = PendingProgramParts::new();
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            let item_start = self.pos;
            let Some(item_token) = self.tokens.get(item_start) else {
                break;
            };
            let declaration_start = item_token.range.start;
            let item_kind = self.syntax_item_kind(item_start);
            let syntax_item = self.syntax_start(item_kind, declaration_start);
            let result = (|| -> ParseResult<()> {
                let attrs = self.parse_function_attributes()?;
                if self.peek(TokenKind::Permission)
                    || (self.peek(TokenKind::Import) && self.peek_n(1, TokenKind::Permission))
                {
                    if kind == SourceUnitKind::Module || !attrs.is_empty() {
                        return Err(self.coded_error(self.current_token(), "E_PERMISSION_DECLARATION", "permissions belong to a seiyaku or an included declaration file and cannot carry attributes"));
                    }
                    parts.permissions.push(self.parse_permission_decl()?);
                    return Ok(());
                }
                if self.peek(TokenKind::Include) || self.peek(TokenKind::Import) {
                    if !attrs.is_empty() {
                        let token = self.current_token();
                        let spelling = self.spelling(&token).to_owned();
                        return Err(self
                            .coded_error(
                                token,
                                "K1001",
                                format!("`#[test]` cannot be attached to an `{spelling}` directive"),
                            )
                            .with_help("attributes apply only to the function declared directly after them; remove the attribute"));
                    }
                    let directive = self.parse_source_directive(parts.items.len())?;
                    parts.directives.push(directive);
                    return Ok(());
                }
                let export = if self.peek(TokenKind::Export) {
                    let token = self.bump();
                    if kind == SourceUnitKind::Seiyaku {
                        let next_start = self.current_start();
                        return Err(self
                            .coded_error(
                                token.clone(),
                                "K1001",
                                "`export` is only permitted in module declarations",
                            )
                            .with_help("a seiyaku is called through its kotoage and view functions; remove `export`, or move the declaration into a `module`")
                            .with_fix(TextRange::new(token.range.start, next_start), ""));
                    }
                    if !matches!(
                        self.tokens.get(self.pos).map(|token| &token.kind),
                        Some(
                            TokenKind::Fn
                                | TokenKind::Struct
                                | TokenKind::Error
                                | TokenKind::Enum
                                | TokenKind::Const
                        )
                    ) {
                        return Err(self
                            .expected_error(
                                self.current_token(),
                                "`fn`, `struct`, `enum`, `error enum` or `const` after `export`",
                            )
                            .with_help("modules export functions, structs, enums and constants"));
                    }
                    Some(token.range)
                } else {
                    None
                };
                let attributes_error = |this: &Self| {
                    let token = this.current_token();
                    let found = describe_found(this.source, &token);
                    this.coded_error(
                        token,
                        "K1001",
                        format!(
                            "`#[test]` must be followed by a function declaration, found {found}"
                        ),
                    )
                    .with_help("place the attribute directly above the `fn` it marks")
                };
                let module_error = |this: &Self, what: &str, help: &str| {
                    let token = this.current_token();
                    let spelling = this.spelling(&token).to_owned();
                    this.coded_error(
                        token,
                        "K1001",
                        format!(
                            "module units cannot declare {}",
                            what.replace("{}", &spelling)
                        ),
                    )
                    .with_help(help.to_owned())
                };
                if self.peek(TokenKind::Struct) {
                    if !attrs.is_empty() {
                        return Err(attributes_error(self));
                    }
                    parts.push_item(self.parse_product_def(false)?);
                } else if self.peek(TokenKind::Event) {
                    if !attrs.is_empty() {
                        return Err(attributes_error(self));
                    }
                    if kind == SourceUnitKind::Module {
                        return Err(module_error(
                            self,
                            "native events",
                            "events belong to the seiyaku that emits them; declare the event and emitting helpers there",
                        ));
                    }
                    parts.push_item(self.parse_product_def(true)?);
                } else if self.peek(TokenKind::Error) || self.peek(TokenKind::Enum) {
                    if !attrs.is_empty() {
                        return Err(attributes_error(self));
                    }
                    parts.push_item(self.parse_enum_def()?);
                } else if self.peek(TokenKind::Const) {
                    if !attrs.is_empty() {
                        return Err(attributes_error(self));
                    }
                    parts.push_item(self.parse_const_decl()?);
                } else if self.peek(TokenKind::State) {
                    if !attrs.is_empty() {
                        return Err(attributes_error(self));
                    }
                    if kind == SourceUnitKind::Module {
                        return Err(module_error(
                            self,
                            "durable state",
                            "durable state belongs to the seiyaku that owns it; declare it there and pass values to module functions as parameters",
                        ));
                    }
                    parts.push_item(self.parse_state_decl()?);
                } else if self.peek(TokenKind::Trigger) {
                    if !attrs.is_empty() {
                        return Err(attributes_error(self));
                    }
                    if kind == SourceUnitKind::Module {
                        return Err(module_error(
                            self,
                            "triggers",
                            "triggers invoke kotoage functions of a seiyaku; declare the trigger in that seiyaku",
                        ));
                    }
                    parts.push_item(self.parse_trigger_decl()?);
                } else if self.peek(TokenKind::Fn) {
                    let fn_token = self.bump();
                    if self.peek(TokenKind::Hajimari) || self.peek(TokenKind::Kaizen) {
                        // `fn hajimari()`: the hook keyword is the whole head.
                        let hook = self.current_token();
                        let spelling = self.spelling(&hook).to_owned();
                        self.report(
                            self.coded_error(
                                fn_token.clone(),
                                "E_DECLARATION_SHAPE",
                                format!(
                                    "`{spelling}` is a lifecycle hook, not a function name: write `{spelling}() {{ ... }}` without `fn`"
                                ),
                            )
                            .with_help(lifecycle_hook_help(&hook.kind))
                            .with_fix(TextRange::new(fn_token.range.start, hook.range.start), ""),
                        )?;
                        if kind == SourceUnitKind::Module {
                            return Err(module_error(
                                self,
                                "a `{}` hook",
                                "lifecycle hooks run when a seiyaku is activated or its code is replaced in place; declare the hook in the seiyaku",
                            ));
                        }
                        self.bump();
                        parts.push_item(self.parse_lifecycle_hook(
                            &hook,
                            &attrs,
                            declaration_start,
                        )?);
                    } else {
                        parts.push_item(self.parse_fn_loose(
                            None,
                            FunctionModifiers {
                                kind: FunctionKind::Private,
                                authorization: None,
                                is_test: attrs.is_test,
                                test_fixture: attrs.test_fixture,
                            },
                            declaration_start,
                            None,
                        )?);
                    }
                } else if self.peek(TokenKind::Kotoage) || self.peek(TokenKind::View) {
                    let role = self.current_token();
                    let is_kotoage = role.kind == TokenKind::Kotoage;
                    if kind == SourceUnitKind::Module {
                        return Err(if is_kotoage {
                            module_error(
                                self,
                                "`{}` functions",
                                "only a seiyaku declares public functions; make this an ordinary `fn` and call it from a kotoage function of the seiyaku",
                            )
                        } else {
                            module_error(
                                self,
                                "`{} fn` functions",
                                "only a seiyaku declares public functions; make this an ordinary `fn` and call it from a view function of the seiyaku",
                            )
                        });
                    }
                    self.bump();
                    if self.peek(TokenKind::Kotoage) || self.peek(TokenKind::View) {
                        let second = self.current_token();
                        return Err(self.mixed_role_error(&role, &second));
                    }
                    if self.peek(TokenKind::Fn) {
                        self.bump();
                    } else if self.peek_n_ident(0) && self.peek_n(1, TokenKind::LParen) {
                        // `kotoage bump()`: the role keyword modifies a `fn`.
                        let spelling = self.spelling(&role).to_owned();
                        let name = self.current_token();
                        let name_text = self.spelling(&name).to_owned();
                        self.report(
                            self.coded_error(
                                role.clone(),
                                "E_DECLARATION_SHAPE",
                                format!(
                                    "`{spelling}` modifies a function declaration: write `{spelling} fn {name_text}(...)`"
                                ),
                            )
                            .with_help("public functions are declared `kotoage fn name(...)` (also `言挙げ fn`) or `view fn name(...)`; only the lifecycle hooks `hajimari` and `kaizen` omit `fn`")
                            .with_fix(TextRange::empty(role.range.end), " fn"),
                        )?;
                    } else {
                        return Err(self.expected_error(self.current_token(), "`fn` after the function role").with_help("public functions are declared `kotoage fn name(...)` (also `言挙げ fn`) or `view fn name(...)`"));
                    }
                    parts.push_item(self.parse_fn_loose(
                        None,
                        FunctionModifiers {
                            kind: if is_kotoage {
                                FunctionKind::Kotoage
                            } else {
                                FunctionKind::View
                            },
                            authorization: None,
                            is_test: attrs.is_test,
                            test_fixture: attrs.test_fixture,
                        },
                        declaration_start,
                        Some(role),
                    )?);
                } else if self.peek(TokenKind::Hajimari) || self.peek(TokenKind::Kaizen) {
                    let hook = self.current_token();
                    if kind == SourceUnitKind::Module {
                        return Err(module_error(
                            self,
                            "a `{}` hook",
                            "lifecycle hooks run when a seiyaku is activated or its code is replaced in place; declare the hook in the seiyaku",
                        ));
                    }
                    self.bump();
                    if self.peek(TokenKind::Fn) {
                        // `hajimari fn()` / `hajimari fn init()`.
                        let fn_token = self.bump();
                        let mut end = fn_token.range.end;
                        if self.peek_n_ident(0) && self.peek_n(1, TokenKind::LParen) {
                            end = self.bump().range.end;
                        }
                        let spelling = self.spelling(&hook).to_owned();
                        self.report(
                            self.coded_error(
                                fn_token,
                                "E_DECLARATION_SHAPE",
                                format!(
                                    "`{spelling}` is itself the declaration: write `{spelling}() {{ ... }}` without `fn` or a name"
                                ),
                            )
                            .with_help(lifecycle_hook_help(&hook.kind))
                            .with_fix(TextRange::new(hook.range.end, end), ""),
                        )?;
                    }
                    parts.push_item(self.parse_lifecycle_hook(&hook, &attrs, declaration_start)?);
                } else if self.peek_ident_n(0, "meta") {
                    let token = self.bump();
                    return Err(self
                        .coded_error(
                            token,
                            "K1001",
                            "source-level `meta { ... }` is not supported",
                        )
                        .with_help("select execution capabilities and the cycle ceiling in the compiler build configuration"));
                } else if self.peek_ident_n(0, "fixture") {
                    if !attrs.is_empty() {
                        return Err(attributes_error(self));
                    }
                    let fixture = self.parse_fixture_decl()?;
                    parts.push_fixture(fixture);
                } else if self.peek_ident_n(0, "koto_test") {
                    if !attrs.is_empty() {
                        return Err(attributes_error(self));
                    }
                    self.parse_test_target_decl()?;
                } else if self.peek(TokenKind::Seiyaku) || self.peek(TokenKind::Module) {
                    let token = self.bump();
                    let spelling = self.spelling(&token).to_owned();
                    return Err(self
                        .coded_error(
                            token,
                            "K1001",
                            format!("`{spelling}` cannot appear inside another source unit"),
                        )
                        .with_help("a source file contains exactly one seiyaku or module; put each unit in its own `.ko` file and connect them with `import`"));
                } else {
                    let token = self.current_token();
                    let (error, recovery) = self.source_item_error(&token, kind);
                    let Some(recovery) = recovery.filter(|_| self.recover) else {
                        self.bump();
                        return Err(error);
                    };
                    self.errors.push(*error);
                    self.bump();
                    match recovery {
                        ItemRecovery::Function(function_kind) => {
                            if self.peek(TokenKind::Fn) {
                                self.bump();
                            }
                            parts.push_item(self.parse_fn_loose(
                                None,
                                FunctionModifiers {
                                    kind: function_kind,
                                    authorization: None,
                                    is_test: attrs.is_test,
                                    test_fixture: attrs.test_fixture,
                                },
                                declaration_start,
                                Some(token),
                            )?);
                        }
                        ItemRecovery::Hook(hook_kind) => {
                            let hook = Token {
                                kind: hook_kind,
                                ..token
                            };
                            parts.push_item(self.parse_lifecycle_hook(
                                &hook,
                                &attrs,
                                declaration_start,
                            )?);
                        }
                    }
                }
                if let Some(range) = export {
                    let name = match parts
                        .items
                        .last()
                        .expect("an exported declaration was parsed")
                    {
                        Item::Function(value) => &value.name,
                        Item::Struct(value) | Item::Event(value) => &value.name,
                        Item::Enum(value) => &value.name,
                        Item::Const(value) => &value.name,
                        Item::State(_) | Item::Trigger(_) => {
                            unreachable!("export kind was checked before parsing")
                        }
                    };
                    parts.exports.push(ExportDecl {
                        name: name.clone(),
                        source: SourceRange::new(self.facts.source_map.source(), range),
                    });
                }
                Ok(())
            })();
            if let Err(error) = result {
                if !self.recover {
                    self.syntax_finish(syntax_item, declaration_start);
                    return Err(error);
                }
                let recovery_start = error.range.start.max(declaration_start);
                self.errors.push(*error);
                let syntax_error = (item_kind != SyntaxKind::ErrorNode)
                    .then(|| self.syntax_start(SyntaxKind::ErrorNode, recovery_start));
                self.synchronize_source_item(item_start);
                if let Some(syntax_error) = syntax_error {
                    self.syntax_finish(syntax_error, recovery_start);
                }
            }
            self.syntax_finish(syntax_item, declaration_start);
        }
        self.syntax_finish_at(syntax_items, self.current_start());
        if kind != SourceUnitKind::Fragment {
            self.expect(TokenKind::RBrace)?;
        }
        self.finish_node(node);
        self.syntax_finish(syntax_unit, start);
        Ok((SourceUnit { kind, name }, parts))
    }
    fn parse_source_directive(&mut self, item_index: usize) -> ParseResult<SourceDirective> {
        let keyword = self.bump();
        if keyword.kind == TokenKind::Import && self.peek_ident_n(0, "type") {
            self.bump();
            let identity_token = self.bump();
            let TokenKind::String(identity) = identity_token.kind.clone() else {
                return Err(
                    self.expected_error(identity_token, "a quoted canonical nominal type identity")
                );
            };
            if !self.peek_ident_n(0, "from") {
                let token = self.bump();
                return Err(self.expected_error(token, "`from` followed by the contract namespace"));
            }
            self.bump();
            let contract = self.expect_ident()?;
            self.expect(TokenKind::As)?;
            let alias = self.expect_ident()?;
            self.expect(TokenKind::Semicolon)?;
            return Ok(SourceDirective {
                kind: SourceDirectiveKind::ContractTypeImport {
                    identity,
                    contract,
                    alias,
                },
                item_index,
                source: SourceRange::new(
                    self.facts.source_map.source(),
                    TextRange::new(keyword.range.start, self.previous_end(keyword.range.start)),
                ),
            });
        }
        let contract = keyword.kind == TokenKind::Import && self.peek(TokenKind::Seiyaku);
        if contract {
            self.bump();
        }
        let path_token = self.bump();
        let TokenKind::String(path) = path_token.kind.clone() else {
            return Err(self
                .expected_error(path_token, "a string literal naming a relative `.ko` path")
                .with_help("directives name their source with a literal, for example `import \"math.ko\" as math;`"));
        };
        if path.trim().is_empty() || path.chars().any(char::is_control) {
            return Err(self
                .coded_error(
                    path_token,
                    "K1001",
                    "a source path must be nonblank and contain no control characters",
                )
                .with_help("write the relative path of a `.ko` file in the same project"));
        }
        let kind = if keyword.kind == TokenKind::Include {
            SourceDirectiveKind::Include { path }
        } else {
            self.expect(TokenKind::As)?;
            let alias = self.expect_ident()?;
            if contract {
                SourceDirectiveKind::ContractImport { path, alias }
            } else {
                SourceDirectiveKind::Import { path, alias }
            }
        };
        self.expect(TokenKind::Semicolon)?;
        Ok(SourceDirective {
            kind,
            item_index,
            source: SourceRange::new(
                self.facts.source_map.source(),
                TextRange::new(keyword.range.start, self.previous_end(keyword.range.start)),
            ),
        })
    }
    fn parse_enum_def(&mut self) -> ParseResult<Item> {
        let node = self.begin_node(AstNodeKind::Enum, self.current_start());
        let kind = if self.peek(TokenKind::Error) {
            self.bump();
            EnumKind::Error
        } else {
            EnumKind::Data
        };
        self.expect(TokenKind::Enum)?;
        let (name, name_token) = self.expect_ident_token()?;
        self.record_declaration(
            node,
            name.clone(),
            name_token.range,
            DeclarationKind::Enum,
            None,
        );
        self.expect(TokenKind::LBrace)?;
        let mut variants = Vec::new();
        let mut names = std::collections::HashSet::new();
        let mut codes = std::collections::HashSet::new();
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            if kind == EnumKind::Data && self.peek(TokenKind::Hash) {
                return Err(self.coded_error(self.current_token(), "E_ENUM_MESSAGE",
                    "ordinary enum variants cannot declare error messages")
                    .with_help("use `error enum` only for raisable failures; ordinary enum variants contain only a name and explicit code"));
            }
            let message = self.parse_error_message_attribute()?;
            let variant_token = self.tokens[self.pos].clone();
            let variant_name = self.expect_ident()?;
            if !names.insert(variant_name.clone()) {
                let duplicate = self.spelling(&variant_token).to_owned();
                return Err(self
                    .coded_error(
                        variant_token,
                        "K1001",
                        format!("enum variant `{duplicate}` is declared more than once"),
                    )
                    .with_help("give every variant of an enum a distinct name"));
            }
            self.expect(TokenKind::Equal)?;
            let code_token = self.bump();
            let code = match &code_token.kind {
                TokenKind::Number(value) => parse_bounded_unsigned(value, u64::from(u32::MAX))
                    .ok()
                    .and_then(|value| u32::try_from(value).ok())
                    .filter(|value| *value != 0)
                    .ok_or_else(|| {
                        self.coded_error(
                            code_token.clone(),
                            "K1001",
                            "enum codes are integers in the range 1..=4294967295",
                        )
                        .with_help("each variant needs a nonzero code that fits in 32 bits, for example `Unauthorized = 1`")
                    })?,
                _ => {
                    return Err(self
                        .expected_error(code_token, "an integer enum code in the range 1..=4294967295")
                        .with_help("each variant needs an explicit code, for example `Unauthorized = 1`"));
                }
            };
            if !codes.insert(code) {
                return Err(self
                    .coded_error(
                        variant_token,
                        "K1001",
                        format!("enum code {code} is already used by another variant"),
                    )
                    .with_help("enum codes identify failures on the ledger, so every variant needs a distinct code"));
            }
            variants.push(EnumVariant {
                name: variant_name,
                code,
                message,
            });
            if self.peek(TokenKind::Comma) || self.peek(TokenKind::Semicolon) {
                self.bump();
            } else if !self.peek(TokenKind::RBrace) {
                let token = self.tokens[self.pos].clone();
                let mut error =
                    self.expected_error(token.clone(), "`,` or `}` after the enum variant");
                if let Some(previous) = self
                    .pos
                    .checked_sub(1)
                    .and_then(|index| self.tokens.get(index))
                    && token.line > previous.line
                {
                    let insertion = TextRange::empty(previous.range.end);
                    error = error.reported_at(insertion).with_fix(insertion, ",");
                }
                return Err(error);
            }
        }
        self.expect(TokenKind::RBrace)?;
        if variants.is_empty() {
            let token = self.tokens[self.pos.saturating_sub(1)].clone();
            return Err(self
                .coded_error(token, "K1001", format!("enum `{name}` declares no variants"))
                .with_help("declare at least one variant with an explicit nonzero code, for example `Unauthorized = 1`"));
        }
        self.finish_node(node);
        Ok(Item::Enum(EnumDef {
            name,
            kind,
            variants,
        }))
    }
    fn parse_error_message_attribute(&mut self) -> ParseResult<Option<String>> {
        let mut message = None;
        while self.peek(TokenKind::Hash) {
            let start = self.current_start();
            let syntax = self.syntax_start(SyntaxKind::Attribute, start);
            let result = (|| -> ParseResult<String> {
                self.bump();
                self.expect(TokenKind::LBracket)?;
                let attribute = self.bump();
                if !matches!(&attribute.kind, TokenKind::Ident(name) if name == "message") {
                    return Err(self
                        .expected_error(attribute, "the error-variant attribute `message`")
                        .with_help("error variants accept only `#[message(\"...\")]`"));
                }
                if message.is_some() {
                    return Err(self
                        .coded_error(
                            attribute,
                            "K1001",
                            "error variant has more than one `#[message(...)]` attribute",
                        )
                        .with_help("keep exactly one message per variant"));
                }
                self.expect(TokenKind::LParen)?;
                let literal = self.bump();
                let TokenKind::String(value) = literal.kind.clone() else {
                    return Err(self
                        .expected_error(literal, "a string literal message")
                        .with_help("error messages are static text, for example `#[message(\"caller is not the owner\")]`"));
                };
                if value.trim().is_empty() || value.len() > 4096 {
                    return Err(self
                        .coded_error(
                            literal,
                            "K1001",
                            "error messages must be nonblank and at most 4096 UTF-8 bytes",
                        )
                        .with_help("shorten the message; detailed context belongs in events or documentation"));
                }
                self.expect(TokenKind::RParen)?;
                self.expect(TokenKind::RBracket)?;
                Ok(value)
            })();
            self.syntax_finish(syntax, start);
            message = Some(result?);
        }
        Ok(message)
    }
    fn parse_trigger_decl(&mut self) -> ParseResult<Item> {
        let node = self.begin_node(AstNodeKind::Trigger, self.current_start());
        let tok = self.bump();
        debug_assert!(matches!(tok.kind, TokenKind::Trigger));
        let (name, name_token) = self.expect_ident_token()?;
        self.record_declaration(
            node,
            name.clone(),
            name_token.range,
            DeclarationKind::Trigger,
            None,
        );
        self.expect(TokenKind::Arrow)?;
        let call = self.parse_trigger_call()?;
        self.expect(TokenKind::LBrace)?;
        let mut filters = PendingValues::new(|filter: TriggerFilter| {
            if let TriggerFilter::Time(TriggerTimeFilter::Schedule {
                start_ms,
                period_ms,
            }) = filter
            {
                crate::ast::drop_expression_iterative(*start_ms);
                if let Some(period_ms) = period_ms {
                    crate::ast::drop_expression_iterative(*period_ms);
                }
            }
        });
        let mut repeats: Option<TriggerRepeats> = None;
        let mut authority: Option<String> = None;
        let mut metadata = PendingValues::new(|entry: TriggerMetadataEntry| {
            crate::ast::drop_expression_iterative(entry.value);
        });
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            let field_tok = self.bump();
            let field_name = match field_tok.kind.clone() {
                TokenKind::Ident(name) => name,
                _ => {
                    return Err(self.expected_error(
                        field_tok,
                        "a trigger field (`on`, `repeats`, `authority` or `metadata`)",
                    ));
                }
            };
            match field_name.as_str() {
                "on" => {
                    if filters.len() != 0 {
                        return Err(self.duplicate_trigger_field(field_tok));
                    }
                    filters.push(self.parse_trigger_filter()?);
                    if self.peek(TokenKind::Semicolon) {
                        self.bump();
                    }
                }
                "repeats" => {
                    if repeats.is_some() {
                        return Err(self.duplicate_trigger_field(field_tok));
                    }
                    repeats = Some(self.parse_trigger_repeats()?);
                    self.expect(TokenKind::Semicolon)?;
                }
                "authority" => {
                    if authority.is_some() {
                        return Err(self.duplicate_trigger_field(field_tok));
                    }
                    authority = Some(self.expect_ident_or_string()?);
                    self.expect(TokenKind::Semicolon)?;
                }
                "metadata" => {
                    metadata = self.parse_trigger_metadata_block()?;
                    if self.peek(TokenKind::Semicolon) {
                        self.bump();
                    }
                }
                _ => {
                    return Err(self.expected_error(
                        field_tok,
                        "a trigger field (`on`, `repeats`, `authority` or `metadata`)",
                    ));
                }
            }
        }
        self.expect(TokenKind::RBrace)?;
        let filter = filters.into_inner().pop().ok_or_else(|| {
            self.coded_error(
                name_token.clone(),
                "K1001",
                format!("trigger `{name}` has no `on` field"),
            )
            .with_help("say when the trigger fires, for example `on time pre_commit;` or `on data account any { ... }`")
        })?;
        let _ = tok;
        self.finish_node(node);
        Ok(Item::Trigger(TriggerDecl {
            name,
            location: SourceLocation {
                line: name_token.line,
                column: name_token.column,
            },
            call,
            filter,
            repeats,
            authority,
            metadata: metadata.into_inner(),
        }))
    }
    fn parse_trigger_call(&mut self) -> ParseResult<TriggerCall> {
        let (entrypoint, token) = self.expect_ident_token()?;
        if self.peek(TokenKind::ColonColon) {
            return Err(self.coded_error(token, "E_TRIGGER_TARGET_NAMESPACE",
                "trigger callbacks must name a local kotoage function")
                .with_help("namespaced callbacks require an authenticated seiyaku interface; use a local `kotoage fn` callback"));
        }
        Ok(TriggerCall { entrypoint })
    }
    fn parse_trigger_filter(&mut self) -> ParseResult<TriggerFilter> {
        let kind = self.expect_ident()?;
        match kind.as_str() {
            "time" => Ok(TriggerFilter::Time(self.parse_trigger_time_filter()?)),
            "execute" => {
                let next = self.expect_trigger_context_ident()?;
                if next != "trigger" {
                    return Err(self
                        .expected_error(
                            self.tokens[self.pos.saturating_sub(1)].clone(),
                            "`trigger` after `execute`",
                        )
                        .with_help("write `on execute trigger <name>;`"));
                }
                let trigger_id = self.expect_ident_or_string()?;
                Ok(TriggerFilter::Execute { trigger_id })
            }
            "data" => Ok(TriggerFilter::Data(self.parse_trigger_data_filter()?)),
            "pipeline" => Ok(TriggerFilter::Pipeline(
                self.parse_trigger_pipeline_filter()?,
            )),
            _ => Err(self.expected_error(
                self.tokens[self.pos.saturating_sub(1)].clone(),
                "a trigger filter (`time`, `execute`, `data` or `pipeline`)",
            )),
        }
    }
    fn parse_trigger_data_filter(&mut self) -> ParseResult<TriggerDataFilter> {
        let kind = self.expect_trigger_context_ident()?;
        match kind.as_str() {
            "any" => Ok(TriggerDataFilter::Any),
            _ => {
                let family = self.parse_trigger_data_family_keyword(&kind)?;
                let event = match self.expect_ident()?.as_str() {
                    "any" => TriggerDataEventKind::Any,
                    other => TriggerDataEventKind::Named(other.to_string()),
                };
                let matchers = self.parse_trigger_data_matcher_block()?;
                Ok(TriggerDataFilter::Structured(TriggerStructuredDataFilter {
                    family,
                    event,
                    matchers,
                }))
            }
        }
    }
    fn parse_trigger_data_family_keyword(&self, family: &str) -> ParseResult<TriggerDataFamily> {
        match family {
            "peer" => Ok(TriggerDataFamily::Peer),
            "domain" => Ok(TriggerDataFamily::Domain),
            "account" => Ok(TriggerDataFamily::Account),
            "asset" => Ok(TriggerDataFamily::Asset),
            "asset_definition" => Ok(TriggerDataFamily::AssetDefinition),
            "nft" => Ok(TriggerDataFamily::Nft),
            "rwa" => Ok(TriggerDataFamily::Rwa),
            "trigger" => Ok(TriggerDataFamily::Trigger),
            "role" => Ok(TriggerDataFamily::Role),
            "configuration" => Ok(TriggerDataFamily::Configuration),
            "executor" => Ok(TriggerDataFamily::Executor),
            _ => Err(self.expected_error(
                self.tokens[self.pos.saturating_sub(1)].clone(),
                "a data family (`any`, `peer`, `domain`, `account`, `asset`, `asset_definition`, `nft`, `rwa`, `trigger`, `role`, `configuration` or `executor`)",
            )),
        }
    }
    fn parse_trigger_data_matcher_block(&mut self) -> ParseResult<Vec<TriggerDataMatcher>> {
        self.expect(TokenKind::LBrace)?;
        let mut matchers = Vec::new();
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            let key = self.expect_trigger_context_ident()?;
            let value = self.expect_ident_or_string()?;
            self.expect(TokenKind::Semicolon)?;
            matchers.push(TriggerDataMatcher { key, value });
        }
        self.expect(TokenKind::RBrace)?;
        Ok(matchers)
    }
    fn parse_trigger_pipeline_filter(&mut self) -> ParseResult<TriggerPipelineFilter> {
        let kind = self.expect_ident()?;
        match kind.as_str() {
            "transaction" => {
                if self.peek_ident_n(0, "approved") {
                    self.bump();
                }
                Ok(TriggerPipelineFilter::TransactionApproved)
            }
            "block" => {
                if self.peek_ident_n(0, "approved") {
                    self.bump();
                }
                Ok(TriggerPipelineFilter::BlockApproved)
            }
            _ => Err(self.expected_error(
                self.tokens[self.pos.saturating_sub(1)].clone(),
                "a pipeline filter (`transaction [approved]` or `block [approved]`)",
            )),
        }
    }
    fn parse_trigger_time_filter(&mut self) -> ParseResult<TriggerTimeFilter> {
        let kind = self.expect_ident()?;
        match kind.as_str() {
            "pre_commit" => Ok(TriggerTimeFilter::PreCommit),
            "schedule" => {
                self.expect(TokenKind::LParen)?;
                let mut start_ms =
                    PendingExpr::new(self.parse_trigger_schedule_argument("start_ms")?);
                let mut period_ms = if self.peek(TokenKind::Comma) {
                    self.bump();
                    if self.peek(TokenKind::RParen) {
                        None
                    } else {
                        Some(PendingExpr::new(
                            self.parse_trigger_schedule_argument("period_ms")?,
                        ))
                    }
                } else {
                    None
                };
                if period_ms.is_some() && self.peek(TokenKind::Comma) {
                    self.bump();
                }
                self.expect(TokenKind::RParen)?;
                let start_ms = start_ms.take();
                let period_ms = period_ms.as_mut().map(PendingExpr::take);
                Ok(TriggerTimeFilter::Schedule {
                    start_ms: Box::new(start_ms),
                    period_ms: period_ms.map(Box::new),
                })
            }
            _ => Err(self.expected_error(
                self.tokens[self.pos.saturating_sub(1)].clone(),
                "a time filter (`pre_commit` or `schedule(...)`)",
            )),
        }
    }
    fn parse_trigger_schedule_argument(&mut self, label: &str) -> ParseResult<Expr> {
        let token = self.bump();
        if !matches!(&token.kind, TokenKind::Ident(name) if name == label) {
            return Err(self.coded_error(token, "E_TRIGGER_SCHEDULE_ARGUMENT",
                format!("schedule requires the `{label}:` argument label"))
                .with_help("write `schedule(start_ms: START, period_ms: 60_000)`; times are compile-time integer expressions in milliseconds"));
        }
        self.expect(TokenKind::Colon)?;
        self.parse_expr()
    }
    fn parse_trigger_repeats(&mut self) -> ParseResult<TriggerRepeats> {
        if self.peek_ident_n(0, "indefinitely") {
            self.bump();
            return Ok(TriggerRepeats::Indefinitely);
        }
        let value = self.parse_u64_literal("repeats")?;
        let count = u32::try_from(value).map_err(|_| {
            self.range_error(
                &self.tokens[self.pos.saturating_sub(1)],
                "repeats integer literal out of range".to_string(),
            )
        })?;
        Ok(TriggerRepeats::Exactly(count))
    }
    fn parse_trigger_metadata_block(&mut self) -> ParseResult<PendingValues<TriggerMetadataEntry>> {
        self.expect(TokenKind::LBrace)?;
        let mut entries = PendingValues::new(|entry: TriggerMetadataEntry| {
            crate::ast::drop_expression_iterative(entry.value);
        });
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            let key_tok = self.bump();
            let key = match key_tok.kind {
                TokenKind::Ident(ref s) => s.clone(),
                TokenKind::String(ref s) => s.clone(),
                _ => {
                    return Err(self
                        .expected_error(key_tok, "a metadata key (identifier or string literal)"));
                }
            };
            self.expect(TokenKind::Colon)?;
            let mut value = PendingExpr::new(self.parse_expr()?);
            self.expect(TokenKind::Semicolon)?;
            entries.push(TriggerMetadataEntry {
                key,
                value: value.take(),
            });
        }
        self.expect(TokenKind::RBrace)?;
        Ok(entries)
    }
    fn parse_u64_literal(&mut self, context: &str) -> ParseResult<u64> {
        let tok = self.bump();
        match tok.kind.clone() {
            TokenKind::Number(n) => parse_bounded_unsigned(&n, u64::MAX).map_err(|_| {
                self.range_error(&tok, format!("{context} integer literal out of range"))
            }),
            _ => Err(self
                .expected_error(
                    tok,
                    &format!("a non-negative integer literal for `{context}`"),
                )
                .with_help("trigger schedules and repeat counts are written as integer literals")),
        }
    }
    fn expect_ident_or_string(&mut self) -> ParseResult<String> {
        let tok = self.bump();
        match tok.kind.clone() {
            TokenKind::Ident(s) => Ok(s),
            TokenKind::String(s) => Ok(s),
            _ => Err(self.expected_error(tok, "an identifier or string literal")),
        }
    }
    fn parse_function_attributes(&mut self) -> ParseResult<FunctionAttributes> {
        let mut attrs = FunctionAttributes::default();
        while self.peek(TokenKind::Hash) {
            let attribute_start = self.current_start();
            let syntax_attribute = self.syntax_start(SyntaxKind::Attribute, attribute_start);
            let result = (|| -> ParseResult<()> {
                self.bump(); // '#'
                self.expect(TokenKind::LBracket)?;
                let attr_tok = self.bump();
                let attr_name = if let TokenKind::Ident(name) = attr_tok.kind.clone() {
                    name
                } else {
                    return Err(self
                        .expected_error(attr_tok, "an attribute name")
                        .with_help("the only function attribute is `#[test]`"));
                };
                match attr_name.as_str() {
                    "access" => {
                        return Err(self
                            .coded_error(
                                attr_tok,
                                "K1001",
                                "manual `#[access(...)]` hints are not supported",
                            )
                            .with_help("access metadata is generated by the compiler from each function's operations; remove the attribute"));
                    }
                    "test" => self.parse_test_attribute_body(&mut attrs)?,
                    _ => {
                        let text = self.spelling(&attr_tok).to_owned();
                        let help = if text == "message" {
                            "`#[message(\"...\")]` belongs on a variant of an `error enum`; the only function attribute is `#[test]`"
                        } else {
                            "the only function attribute is `#[test]`"
                        };
                        return Err(self
                            .coded_error(
                                attr_tok,
                                "K1001",
                                format!("unknown function attribute `#[{text}]`"),
                            )
                            .with_help(help));
                    }
                }
                let next_item = self
                    .tokens
                    .get(self.pos)
                    .is_some_and(Self::token_starts_source_item);
                self.expect_or_insert(TokenKind::RBracket, next_item)?;
                Ok(())
            })();
            self.syntax_finish(syntax_attribute, attribute_start);
            result?;
        }
        Ok(attrs)
    }
    fn parse_test_attribute_body(&mut self, attrs: &mut FunctionAttributes) -> ParseResult<()> {
        attrs.is_test = true;
        if !self.peek(TokenKind::LParen) {
            return Ok(());
        }
        self.bump(); // '('
        while !self.peek(TokenKind::RParen) && !self.peek(TokenKind::EOF) {
            let key = self.expect_ident()?;
            self.expect(TokenKind::Equal)?;
            match key.as_str() {
                "fixture" => {
                    if attrs.test_fixture.is_some() {
                        return Err(ParseError::at(
                            &self.tokens[self.pos.saturating_sub(1)],
                            "K1001",
                            "`#[test(...)]` names `fixture` more than once",
                        )
                        .with_help("a test runs against exactly one fixture"));
                    }
                    attrs.test_fixture = Some(self.expect_ident_or_string()?);
                }
                _ => {
                    return Err(ParseError::at(
                        &self.tokens[self.pos.saturating_sub(1)],
                        "K1001",
                        format!("unknown `#[test(...)]` option `{key}`"),
                    )
                    .with_help("the only test option is `fixture = name`"));
                }
            }
            if self.peek(TokenKind::Comma) {
                self.bump();
            } else {
                break;
            }
        }
        self.expect(TokenKind::RParen)?;
        Ok(())
    }
    fn parse_test_target_decl(&mut self) -> ParseResult<()> {
        let tok = self.bump();
        if !matches!(tok.kind, TokenKind::Ident(ref s) if s == "koto_test") {
            return Err(self.expected_error(tok, "`koto_test`"));
        }
        self.expect(TokenKind::LBrace)?;
        let mut target = None;
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            let key = self.expect_ident()?;
            self.expect(TokenKind::Colon)?;
            match key.as_str() {
                "target" => target = Some(self.expect_ident_or_string()?),
                _ => {
                    return Err(self
                        .coded_error(
                            self.tokens[self.pos.saturating_sub(1)].clone(),
                            "K1001",
                            format!("unknown `koto_test` field `{key}`"),
                        )
                        .with_help("the only `koto_test` field is `target: \"...\"`"));
                }
            }
            if self.peek(TokenKind::Semicolon) || self.peek(TokenKind::Comma) {
                self.bump();
            }
        }
        self.expect(TokenKind::RBrace)?;
        let target = target.ok_or_else(|| {
            *ParseError::at(
                &tok,
                "K1001",
                "`koto_test` block requires `target: \"...\"`",
            )
            .with_help(
                "name the seiyaku under test, for example `koto_test { target: \"counter.ko\"; }`",
            )
        })?;
        self.test_target = Some(TestTargetDecl { target });
        Ok(())
    }
    fn parse_fixture_decl(&mut self) -> ParseResult<FixtureDecl> {
        let tok = self.bump();
        if !matches!(tok.kind, TokenKind::Ident(ref s) if s == "fixture") {
            return Err(self.expected_error(tok, "`fixture`"));
        }
        let name = self.expect_ident()?;
        self.expect(TokenKind::LBrace)?;
        let mut actions = PendingValues::new(|action: FixtureAction| {
            for argument in action.args {
                crate::ast::drop_expression_iterative(argument);
            }
        });
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            let action_name = self.expect_ident()?;
            self.expect(TokenKind::LParen)?;
            let mut args = PendingExprs::new(Vec::new());
            if !self.peek(TokenKind::RParen) {
                loop {
                    args.push(self.parse_expr()?);
                    if self.peek(TokenKind::Comma) {
                        self.bump();
                        if self.peek(TokenKind::RParen) {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            self.expect(TokenKind::RParen)?;
            if self.peek(TokenKind::Semicolon) {
                self.bump();
            }
            actions.push(FixtureAction {
                name: action_name,
                args: args.into_inner(),
            });
        }
        self.expect(TokenKind::RBrace)?;
        Ok(FixtureDecl {
            name,
            actions: actions.into_inner(),
        })
    }
    fn parse_product_def(&mut self, event: bool) -> ParseResult<Item> {
        // struct Name { Type field; ... }
        let node = self.begin_node(
            if event {
                AstNodeKind::Event
            } else {
                AstNodeKind::Struct
            },
            self.current_start(),
        );
        self.expect(if event {
            TokenKind::Event
        } else {
            TokenKind::Struct
        })?;
        let (name, name_token) = self.expect_ident_token()?;
        self.record_declaration(
            node,
            name.clone(),
            name_token.range,
            if event {
                DeclarationKind::Event
            } else {
                DeclarationKind::Struct
            },
            None,
        );
        self.expect(TokenKind::LBrace)?;
        let mut fields = PendingValues::new(|(_, ty): (String, TypeExpr)| {
            crate::ast::drop_type_iterative(ty);
        });
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            // Allow stray separators.
            if self.peek(TokenKind::Semicolon) || self.peek(TokenKind::Comma) {
                self.bump();
                continue;
            }
            if self.peek_n_ident(0) && self.peek_n(1, TokenKind::Colon) {
                let (ty, name_token) = self.colon_declaration(DeclarationSite::StructField)?;
                fields.push((self.spelling(&name_token).to_owned(), ty));
                if self.peek(TokenKind::Semicolon) || self.peek(TokenKind::Comma) {
                    self.bump();
                }
                continue;
            }
            let mut ty = PendingType::new(self.parse_type_expr()?);
            if self.peek(TokenKind::Colon) {
                return Err(
                    self.type_then_colon_error("struct fields are type-first: write `Type name;`")
                );
            }
            let field_name = self.expect_ident()?;
            fields.push((field_name, ty.take()));
            if self.peek(TokenKind::Semicolon) || self.peek(TokenKind::Comma) {
                self.bump();
            }
        }
        self.expect(TokenKind::RBrace)?;
        self.finish_node(node);
        let definition = super::ast::StructDef {
            name,
            fields: fields.into_inner(),
        };
        Ok(if event {
            Item::Event(definition)
        } else {
            Item::Struct(definition)
        })
    }
    fn parse_permission_decl(&mut self) -> ParseResult<PermissionDecl> {
        let node = self.begin_node(AstNodeKind::Permission, self.current_start());
        let imported = self.peek(TokenKind::Import);
        if imported {
            self.bump();
        }
        self.expect(TokenKind::Permission)?;
        let chain_permission = if imported {
            let token = self.bump();
            let TokenKind::String(name) = &token.kind else {
                return Err(self.expected_error(token, "a chain permission string literal"));
            };
            if name.parse::<iroha_model_base::name::Name>().is_err() {
                return Err(self.coded_error(
                    token,
                    "E_PERMISSION_DECLARATION",
                    "the imported chain permission must be a valid nonempty Name",
                ));
            }
            let name = name.clone();
            self.expect(TokenKind::As)?;
            Some(name)
        } else {
            None
        };
        let (name, token) = self.expect_ident_token()?;
        if name == "anyone"
            || !iroha_data_model::smart_contract::entrypoint::is_canonical_kotodama_identifier(
                &name,
            )
        {
            return Err(self.coded_error(
                token,
                "E_PERMISSION_DECLARATION",
                "a permission declaration needs a canonical identifier other than `anyone`",
            ));
        }
        self.record_declaration(
            node,
            name.clone(),
            token.range,
            DeclarationKind::Permission,
            None,
        );
        self.expect(TokenKind::Semicolon)?;
        self.finish_node(node);
        Ok(PermissionDecl {
            name,
            chain_permission,
        })
    }
    fn parse_state_decl(&mut self) -> ParseResult<Item> {
        // Canonical V1 form: `state Type name;`.
        let node = self.begin_node(AstNodeKind::State, self.current_start());
        self.expect(TokenKind::State)?;
        let (mut ty, name, name_token) = if self.peek_n_ident(0) && self.peek_n(1, TokenKind::Colon)
        {
            let (ty, name_token) = self.colon_declaration(DeclarationSite::State)?;
            let name = self.spelling(&name_token).to_owned();
            (PendingType::new(ty), name, name_token)
        } else {
            if self.peek_n_ident(0)
                && self.peek_n(1, TokenKind::Semicolon)
                && !self.current_names_a_type()
            {
                return Err(self.missing_type_error(DeclarationSite::State));
            }
            let ty = PendingType::new(self.parse_type_expr()?);
            if self.peek(TokenKind::Colon) {
                return Err(self.type_then_colon_error(
                    "state declarations are type-first: write `state Type name;`",
                ));
            }
            let (name, name_token) = self.expect_ident_token()?;
            (ty, name, name_token)
        };
        self.record_declaration(
            node,
            name.clone(),
            name_token.range,
            DeclarationKind::State,
            None,
        );
        self.expect(TokenKind::Semicolon)?;
        self.finish_node(node);
        Ok(Item::State(super::ast::StateDecl {
            name,
            ty: ty.take(),
        }))
    }
    fn parse_const_decl(&mut self) -> ParseResult<Item> {
        let node = self.begin_node(AstNodeKind::Const, self.current_start());
        self.expect(TokenKind::Const)?;
        let (mut ty, name, name_token) = if self.peek_n_ident(0) && self.peek_n(1, TokenKind::Colon)
        {
            let (ty, name_token) = self.colon_declaration(DeclarationSite::Const)?;
            let name = self.spelling(&name_token).to_owned();
            (PendingType::new(ty), name, name_token)
        } else {
            if self.peek_n_ident(0)
                && self.peek_n(1, TokenKind::Equal)
                && !self.current_names_a_type()
            {
                return Err(self.missing_type_error(DeclarationSite::Const));
            }
            let ty = PendingType::new(self.parse_type_expr()?);
            if self.peek(TokenKind::Colon) {
                return Err(self.type_then_colon_error(
                    "constants are type-first: write `const Type name = ...;`",
                ));
            }
            let (name, name_token) = self.expect_ident_token()?;
            (ty, name, name_token)
        };
        self.record_declaration(
            node,
            name.clone(),
            name_token.range,
            DeclarationKind::Const,
            None,
        );
        self.expect(TokenKind::Equal)?;
        let mut value = PendingExpr::new(self.parse_expr()?);
        self.expect(TokenKind::Semicolon)?;
        self.finish_node(node);
        Ok(Item::Const(super::ast::ConstDecl {
            name,
            ty: Some(ty.take()),
            value: value.take(),
        }))
    }
    /// Parse a function after its head keywords.
    ///
    /// `role` is the token that declared the function's role (`kotoage`,
    /// `view`, `hajimari`, `kaizen`, or a recovered stand-in) so diagnostics
    /// echo the user's spelling. Lifecycle hooks pass their canonical name in
    /// `name_override` and are located at `role`.
    fn parse_fn_loose(
        &mut self,
        name_override: Option<String>,
        mut modifiers: FunctionModifiers,
        declaration_start: u32,
        role: Option<Token>,
    ) -> ParseResult<Item> {
        let role_spelling = role.as_ref().map(|token| self.spelling(token).to_owned());
        // A role recovered from an English word or typo was already reported.
        let role_recovered = role
            .as_ref()
            .is_some_and(|token| matches!(token.kind, TokenKind::Ident(_)));
        let (location, name, name_range) = if let Some(name) = name_override {
            let token = role
                .clone()
                .unwrap_or_else(|| self.tokens[self.pos.saturating_sub(1)].clone());
            (
                SourceLocation {
                    line: token.line,
                    column: token.column,
                },
                name,
                token.range,
            )
        } else {
            let (name, token) = self.expect_ident_token()?;
            (
                SourceLocation {
                    line: token.line,
                    column: token.column,
                },
                name,
                token.range,
            )
        };
        let node = self.begin_node(AstNodeKind::Function, declaration_start);
        self.record_declaration(
            node,
            name.clone(),
            name_range,
            DeclarationKind::Function,
            None,
        );
        let previous_function = self.current_function.replace(node);
        let result = (|| -> ParseResult<Item> {
            let params_start = self.current_start();
            let params = self.with_syntax(SyntaxKind::ParamList, params_start, |this| {
                this.expect(TokenKind::LParen)?;
                let mut params = PendingValues::new(|parameter: Param| {
                    if let Some(ty) = parameter.ty {
                        crate::ast::drop_type_iterative(ty);
                    }
                });
                let mut named_parameter_seen = false;
                if !this.peek(TokenKind::RParen) {
                    loop {
                        let parameter_start = this.tokens[this.pos].clone();
                        let parameter = this.parse_param()?;
                        if parameter.call_mode == ParameterCallMode::Positional
                            && named_parameter_seen
                        {
                            return Err(this.coded_error(
                                parameter_start,
                                "E_POSITIONAL_PARAMETER_ORDER",
                                "positional parameters must form a prefix before named parameters",
                            ));
                        }
                        named_parameter_seen |= parameter.call_mode == ParameterCallMode::Named;
                        params.push(parameter);
                        if this.peek(TokenKind::Comma) {
                            this.bump();
                            if this.peek(TokenKind::RParen) {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
                let function_body_or_modifier = this.peek(TokenKind::LBrace)
                    || this.peek(TokenKind::Arrow)
                    || this.peek(TokenKind::Authorize);
                this.expect_or_insert(TokenKind::RParen, function_body_or_modifier)?;
                Ok(params)
            });
            let params = params?;
            let parameter_names = params
                .iter()
                .map(|parameter| parameter.name.clone())
                .collect::<Vec<_>>();
            self.declared_function_parameters
                .entry(name.clone())
                .and_modify(|known| *known = None)
                .or_insert_with(|| Some(parameter_names));
            let mut ret_ty = None;
            let mut return_clause = None;
            let mut authorize_clause: Option<TextRange> = None;
            while !self.peek(TokenKind::LBrace) && !self.peek(TokenKind::EOF) {
                if self.peek(TokenKind::Authorize) {
                    let authorize = self.bump();
                    if matches!(
                        modifiers.kind,
                        FunctionKind::Hajimari | FunctionKind::Kaizen
                    ) {
                        let clause = self.skip_balanced_clause(&authorize);
                        let hook = role_spelling.clone().unwrap_or_else(|| name.clone());
                        self.report(self.coded_error(authorize, "E_LIFECYCLE_AUTHORIZATION",
                            format!("`{hook}` cannot declare `authorize(...)`: lifecycle hooks are authorized by the runtime"))
                            .reported_at(clause)
                            .with_help("remove the clause; lifecycle authority is checked by the runtime")
                            .with_fix(self.leading_space_range(clause), ""))?;
                        continue;
                    }
                    self.expect(TokenKind::LParen)?;
                    let permission_token = self.bump();
                    let perm = match permission_token.kind.clone() {
                        TokenKind::Ident(permission) => permission,
                        TokenKind::String(_) => return Err(self.coded_error(permission_token,
                            "E_AUTHORIZATION_STRING", "authorization requires a declared permission identifier or `anyone`, not a string")
                            .with_help("declare `permission Admin;` and write `authorize(Admin)`, or explicitly choose `authorize(anyone)`")),
                        _ => return Err(self.expected_error(permission_token, "a declared permission identifier or `anyone`")),
                    };
                    self.expect(TokenKind::RParen)?;
                    let clause = TextRange::new(
                        authorize.range.start,
                        self.previous_end(authorize.range.start),
                    );
                    if !matches!(modifiers.kind, FunctionKind::Kotoage | FunctionKind::View) {
                        return Err(self.coded_error(authorize, "K1001", format!("`authorize(...)` is only valid on public functions; `{name}` is a private `fn`"))
                            .reported_at(clause).with_help("private helpers run with their caller's authority; remove the clause"));
                    }
                    if let Some(first) = authorize_clause {
                        return Err(self
                            .coded_error(
                                authorize,
                                "K1001",
                                format!("function `{name}` declares `authorize(...)` twice"),
                            )
                            .reported_at(clause)
                            .with_label(first, "first `authorize(...)` clause")
                            .with_help("a function declares exactly one authorization policy")
                            .with_fix(self.leading_space_range(clause), ""));
                    }
                    if let Some(return_range) = return_clause {
                        let return_range: TextRange = return_range;
                        let return_text =
                            &self.source[return_range.start as usize..return_range.end as usize];
                        let clause_text = &self.source[clause.start as usize..clause.end as usize];
                        let separator =
                            &self.source[return_range.end as usize..clause.start as usize];
                        self.report(
                            self.coded_error(
                                authorize,
                                "E_AUTHORIZE_POSITION",
                                "`authorize(...)` comes before the return type",
                            )
                            .reported_at(TextRange::new(return_range.start, clause.end))
                            .with_help(
                                "write `kotoage fn name(params) authorize(Admin) -> Type { ... }`",
                            )
                            .with_fix(
                                TextRange::new(return_range.start, clause.end),
                                format!("{clause_text}{separator}{return_text}"),
                            ),
                        )?;
                    }
                    let name_node = self.facts.source_map.allocate_owned(
                        AstNodeKind::Name,
                        permission_token.range,
                        self.current_function,
                    );
                    self.facts
                        .authorizations
                        .push(crate::spanned_ast::AuthorizationFact {
                            name_node,
                            name: perm.clone(),
                        });
                    authorize_clause = Some(clause);
                    modifiers.authorization = Some(perm);
                } else if self.peek(TokenKind::Arrow) && ret_ty.is_none() {
                    let arrow = self.bump();
                    ret_ty = Some(PendingType::new(self.parse_type_expr()?));
                    return_clause = Some(TextRange::new(
                        arrow.range.start,
                        self.previous_end(arrow.range.end),
                    ));
                } else {
                    let tok = self.current_token();
                    if let TokenKind::Ident(word) = &tok.kind
                        && crate::diagnostic::suggest::closest(word, ["authorize"]).is_some()
                    {
                        return Err(self.keyword_typo_error(&tok, "authorize"));
                    }
                    return Err(self.expected_error(
                        tok,
                        "`authorize(Admin)`, a return type, or the function body `{`",
                    ));
                }
            }
            if matches!(modifiers.kind, FunctionKind::Kotoage | FunctionKind::View)
                && modifiers.authorization.is_none()
                && !role_recovered
            {
                let spelling = role_spelling.clone().unwrap_or_else(|| "public".to_owned());
                let insertion = TextRange::empty(
                    return_clause.map_or(self.previous_end(declaration_start), |range| range.start),
                );
                let code = if modifiers.kind == FunctionKind::View {
                    "E_VIEW_AUTHORIZATION_MISSING"
                } else {
                    "E_KOTOAGE_AUTHORIZATION_MISSING"
                };
                self.report(self.coded_error(self.current_token(), code,
                    format!("{spelling} function `{name}` requires an explicit `authorize(...)` policy"))
                    .reported_at(insertion)
                    .with_help("use a declared permission such as `authorize(Admin)`, or explicitly allow every caller with `authorize(anyone)`"))?;
            }
            let body = self.parse_block()?;
            Ok(Item::Function(Function {
                name,
                params: params.into_inner(),
                ret_ty: ret_ty.as_mut().map(PendingType::take),
                body,
                modifiers,
                location,
            }))
        })();
        self.current_function = previous_function;
        if result.is_ok() {
            self.finish_node(node);
        }
        result
    }
    fn parse_block(&mut self) -> ParseResult<Block> {
        let block_start = self.current_start();
        let syntax_block = self.syntax_start(SyntaxKind::Block, block_start);
        let open_brace = self.current_token();
        self.expect(TokenKind::LBrace)?;
        let syntax_statements =
            self.syntax_start(SyntaxKind::StatementList, self.previous_end(block_start));
        let mut block = PendingBlock::new();
        let mut closed_early = false;
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            if self.recover && self.declaration_starts_here() {
                // A declaration keyword inside a body means the body's `}` is
                // missing. Close the block here so the declaration parses as
                // the next item instead of cascading statement errors.
                let token = self.current_token();
                if self.missing_close_reported != Some(token.range.start) {
                    self.missing_close_reported = Some(token.range.start);
                    let previous = self.tokens[self.pos.saturating_sub(1)].clone();
                    let insertion = TextRange::empty(previous.range.end);
                    // The `}` goes on its own line, indented like the line
                    // that opened the block.
                    let closing = format!("\n{}}}", self.line_indentation(open_brace.range.start));
                    let mut error = self
                        .expected_error(token, "`}` to close the block")
                        .reported_at(insertion)
                        .with_label(open_brace.range, "this `{` is not closed")
                        .with_help("declarations cannot appear inside a function body; close the body with `}` before the next declaration")
                        .with_fix(insertion, closing);
                    error.expected = Some(SyntaxKind::RBrace);
                    error.expected_owner = self.syntax.current();
                    self.errors.push(*error);
                }
                closed_early = true;
                break;
            }
            let statement_start = self.pos;
            let start = self.tokens[statement_start].range.start;
            let initial_kind = self.syntax_statement_kind(statement_start);
            let syntax_statement = self.syntax_start(initial_kind, start);
            match self.parse_block_element() {
                Ok(element @ ParsedBlockElement::Statement(_)) => {
                    self.syntax_set_kind(syntax_statement, block_element_syntax_kind(&element));
                    let ParsedBlockElement::Statement(statement) = element else {
                        unreachable!("matched statement block element")
                    };
                    let start = self.tokens[statement_start].range.start;
                    let end = self.previous_end(start);
                    block.push_statement(if statement.source_node().is_some() {
                        statement
                    } else {
                        self.source_statement(TextRange::new(start, end), statement)
                    });
                    self.syntax_finish(syntax_statement, start);
                }
                Ok(element @ ParsedBlockElement::Tail(_)) => {
                    self.syntax_set_kind(syntax_statement, block_element_syntax_kind(&element));
                    let ParsedBlockElement::Tail(expression) = element else {
                        unreachable!("matched tail block element")
                    };
                    block.set_tail(expression);
                    self.syntax_finish(syntax_statement, start);
                    break;
                }
                Err(error) if self.recover => {
                    let recovery_start = error.range.start.max(start);
                    self.errors.push(*error);
                    let syntax_error = self.syntax_start(SyntaxKind::ErrorNode, recovery_start);
                    self.synchronize_statement(statement_start);
                    self.syntax_finish(syntax_error, recovery_start);
                    self.syntax_finish(syntax_statement, start);
                }
                Err(error) => {
                    self.syntax_finish(syntax_statement, start);
                    return Err(error);
                }
            }
        }
        self.syntax_finish_at(syntax_statements, self.current_start());
        if !closed_early {
            self.expect(TokenKind::RBrace)?;
        }
        self.syntax_finish(syntax_block, block_start);
        Ok(block.into_inner())
    }
    /// Whether the current token can only start a source-unit declaration,
    /// never a statement.
    fn declaration_starts_here(&self) -> bool {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(
                TokenKind::Fn
                | TokenKind::Kotoage
                | TokenKind::View
                | TokenKind::Hajimari
                | TokenKind::Kaizen
                | TokenKind::Struct
                | TokenKind::Event
                | TokenKind::Enum
                | TokenKind::Trigger
                | TokenKind::Seiyaku
                | TokenKind::Module
                | TokenKind::Import
                | TokenKind::Include
                | TokenKind::Export
                | TokenKind::Const
                | TokenKind::Hash,
            ) => true,
            Some(TokenKind::Permission) => self
                .tokens
                .get(self.pos + 1)
                .is_some_and(|token| matches!(token.kind, TokenKind::Ident(_))),
            Some(TokenKind::Error) => self.peek_n(1, TokenKind::Enum),
            Some(TokenKind::State) => !self.peek_n(1, TokenKind::ColonColon),
            _ => false,
        }
    }
    fn parse_block_element(&mut self) -> ParseResult<ParsedBlockElement> {
        if self.peek(TokenKind::Emit) {
            let statement_start = self.current_start();
            let owner = self.begin_node(AstNodeKind::Statement, statement_start);
            self.bump();
            let mut payload = PendingExpr::new(self.parse_expr()?);
            if !matches!(payload.as_ref().kind(), Expr::StructLiteral { .. }) {
                return Err(self.coded_error(
                    self.current_token(),
                    "E_EVENT_PAYLOAD",
                    "emit requires a declared event record: `emit Event { field: value };`",
                ));
            }
            self.expect(TokenKind::Semicolon)?;
            return Ok(ParsedBlockElement::Statement(self.finish_owned_statement(
                owner,
                TextRange::new(statement_start, self.previous_end(statement_start)),
                Statement::Emit(payload.take()),
            )));
        }
        if self.peek(TokenKind::Let) || self.peek(TokenKind::Var) {
            let statement_start = self.current_start();
            let owner = self.begin_node(AstNodeKind::Statement, statement_start);
            let mut mutable = self.peek(TokenKind::Var);
            let keyword = self.bump();
            if self.peek_ident_n(0, "mut")
                && (self.peek_n_ident(1) || self.peek_n(1, TokenKind::LParen))
            {
                // `let mut x`: mutability is spelled `var`.
                let mut_token = self.bump();
                let replaced = TextRange::new(keyword.range.start, mut_token.range.end);
                let next_start = self.current_start();
                let error = if mutable {
                    self.coded_error(
                        mut_token.clone(),
                        "E_LET_MUT",
                        "`var` bindings are already mutable; remove `mut`",
                    )
                    .with_fix(TextRange::new(mut_token.range.start, next_start), "")
                } else {
                    self.coded_error(
                        mut_token.clone(),
                        "E_LET_MUT",
                        "a mutable local is declared with `var`, not `let mut`",
                    )
                    .reported_at(replaced)
                    .with_fix(replaced, "var")
                };
                self.report(error.with_help(
                    "`let` binds an immutable local and `var` a mutable one: `var total = 0;` or `var int total = 0;`",
                ))?;
                mutable = true;
            }
            // `let y: int = ...` is reported once and continues as `let int y`.
            let mut colon_binding = None;
            let mut ty = if self.peek_n_ident(0) && self.peek_n(1, TokenKind::Colon) {
                let (ty, token) = self.colon_declaration(DeclarationSite::Local)?;
                colon_binding = Some(token);
                Some(PendingType::new(ty))
            } else if self.typed_local_starts_here() {
                Some(PendingType::new(self.parse_type_expr()?))
            } else {
                None
            };
            // pattern
            let pat = if let Some(token) = colon_binding {
                let name = self.spelling(&token).to_owned();
                self.record_binding(owner, 0, name.clone(), token.range, BindingFactKind::Local);
                Pattern::Name(name)
            } else if self.struct_pattern_starts_here() {
                self.parse_struct_pattern(owner, BindingFactKind::Local)?
            } else if self.peek(TokenKind::LParen) {
                self.bump();
                let mut names = Vec::new();
                loop {
                    let (name, token) = self.expect_ident_token()?;
                    self.record_binding(
                        owner,
                        names.len(),
                        name.clone(),
                        token.range,
                        BindingFactKind::Local,
                    );
                    names.push(name);
                    if self.peek(TokenKind::Comma) {
                        self.bump();
                    } else {
                        break;
                    }
                }
                self.expect(TokenKind::RParen)?;
                Pattern::Tuple(names)
            } else {
                let (name, token) = self.expect_ident_token()?;
                self.record_binding(owner, 0, name.clone(), token.range, BindingFactKind::Local);
                Pattern::Name(name)
            };
            if self.peek(TokenKind::Colon) {
                let token = self.bump();
                return Err(self
                    .coded_error(
                        token,
                        "E_RETIRED_DECLARATION_ORDER",
                        "typed locals are type-first: write `let int value = ...;`",
                    )
                    .with_help(declaration_order_help()));
            }
            self.expect(TokenKind::Equal)?;
            let mut expr = PendingExpr::new(self.parse_expr()?);
            self.expect(TokenKind::Semicolon)?;
            let range = TextRange::new(statement_start, self.previous_end(statement_start));
            Ok(ParsedBlockElement::Statement(self.finish_owned_statement(
                owner,
                range,
                Statement::Let {
                    mutable,
                    pat,
                    ty: ty.as_mut().map(PendingType::take),
                    value: expr.take(),
                },
            )))
        } else if self.peek(TokenKind::Return) {
            self.bump();
            if self.peek(TokenKind::Semicolon) {
                self.bump();
                Ok(ParsedBlockElement::Statement(Statement::Return(None)))
            } else if self.peek(TokenKind::RBrace) {
                // `return` is a statement even when it has no value. At the
                // block boundary the only possible continuation is its
                // required semicolon, so recover that exact token instead of
                // fabricating a missing expression.
                self.expect(TokenKind::Semicolon)?;
                unreachable!("a missing return semicolon always reports an error")
            } else {
                let mut expr = PendingExpr::new(self.parse_expr()?);
                self.expect(TokenKind::Semicolon)?;
                Ok(ParsedBlockElement::Statement(Statement::Return(Some(
                    expr.take(),
                ))))
            }
        } else if self.peek(TokenKind::Break) {
            self.bump();
            self.expect(TokenKind::Semicolon)?;
            Ok(ParsedBlockElement::Statement(Statement::Break))
        } else if self.peek(TokenKind::Continue) {
            self.bump();
            self.expect(TokenKind::Semicolon)?;
            Ok(ParsedBlockElement::Statement(Statement::Continue))
        } else if self.peek(TokenKind::If) {
            let expression = self.parse_if_expression(true)?;
            self.finish_block_expression(expression)
        } else if self.peek(TokenKind::Match) {
            let expression = self.parse_match_expression()?;
            self.finish_block_expression(expression)
        } else if self.peek(TokenKind::For) {
            let for_line = self.tokens.get(self.pos).map(|t| t.line).unwrap_or(0);
            let for_start = self.current_start();
            self.expect(TokenKind::For)?;
            if self.peek(TokenKind::LParen) && self.peek_n_ident(1) && self.peek_n(2, TokenKind::In)
            {
                // `for (i in xs)`: the loop header is not parenthesized.
                self.report_parenthesized_for_header()?;
            }
            if self.peek(TokenKind::LParen)
                && let Some(error) = self.three_clause_for_error()
            {
                return Err(error);
            }
            if let Some((init, cond, step)) = self.parse_for_range()? {
                let mut init = PendingStatement::new(init);
                let mut cond = PendingExpr::new(cond);
                let mut step = PendingStatement::new(step);
                let body = self.parse_block()?;
                Ok(ParsedBlockElement::Statement(Statement::For {
                    line: for_line,
                    init: Some(Box::new(init.take())),
                    cond: Some(cond.take()),
                    step: Some(Box::new(step.take())),
                    body,
                }))
            } else if let Some((owner, pat, map)) = self.parse_for_each_map(for_start)? {
                let mut map = PendingExpr::new(map);
                if self.peek(TokenKind::DotDot) {
                    self.report_range_operator(map.as_ref())?;
                }
                let body = self.parse_block()?;
                let range = TextRange::new(for_start, self.previous_end(for_start));
                Ok(ParsedBlockElement::Statement(self.finish_owned_statement(
                    owner,
                    range,
                    Statement::ForEachMap {
                        pat,
                        map: map.take(),
                        body,
                    },
                )))
            } else {
                Err(self
                    .expected_error(
                        self.current_token(),
                        "a bounded loop header (`for i in range(N)` or `for pattern in collection`)",
                    )
                    .with_help("loops are bounded: `for i in range(10) { ... }` or `for item in list { ... }`"))
            }
        } else if (self.peek_ident_n(0, "while") && !self.peek_n(1, TokenKind::Equal))
            || (self.peek_ident_n(0, "loop") && self.peek_n(1, TokenKind::LBrace))
        {
            let token = self.bump();
            let spelling = self.spelling(&token).to_owned();
            Err(self
                .coded_error(
                    token,
                    "E_UNSUPPORTED_LOOP",
                    format!(
                        "`{spelling}` loops are not part of Kotodama; every loop is a `for` loop with a compiler-proven bound"
                    ),
                )
                .with_help("execution is metered and must be bounded: iterate `for i in range(N)` with a compile-time `N`, or a collection with a proven capacity, and exit early with `break`"))
        } else {
            // Try assignments including compound ops and field/indexed lvalues
            let save = self.pos;
            let syntax_checkpoint = self.syntax_checkpoint();
            let mut target = self.try_parse_lvalue_expr().ok().map(PendingExpr::new);
            if let Some(target) = target.as_mut()
                && (self.peek(TokenKind::Equal)
                    || self.peek(TokenKind::PlusEqual)
                    || self.peek(TokenKind::MinusEqual)
                    || self.peek(TokenKind::StarEqual)
                    || self.peek(TokenKind::SlashEqual)
                    || self.peek(TokenKind::PercentEqual))
            {
                let op_tok = self.bump();
                let mut rhs = PendingExpr::new(self.parse_expr()?);
                self.expect(TokenKind::Semicolon)?;
                let op = match op_tok.kind {
                    TokenKind::Equal => AssignOp::Set,
                    TokenKind::PlusEqual => AssignOp::Add,
                    TokenKind::MinusEqual => AssignOp::Sub,
                    TokenKind::StarEqual => AssignOp::Mul,
                    TokenKind::SlashEqual => AssignOp::Div,
                    TokenKind::PercentEqual => AssignOp::Mod,
                    _ => {
                        return Err(self.expected_error(
                            op_tok,
                            "an assignment operator (`=`, `+=`, `-=`, `*=`, `/=` or `%=`)",
                        ));
                    }
                };
                let target = target.take();
                return Ok(match (target, op) {
                    (Expr::Ident(name), AssignOp::Set) => {
                        ParsedBlockElement::Statement(Statement::Assign {
                            name,
                            value: rhs.take(),
                        })
                    }
                    (t, op) => ParsedBlockElement::Statement(Statement::AssignExpr {
                        target: t,
                        op,
                        value: rhs.take(),
                    }),
                });
            }
            // Not an assignment (or not an lvalue); rewind both the token view
            // and syntax events before parsing the expression authoritatively.
            drop(target.take());
            self.pos = save;
            self.syntax_rollback(syntax_checkpoint);
            let expr = self.parse_statement_expression_candidate()?;
            self.finish_block_expression(expr)
        }
    }
    fn finish_block_expression(&mut self, expression: Expr) -> ParseResult<ParsedBlockElement> {
        let mut expression = PendingExpr::new(expression);
        if self.peek(TokenKind::Semicolon) {
            self.bump();
            let exact =
                self.guard_expression_depth_at(expression.take(), self.current_delimiter_depth());
            return Ok(ParsedBlockElement::Statement(Statement::Expr(exact)));
        }
        let missing_else = matches!(
            expression.as_ref().kind(),
            Expr::If {
                else_branch: None,
                ..
            } | Expr::IfLet {
                else_branch: None,
                ..
            }
        );
        if self.peek(TokenKind::RBrace)
            && !missing_else
            && block_expression_flow(expression.as_ref()) != BlockExpressionFlow::Unit
        {
            let exact =
                self.guard_expression_depth_at(expression.take(), self.current_delimiter_depth());
            return Ok(ParsedBlockElement::Tail(exact));
        }
        if matches!(
            expression.as_ref().kind(),
            Expr::If { .. } | Expr::IfLet { .. }
        ) {
            return Ok(ParsedBlockElement::Statement(
                self.if_expression_statement(expression.take()),
            ));
        }
        if matches!(expression.as_ref().kind(), Expr::Match { .. }) {
            return Ok(ParsedBlockElement::Statement(Statement::Expr(
                expression.take(),
            )));
        }
        let token = self.current_token();
        // `retrun total;`: a misspelled statement keyword parses as a name
        // followed by an unexpected operand.
        if let Expr::Ident(name) = expression.as_ref().kind()
            && Self::token_starts_expression(&token.kind)
            && let Some(keyword) = crate::diagnostic::suggest::closest(
                name,
                [
                    "return", "let", "var", "for", "if", "match", "break", "continue",
                ],
            )
            && let Some(word) = self
                .pos
                .checked_sub(1)
                .and_then(|index| self.tokens.get(index))
        {
            return Err(self.keyword_typo_error(&word.clone(), keyword));
        }
        Err(self.expected_token_error(token, &TokenKind::Semicolon))
    }
    fn if_expression_statement(&mut self, expression: Expr) -> Statement {
        let mut expression = expression;
        let mut wrappers = Vec::new();
        while let Expr::Source {
            node,
            source,
            expression: inner,
        } = expression
        {
            wrappers.push((node, source));
            expression = *inner;
        }
        assert!(
            !wrappers.is_empty(),
            "direct if-expression parser always returns a source owner"
        );
        let mut statement = if_expression_statement_inner(expression);
        for (node, source) in wrappers.into_iter().rev() {
            self.facts.source_map.set_kind(node, AstNodeKind::Statement);
            statement = Statement::Source {
                node,
                source,
                statement: Box::new(statement),
            };
        }
        statement
    }
    fn parse_if_expression(&mut self, statement_context: bool) -> ParseResult<Expr> {
        // Delimiter-free `else if` chains may legally reach the V1 depth
        // boundary. Collection and reconstruction use separate call frames as
        // well as explicit heap stacks so parsing a condition does not retain
        // all of the reconstruction temporaries on a small editor stack.
        let (frames, terminal_else) = self.parse_if_expression_frames(statement_context)?;
        Ok(self.finish_if_expression_frames(frames, terminal_else, statement_context))
    }
    fn parse_if_expression_frames(
        &mut self,
        statement_context: bool,
    ) -> ParseResult<(Vec<PendingIfFrame>, Option<PendingBlock>)> {
        let mut frames = Vec::new();
        let mut open_syntax = Vec::new();
        let terminal_else = (|| -> ParseResult<Option<PendingBlock>> {
            loop {
                self.enter_recursive_expression()?;
                let start = self.current_start();
                let syntax = self.syntax_start(SyntaxKind::IfExpr, start);
                open_syntax.push((syntax, start));
                let owner = self.begin_node(AstNodeKind::Expression, start);
                self.expect(TokenKind::If)?;
                if statement_context {
                    self.statement_if_condition_depths
                        .push(self.current_delimiter_depth());
                }
                let parsed_condition = (|| -> ParseResult<_> {
                    if self.peek(TokenKind::Let) {
                        self.bump();
                        let pattern = self.parse_sum_pattern(owner, 0)?;
                        self.expect(TokenKind::Equal)?;
                        let value = PendingExpr::new(self.parse_expr_before_block()?);
                        Ok((Some(pattern), Some(value), None))
                    } else {
                        Ok((
                            None,
                            None,
                            Some(PendingExpr::new(self.parse_expr_before_block()?)),
                        ))
                    }
                })();
                if statement_context {
                    self.statement_if_condition_depths
                        .pop()
                        .expect("statement-if condition depth must be balanced");
                }
                let (pattern, value, condition) = parsed_condition?;
                let then_branch = PendingBlock::from_block(self.parse_block()?);
                frames.push(PendingIfFrame {
                    start,
                    owner,
                    syntax,
                    pattern,
                    value,
                    condition,
                    then_branch,
                });
                if !self.peek(TokenKind::Else) {
                    break Ok(None);
                }
                self.bump();
                if self.peek(TokenKind::If) {
                    continue;
                }
                break self.parse_block().map(PendingBlock::from_block).map(Some);
            }
        })();
        match terminal_else {
            Ok(else_branch) => {
                debug_assert_eq!(frames.len(), open_syntax.len());
                Ok((frames, else_branch))
            }
            Err(error) => {
                let entered = open_syntax.len();
                while let Some((syntax, start)) = open_syntax.pop() {
                    self.syntax_finish(syntax, start);
                }
                for _ in 0..entered {
                    self.leave_recursive_expression();
                }
                Err(error)
            }
        }
    }
    fn finish_if_expression_frames(
        &mut self,
        mut frames: Vec<PendingIfFrame>,
        mut terminal_else: Option<PendingBlock>,
        statement_context: bool,
    ) -> Expr {
        let mut entered = frames.len();
        let mut nested: Option<PendingExpr> = None;
        while let Some(frame) = frames.pop() {
            let PendingIfFrame {
                start,
                owner,
                syntax,
                pattern,
                mut value,
                mut condition,
                then_branch,
            } = frame;
            let else_branch = if let Some(mut nested) = nested.take() {
                if block_expression_flow(nested.as_ref()) != BlockExpressionFlow::Unit {
                    Some(PendingBlock::from_block(Block {
                        statements: Vec::new(),
                        tail: Some(Box::new(nested.take())),
                    }))
                } else {
                    let statement = self.if_expression_statement(nested.take());
                    Some(PendingBlock::from_block(Block {
                        statements: vec![statement],
                        tail: None,
                    }))
                }
            } else {
                terminal_else.take()
            };
            let expression = if let Some(pattern) = pattern {
                Expr::IfLet {
                    pattern,
                    value: Box::new(value.as_mut().expect("if let value").take()),
                    then_branch: then_branch.into_inner(),
                    else_branch: else_branch.map(PendingBlock::into_inner),
                }
            } else {
                Expr::If {
                    condition: Box::new(condition.as_mut().expect("if condition").take()),
                    then_branch: then_branch.into_inner(),
                    else_branch: else_branch.map(PendingBlock::into_inner),
                }
            };
            self.syntax_finish(syntax, start);
            let range = TextRange::new(start, self.previous_end(start));
            let recursive_depth = self
                .recursive_expression_entry_depths
                .iter()
                .filter(|depth| **depth >= self.current_delimiter_depth())
                .count();
            let statement_condition_adjustment = self
                .statement_if_condition_depths
                .iter()
                .filter(|depth| **depth >= self.current_delimiter_depth())
                .count();
            let root_depth = self
                .current_delimiter_depth()
                .saturating_add(recursive_depth)
                .saturating_sub(
                    usize::from(statement_context)
                        .saturating_add(statement_condition_adjustment)
                        .saturating_add(1),
                );
            let expression = self.finish_owned_expression_at_depth(
                owner,
                AstNodeKind::Expression,
                range,
                expression,
                root_depth,
            );
            self.leave_recursive_expression();
            entered = entered.saturating_sub(1);
            nested = Some(PendingExpr::new(expression));
        }
        debug_assert_eq!(entered, 0);
        nested
            .expect("one if-expression parse must produce one frame")
            .into_inner()
    }
    fn parse_match_expression(&mut self) -> ParseResult<Expr> {
        self.enter_recursive_expression()?;
        let result = (|| {
            let start = self.current_start();
            let owner = self.begin_node(AstNodeKind::Expression, start);
            let expression = self.with_syntax(SyntaxKind::MatchExpr, start, |parser| {
                parser.parse_match_expression_inner(owner)
            })?;
            let range = TextRange::new(start, self.previous_end(start));
            Ok(self.finish_owned_expression(owner, AstNodeKind::Expression, range, expression))
        })();
        self.leave_recursive_expression();
        result
    }
    fn parse_match_expression_inner(&mut self, owner: NodeId) -> ParseResult<Expr> {
        self.expect(TokenKind::Match)?;
        let mut value = PendingExpr::new(self.parse_expr_before_block()?);
        self.expect(TokenKind::LBrace)?;
        let mut arms = PendingValues::new(|arm: MatchArm| {
            crate::ast::drop_block_iterative(arm.body);
        });
        let mut binding_ordinal = 0_usize;
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            let arm_start = self.current_start();
            let arm_index = self.pos;
            let syntax_arm = self.syntax_start(SyntaxKind::MatchArm, arm_start);
            let arm = (|| -> ParseResult<(SumPattern, Block)> {
                let pattern = self.parse_sum_pattern(owner, binding_ordinal)?;
                if matches!(&pattern.binding, Some(PatternBinding::Name(_))) {
                    binding_ordinal = binding_ordinal.saturating_add(1);
                }
                self.expect(TokenKind::FatArrow)?;
                let body = if self.peek(TokenKind::LBrace) {
                    self.parse_block()?
                } else {
                    Block {
                        statements: Vec::new(),
                        tail: Some(Box::new(self.parse_expr()?)),
                    }
                };
                Ok((pattern, body))
            })();
            self.syntax_finish(syntax_arm, arm_start);
            let (pattern, body) = match arm {
                Ok(arm) => arm,
                Err(error) if self.recover => {
                    // Recover at the next arm so one bad arm does not unbalance
                    // the enclosing blocks.
                    self.errors.push(*error);
                    self.synchronize_match_arm(arm_index);
                    if self.peek(TokenKind::Comma) {
                        self.bump();
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            arms.push(MatchArm { pattern, body });
            if !self.peek(TokenKind::Comma) {
                if !self.peek(TokenKind::RBrace) {
                    let token = self.current_token();
                    let previous = self.tokens[self.pos.saturating_sub(1)].clone();
                    let mut error = self
                        .expected_error(token.clone(), "`,` or `}` after the match arm")
                        .with_help(
                            "separate match arms with `,`, including arms whose body is a block",
                        );
                    // A namespaced pattern (`Option::none =>`) cannot
                    // continue an arm body, so it starts the next arm.
                    let next_arm = self.peek_n_ident(0) && self.peek_n(1, TokenKind::ColonColon);
                    if token.line > previous.line || previous.kind == TokenKind::RBrace || next_arm
                    {
                        // A comma-less arm followed by another arm.
                        let insertion = TextRange::empty(previous.range.end);
                        error = error.reported_at(insertion).with_fix(insertion, ",");
                        self.report(error)?;
                        continue;
                    }
                    return Err(error);
                }
                break;
            }
            self.bump();
        }
        self.expect(TokenKind::RBrace)?;
        Ok(Expr::Match {
            value: Box::new(value.take()),
            arms: arms.into_inner(),
        })
    }
    fn parse_struct_pattern(
        &mut self,
        owner: NodeId,
        kind: BindingFactKind,
    ) -> ParseResult<Pattern> {
        let start = self.current_start();
        self.with_syntax(SyntaxKind::StructPattern, start, |this| {
            let (name, type_token) = this.parse_type_path()?;
            this.record_type_use(name.clone(), type_token.range);
            this.expect(TokenKind::LBrace)?;
            let mut fields: Vec<StructPatternField> = Vec::new();
            let mut rest = false;
            while !this.peek(TokenKind::RBrace) {
                if this.peek(TokenKind::DotDot) {
                    this.bump();
                    rest = true;
                    if this.peek(TokenKind::Comma) {
                        this.bump();
                    }
                    if !this.peek(TokenKind::RBrace) {
                        let token = this.tokens[this.pos].clone();
                        return Err(this.coded_error(
                            token,
                            "E_STRUCT_PATTERN_REST",
                            "`..` must appear once, at the end of a struct pattern",
                        ));
                    }
                    break;
                }
                let field_start = this.current_start();
                let ordinal = fields.len();
                let field =
                    this.with_syntax(SyntaxKind::StructPatternField, field_start, |this| {
                        let (field, field_token) = this.expect_ident_token()?;
                        if fields.iter().any(|existing| existing.name == field) {
                            return Err(this.coded_error(
                                field_token,
                                "E_DUPLICATE_STRUCT_PATTERN_FIELD",
                                format!("field `{field}` occurs more than once in the pattern"),
                            ));
                        }
                        let (binding, binding_token) = if this.peek(TokenKind::Colon) {
                            this.bump();
                            this.expect_ident_token()?
                        } else {
                            (field.clone(), field_token.clone())
                        };
                        this.record_binding(
                            owner,
                            ordinal,
                            binding.clone(),
                            binding_token.range,
                            kind,
                        );
                        Ok(StructPatternField {
                            name: field,
                            binding,
                            source: Some(SourceRange::new(
                                this.facts.source_map.source(),
                                field_token.range,
                            )),
                        })
                    })?;
                fields.push(field);
                if !this.peek(TokenKind::Comma) {
                    break;
                }
                this.bump();
            }
            this.expect(TokenKind::RBrace)?;
            Ok(Pattern::Struct { name, fields, rest })
        })
    }
    fn parse_sum_pattern(&mut self, owner: NodeId, ordinal: usize) -> ParseResult<SumPattern> {
        let start = self.current_start();
        self.with_syntax(SyntaxKind::SumPattern, start, |parser| {
            parser.parse_sum_pattern_inner(owner, ordinal)
        })
    }
    fn parse_sum_pattern_inner(
        &mut self,
        owner: NodeId,
        ordinal: usize,
    ) -> ParseResult<SumPattern> {
        let namespace_token = self.bump();
        let TokenKind::Ident(mut namespace) = namespace_token.kind.clone() else {
            return Err(self
                .expected_error(
                    namespace_token,
                    "an `Option::`, `Result::` or error-variant pattern",
                )
                .with_help("`match` arms name the variants of an `Option`, `Result`, `enum` or `error enum`; branch on a `bool` or number with `if`/`else`"));
        };
        if !self.peek(TokenKind::ColonColon) {
            return Err(self.bare_pattern_error(&namespace_token, &namespace));
        }
        let mut namespace_end = namespace_token.range.end;
        self.expect(TokenKind::ColonColon)?;
        let mut variant_token = self.bump();
        let TokenKind::Ident(mut variant_name) = variant_token.kind.clone() else {
            return Err(self.expected_error(variant_token, "a variant name after `::`"));
        };
        while self.peek(TokenKind::ColonColon) {
            self.bump();
            namespace.push_str("::");
            namespace.push_str(&variant_name);
            namespace_end = variant_token.range.end;
            variant_token = self.bump();
            let TokenKind::Ident(name) = variant_token.kind.clone() else {
                return Err(self.expected_error(variant_token, "an error variant name after `::`"));
            };
            variant_name = name;
        }
        if let Some(canonical) = canonical_sum_path(&namespace, &variant_name)
            && canonical != format!("{namespace}::{variant_name}")
        {
            let written = TextRange::new(namespace_token.range.start, variant_token.range.end);
            return Err(self
                .coded_error(
                    namespace_token,
                    "E_LEGACY_SUM_CONSTRUCTOR",
                    format!("`{namespace}::{variant_name}` is spelled `{canonical}`"),
                )
                .reported_at(written)
                .with_help(sum_constructor_help())
                .with_fix(written, canonical));
        }
        let variant_label = format!("{namespace}::{variant_name}");
        let variant = match (namespace.as_str(), variant_name.as_str()) {
            ("Option", "some") => SumVariant::OptionSome,
            ("Option", "none") => SumVariant::OptionNone,
            ("Result", "ok") => SumVariant::ResultOk,
            ("Result", "err") => SumVariant::ResultErr,
            ("Option" | "Result", _) => {
                return Err(self
                    .expected_error(
                        variant_token,
                        if namespace == "Option" {
                            "`some` or `none` after `Option::`"
                        } else {
                            "`ok` or `err` after `Result::`"
                        },
                    )
                    .with_help(sum_constructor_help()));
            }
            _ => {
                self.record_type_use(
                    namespace.clone(),
                    TextRange::new(namespace_token.range.start, namespace_end),
                );
                SumVariant::Nominal {
                    namespace,
                    variant: variant_name,
                }
            }
        };
        let binding = if matches!(variant, SumVariant::OptionNone | SumVariant::Nominal { .. }) {
            if self.peek(TokenKind::LParen) {
                let token = self.bump();
                let clause = self.skip_balanced_clause(&token);
                return Err(self
                    .coded_error(
                        token,
                        "K1001",
                        format!("`{variant_label}` has no payload to bind"),
                    )
                    .reported_at(clause)
                    .with_help("payloadless variants are matched by name alone, for example `Option::none => ...`")
                    .with_fix(clause, ""));
            }
            None
        } else {
            self.expect(TokenKind::LParen)?;
            let token = self.bump();
            let TokenKind::Ident(name) = token.kind.clone() else {
                return Err(self
                    .expected_error(token, "a payload binding name or `_`")
                    .with_help(format!(
                        "a `{variant_label}` arm binds its payload to a name, or to `_` when the arm does not use it: `{variant_label}(value) => ...`"
                    )));
            };
            if self.peek(TokenKind::ColonColon) || self.peek(TokenKind::LParen) {
                return Err(self
                    .coded_error(
                        token,
                        "K1001",
                        format!("match patterns do not nest; bind the `{variant_label}` payload to a name"),
                    )
                    .with_help("bind the payload, then match it in the arm body: `Option::some(inner) => match inner { ... }`"));
            }
            let binding = if name == "_" {
                PatternBinding::Wildcard
            } else {
                self.record_binding(
                    owner,
                    ordinal,
                    name.clone(),
                    token.range,
                    BindingFactKind::Pattern,
                );
                PatternBinding::Name(name)
            };
            self.expect(TokenKind::RParen)?;
            Some(binding)
        };
        Ok(SumPattern { variant, binding })
    }
    fn inc_statement(&mut self, name: String, range: TextRange) -> Statement {
        let left =
            self.source_expression(AstNodeKind::Expression, range, Expr::Ident(name.clone()));
        let right = self.source_expression(
            AstNodeKind::Expression,
            range,
            Expr::IntLiteral(BigInt::one()),
        );
        let value = self.source_expression(
            AstNodeKind::Expression,
            range,
            Expr::Binary {
                op: BinaryOp::Add,
                left: Box::new(left),
                right: Box::new(right),
            },
        );
        self.source_statement(range, Statement::Assign { name, value })
    }
    fn parse_for_range(&mut self) -> ParseResult<Option<(Statement, Expr, Statement)>> {
        let save = self.pos;
        let header_start = self.current_start();
        let syntax_checkpoint = self.syntax_checkpoint();
        if let Some(var_token) = self.tokens.get(self.pos).cloned()
            && matches!(&var_token.kind, TokenKind::Ident(_))
            && self.peek_n(1, TokenKind::In)
            && self.peek_ident_n(2, "range")
        {
            let Token {
                kind: TokenKind::Ident(var),
                range: var_range,
                ..
            } = var_token
            else {
                unreachable!("the let-chain established an identifier token")
            };
            let init_owner = self.begin_node(AstNodeKind::Statement, header_start);
            self.bump();
            // The range syntax lowers to a direct `let` binding in the AST, so
            // its parser fact must carry the same binding role consumed by HIR.
            self.record_binding(
                init_owner,
                0,
                var.clone(),
                var_range,
                BindingFactKind::Local,
            );
            self.bump(); // in
            self.bump(); // range
            self.expect(TokenKind::LParen)?;
            let mut end = PendingExpr::new(self.parse_expr()?);
            self.expect(TokenKind::RParen)?;
            let range = TextRange::new(header_start, self.previous_end(header_start));
            let zero = self.source_expression(
                AstNodeKind::Expression,
                range,
                Expr::IntLiteral(BigInt::zero()),
            );
            let init = self.finish_owned_statement(
                init_owner,
                range,
                Statement::Let {
                    mutable: true,
                    pat: Pattern::Name(var.clone()),
                    ty: None,
                    value: zero,
                },
            );
            let left =
                self.source_expression(AstNodeKind::Expression, range, Expr::Ident(var.clone()));
            let cond = self.source_expression(
                AstNodeKind::Expression,
                range,
                Expr::Binary {
                    op: BinaryOp::Lt,
                    left: Box::new(left),
                    right: Box::new(end.take()),
                },
            );
            let step = self.inc_statement(var.clone(), range);
            return Ok(Some((init, cond, step)));
        }
        self.pos = save;
        self.syntax_rollback(syntax_checkpoint);
        Ok(None)
    }
    fn expect_ident(&mut self) -> ParseResult<String> {
        self.expect_ident_token().map(|(name, _)| name)
    }
    fn expect_ident_token(&mut self) -> ParseResult<(String, Token)> {
        let tok = self.bump();
        match &tok.kind {
            TokenKind::Ident(name) => Ok((name.clone(), tok.clone())),
            TokenKind::Permission => Ok(("permission".to_owned(), tok.clone())),
            _ => {
                let is_keyword = crate::lexer::v1_keyword_spelling(&tok.kind).is_some();
                let mut error = self
                    .expected_error(tok, "identifier")
                    .with_help(if is_keyword {
                        "keywords cannot be used as names; choose a different identifier"
                    } else {
                        "a name goes here: ASCII letters, digits and `_`, not starting with a digit"
                    });
                error.expected = Some(SyntaxKind::Ident);
                Err(error)
            }
        }
    }
    /// Admit the reserved `trigger` spelling only where trigger-filter grammar
    /// defines it as a data-family or matcher keyword.
    fn expect_trigger_context_ident(&mut self) -> ParseResult<String> {
        let tok = self.bump();
        match &tok.kind {
            TokenKind::Ident(name) => Ok(name.clone()),
            TokenKind::Trigger => Ok("trigger".to_owned()),
            _ => Err(self.expected_error(tok, "a trigger-filter name")),
        }
    }
    fn expect_namespace_segment(&mut self) -> ParseResult<String> {
        let tok = self.bump();
        match &tok.kind {
            TokenKind::Ident(name) => Ok(name.clone()),
            TokenKind::Trigger if self.peek(TokenKind::ColonColon) => Ok("trigger".to_owned()),
            TokenKind::Seiyaku if self.peek(TokenKind::ColonColon) => Ok("seiyaku".to_owned()),
            TokenKind::Kotoage => Ok("kotoage".to_owned()),
            TokenKind::Permission => Ok("permission".to_owned()),
            _ => {
                let mut error = self.expected_error(tok, "a path segment after `::`");
                error.expected = Some(SyntaxKind::Ident);
                Err(error)
            }
        }
    }
    fn parse_type_expr(&mut self) -> ParseResult<TypeExpr> {
        let start = self.current_start();
        let ty = self.parse_type_expr_inner()?;
        let end = self.previous_end(start);
        let node = self.facts.source_map.allocate_owned(
            AstNodeKind::Type,
            TextRange::new(start, end),
            self.current_function,
        );
        Ok(TypeExpr::Source {
            node,
            source: SourceRange::new(self.facts.source_map.source(), TextRange::new(start, end)),
            ty: Box::new(ty),
        })
    }
    fn parse_type_expr_inner(&mut self) -> ParseResult<TypeExpr> {
        enum Frame {
            Generic {
                start: u32,
                base: String,
                args: PendingValues<TypeExpr>,
            },
            Tuple {
                opening: Token,
                args: PendingValues<TypeExpr>,
            },
        }
        let mut frames = Vec::new();
        'next_type: loop {
            let mut current = PendingType::new(loop {
                if frames.last().is_some_and(|frame| matches!(frame,
                    Frame::Generic { base, args, .. }
                        if (base == "List" && args.len() == 1) || (base == "StatePage" && args.len() == 2)
                )) {
                    let start = self.current_start();
                    let expression = self.parse_term()?;
                    let range = TextRange::new(start, self.previous_end(start));
                    break self.source_type(range, TypeExpr::ConstExpression(Box::new(expression)));
                }
                if self.peek(TokenKind::LParen) {
                    let opening = self.bump();
                    if self.peek(TokenKind::RParen) {
                        let closing = self.bump();
                        break self.source_type(
                            TextRange::new(opening.range.start, closing.range.end),
                            TypeExpr::Tuple(Vec::new()),
                        );
                    }
                    frames.push(Frame::Tuple {
                        opening,
                        args: PendingValues::new(crate::ast::drop_type_iterative),
                    });
                    continue;
                }
                if let Some(Token {
                    kind: TokenKind::Number(value),
                    ..
                }) = self.tokens.get(self.pos).cloned()
                {
                    let token = self.bump();
                    let value = parse_bounded_unsigned(&value, u64::MAX).map_err(|_| {
                        self.range_error(
                            &token,
                            "compile-time integer type argument is outside the u64 range"
                                .to_owned(),
                        )
                    })?;
                    break self.source_type(token.range, TypeExpr::Const(value));
                }
                let (base, base_token) = self.parse_type_path()?;
                if let Some(replacement) = retired_numeric_type_replacement(&base) {
                    let replacement_message = replacement.map_or_else(
                        || {
                            "use `int`, `decimal`, or `quantity` according to the value's domain"
                                .to_owned()
                        },
                        |replacement| format!("use `{replacement}`"),
                    );
                    let mut error = self
                        .coded_error(
                            base_token.clone(),
                            "E_RETIRED_NUMERIC_TYPE",
                            format!(
                                "numeric type `{base}` is not part of Kotodama V1; {replacement_message}"
                            ),
                        )
                        .with_help("Kotodama has three numeric types: `int` (signed integer), `decimal` (exact fixed-point) and `quantity` (non-negative asset amount)");
                    if let Some(replacement) = replacement {
                        error = error.with_fix(base_token.range, replacement);
                    }
                    if self.recover {
                        self.errors.push(*error);
                    } else {
                        return Err(error);
                    }
                }
                self.record_type_use(base.clone(), base_token.range);
                if self.peek(TokenKind::Less) {
                    let opening = self.bump();
                    let generic_depth = frames
                        .iter()
                        .filter(|frame| matches!(frame, Frame::Generic { .. }))
                        .count()
                        .saturating_add(1);
                    if self.current_delimiter_depth().saturating_add(generic_depth)
                        > self.max_nesting
                    {
                        return Err(self.nesting_error(opening.range));
                    }
                    if self.peek(TokenKind::Greater) {
                        self.bump();
                        let range = TextRange::new(
                            base_token.range.start,
                            self.previous_end(base_token.range.end),
                        );
                        break self.source_type(
                            range,
                            TypeExpr::Generic {
                                base,
                                args: Vec::new(),
                            },
                        );
                    }
                    frames.push(Frame::Generic {
                        start: base_token.range.start,
                        base,
                        args: PendingValues::new(crate::ast::drop_type_iterative),
                    });
                    continue;
                }
                break self.source_type(base_token.range, TypeExpr::Path(base));
            });
            loop {
                let Some(frame) = frames.pop() else {
                    return Ok(current.into_inner());
                };
                match frame {
                    Frame::Generic {
                        start,
                        base,
                        mut args,
                    } => {
                        args.push(current.take());
                        if self.peek(TokenKind::Comma) {
                            self.bump();
                            frames.push(Frame::Generic { start, base, args });
                            continue 'next_type;
                        }
                        self.expect(TokenKind::Greater)?;
                        current.replace(self.source_type(
                            TextRange::new(start, self.previous_end(start)),
                            TypeExpr::Generic {
                                base,
                                args: args.into_inner(),
                            },
                        ));
                    }
                    Frame::Tuple { opening, mut args } => {
                        args.push(current.take());
                        if self.peek(TokenKind::Comma) {
                            self.bump();
                            frames.push(Frame::Tuple { opening, args });
                            continue 'next_type;
                        }
                        self.expect(TokenKind::RParen)?;
                        let closing = &self.tokens[self.pos.saturating_sub(1)];
                        if args.len() < 2 {
                            return Err(self.tuple_type_arity_error(&opening, closing));
                        }
                        current.replace(self.source_type(
                            TextRange::new(opening.range.start, closing.range.end),
                            TypeExpr::Tuple(args.into_inner()),
                        ));
                    }
                }
            }
        }
    }
    fn tuple_type_arity_error(&self, opening: &Token, closing: &Token) -> Box<ParseError> {
        ParseError::at_range(
            TextRange::new(opening.range.start, closing.range.end),
            opening.line,
            opening.column,
            "K1001",
            "tuple types require at least two elements; use `()` for Unit",
        )
        .with_help("write the element type itself for one value, or `()` for the Unit type")
    }
    fn try_parse_lvalue_expr(&mut self) -> ParseResult<Expr> {
        // Parse an identifier then tail of member/index chains
        let expression_start = self.current_start();
        let (name, name_token) = self.expect_ident_token()?;
        let node = self.facts.source_map.allocate_owned(
            AstNodeKind::Expression,
            name_token.range,
            self.current_function,
        );
        let mut expr = PendingExpr::new(self.sourced_expression(
            node,
            SourceRange::new(self.facts.source_map.source(), name_token.range),
            Expr::Ident(name),
        ));
        loop {
            if self.peek(TokenKind::Dot) {
                self.bump();
                let field = if let Some(Token {
                    kind: TokenKind::Ident(s),
                    ..
                }) = self.tokens.get(self.pos)
                {
                    let s = s.clone();
                    self.bump();
                    s
                } else if let Some(token) = self.tokens.get(self.pos).cloned()
                    && let TokenKind::Number(n) = token.kind.clone()
                {
                    self.bump();
                    let index = self.number_to_usize(&token, &n, "tuple index")?;
                    index.to_string()
                } else {
                    let tok = self.bump();
                    return Err(self.expected_error(tok, "a field name or tuple index after `.`"));
                };
                let range = TextRange::new(expression_start, self.previous_end(expression_start));
                let node = self.facts.source_map.allocate_owned(
                    AstNodeKind::Expression,
                    range,
                    self.current_function,
                );
                let expression = self.sourced_expression(
                    node,
                    SourceRange::new(self.facts.source_map.source(), range),
                    Expr::Member {
                        object: Box::new(expr.take()),
                        field,
                    },
                );
                expr.replace(expression);
            } else if self.peek(TokenKind::LBracket) {
                self.bump();
                let mut idx = PendingExpr::new(self.parse_expr()?);
                self.expect(TokenKind::RBracket)?;
                let range = TextRange::new(expression_start, self.previous_end(expression_start));
                let node = self.facts.source_map.allocate_owned(
                    AstNodeKind::IndexExpression,
                    range,
                    self.current_function,
                );
                let expression = self.sourced_expression(
                    node,
                    SourceRange::new(self.facts.source_map.source(), range),
                    Expr::Index {
                        target: Box::new(expr.take()),
                        index: Box::new(idx.take()),
                    },
                );
                expr.replace(expression);
            } else {
                break;
            }
        }
        Ok(expr.into_inner())
    }
    fn parse_for_each_map(
        &mut self,
        statement_start: u32,
    ) -> ParseResult<Option<ForEachMapBinding>> {
        if !(self.struct_pattern_starts_here()
            || self.peek(TokenKind::LParen)
            || matches!(
                self.tokens.get(self.pos).map(|token| &token.kind),
                Some(TokenKind::Ident(_))
            ) && self.peek_n(1, TokenKind::In))
        {
            return Ok(None);
        }
        let owner = self.begin_node(AstNodeKind::Statement, statement_start);
        let pat = if self.struct_pattern_starts_here() {
            self.parse_struct_pattern(owner, BindingFactKind::Iterator)?
        } else if self.peek(TokenKind::LParen) {
            self.bump();
            let mut names = Vec::new();
            loop {
                let (name, token) = self.expect_ident_token()?;
                self.record_binding(
                    owner,
                    names.len(),
                    name.clone(),
                    token.range,
                    BindingFactKind::Iterator,
                );
                names.push(name);
                if !self.peek(TokenKind::Comma) {
                    break;
                }
                self.bump();
            }
            self.expect(TokenKind::RParen)?;
            Pattern::Tuple(names)
        } else {
            let (name, token) = self.expect_ident_token()?;
            self.record_binding(
                owner,
                0,
                name.clone(),
                token.range,
                BindingFactKind::Iterator,
            );
            Pattern::Name(name)
        };
        self.expect(TokenKind::In)?;
        let iterable = self.parse_expr_before_block()?;
        Ok(Some((owner, pat, iterable)))
    }
    fn parse_param_type_annotation(&mut self) -> ParseResult<(bool, TypeExpr)> {
        if self.peek(TokenKind::State) {
            let token = self.bump();
            return Err(self
                .coded_error(token, "K1001", "state cannot be passed as a parameter")
                .with_help("functions read and write declared `state` directly by name; remove the parameter"));
        }
        let ty = self.parse_type_expr()?;
        Ok((false, ty))
    }
    fn parse_param(&mut self) -> ParseResult<Param> {
        // Canonical V1 form: `Type name`. `name: Type` is reported once and
        // continues as `Type name`, so later parameters are still checked.
        let (is_state, mut ty, call_mode, name, name_token) =
            if self.peek_n_ident(0) && self.peek_n(1, TokenKind::Colon) {
                let (ty, name_token) = self.colon_declaration(DeclarationSite::Parameter)?;
                let name = self.spelling(&name_token).to_owned();
                (
                    false,
                    PendingType::new(ty),
                    ParameterCallMode::Named,
                    name,
                    name_token,
                )
            } else {
                if self.peek_n_ident(0)
                    && (self.peek_n(1, TokenKind::Comma) || self.peek_n(1, TokenKind::RParen))
                    && !self.current_names_a_type()
                {
                    return Err(self.missing_type_error(DeclarationSite::Parameter));
                }
                let (is_state, ty) = self.parse_param_type_annotation()?;
                let ty = PendingType::new(ty);
                if self.peek(TokenKind::Colon) {
                    return Err(
                        self.type_then_colon_error("parameters are type-first: write `Type name`")
                    );
                }
                let call_mode = if self.peek_ident_n(0, "_") {
                    self.bump();
                    ParameterCallMode::Positional
                } else {
                    ParameterCallMode::Named
                };
                let (name, name_token) = self.expect_ident_token()?;
                (is_state, ty, call_mode, name, name_token)
            };
        let node = self.begin_node(AstNodeKind::Parameter, name_token.range.start);
        self.record_declaration(
            node,
            name.clone(),
            name_token.range,
            DeclarationKind::Parameter,
            self.current_function,
        );
        self.finish_node(node);
        Ok(Param {
            ty: Some(ty.take()),
            name,
            call_mode,
            is_state,
        })
    }
    /// The current token, or a zero-width end-of-file token after the input.
    fn current_token(&self) -> Token {
        self.tokens.get(self.pos).cloned().unwrap_or_else(|| Token {
            kind: TokenKind::EOF,
            line: self.tokens.last().map_or(1, |token| token.line),
            column: self.tokens.last().map_or(1, |token| token.column),
            range: self.tokens.last().map_or(TextRange::empty(0), |token| {
                TextRange::empty(token.range.end)
            }),
        })
    }
    fn expect(&mut self, kind: TokenKind) -> ParseResult<()> {
        let tok = self.current_token();
        if tok.kind == kind {
            self.bump();
            Ok(())
        } else {
            let mut error = self.expected_token_error(tok, &kind);
            error.expected = expected_syntax_kind(&kind);
            error.expected_owner = self.syntax.current();
            Err(error)
        }
    }
    fn expect_or_insert(
        &mut self,
        kind: TokenKind,
        insertion_is_unambiguous: bool,
    ) -> ParseResult<()> {
        if self.peek(kind.clone()) {
            self.bump();
            return Ok(());
        }
        if self.recover && insertion_is_unambiguous {
            let token = self.current_token();
            let mut error = self.expected_token_error(token, &kind);
            error.expected = expected_syntax_kind(&kind);
            error.expected_owner = self.syntax.current();
            self.errors.push(*error);
            return Ok(());
        }
        self.expect(kind)
    }
    /// "expected `X`, found Y" for one missing token.
    ///
    /// A missing terminator (`;`, `)`, `]`, `}`) is reported at the insertion
    /// point right after the previous token, with a fix that inserts it, so
    /// the caret does not land on the next line. A missing closing delimiter
    /// also labels the unclosed opener.
    fn expected_token_error(&self, tok: Token, kind: &TokenKind) -> Box<ParseError> {
        let spelling = expected_token_spelling(kind);
        let mut error = self.expected_error(tok.clone(), &spelling);
        if let Some(help) = expected_token_help(kind) {
            error = error.with_help(help);
        }
        if tok.kind == TokenKind::As {
            // `value as T`: `as` only names import aliases.
            return error.with_help(
                "Kotodama has no `as` casts; convert with the named conversion for the target type, for example `decimal::from_int(value)`",
            );
        }
        if tok.kind == TokenKind::DotDot {
            // `let r = 0..10;` or `xs[1..3]`: ranges exist only as the
            // `range(N)` bound of a counted loop.
            let inclusive = self
                .source
                .get(tok.range.end as usize..)
                .is_some_and(|rest| rest.starts_with('='));
            return self
                .coded_error(
                    tok,
                    "E_RANGE_SYNTAX",
                    format!(
                        "Kotodama has no `{}` range operator",
                        if inclusive { "..=" } else { ".." }
                    ),
                )
                .with_help("counted loops iterate `for i in range(N)`, which counts from 0 up to N - 1 with a compile-time `N`; there are no range values or list slices");
        }
        let previous = self
            .pos
            .checked_sub(1)
            .and_then(|index| self.tokens.get(index));
        let (opener, closing) = match kind {
            TokenKind::RParen => (Some(TokenKind::LParen), ")"),
            TokenKind::RBracket => (Some(TokenKind::LBracket), "]"),
            TokenKind::RBrace => (Some(TokenKind::LBrace), "}"),
            TokenKind::Semicolon => (None, ";"),
            _ => return error,
        };
        let Some(previous) = previous else {
            return error;
        };
        // The terminator was omitted (rather than something else written in
        // its place) when the next token starts a later line, closes the
        // enclosing block, is the end of the file, or, for `;`, is a keyword
        // that can only start the next statement.
        let omitted = tok.line > previous.line
            || matches!(tok.kind, TokenKind::EOF)
            // `;` cannot appear inside parentheses or brackets.
            || (matches!(kind, TokenKind::RParen | TokenKind::RBracket)
                && matches!(tok.kind, TokenKind::Semicolon))
            || (matches!(kind, TokenKind::Semicolon)
                && matches!(
                    tok.kind,
                    TokenKind::RBrace
                        | TokenKind::Let
                        | TokenKind::Var
                        | TokenKind::Return
                        | TokenKind::Break
                        | TokenKind::Continue
                        | TokenKind::For
                ));
        if omitted {
            let insertion = TextRange::empty(previous.range.end);
            error = error.reported_at(insertion).with_fix(insertion, closing);
        }
        if let Some(opener) = opener
            && let Some(open) = self.unclosed_opener(&opener, kind)
            && self.never_closed(&open, kind)
        {
            let text = token_text(self.source, &open).to_owned();
            error = error.with_label(open.range, format!("this `{text}` is not closed"));
        }
        if matches!(kind, TokenKind::Semicolon) {
            error = error.with_help(
                "every statement and `state`/`const` declaration ends with `;`; block-valued `if`, `match` and `for` statements do not",
            );
        }
        error
    }
    /// Whether `open` has no matching `closing` anywhere in the file.
    fn never_closed(&self, open: &Token, closing: &TokenKind) -> bool {
        let Some(start) = self
            .tokens
            .iter()
            .position(|token| token.range == open.range)
        else {
            return false;
        };
        let mut depth = 0_usize;
        for token in &self.tokens[start..] {
            if token.kind == open.kind {
                depth += 1;
            } else if &token.kind == closing {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return false;
                }
            }
        }
        true
    }
    /// The innermost opening delimiter before the cursor without a matching
    /// closer, scanning backwards over balanced pairs.
    fn unclosed_opener(&self, opening: &TokenKind, closing: &TokenKind) -> Option<Token> {
        let mut depth = 0_usize;
        for token in self.tokens[..self.pos.min(self.tokens.len())].iter().rev() {
            if &token.kind == closing {
                depth = depth.saturating_add(1);
            } else if &token.kind == opening {
                if depth == 0 {
                    return Some(token.clone());
                }
                depth -= 1;
            }
        }
        None
    }
    fn number_to_usize(&self, token: &Token, value: &str, context: &str) -> ParseResult<usize> {
        parse_bounded_unsigned(value, usize::MAX as u64)
            .and_then(|value| usize::try_from(value).map_err(|_| ()))
            .map_err(|()| {
                self.range_error(token, format!("{context} integer literal out of range"))
            })
    }
    fn range_error(&self, token: &Token, message: String) -> Box<ParseError> {
        ParseError::at(token, "K1001", message)
            .with_help("use a smaller non-negative integer literal")
    }
    fn peek(&self, kind: TokenKind) -> bool {
        self.tokens.get(self.pos).map(|t| t.kind.clone()) == Some(kind)
    }
    fn peek_n(&self, offset: usize, kind: TokenKind) -> bool {
        self.tokens.get(self.pos + offset).map(|t| t.kind.clone()) == Some(kind)
    }
    fn peek_ident_n(&self, offset: usize, name: &str) -> bool {
        matches!(
            self.tokens.get(self.pos + offset),
            Some(Token { kind: TokenKind::Ident(s), .. }) if s == name
        )
    }
    fn parse_type_path(&mut self) -> ParseResult<(String, Token)> {
        let (mut name, mut token) = self.expect_ident_token()?;
        while self.peek(TokenKind::ColonColon) {
            self.bump();
            let (member, member_token) = self.expect_ident_token()?;
            name.push_str("::");
            name.push_str(&member);
            token.range.end = member_token.range.end;
        }
        Ok((name, token))
    }
    fn struct_pattern_starts_here(&self) -> bool {
        if !self.peek_n_ident(0) {
            return false;
        }
        let mut offset = 1;
        while self.peek_n(offset, TokenKind::ColonColon) && self.peek_n_ident(offset + 1) {
            offset += 2;
        }
        self.peek_n(offset, TokenKind::LBrace)
    }
    fn typed_local_starts_here(&self) -> bool {
        if self.struct_pattern_starts_here() {
            return false;
        }
        if matches!(
            self.tokens.get(self.pos).map(|token| &token.kind),
            Some(TokenKind::Ident(_) | TokenKind::Permission)
        ) && self.peek_n(1, TokenKind::ColonColon)
        {
            return true;
        }
        if matches!(
            (self.tokens.get(self.pos), self.tokens.get(self.pos + 1)),
            (
                Some(Token {
                    kind: TokenKind::Ident(_),
                    ..
                }),
                Some(
                    Token {
                        kind: TokenKind::Ident(_),
                        ..
                    } | Token {
                        kind: TokenKind::Less,
                        ..
                    }
                )
            )
        ) {
            return true;
        }
        if !self.peek(TokenKind::LParen) {
            return false;
        }
        let mut depth = 0_usize;
        for (offset, token) in self.tokens[self.pos..].iter().enumerate() {
            match &token.kind {
                TokenKind::LParen => depth += 1,
                TokenKind::RParen => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return matches!(
                            self.tokens.get(self.pos + offset + 1),
                            Some(Token {
                                kind: TokenKind::Ident(_),
                                ..
                            })
                        );
                    }
                }
                TokenKind::EOF | TokenKind::Equal if depth == 1 => return false,
                _ => {}
            }
        }
        false
    }
    fn question_starts_ternary(&self) -> bool {
        if !self.peek(TokenKind::Question)
            || !self
                .tokens
                .get(self.pos.saturating_add(1))
                .is_some_and(|token| Self::token_starts_expression(&token.kind))
        {
            return false;
        }
        // `value?[index]` is postfix propagation followed by indexing, while
        // `flag ? [value] : [fallback]` is a conditional whose first branch is
        // a list literal. Look for the conditional's top-level `:` instead of
        // deciding from `[` alone. Colons inside calls, structs, JSON, lists,
        // or parenthesized expressions cannot terminate the true branch.
        let mut paren_depth = 0_usize;
        let mut bracket_depth = 0_usize;
        let mut brace_depth = 0_usize;
        for token in self.tokens.iter().skip(self.pos.saturating_add(1)) {
            let at_top_level = paren_depth == 0 && bracket_depth == 0 && brace_depth == 0;
            match token.kind {
                TokenKind::Colon if at_top_level => return true,
                TokenKind::LParen => paren_depth = paren_depth.saturating_add(1),
                TokenKind::LBracket => bracket_depth = bracket_depth.saturating_add(1),
                TokenKind::LBrace => brace_depth = brace_depth.saturating_add(1),
                TokenKind::RParen => {
                    if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 {
                        return false;
                    }
                    paren_depth = paren_depth.saturating_sub(1);
                }
                TokenKind::RBracket => {
                    if bracket_depth == 0 && paren_depth == 0 && brace_depth == 0 {
                        return false;
                    }
                    bracket_depth = bracket_depth.saturating_sub(1);
                }
                TokenKind::RBrace => {
                    if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 {
                        return false;
                    }
                    brace_depth = brace_depth.saturating_sub(1);
                }
                TokenKind::Semicolon | TokenKind::Comma | TokenKind::EOF if at_top_level => {
                    return false;
                }
                _ => {}
            }
        }
        false
    }
    fn token_starts_expression(kind: &TokenKind) -> bool {
        matches!(
            kind,
            TokenKind::True
                | TokenKind::False
                | TokenKind::Number(_)
                | TokenKind::DecimalLiteral(_)
                | TokenKind::String(_)
                | TokenKind::Bytes(_)
                | TokenKind::Ident(_)
                | TokenKind::State
                | TokenKind::LParen
                | TokenKind::LBracket
                | TokenKind::If
                | TokenKind::Match
                | TokenKind::Minus
                | TokenKind::Bang
        )
    }
    fn synchronize_source_item(&mut self, item_start: usize) {
        let start_column = self
            .tokens
            .get(item_start)
            .map_or(usize::MAX, |token| token.column);
        self.pos = item_start.saturating_add(1).min(self.tokens.len());
        let mut brace_depth = 0_usize;
        // Minified source has no indentation cue, so a completed top-level
        // item delimiter must also make the next declaration recoverable.
        let mut reached_item_boundary = false;
        while let Some(token) = self.tokens.get(self.pos) {
            match &token.kind {
                TokenKind::LBrace => {
                    brace_depth = brace_depth.saturating_add(1);
                    reached_item_boundary = false;
                }
                TokenKind::RBrace if brace_depth == 0 => return,
                TokenKind::RBrace => {
                    brace_depth = brace_depth.saturating_sub(1);
                    reached_item_boundary = brace_depth == 0;
                }
                TokenKind::Semicolon if brace_depth == 0 => reached_item_boundary = true,
                _ if brace_depth == 0
                    && Self::token_starts_source_item(token)
                    && (reached_item_boundary || token.column <= start_column) =>
                {
                    return;
                }
                // After a completed item, a line that starts at the item
                // column with `name(`, `name name` or `name {` is the next
                // declaration head, even when its keyword is misspelled
                // (`kaizan() { }`), so it is diagnosed instead of skipped.
                TokenKind::Ident(_)
                    if brace_depth == 0
                        && reached_item_boundary
                        && token.column <= start_column
                        && self
                            .tokens
                            .get(self.pos.saturating_sub(1))
                            .is_some_and(|previous| previous.line < token.line)
                        && matches!(
                            self.tokens.get(self.pos + 1).map(|next| &next.kind),
                            Some(TokenKind::LParen | TokenKind::Ident(_) | TokenKind::LBrace)
                        ) =>
                {
                    return;
                }
                _ => {}
            }
            self.pos = self.pos.saturating_add(1);
        }
    }
    /// Skip the rest of a failed statement.
    ///
    /// Nesting opened between the statement start and the failure point is
    /// replayed first, so a failure inside a nested `{ ... }` (a match arm or
    /// an `if` body) skips to the end of that construct instead of mistaking
    /// its closing brace for the end of the enclosing block. Parentheses and
    /// brackets are weak: a line that starts a new statement or a `}` ends the
    /// skip even while they are unbalanced.
    fn synchronize_statement(&mut self, statement_start: usize) {
        if self.pos > statement_start
            && self
                .tokens
                .get(self.pos.saturating_sub(1))
                .is_some_and(|token| matches!(&token.kind, TokenKind::Semicolon))
        {
            return;
        }
        let start_column = self
            .tokens
            .get(statement_start)
            .map_or(usize::MAX, |token| token.column);
        let mut open_braces = 0_usize;
        let mut weak_stack = Vec::new();
        let replay =
            |kind: &TokenKind, open_braces: &mut usize, weak_stack: &mut Vec<DelimiterKind>| {
                match kind {
                    TokenKind::LBrace => *open_braces += 1,
                    TokenKind::RBrace => {
                        *open_braces = open_braces.saturating_sub(1);
                        weak_stack.clear();
                    }
                    _ => update_delimiter_stack(weak_stack, kind),
                }
            };
        for token in &self.tokens[statement_start..self.pos.min(self.tokens.len())] {
            replay(&token.kind, &mut open_braces, &mut weak_stack);
        }
        while let Some(token) = self.tokens.get(self.pos) {
            if matches!(token.kind, TokenKind::EOF) {
                return;
            }
            if open_braces == 0 {
                if matches!(token.kind, TokenKind::RBrace) {
                    return;
                }
                if self.pos != statement_start
                    && token.column <= start_column
                    && Self::token_starts_statement(token)
                    && self
                        .tokens
                        .get(self.pos.saturating_sub(1))
                        .is_some_and(|previous| previous.line < token.line)
                {
                    return;
                }
                if matches!(token.kind, TokenKind::Semicolon) && weak_stack.is_empty() {
                    self.pos = self.pos.saturating_add(1);
                    return;
                }
            }
            replay(&token.kind, &mut open_braces, &mut weak_stack);
            self.pos = self.pos.saturating_add(1);
            // A completed nested block followed by the end of the line ends
            // block-valued statements such as `if` and `match`.
            if open_braces == 0
                && matches!(token.kind, TokenKind::RBrace)
                && self
                    .tokens
                    .get(self.pos)
                    .is_some_and(|next| next.line > token.line && next.column <= start_column)
            {
                return;
            }
        }
    }
    fn token_starts_statement(token: &Token) -> bool {
        matches!(
            &token.kind,
            TokenKind::Let
                | TokenKind::Var
                | TokenKind::Return
                | TokenKind::Break
                | TokenKind::Continue
                | TokenKind::If
                | TokenKind::For
                | TokenKind::LBrace
                | TokenKind::State
                | TokenKind::Ident(_)
        )
    }
    fn token_starts_source_item(token: &Token) -> bool {
        matches!(
            &token.kind,
            TokenKind::Hash
                | TokenKind::Struct
                | TokenKind::Event
                | TokenKind::Error
                | TokenKind::Enum
                | TokenKind::Const
                | TokenKind::State
                | TokenKind::Trigger
                | TokenKind::Fn
                | TokenKind::Kotoage
                | TokenKind::View
                | TokenKind::Hajimari
                | TokenKind::Kaizen
                | TokenKind::Seiyaku
                | TokenKind::Module
                | TokenKind::Include
                | TokenKind::Import
                | TokenKind::Permission
                | TokenKind::Export
        ) || matches!(
            &token.kind,
            TokenKind::Ident(name) if matches!(name.as_str(), "fixture" | "koto_test")
        )
    }
    fn bump(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token {
            kind: TokenKind::EOF,
            line: self.tokens.last().map_or(0, |t| t.line),
            column: self.tokens.last().map_or(0, |t| t.column),
            range: self.tokens.last().map_or(TextRange::empty(0), |token| {
                TextRange::empty(token.range.end)
            }),
        });
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }
    /// `expected {expected}, found {token}` under the generic grammar code.
    ///
    /// `expected` is a noun phrase naming what the grammar allows here, with
    /// source spellings in backticks; never pass a sentence.
    fn expected_error(&self, token: Token, expected: &str) -> Box<ParseError> {
        let found = describe_found(self.source, &token);
        ParseError::at(
            &token,
            "K1001",
            format!("expected {expected}, found {found}"),
        )
    }
    /// A rule violation stated as a complete sentence under its own code.
    fn coded_error(
        &self,
        token: Token,
        code: &'static str,
        message: impl Into<String>,
    ) -> Box<ParseError> {
        ParseError::at(&token, code, message)
    }
    /// Exact source spelling of `token`.
    fn spelling(&self, token: &Token) -> &'a str {
        token_text(self.source, token)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockExpressionFlow {
    Unit,
    Value,
    Diverges,
}
fn combine_expression_branch_flows(
    branches: impl IntoIterator<Item = BlockExpressionFlow>,
) -> BlockExpressionFlow {
    let mut saw_branch = false;
    let mut saw_value = false;
    for branch in branches {
        saw_branch = true;
        match branch {
            BlockExpressionFlow::Unit => return BlockExpressionFlow::Unit,
            BlockExpressionFlow::Value => saw_value = true,
            BlockExpressionFlow::Diverges => {}
        }
    }
    if !saw_branch {
        BlockExpressionFlow::Unit
    } else if saw_value {
        BlockExpressionFlow::Value
    } else {
        BlockExpressionFlow::Diverges
    }
}
fn block_expression_flow(expression: &Expr) -> BlockExpressionFlow {
    enum Pending<'a> {
        Expr(&'a Expr),
        Block(&'a Block),
        Statement(&'a Statement),
        FinishBranches(usize),
        FinishBlock { statements: usize, has_tail: bool },
        FinishIfStatement,
        FinishExpressionStatement,
        FinishAssignExpression,
    }

    let mut pending = vec![Pending::Expr(expression)];
    let mut results = Vec::new();
    while let Some(task) = pending.pop() {
        match task {
            Pending::Expr(expression) => match expression {
                Expr::Source { expression, .. } | Expr::Resolved { expression, .. } => {
                    pending.push(Pending::Expr(expression));
                }
                Expr::If {
                    then_branch,
                    else_branch: Some(else_branch),
                    ..
                }
                | Expr::IfLet {
                    then_branch,
                    else_branch: Some(else_branch),
                    ..
                } => {
                    pending.push(Pending::FinishBranches(2));
                    pending.push(Pending::Block(else_branch));
                    pending.push(Pending::Block(then_branch));
                }
                Expr::Match { arms, .. } => {
                    pending.push(Pending::FinishBranches(arms.len()));
                    pending.extend(arms.iter().rev().map(|arm| Pending::Block(&arm.body)));
                }
                Expr::If {
                    else_branch: None, ..
                }
                | Expr::IfLet {
                    else_branch: None, ..
                } => results.push(BlockExpressionFlow::Unit),
                _ => results.push(BlockExpressionFlow::Value),
            },
            Pending::Block(block) => {
                pending.push(Pending::FinishBlock {
                    statements: block.statements.len(),
                    has_tail: block.tail.is_some(),
                });
                if let Some(tail) = block.tail.as_deref() {
                    pending.push(Pending::Expr(tail));
                }
                pending.extend(block.statements.iter().rev().map(Pending::Statement));
            }
            Pending::Statement(statement) => match statement {
                Statement::Source { statement, .. } | Statement::Resolved { statement, .. } => {
                    pending.push(Pending::Statement(statement));
                }
                Statement::Return(_) | Statement::Break | Statement::Continue => {
                    results.push(BlockExpressionFlow::Diverges);
                }
                Statement::If {
                    then_branch,
                    else_branch: Some(else_branch),
                    ..
                }
                | Statement::IfLet {
                    then_branch,
                    else_branch: Some(else_branch),
                    ..
                } => {
                    pending.push(Pending::FinishIfStatement);
                    pending.push(Pending::Block(else_branch));
                    pending.push(Pending::Block(then_branch));
                }
                Statement::Expr(expression)
                | Statement::Emit(expression)
                | Statement::Let {
                    value: expression, ..
                }
                | Statement::Assign {
                    value: expression, ..
                } => {
                    pending.push(Pending::FinishExpressionStatement);
                    pending.push(Pending::Expr(expression));
                }
                Statement::AssignExpr { target, value, .. } => {
                    pending.push(Pending::FinishAssignExpression);
                    pending.push(Pending::Expr(value));
                    pending.push(Pending::Expr(target));
                }
                Statement::If {
                    else_branch: None, ..
                }
                | Statement::IfLet {
                    else_branch: None, ..
                }
                | Statement::While { .. }
                | Statement::For { .. }
                | Statement::ForEachMap { .. } => results.push(BlockExpressionFlow::Unit),
            },
            Pending::FinishBranches(branches) => {
                let start = results.len().saturating_sub(branches);
                let branch_results = results.split_off(start);
                results.push(combine_expression_branch_flows(branch_results));
            }
            Pending::FinishBlock {
                statements,
                has_tail,
            } => {
                let tail = has_tail.then(|| {
                    results
                        .pop()
                        .expect("a scheduled block tail must produce one flow result")
                });
                let start = results.len().saturating_sub(statements);
                let diverges = results[start..].contains(&BlockExpressionFlow::Diverges);
                results.truncate(start);
                results.push(if diverges {
                    BlockExpressionFlow::Diverges
                } else {
                    tail.unwrap_or(BlockExpressionFlow::Unit)
                });
            }
            Pending::FinishIfStatement => {
                let else_flow = results
                    .pop()
                    .expect("an if else branch must produce one flow result");
                let then_flow = results
                    .pop()
                    .expect("an if then branch must produce one flow result");
                results.push(
                    if then_flow == BlockExpressionFlow::Diverges
                        && else_flow == BlockExpressionFlow::Diverges
                    {
                        BlockExpressionFlow::Diverges
                    } else {
                        BlockExpressionFlow::Unit
                    },
                );
            }
            Pending::FinishExpressionStatement => {
                let expression_flow = results
                    .pop()
                    .expect("an expression statement must produce one flow result");
                results.push(if expression_flow == BlockExpressionFlow::Diverges {
                    BlockExpressionFlow::Diverges
                } else {
                    BlockExpressionFlow::Unit
                });
            }
            Pending::FinishAssignExpression => {
                let value_flow = results
                    .pop()
                    .expect("an assignment value must produce one flow result");
                let target_flow = results
                    .pop()
                    .expect("an assignment target must produce one flow result");
                results.push(
                    if target_flow == BlockExpressionFlow::Diverges
                        || value_flow == BlockExpressionFlow::Diverges
                    {
                        BlockExpressionFlow::Diverges
                    } else {
                        BlockExpressionFlow::Unit
                    },
                );
            }
        }
    }
    results
        .pop()
        .expect("one expression flow evaluation must produce one result")
}
fn if_expression_statement_inner(expression: Expr) -> Statement {
    match expression.into_kind() {
        Expr::If {
            condition,
            then_branch,
            else_branch,
        } => Statement::If {
            cond: *condition,
            then_branch,
            else_branch,
        },
        Expr::IfLet {
            pattern,
            value,
            then_branch,
            else_branch,
        } => Statement::IfLet {
            pattern,
            value: *value,
            then_branch,
            else_branch,
        },
        _ => unreachable!("else-if parsing produces an if expression"),
    }
}
fn removed_method_helper_message(name: &str) -> Option<&'static str> {
    match name {
        "account_id" | "asset_definition" | "asset_id" | "nft_id" | "name" | "json" | "domain"
        | "domain_id" | "blob" | "norito_bytes" | "dataspace_id" | "axt_descriptor"
        | "asset_handle" | "proof_blob" | "soracloud_request" | "soracloud_response" => Some(
            "constructor method aliases were removed; call the canonical constructor explicitly",
        ),
        "has" => Some("`map.has(key)` was removed; use `map.contains(key)`"),
        "get_or_insert_default" => Some(
            "`map.get_or_insert_default(key, default)` was removed; use `map.get_or_insert(key, default)`",
        ),
        "path_map_key" | "path_map_key_norito" => {
            Some("`base.path_map_key(segment)` was removed; use `base.path(segment)`")
        }
        "json_get_int" => Some("`json.json_get_int(key)` was removed; use `json.get_int(key)`"),
        "get_amount" | "json_get_amount" | "get_numeric" | "json_get_numeric" => {
            Some("legacy numeric JSON getters were retired; use `.get_quantity(key)`")
        }
        "json_get_json" => Some("`json.json_get_json(key)` was removed; use `json.get_json(key)`"),
        "json_get_name" => Some("`json.json_get_name(key)` was removed; use `json.get_name(key)`"),
        "json_get_account_id" => {
            Some("`json.json_get_account_id(key)` was removed; use `json.get_account_id(key)`")
        }
        "json_get_asset_definition_id" => Some(
            "`json.json_get_asset_definition_id(key)` was removed; use `json.get_asset_definition_id(key)`",
        ),
        "json_get_nft_id" => {
            Some("`json.json_get_nft_id(key)` was removed; use `json.get_nft_id(key)`")
        }
        "json_get_blob_hex" | "get_blob_hex" => {
            Some("`json.get_blob_hex(key)` is not a Json method; use `json.get_bytes_hex(key)`")
        }
        _ => None,
    }
}
fn removed_method_helper_code(name: &str) -> &'static str {
    if matches!(
        name,
        "get_amount" | "json_get_amount" | "get_numeric" | "json_get_numeric"
    ) {
        "E_LEGACY_JSON_GETTER"
    } else {
        "K1001"
    }
}
pub(crate) fn removed_free_helper_message(name: &str) -> Option<&'static str> {
    match name {
        "ledger::trigger::create" => Some(
            "`ledger::trigger::create` is not part of Kotodama V1; use `ledger::trigger::register`",
        ),
        "ledger::trigger::remove" => Some(
            "`ledger::trigger::remove` is not part of Kotodama V1; use `ledger::trigger::unregister`",
        ),
        "json::set_i64" | "json::set_int" => Some(
            "scalar JSON setters are not part of Kotodama V1; use native `json { key: value }` construction so adaptive-width int values remain exact",
        ),
        "numeric::to_i64" | "numeric::neg" | "numeric::add" | "numeric::sub" | "numeric::mul"
        | "numeric::div" | "numeric::rem" | "numeric::eq" | "numeric::ne" | "numeric::lt"
        | "numeric::le" | "numeric::gt" | "numeric::ge" => Some(
            "generic numeric helpers are not part of Kotodama V1; use operators and the named int, decimal, or quantity conversions",
        ),
        "contains" | "std::map::contains" | "has" | "std::map::has" => {
            Some("`contains(...)` was removed; use `map.contains(key)`")
        }
        "get_or" | "std::map::get_or" | "get_or_default" | "std::map::get_or_default" => Some(
            "`get_or(...)` is not a StateMap helper; read with `map.get(key)` and handle absence with `.unwrap_or(default)`, `.expect(Error)`, or `match`",
        ),
        "get_or_insert_default"
        | "std::map::get_or_insert_default"
        | "get_or_insert"
        | "std::map::get_or_insert"
        | "ensure"
        | "std::map::ensure" => Some(
            "`get_or_insert(...)` is not a free helper; use `map.get_or_insert(key, default)`, which writes the default when the key is absent",
        ),
        "remove" | "std::map::remove" => {
            Some("`remove(...)` is not a free helper; use `map.remove(key)`")
        }
        "path"
        | "path_map_key"
        | "path_map_key_norito"
        | "host::path"
        | "host::path_map_key"
        | "host::path_map_key_norito" => {
            Some("`path(...)` was removed as a free helper; use `base.path(segment)`")
        }
        "get_int" | "json_get_int" | "json::get_int" => {
            Some("`get_int(...)` was removed as a free helper; use `json.get_int(key)`")
        }
        "get_amount" | "json_get_amount" | "json::get_amount" | "get_numeric"
        | "json_get_numeric" | "json::get_numeric" => {
            Some("legacy numeric JSON getters were retired; use `value.get_quantity(key)`")
        }
        "get_json" | "json_get_json" | "json::get_json" => {
            Some("`get_json(...)` was removed as a free helper; use `json.get_json(key)`")
        }
        "get_name" | "json_get_name" | "json::get_name" => {
            Some("`get_name(...)` was removed as a free helper; use `json.get_name(key)`")
        }
        "get_account_id" | "json_get_account_id" | "json::get_account_id" => Some(
            "`get_account_id(...)` was removed as a free helper; use `json.get_account_id(key)`",
        ),
        "get_asset_definition_id"
        | "json_get_asset_definition_id"
        | "json::get_asset_definition_id" => Some(
            "`get_asset_definition_id(...)` was removed as a free helper; use `json.get_asset_definition_id(key)`",
        ),
        "get_nft_id" | "json_get_nft_id" | "json::get_nft_id" => {
            Some("`get_nft_id(...)` was removed as a free helper; use `json.get_nft_id(key)`")
        }
        "get_blob_hex"
        | "json_get_blob_hex"
        | "json::get_blob_hex"
        | "get_bytes_hex"
        | "json::get_bytes_hex" => {
            Some("`get_bytes_hex(...)` is not a free helper; use `json.get_bytes_hex(key)`")
        }
        "state_map_get" => Some("`state_map_get(...)` is compiler-internal; use `map.get(key)`"),
        "is_some" | "is_none" | "is_ok" | "is_err" | "unwrap_or" | "unwrap_err_or" | "expect" => {
            Some("Option/Result inspection is method-only; call the method on the value")
        }
        "option_some" | "option_none" | "result_ok" | "result_err" => Some(
            "flat Option/Result constructors are not part of Kotodama V1; obtain typed values from parameters or APIs",
        ),
        _ => None,
    }
}
pub(crate) fn removed_free_helper_code(name: &str) -> &'static str {
    if retired_trigger_alias_replacement(name).is_some() {
        "E_RETIRED_TRIGGER_ALIAS"
    } else if matches!(
        name,
        "json::set_i64"
            | "json::set_int"
            | "numeric::to_i64"
            | "numeric::neg"
            | "numeric::add"
            | "numeric::sub"
            | "numeric::mul"
            | "numeric::div"
            | "numeric::rem"
            | "numeric::eq"
            | "numeric::ne"
            | "numeric::lt"
            | "numeric::le"
            | "numeric::gt"
            | "numeric::ge"
    ) {
        "E_RETIRED_NUMERIC_HELPER"
    } else if matches!(
        name,
        "get_amount"
            | "json_get_amount"
            | "json::get_amount"
            | "get_numeric"
            | "json_get_numeric"
            | "json::get_numeric"
    ) {
        "E_LEGACY_JSON_GETTER"
    } else {
        "K1001"
    }
}
fn retired_trigger_alias_replacement(name: &str) -> Option<&'static str> {
    match name {
        "ledger::trigger::create" => Some("ledger::trigger::register"),
        "ledger::trigger::remove" => Some("ledger::trigger::unregister"),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_model_base::domain::DomainId;
    #[test]
    fn mismatched_closers_preserve_all_parser_depth_views() {
        let depth = crate::source::MAX_NESTING_DEPTH - 1;
        let mut text = String::from("seiyaku Demo { fn f() {");
        text.push_str(&"for item in range(1) { );".repeat(depth));
        text.push_str(&"}".repeat(depth));
        text.push_str("} }");
        let source = SourceFile::new(SourceId(0), "mismatched-depth.ko", text);
        let lexed = crate::syntax::lexer::lex(&source, FrontendBudget::v1());
        let (tokens, _, _) = crate::lexer::lower_lexed_recovering_with_omissions(
            &source,
            FrontendBudget::v1(),
            lexed,
        );
        let diagnostics = validate_nesting(&source, FrontendBudget::v1(), &tokens)
            .expect_err("mismatched closers must not hide excessive block depth");
        assert!(
            diagnostics
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "K0003")
        );

        let lowerer = CstAstLowerer::new(&tokens, &source, true, FrontendBudget::v1());
        assert!(
            lowerer
                .delimiter_depths
                .iter()
                .copied()
                .max()
                .is_some_and(|maximum| maximum > crate::source::MAX_NESTING_DEPTH)
        );
    }
    #[test]
    fn statement_recovery_ignores_crossed_closing_delimiters() {
        let source = SourceFile::new(SourceId(0), "crossed-recovery.ko", "(];)\nlet x = 0;");
        let tokens = crate::lexer::lex(source.text()).expect("lex recovery fixture");
        let mut lowerer = CstAstLowerer::new(&tokens, &source, true, FrontendBudget::v1());
        lowerer.synchronize_statement(0);
        assert!(matches!(
            lowerer.tokens.get(lowerer.pos).map(|token| &token.kind),
            Some(TokenKind::Let)
        ));
    }
    fn parse_module(body: &str) -> Result<Program, String> {
        parse(&format!("module TestModule {{ {body} }}"))
    }
    fn sample_account_literal() -> String {
        iroha_data_model::account::AccountId::new(
            "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D"
                .parse()
                .expect("public key"),
        )
        .to_string()
    }
    #[test]
    fn parse_return_statements() {
        let src = "fn f() { return; return 1; }";
        let prog = parse_module(src).unwrap();
        assert_eq!(prog.items.len(), 1);
        let f = match &prog.items[0] {
            Item::Function(f) => f,
            _ => panic!("expected function item"),
        };
        assert_eq!(f.body.statements.len(), 2);
        match f.body.statements[0].kind() {
            Statement::Return(None) => {}
            _ => panic!("no return;"),
        }
        match f.body.statements[1].kind() {
            Statement::Return(Some(_)) => {}
            _ => panic!("no return expr"),
        }
    }
    #[test]
    fn conditional_parser_preserves_nested_then_and_else_associativity() {
        let program = parse_module("fn f() { return a ? b ? c : d : e ? f : g; }")
            .expect("parse nested conditional");
        let Item::Function(function) = &program.items[0] else {
            panic!("expected function item");
        };
        let Statement::Return(Some(expression)) = function.body.statements[0].kind() else {
            panic!("expected return expression");
        };
        let Expr::Conditional {
            then_expr,
            else_expr,
            ..
        } = expression.kind()
        else {
            panic!("expected outer conditional return");
        };
        assert!(
            matches!(then_expr.kind(), Expr::Conditional { .. }),
            "the nested then arm must bind to the outer conditional"
        );
        assert!(
            matches!(else_expr.kind(), Expr::Conditional { .. }),
            "the nested else arm must bind to the outer conditional"
        );
    }
    #[test]
    fn iterative_type_parser_preserves_nested_generic_and_tuple_shapes() {
        let program = parse_module("struct Wrapper { Result<Option<int>, (bool, string)> value }")
            .expect("parse nested type");
        let Item::Struct(definition) = &program.items[0] else {
            panic!("expected struct item");
        };
        let TypeExpr::Generic { base, args } = definition.fields[0].1.kind() else {
            panic!("expected Result generic");
        };
        assert_eq!(base, "Result");
        let TypeExpr::Generic {
            base: option_base,
            args: option_args,
        } = args[0].kind()
        else {
            panic!("expected Option generic");
        };
        assert_eq!(option_base, "Option");
        assert!(matches!(option_args[0].kind(), TypeExpr::Path(path) if path == "int"));
        let TypeExpr::Tuple(elements) = args[1].kind() else {
            panic!("expected tuple type");
        };
        assert!(matches!(elements[0].kind(), TypeExpr::Path(path) if path == "bool"));
        assert!(matches!(elements[1].kind(), TypeExpr::Path(path) if path == "string"));

        std::thread::Builder::new()
            .name("kotodama-type-error-drop".to_owned())
            .stack_size(64 * 1024)
            .spawn(|| {
                let depth = FrontendBudget::v1().max_nesting().saturating_sub(3);
                let nested = format!("{}int{}", "Option<".repeat(depth), ">".repeat(depth));
                let source = format!("module TestModule {{ struct Wrapper {{ {nested} : }} }}");
                let error = parse(&source).expect_err("a field name is required after its type");
                assert!(
                    error.contains("type-first"),
                    "the later declaration-order error must survive iterative type cleanup: {error}"
                );
            })
            .expect("spawn small-stack type cleanup test")
            .join()
            .expect("small-stack type cleanup test");
    }
    #[test]
    fn parses_list_literals_and_filtered_comprehensions() {
        let program = parse_module(
            "fn lists() { let values = [1, 2,]; let doubled = [value * 2 for value in values if value > 0]; }",
        )
        .expect("parse bounded List forms");
        let Item::Function(function) = &program.items[0] else {
            panic!("expected function item");
        };
        let Statement::Let { value, .. } = function.body.statements[0].kind() else {
            panic!("expected literal binding");
        };
        assert!(matches!(value.kind(), Expr::List(items) if items.len() == 2));
        let Statement::Let { value, .. } = function.body.statements[1].kind() else {
            panic!("expected comprehension binding");
        };
        assert!(matches!(
            value.kind(),
            Expr::ListComprehension {
                item,
                condition: Some(_),
                ..
            } if item == "value"
        ));
    }
    #[test]
    fn canonical_public_parse_output_contains_no_provenance_wrappers() {
        let program = parse_module(
            "fn clean(List<int, 4> values) -> bool { let copy = [item for item in values if true]; copy.contains(1) }",
        )
        .expect("parse representative source-backed tree");
        let Item::Function(function) = &program.items[0] else {
            panic!("expected function item")
        };
        let parameter_ty = function.params[0].ty.as_ref().expect("parameter type");
        assert!(parameter_ty.source().is_none());
        let TypeExpr::Generic { args, .. } = parameter_ty else {
            panic!("List type")
        };
        assert!(args.iter().all(|ty| ty.source().is_none()));
        let statement = &function.body.statements[0];
        assert!(statement.source().is_none());
        let Statement::Let { value, .. } = statement else {
            panic!("comprehension binding")
        };
        assert!(value.source().is_none());
        let Expr::ListComprehension {
            expression,
            source,
            condition: Some(condition),
            ..
        } = value
        else {
            panic!("filtered comprehension")
        };
        assert!(expression.source().is_none());
        assert!(source.source().is_none());
        assert!(condition.source().is_none());
        let tail = function.body.tail.as_deref().expect("call tail");
        assert!(tail.source().is_none());
        let Expr::Call { args, .. } = tail else {
            panic!("method call")
        };
        assert!(args.iter().all(|argument| argument.source().is_none()));
    }
    #[test]
    fn list_type_capacity_is_preserved_as_a_constant_argument() {
        let program = parse_module("fn values(List<Option<int>, 64> input) {}").expect("List type");
        let Item::Function(function) = &program.items[0] else {
            panic!("expected function item");
        };
        let Some(parameter_type) = &function.params[0].ty else {
            panic!("expected parameter type");
        };
        let TypeExpr::Generic { base, args } = parameter_type.kind() else {
            panic!("expected generic List type");
        };
        assert_eq!(base, "List");
        assert!(matches!(args[0].kind(), TypeExpr::Generic { base, .. } if base == "Option"));
        assert!(
            matches!(args[1].kind(), TypeExpr::ConstExpression(value) if matches!(value.kind(), Expr::IntLiteral(value) if value == &BigInt::from(64_u32)))
        );
    }
    #[test]
    fn malformed_list_expression_reports_the_closing_delimiter() {
        let error = parse_module("fn invalid() { let values = [1, 2; }")
            .expect_err("unterminated List must fail");
        assert!(error.contains("expected `]`, found `;`"), "{error}");
        assert!(error.contains("this `[` is not closed"), "{error}");
    }
    #[test]
    fn accepts_unit_values_and_types_but_rejects_singleton_tuple_types() {
        let error = parse_module("fn invalid((int) value) {}")
            .expect_err("singleton tuple types must fail");
        assert!(
            error.contains("tuple types require at least two elements"),
            "unexpected error: {error}"
        );
        parse_module("fn unit(() value) -> () { let () item = (); value }")
            .expect("Unit literals, annotations, parameters and returns must parse");
        let grouped = parse_module(
            "fn grouped() -> int { return (1); } fn pair((int, bool) value) -> (int, bool) { return (1, true); } fn omitted() { return; }",
        )
        .expect("grouping, real tuples, and omitted Unit returns remain valid");
        let Item::Function(grouped_function) = &grouped.items[0] else {
            panic!("expected grouped function")
        };
        assert!(matches!(
            grouped_function.body.statements[0].kind(),
            Statement::Return(Some(value)) if matches!(value.kind(), Expr::IntLiteral(value) if value == &BigInt::one())
        ));
    }
    #[test]
    fn else_if_is_represented_as_a_nested_if_in_the_else_block() {
        let program = parse_module(
            "fn classify(int value) -> int { if value < 0 { return -1; } else if value == 0 { return 0; } else { return 1; } }",
        )
        .expect("parse documented else-if chain");
        let Item::Function(function) = &program.items[0] else {
            panic!("expected function")
        };
        let Expr::If {
            else_branch: Some(outer_else),
            ..
        } = function
            .body
            .tail
            .as_deref()
            .expect("divergent if tail")
            .kind()
        else {
            panic!("expected outer divergent if tail with else")
        };
        let Expr::If {
            else_branch: Some(inner_else),
            ..
        } = outer_else
            .tail
            .as_deref()
            .expect("nested divergent if tail")
            .kind()
        else {
            panic!("else-if must remain one nested divergent if expression")
        };
        assert_eq!(inner_else.statements.len(), 1);
    }
    #[test]
    fn mixed_value_and_divergent_control_flow_remains_a_tail_expression() {
        let program = parse_module(
            r#"
            fn via_if(bool flag) -> int {
                if flag { 7 } else { return 9; }
            }
            fn via_if_let(Option<int> value) -> int {
                if let Option::some(item) = value { item } else { return 0; }
            }
            fn via_match(Option<int> value) -> int {
                match value {
                    Option::some(item) => item,
                    Option::none => { return 0; },
                }
            }
            "#,
        )
        .expect("parse mixed value/divergent tails");
        for (function, expected) in program.items.iter().zip(["if", "if let", "match"]) {
            let Item::Function(function) = function else {
                panic!("expected function")
            };
            assert!(
                function.body.statements.is_empty(),
                "{expected} tail must not be demoted to a statement"
            );
            let tail = function.body.tail.as_deref().expect("control-flow tail");
            assert!(
                matches!(
                    (expected, tail.kind()),
                    ("if", Expr::If { .. })
                        | ("if let", Expr::IfLet { .. })
                        | ("match", Expr::Match { .. })
                ),
                "unexpected {expected} tail: {tail:?}"
            );
        }
    }
    #[test]
    fn list_literal_ternary_is_distinct_from_propagation_followed_by_indexing() {
        let program = parse_module(
            r#"
            fn choose(bool flag) -> List<int, 1> { flag ? [1] : [2] }
            fn index_after_propagation(Option<List<int, 1>> value) -> int { value?[0] }
            "#,
        )
        .expect("parse list ternary and propagation-index adjacency");
        let Item::Function(choose) = &program.items[0] else {
            panic!("expected choose function")
        };
        assert!(matches!(
            choose.body.tail.as_deref().map(Expr::kind),
            Some(Expr::Conditional {
                then_expr,
                else_expr,
                ..
            }) if matches!(then_expr.kind(), Expr::List(_))
                && matches!(else_expr.kind(), Expr::List(_))
        ));
        let Item::Function(index) = &program.items[1] else {
            panic!("expected index function")
        };
        assert!(matches!(
            index.body.tail.as_deref().map(Expr::kind),
            Some(Expr::Index { target, .. })
                if matches!(target.kind(), Expr::Propagate(_))
        ));
    }
    #[test]
    fn parses_value_tails_and_expression_oriented_control_flow() {
        let program = parse_module(
            r#"
            fn identity(int value) -> int { value }
            fn choose(bool flag) -> int { if flag { 1 } else { 2 } }
            fn unwrap(Option<int> value) -> int {
                match value {
                    Option::some(item) => item,
                    Option::none => 0,
                }
            }
            fn observe(Option<int> value) {
                if let Option::some(item) = value { let _seen = item; }
            }
            "#,
        )
        .expect("parse expression-oriented V1 control flow");
        let functions = program
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            functions[0].body.tail.as_deref().map(Expr::kind),
            Some(Expr::Ident(name)) if name == "value"
        ));
        assert!(matches!(
            functions[1].body.tail.as_deref().map(Expr::kind),
            Some(Expr::If {
                else_branch: Some(_),
                ..
            })
        ));
        assert!(matches!(
            functions[2].body.tail.as_deref().map(Expr::kind),
            Some(Expr::Match { arms, .. }) if arms.len() == 2
        ));
        assert_eq!(functions[3].body.statements.len(), 1);
        assert!(matches!(
            functions[3].body.statements[0].kind(),
            Statement::IfLet {
                else_branch: None,
                ..
            }
        ));
    }
    #[test]
    fn postfix_propagation_binds_tighter_than_ternary() {
        let program = parse_module(
            "fn choose(bool condition, Option<int> maybe, int fallback) -> int { condition ? maybe? : fallback }",
        )
        .expect("parse ternary containing postfix propagation");
        let Item::Function(function) = &program.items[0] else {
            panic!("function item")
        };
        assert!(matches!(
            function.body.tail.as_deref().map(Expr::kind),
            Some(Expr::Conditional { then_expr, .. })
                if matches!(then_expr.kind(), Expr::Propagate(value)
                    if matches!(value.kind(), Expr::Ident(name) if name == "maybe"))
        ));
    }
    #[test]
    fn active_only_sum_constructors_have_no_placeholder_payloads() {
        let program = parse_module(
            r#"
            fn some(int value) -> Option<int> { Option::some(value) }
            fn none() -> Option<int> { Option::none }
            fn ok(int value) -> Result<int, string> { Result::ok(value) }
            fn err(string message) -> Result<int, string> { Result::err(message) }
            "#,
        )
        .expect("parse canonical active-only constructors");
        let tails = program.items.iter().filter_map(|item| match item {
            Item::Function(function) => function.body.tail.as_deref().map(Expr::kind),
            _ => None,
        });
        assert!(matches!(
            tails.collect::<Vec<_>>().as_slice(),
            [
                Expr::OptionSome(_),
                Expr::OptionNone,
                Expr::ResultOk(_),
                Expr::ResultErr(_),
            ]
        ));
        for (source, replacement) in [
            ("fn f() -> Option<int> { option::none(0) }", "Option::none"),
            (
                "fn f() -> Result<int, string> { result::ok(1, \"unused\") }",
                "Result::ok(1)",
            ),
        ] {
            let error = parse_module(source).expect_err("legacy constructor must be rejected");
            assert!(error.contains("E_LEGACY_SUM_CONSTRUCTOR"), "{error}");
            assert!(error.contains(replacement), "{error}");
        }
    }
    #[test]
    fn mutable_bindings_still_require_initializers() {
        let error = parse_module("fn invalid() { var int value; }")
            .expect_err("uninitialized locals are not part of V1");
        assert!(
            error.contains("expected `=`, found `;`"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn ordinary_enums_use_explicit_codes_and_reject_error_messages_and_payloads() {
        let program =
            parse("module Data { export enum Status { Active = 1, Paused = 4294967295 } }")
                .expect("ordinary exported enum");
        let Item::Enum(definition) = &program.items[0] else {
            panic!("enum declaration");
        };
        assert_eq!(definition.kind, EnumKind::Data);
        assert_eq!(definition.variants[1].code, u32::MAX);
        for declaration in [
            "enum Empty {}",
            "enum Zero { A = 0 }",
            "enum Duplicate { A = 1, B = 1 }",
            "enum Duplicate { A = 1, A = 2 }",
            "enum Missing { A }",
            "enum Wide { A = 4294967296 }",
            "enum Payload { A(int value) = 1 }",
            "enum Generic<T> { A = 1 }",
            "enum Message { #[message(\"Not a rejection\")] A = 1 }",
        ] {
            assert!(
                parse(&format!("module Data {{ {declaration} }}")).is_err(),
                "{declaration}"
            );
        }
    }
    #[test]
    fn error_enum_requires_explicit_unique_nonzero_u32_codes() {
        let program =
            parse("seiyaku Errors { error enum Payment { Unauthorized = 1001, Expired = 1002 } }")
                .expect("parse stable error enum");
        let Item::Enum(errors) = &program.items[0] else {
            panic!("expected error enum")
        };
        assert_eq!(errors.name, "Payment");
        assert_eq!(errors.variants[0].name, "Unauthorized");
        assert_eq!(errors.variants[0].code, 1001);
        for body in [
            "error enum Empty {}",
            "error enum Zero { Invalid = 0 }",
            "error enum Missing { Invalid }",
            "error enum Duplicate { First = 7, Second = 7 }",
            "error enum Overflow { Invalid = 4294967296 }",
        ] {
            let error = parse(&format!("seiyaku Errors {{ {body} }}"))
                .expect_err("invalid error enum must fail parsing");
            assert!(!error.is_empty(), "empty diagnostic for `{body}`");
        }
    }
    #[test]
    fn parse_bools_and_logical_ops() {
        let src = "fn g() { let x = true && !false; }";
        let prog = parse_module(src).unwrap();
        assert_eq!(prog.items.len(), 1);
    }
    #[test]
    fn parse_assignment_and_break_continue() {
        let src = "fn h() { var x = 0; x = 1; for i in range(10) { if i == 3 { break; } if i == 5 { continue; } } }";
        let prog = parse_module(src).unwrap();
        assert_eq!(prog.items.len(), 1);
    }
    #[test]
    fn parse_preserves_local_binding_mutability() {
        let program = parse_module("fn f() { let fixed = 1; var int changing = 2; }")
            .expect("parse let and var bindings");
        let Item::Function(function) = &program.items[0] else {
            panic!("expected function")
        };
        assert!(matches!(
            function.body.statements[0].kind(),
            Statement::Let { mutable: false, .. }
        ));
        assert!(matches!(
            function.body.statements[1].kind(),
            Statement::Let { mutable: true, .. }
        ));
    }
    #[test]
    fn parse_canonical_seiyaku_surface_and_preserve_identity() {
        let src = r#"
        seiyaku Payments { permission Submit;
            state int counter;
            struct Pair { int left; int right; }
            hajimari() { counter = 0; }
            kaizen() {}
            kotoage fn submit(AccountId who, quantity amount) authorize(Submit) {}
            view fn read(Name key) authorize(anyone) -> int { return counter; }
            fn helper(int left, int right) -> int { return left + right; }
        }
        "#;
        let prog = parse(src).unwrap();
        assert_eq!(prog.unit.kind, SourceUnitKind::Seiyaku);
        assert_eq!(prog.unit.name, "Payments");
        let functions = prog
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(functions.len(), 5);
        assert_eq!(functions[0].name, "hajimari");
        assert_eq!(functions[0].modifiers.kind, FunctionKind::Hajimari);
        assert_eq!(functions[0].modifiers.authorization, None);
        assert_eq!(functions[1].name, "kaizen");
        assert_eq!(functions[1].modifiers.kind, FunctionKind::Kaizen);
        assert_eq!(functions[1].modifiers.authorization, None);
        assert_eq!(functions[2].modifiers.kind, FunctionKind::Kotoage);
        assert_eq!(
            functions[2].modifiers.authorization.as_deref(),
            Some("Submit")
        );
        assert_eq!(functions[3].modifiers.kind, FunctionKind::View);
        assert_eq!(functions[4].modifiers.kind, FunctionKind::Private);
    }
    #[test]
    fn lifecycle_declarations_reject_source_authorization() {
        for source in [
            "seiyaku Demo { hajimari() authorize(\"HajimariPermission\") {} }",
            "seiyaku Demo { kaizen() authorize(\"KaizenPermission\") {} }",
        ] {
            let error = parse(source).expect_err("lifecycle authorization is runtime-owned");
            assert!(
                error.contains("E_LIFECYCLE_AUTHORIZATION")
                    && error.contains("lifecycle hooks are authorized by the runtime"),
                "unexpected error: {error}"
            );
        }
    }
    #[test]
    fn parse_canonical_module_surface_and_preserve_identity() {
        let prog =
            parse("module Math { fn add(int left, int right) -> int { return left + right; } }")
                .expect("parse module");
        assert_eq!(prog.unit.kind, SourceUnitKind::Module);
        assert_eq!(prog.unit.name, "Math");
    }
    #[test]
    fn parse_canonical_context_and_ledger_namespaces() {
        let program = parse(
            r#"
            seiyaku Payments { permission TransferAsset;
                kotoage fn transfer(
                    AccountId recipient,
                    AssetDefinitionId asset,
                    quantity amount,
                    DataSpaceId dataspace
                ) authorize(TransferAsset) {
                    let sender = context::authority();
                    ledger::asset::transfer(
                        source: sender,
                        destination: recipient,
                        asset_definition: asset,
                        amount: amount,
                        dataspace: dataspace,
                    );
                }
            }
            "#,
        )
        .expect("parse canonical namespaces");
        let Item::Function(function) = &program.items[0] else {
            panic!("expected function")
        };
        let Statement::Let { value, .. } = function.body.statements[0].kind() else {
            panic!("expected authority binding")
        };
        assert!(matches!(
            value.kind(),
            Expr::Call { name, .. } if name == "context::authority"
        ));
        let Statement::Expr(call) = function.body.statements[1].kind() else {
            panic!("expected ledger call statement");
        };
        assert!(
            matches!(call.kind(), Expr::Call { name, .. } if name == "ledger::asset::transfer")
        );
    }
    #[test]
    fn keyword_tokens_are_admitted_only_in_required_namespace_positions() {
        let program = parse(
            r#"
            seiyaku Controls { permission Control;
                kotoage fn update(Name path, Name trigger_id) authorize(Control) {
                    state::set(path, 1);
                    ledger::trigger::set_enabled(trigger_id, true);
                }
            }
            "#,
        )
        .expect("parse keyword-backed V1 namespaces");
        let function = program
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "update" => Some(function),
                _ => None,
            })
            .expect("update entrypoint");
        let Statement::Expr(state_call) = function.body.statements[0].kind() else {
            panic!("expected state call statement");
        };
        assert!(matches!(state_call.kind(), Expr::Call { name, .. } if name == "state::set"));
        let Statement::Expr(trigger_call) = function.body.statements[1].kind() else {
            panic!("expected trigger call statement");
        };
        assert!(
            matches!(trigger_call.kind(), Expr::Call { name, .. } if name == "ledger::trigger::set_enabled")
        );
        for binding in ["state", "trigger"] {
            let source = format!("seiyaku Reserved {{ fn bad() {{ let {binding} = 1; }} }}");
            parse(&source).expect_err("keyword must remain unavailable as a binding");
        }
        parse("seiyaku Reserved { fn bad() { seiyaku::register_code(); } }")
            .expect_err("declaration keywords must remain unavailable as namespace roots");
    }
    #[test]
    fn english_declaration_spellings_are_rejected() {
        for source in [
            "contract Legacy {}",
            "seiyaku Legacy { entry fn run() authorize(anyone) {} }",
            "seiyaku Legacy { init() {} }",
            "seiyaku Legacy { upgrade() {} }",
            "seiyaku Legacy { kotoage fn run() authorize(anyone) permission(Admin) {} }",
        ] {
            parse(source).expect_err("English declaration spelling must be rejected");
        }
    }
    #[test]
    fn branded_keywords_are_contextual_namespace_segments_only() {
        for source in [
            "module M { fn f() { context::kotoage(); ledger::seiyaku::grant_permission(); test::invoke_kotoage(kotoage: \"run\", arguments: {}); } }",
            "module M { fn f() { context::言挙げ(); ledger::誓約::grant_permission(); test::invoke_kotoage(言挙げ: \"run\", arguments: {}); } }",
        ] {
            parse(source).expect("branded capability path must parse");
        }
        for source in [
            "module M { fn f() { kotoage(); } }",
            "module M { fn f() { seiyaku::grant_permission(); } }",
            "module M { fn f() { let kotoage = 1; } }",
            "module M { fn f() { let seiyaku = 1; } }",
        ] {
            parse(source).expect_err("branded declaration keyword must stay reserved");
        }
    }
    #[test]
    fn branded_japanese_declaration_keywords_are_first_class() {
        for source in [
            "誓約 Demo {}",
            "seiyaku Demo { 始まり() {} }",
            "seiyaku Demo { permission Run;  言挙げ fn run() authorize(Run) {} }",
            "seiyaku Demo { 改善() {} }",
        ] {
            parse(source).expect("branded Japanese declaration syntax must parse");
        }
    }
    #[test]
    fn exactly_one_named_source_unit_is_required() {
        for source in [
            "fn main() {}",
            "seiyaku First {} seiyaku Second {}",
            "module First {} module Second {}",
        ] {
            parse(source).expect_err("invalid source-unit cardinality must fail");
        }
    }
    #[test]
    fn canonical_declaration_shapes_are_required() {
        for source in [
            "module M { fn f(value: int) {} }",
            "module M { fn f(value) {} }",
            "module M { const VALUE = 1; }",
            "seiyaku C { state value: int; }",
            "module M { struct Pair { value: int; } }",
            "seiyaku C { kotoage fn f() authorize(\"Admin\") {} }",
        ] {
            parse(source).expect_err("legacy declaration shape must fail");
        }
    }
    #[test]
    fn retired_colon_declarations_report_the_type_first_replacement() {
        for (source, replacement) in [
            ("module M { fn f(value: int) {} }", "`int value`"),
            (
                "module M { const limit: int = 1; }",
                "`const int limit = ...;`",
            ),
            ("seiyaku C { state value: int; }", "`state int value;`"),
            ("module M { struct Pair { value: int; } }", "`int value;`"),
            (
                "module M { fn f() { let value: int = 1; } }",
                "`let int value = ...;`",
            ),
        ] {
            let error = parse(source).expect_err("retired declaration order must fail closed");
            assert!(error.contains("E_RETIRED_DECLARATION_ORDER"), "{error}");
            assert!(error.contains(replacement), "{error}");
        }
    }
    #[test]
    fn retired_numeric_type_spellings_are_rejected_with_replacements() {
        for legacy in kotodama_surface::source_policy::V1_RETIRED_NUMERIC_TYPE_NAMES {
            let source = format!("module Types {{ fn use_type({legacy} value) {{}} }}");
            let error = parse(&source).expect_err("retired numeric type must fail closed");
            assert!(
                error.contains("E_RETIRED_NUMERIC_TYPE"),
                "unexpected diagnostic for `{legacy}`: {error}"
            );
        }
    }
    #[test]
    fn exact_amount_is_rejected_in_every_identifier_context() {
        for source in [
            "module Amount { fn f() {} }",
            "module M { fn Amount() {} }",
            "module M { fn f(int Amount) {} }",
            "module M { fn f() { let int Amount = 1; } }",
            "module M { struct Record { int Amount; } }",
            "module M { struct Record { int value; } fn f() { let item = Record { Amount: 1 }; } }",
            "module M { fn f() { for Amount in range(1) {} } }",
            "module M { fn f() { let values = [1]; let copy = [item for Amount in values]; } }",
            "module M { fn f(Option<int> value) { if let Option::some(Amount) = value {} } }",
            "module M { fn target(int value) {} fn f() { target(Amount: 1); } }",
            "module M { fn f(Json value) { let found = value.Amount; } }",
            "module M { fn f() { Amount::call(); } }",
            "module M { fn f() { let payload = json { Amount: 1 }; } }",
        ] {
            let error = parse(source).expect_err("exact `Amount` identifier must fail closed");
            assert!(
                error.contains("E_FORBIDDEN_SOURCE_IDENTIFIER"),
                "unexpected diagnostic for `{source}`: {error}"
            );
        }
    }
    #[test]
    fn lowercase_amount_and_non_identifier_amount_text_remain_valid() {
        parse(
            r#"module AmountText {
                struct Record { int amount; }
                fn target(int amount) {}
                fn amount(Json value) {
                    let int amount = 1;
                    for amount_item in range(1) {
                        target(amount: amount_item);
                        let member = value.amount;
                        let payload = json { amount: amount_item, "Amount": 1 };
                        let text = "Amount";
                        // Amount remains legal documentation text.
                    }
                }
            }"#,
        )
        .expect("lowercase `amount`, strings, comments, and quoted JSON keys remain valid");
    }
    #[test]
    fn retired_amount_type_keeps_its_quantity_fix_diagnostic_only() {
        let error = parse("module M { fn f(Amount value) {} }")
            .expect_err("retired `Amount` type must fail closed");
        assert!(error.contains("E_RETIRED_NUMERIC_TYPE"), "{error}");
        assert!(error.contains("use `quantity`"), "{error}");
        assert!(!error.contains("E_FORBIDDEN_SOURCE_IDENTIFIER"), "{error}");
    }
    #[test]
    fn every_retired_amount_type_keeps_its_quantity_fix_during_recovery() {
        for (index, (source, retired_count, forbidden_count)) in [
            ("module M { fn f(Amount a, Amount b) {} }", 2, 0),
            ("module M { fn f(Result<Amount, Amount> value) {} }", 2, 0),
            ("module M { fn f(Amount type_value, int Amount) {} }", 1, 1),
        ]
        .into_iter()
        .enumerate()
        {
            let source_file = SourceFile::new(
                SourceId(40 + index as u32),
                "retired-amount-recovery.ko",
                source,
            );
            let diagnostics = parse_source(&source_file, FrontendBudget::v1())
                .expect_err("every exact `Amount` occurrence must fail closed");
            let retired = diagnostics
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "E_RETIRED_NUMERIC_TYPE")
                .collect::<Vec<_>>();
            assert_eq!(retired.len(), retired_count, "{source}");
            for diagnostic in retired {
                assert_eq!(
                    diagnostic.fix.as_ref().map(|fix| fix.replacement.as_str()),
                    Some("quantity"),
                    "{source}"
                );
            }
            assert_eq!(
                diagnostics
                    .diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "E_FORBIDDEN_SOURCE_IDENTIFIER")
                    .count(),
                forbidden_count,
                "{source}"
            );
        }
    }
    #[test]
    fn retired_numeric_helpers_are_rejected_before_resolution() {
        for source in [
            "module M { fn f() { let value = numeric::add(left: 1, right: 2); } }",
            "module M { fn f() { let value = numeric::to_i64(1); } }",
            "module M { fn f() { let value = json::set_i64(json::object(), Name::parse(\"n\"), 1); } }",
            "module M { fn f() { let value = json::set_int(json::object(), Name::parse(\"n\"), 1); } }",
        ] {
            let error = parse(source).expect_err("retired numeric helper must fail closed");
            assert!(error.contains("E_RETIRED_NUMERIC_HELPER"), "{error}");
        }
    }
    #[test]
    fn retired_trigger_aliases_have_exact_canonical_fixes() {
        for (retired, replacement) in [
            ("ledger::trigger::create", "ledger::trigger::register"),
            ("ledger::trigger::remove", "ledger::trigger::unregister"),
        ] {
            let text =
                format!("module RetiredTrigger {{ fn main(Json value) {{ {retired}(value); }} }}");
            let source = SourceFile::new(SourceId(7), "retired-trigger.ko", &text);
            let bundle = parse_source(&source, FrontendBudget::v1())
                .expect_err("retired trigger alias must fail closed");
            let diagnostic = bundle
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "E_RETIRED_TRIGGER_ALIAS")
                .expect("retired trigger alias diagnostic");
            let fix = diagnostic.fix.as_ref().expect("machine-applicable fix");
            let range = fix.span.byte_range.expect("exact source range");
            assert_eq!(&text[range.start as usize..range.end as usize], retired);
            assert_eq!(fix.replacement, replacement);
            let mut repaired = text.clone();
            repaired.replace_range(range.start as usize..range.end as usize, &fix.replacement);
            parse(&repaired).expect("canonical replacement must parse");
        }
    }
    #[test]
    fn modules_reject_deployable_contract_items() {
        for body in [
            "kotoage fn run() authorize(anyone) {}",
            "view fn read() authorize(anyone) -> int { return 1; }",
            "hajimari() {}",
            "kaizen() {}",
            "state int value;",
            "meta { abi_version: 1; }",
        ] {
            let source = format!("module Library {{ {body} }}");
            parse(&source).expect_err("module must reject deployable item");
        }
    }
    #[test]
    fn while_and_c_style_for_forms_are_rejected() {
        for body in [
            "fn f() { while true {} }",
            "fn f() { for let i = 0; i < 3; i = i + 1 {} }",
        ] {
            parse_module(body).expect_err("unbounded loop form must fail");
        }
    }
    #[test]
    fn range_and_collection_bound_validation_is_semantic() {
        for body in [
            "fn f(int n) { for i in range(n) {} }",
            "fn f(StateMap<int, int> values) { for (key, value) in values {} }",
        ] {
            parse_module(body).expect("bounds are resolved and checked after parsing");
        }
    }
    #[test]
    fn parse_for_range_loop() {
        let src = "fn f() { for x in range(6) { let y = x; } }";
        let prog = parse_module(src).expect("parse failed");
        let func = prog
            .items
            .iter()
            .find_map(|it| match it {
                Item::Function(f) => Some(f),
                _ => None,
            })
            .expect("function present");
        assert!(!func.body.statements.is_empty());
    }
    #[test]
    fn source_meta_is_rejected_in_favor_of_build_configuration() {
        for body in [
            "zk: true",
            "zk: false",
            "abi_version: 1",
            "vector_length: 4",
            "vector: true",
            "features: [\"zk\"]",
            "max_cycles: 1000",
        ] {
            let source = format!("seiyaku C {{ meta {{ {body}; }} }}");
            let err = parse(&source).expect_err("source policy toggle must be rejected");
            assert!(
                err.contains("source-level `meta { ... }` is not supported")
                    && err.contains("compiler build configuration"),
                "unexpected error for {body}: {err}"
            );
        }
    }
    #[test]
    fn parse_reports_unexpected_top_level_tokens() {
        let src = "let orphan = 1;";
        let err = parse(src).unwrap_err();
        assert!(err.contains("exactly one"));
    }
    #[test]
    fn parse_reports_unexpected_contract_items() {
        let src = r#"
        seiyaku C {
            123
        }
        "#;
        let err = parse(src).unwrap_err();
        assert!(err.contains("expected a declaration ("), "{err}");
    }
    #[test]
    fn parse_function_modifiers_are_preserved() {
        let src = r#"
        seiyaku Demo { permission Admin;
            kotoage fn foo() authorize(Admin) {}
        }
        "#;
        let prog = parse(src).expect("parse modifiers");
        let func = prog
            .items
            .into_iter()
            .find_map(|item| match item {
                Item::Function(f) => Some(f),
                _ => None,
            })
            .expect("function present");
        assert_eq!(func.name, "foo");
        assert_eq!(func.modifiers.kind, FunctionKind::Kotoage);
        assert_eq!(func.modifiers.authorization.as_deref(), Some("Admin"));
    }
    #[test]
    fn kotoage_authorization_is_a_parse_time_grammar_requirement() {
        for (source, code) in [
            (
                "seiyaku Demo { kotoage fn run() {} }",
                "E_KOTOAGE_AUTHORIZATION_MISSING",
            ),
            (
                "誓約 Demo { 言挙げ fn run() -> int { 1 } }",
                "E_KOTOAGE_AUTHORIZATION_MISSING",
            ),
            (
                "seiyaku Demo { view fn read() -> int { 1 } }",
                "E_VIEW_AUTHORIZATION_MISSING",
            ),
        ] {
            let error = parse(source).expect_err("public functions need explicit authorization");
            assert!(error.contains(code), "{error}");
            assert!(
                error.contains("requires an explicit `authorize(...)` policy"),
                "{error}"
            );
        }
        parse("seiyaku Demo { view fn read() authorize(anyone) -> int { 1 } }")
            .expect("explicit open view");
    }
    #[test]
    fn authorization_declarations_and_order_are_explicit() {
        let source = r#"誓約 Payments { permission Admin; import permission "CanSetParameters" as ChainAdmin;
            言挙げ fn write() authorize(Admin) -> int { 1 }
            view fn read() authorize(ChainAdmin) -> int { 2 }
            kotoage fn open() authorize(anyone) {} 始まり() {} kaizen() {}
        }"#;
        let program = parse(source).expect("mixed spellings with explicit authorization");
        assert_eq!(program.permissions.len(), 2);
        assert_eq!(program.permissions[0].name, "Admin");
        assert_eq!(
            program.permissions[1].chain_permission.as_deref(),
            Some("CanSetParameters")
        );
        for (source, code) in [
            (
                r#"seiyaku C { kotoage fn f() authorize("Admin") {} }"#,
                "E_AUTHORIZATION_STRING",
            ),
            (
                "seiyaku C { permission Admin; kotoage fn f() -> int authorize(Admin) { 1 } }",
                "E_AUTHORIZE_POSITION",
            ),
            ("module M { permission Admin; }", "E_PERMISSION_DECLARATION"),
            (
                "seiyaku C { permission anyone; }",
                "E_PERMISSION_DECLARATION",
            ),
            (
                "seiyaku C { permission permission; }",
                "E_PERMISSION_DECLARATION",
            ),
        ] {
            let error = parse(source).expect_err("invalid permission grammar");
            assert!(error.contains(code), "{error}");
        }
    }
    include!("parser/tests/numeric_literal_tests.rs");
    #[test]
    fn native_json_preserves_decoded_keys_and_exact_source_spelling() {
        let program = parse_module(
            r#"fn build(string label) -> Json {
                json { owner: label, "owner-alias": json [label] }
            }"#,
        )
        .expect("parse native JSON object and array");
        let function = program
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("function");
        let Expr::JsonObject(entries) = function.body.tail.as_deref().expect("JSON tail").kind()
        else {
            panic!("expected native JSON object");
        };
        assert_eq!(entries[0].key, "owner");
        assert_eq!(entries[0].key_spelling, "owner");
        assert_eq!(entries[1].key, "owner-alias");
        assert_eq!(entries[1].key_spelling, "\"owner-alias\"");
        assert!(matches!(entries[1].value.kind(), Expr::JsonArray(items) if items.len() == 1));
    }
    #[test]
    fn named_calls_preserve_source_names_and_trailing_comma() {
        let program = parse_module(
            "fn target(int first, string second) {} fn main() { target(second: \"two\", first: 1,); }",
        )
        .expect("parse named call");
        let main = program
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function");
        let Statement::Expr(call) = main.body.statements[0].kind() else {
            panic!("expected call statement");
        };
        let Expr::Call {
            args,
            argument_names,
            implicit_receiver,
            ..
        } = call.kind()
        else {
            panic!("expected call expression");
        };
        assert_eq!(args.len(), 2);
        assert_eq!(
            argument_names.as_deref(),
            Some([Some("second".to_owned()), Some("first".to_owned())].as_slice())
        );
        assert!(!implicit_receiver);
    }
    #[test]
    fn method_named_arguments_exclude_the_implicit_receiver() {
        let program =
            parse_module("fn main(Json value, Name key) { let found = value.get_int(key: key); }")
                .expect("parse named method call");
        let function = program
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("function");
        let Statement::Let { value, .. } = function.body.statements[0].kind() else {
            panic!("expected binding");
        };
        let Expr::Call {
            args,
            argument_names,
            implicit_receiver,
            ..
        } = value.kind()
        else {
            panic!("expected method call");
        };
        assert_eq!(args.len(), 2);
        assert_eq!(
            argument_names.as_deref(),
            Some([Some("key".to_owned())].as_slice())
        );
        assert!(implicit_receiver);
    }
    #[test]
    fn quantity_json_getter_uses_canonical_source_name_and_rejects_legacy_names() {
        let program =
            parse_module("fn main(Json value, Name key) { let found = value.get_quantity(key); }")
                .expect("parse canonical quantity JSON getter");
        let function = program
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("function");
        let Statement::Let { value, .. } = function.body.statements[0].kind() else {
            panic!("expected quantity getter binding");
        };
        let Expr::Call {
            name,
            implicit_receiver,
            ..
        } = value.kind()
        else {
            panic!("expected quantity getter call");
        };
        assert_eq!(name, "get_quantity");
        assert!(implicit_receiver);
        for legacy in ["get_amount", "get_numeric"] {
            let source =
                format!("fn main(Json value, Name key) {{ let found = value.{legacy}(key); }}");
            let error = parse_module(&source).expect_err("retired JSON getter must fail");
            assert!(error.contains("E_LEGACY_JSON_GETTER"), "{error}");
        }
    }
    #[test]
    fn explicit_parameter_labels_and_mixed_call_prefix_are_preserved() {
        let program = parse_module(
            "fn target(int _ value, int lower, int upper) {} fn main() { target(5, upper: 10, lower: 0); }",
        ).expect("explicit labels and mixed prefix");
        let Item::Function(target) = &program.items[0] else {
            panic!("target")
        };
        assert_eq!(target.params[0].call_mode, ParameterCallMode::Positional);
        assert_eq!(target.params[1].call_mode, ParameterCallMode::Named);
        let Item::Function(main) = &program.items[1] else {
            panic!("main")
        };
        let Statement::Expr(expression) = main.body.statements[0].kind() else {
            panic!("call")
        };
        let Expr::Call { argument_names, .. } = expression.kind() else {
            panic!("call")
        };
        assert_eq!(
            argument_names.as_deref(),
            Some([None, Some("upper".into()), Some("lower".into())].as_slice())
        );
    }
    #[test]
    fn invalid_parameter_and_argument_order_is_rejected() {
        for (source, code) in [
            (
                "fn target(int first, int _ second) {}",
                "E_POSITIONAL_PARAMETER_ORDER",
            ),
            (
                "fn main() { target(first: 1, 2); }",
                "E_POSITIONAL_ARGUMENT_ORDER",
            ),
            (
                "fn main() { target(first: 1, first: 2); }",
                "E_DUPLICATE_NAMED_ARGUMENT",
            ),
        ] {
            let error = parse_module(source).expect_err("invalid source-call mode");
            assert!(error.contains(code), "{error}");
        }
    }
    #[test]
    fn named_struct_patterns_preserve_fields_aliases_discards_and_rest() {
        let program = parse_module(
            "struct Receipt { int amount; int recipient; int memo; } fn inspect(Receipt receipt) { let Receipt { recipient: payee, memo: _, .. } = receipt; }",
        ).expect("named struct pattern");
        let Item::Function(function) = &program.items[1] else {
            panic!("function")
        };
        let Statement::Let {
            pat: Pattern::Struct { name, fields, rest },
            ..
        } = function.body.statements[0].kind()
        else {
            panic!("struct pattern")
        };
        assert_eq!(name, "Receipt");
        assert!(*rest);
        assert_eq!(fields[0].name, "recipient");
        assert_eq!(fields[0].binding, "payee");
        assert_eq!(fields[1].binding, "_");
        assert!(fields.iter().all(|field| field.source.is_none()));
        let file = SourceFile::new(
            SourceId(23),
            "pattern.ko",
            "module M { struct S { int field; } fn inspect(S value) { let S { field: alias } = value; } }",
        );
        let (spanned, _) =
            parse_source_spanned(&file, FrontendBudget::v1()).expect("spanned pattern");
        let Item::Function(function) = &spanned.program.items[1] else {
            panic!("function")
        };
        let Statement::Let {
            pat: Pattern::Struct { fields, .. },
            ..
        } = function.body.statements[0].kind()
        else {
            panic!("struct pattern")
        };
        assert_eq!(
            file.slice(fields[0].source.expect("field source").range),
            Some("field")
        );
    }
    #[test]
    fn named_struct_patterns_reject_duplicate_fields_and_misplaced_rest() {
        for (source, code) in [
            (
                "fn inspect(Receipt receipt) { let Receipt { amount, amount } = receipt; }",
                "E_DUPLICATE_STRUCT_PATTERN_FIELD",
            ),
            (
                "fn inspect(Receipt receipt) { let Receipt { .., amount } = receipt; }",
                "E_STRUCT_PATTERN_REST",
            ),
        ] {
            let error = parse_module(source).expect_err("invalid struct pattern");
            assert!(error.contains(code), "{error}");
        }
    }
    #[test]
    fn named_struct_literals_support_shorthand_and_trailing_comma() {
        let program = parse_module(
            "struct Transfer { int source, int destination, quantity amount } fn main(int source, int destination) { let value = Transfer { amount: 10, source, destination, }; }",
        )
        .expect("parse named struct literal");
        let function = program
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("function");
        let Statement::Let { value, .. } = function.body.statements[0].kind() else {
            panic!("expected binding");
        };
        let Expr::StructLiteral { name, fields } = value.kind() else {
            panic!("expected struct literal");
        };
        assert_eq!(name, "Transfer");
        assert_eq!(
            fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["amount", "source", "destination"]
        );
        assert!(!fields[0].shorthand);
        assert!(fields[1].shorthand && fields[2].shorthand);
    }
    #[test]
    fn duplicate_struct_literal_fields_are_rejected() {
        let error = parse_module(
            "struct Pair { int first, int second } fn main() { let pair = Pair { first: 1, first: 2, second: 3 }; }",
        )
        .expect_err("duplicate field must fail");
        assert!(error.contains("E_DUPLICATE_STRUCT_FIELD"), "{error}");
    }
    #[test]
    fn control_flow_block_is_not_parsed_as_a_struct_literal() {
        parse_module("fn main(bool ready) { if ready {} }")
            .expect("if block must remain unambiguous");
    }
    #[test]
    fn negative_unsuffixed_literal_remains_available_for_semantic_quantity_validation() {
        parse_module("fn main() { let quantity value = -10; }")
            .expect("the parser leaves nominal quantity validation to semantics");
    }
    #[test]
    fn signed_512_bit_integer_endpoints_are_accepted() {
        for spelling in [
            "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047",
            "-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048",
        ] {
            parse_module(&format!("fn main() {{ let int value = {spelling}; }}"))
                .expect("signed 512-bit endpoint must parse");
        }
    }
    #[test]
    fn signed_512_bit_integer_neighbors_are_rejected() {
        for spelling in [
            "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048",
            "-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042049",
        ] {
            let error = parse_module(&format!("fn main() {{ let int value = {spelling}; }}"))
                .expect_err("out-of-domain int literal must fail");
            assert!(error.contains("E_INT_LITERAL_OVERFLOW"), "{error}");
        }
    }
    #[test]
    fn radix_literals_use_the_same_signed_512_bit_domain() {
        let maximum_hex = format!("0x7{}", "f".repeat(127));
        let minimum_hex = format!("-0x8{}", "0".repeat(127));
        let maximum_binary = format!("0b{}", "1".repeat(511));
        let minimum_binary = format!("-0b1{}", "0".repeat(511));
        for spelling in [maximum_hex, minimum_hex, maximum_binary, minimum_binary] {
            parse_module(&format!("fn main() {{ let int value = {spelling}; }}"))
                .unwrap_or_else(|error| panic!("signed endpoint `{spelling}` failed: {error}"));
        }
        let positive_neighbor_hex = format!("0x8{}", "0".repeat(127));
        let negative_neighbor_hex = format!("-0x8{}1", "0".repeat(126));
        let positive_neighbor_binary = format!("0b1{}", "0".repeat(511));
        let negative_neighbor_binary = format!("-0b1{}1", "0".repeat(510));
        for spelling in [
            positive_neighbor_hex,
            negative_neighbor_hex,
            positive_neighbor_binary,
            negative_neighbor_binary,
        ] {
            let error = parse_module(&format!("fn main() {{ let int value = {spelling}; }}"))
                .expect_err("neighbor outside the signed domain must fail");
            assert!(
                error.contains("E_INT_LITERAL_OVERFLOW"),
                "{spelling}: {error}"
            );
        }
    }
    #[test]
    fn source_macros_are_rejected_without_ast_rewriting() {
        for src in [
            r#"fn main() { let x = account!("alice"); }"#,
            r#"fn main() { let x = json!{ value: 1 }; }"#,
            r#"fn main() { let x = blob!("bytes"); }"#,
        ] {
            let err = parse_module(src).expect_err("V1 source macro must be rejected");
            assert!(
                err.contains("Kotodama has no macros"),
                "unexpected error: {err}"
            );
        }
    }
    #[test]
    fn parse_tuple_index_literal() {
        let src = "fn main() { let t = (1, 2); let x = t.1; }";
        parse_module(src).expect("parse tuple index");
    }
    #[test]
    fn bounded_collection_attribute_is_rejected() {
        let src = "fn f(StateMap<int, int> m) { for (k, v) in m #[bounded(1)] { let z = k; } }";
        let error = parse_module(src).expect_err("#[bounded] is not Kotodama V1 syntax");
        assert!(error.contains("expected"), "{error}");
    }
    #[test]
    fn collection_call_bounds_are_checked_by_semantics() {
        for iterator in ["take(m, 1)", "range(m, 0, 1)"] {
            let source = format!(
                "fn f(StateMap<int, int> m) {{ for (k, v) in {iterator} {{ let z = k; }} }}"
            );
            parse_module(&source).expect("collection expressions are parsed uniformly");
        }
    }
    #[test]
    fn parse_compound_assignment_keeps_rhs() {
        let src = "fn f() { m[0] += 1; }";
        let prog = parse_module(src).expect("parse compound assignment");
        let func = prog
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(f) => Some(f),
                _ => None,
            })
            .expect("function present");
        let stmt = func.body.statements.first().expect("statement present");
        match stmt.kind() {
            Statement::AssignExpr { op, value, .. } => {
                assert_eq!(*op, AssignOp::Add);
                assert!(matches!(value.kind(), Expr::IntLiteral(value) if value == &BigInt::one()));
            }
            other => panic!("expected compound assignment, got {other:?}"),
        }
    }
    #[test]
    fn parse_bytes_literal() {
        let src = r#"fn main() { let b = b"ab"; }"#;
        let prog = parse_module(src).expect("parse bytes literal");
        let func = prog
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(f) => Some(f),
                _ => None,
            })
            .expect("function present");
        let stmt = func.body.statements.first().expect("statement present");
        match stmt.kind() {
            Statement::Let { value, .. } => match value.kind() {
                Expr::Bytes(bytes) => assert_eq!(bytes, b"ab"),
                other => panic!("expected bytes literal, got {other:?}"),
            },
            other => panic!("expected let statement, got {other:?}"),
        }
    }
    #[test]
    fn parse_access_attributes_are_rejected() {
        let src = r#"
        #[access(read="state:Foo", write=["state:Foo/1", "state:Foo/2"])]
        fn main() {}
        "#;
        let err = parse_module(src).expect_err("manual access attributes should be rejected");
        assert!(err.contains("manual `#[access(...)]` hints are not supported"));
        assert!(err.contains("access metadata is generated by the compiler"));
    }
    #[test]
    fn parse_rejects_state_parameter_annotations() {
        let src = r#"
        fn helper(state StateMap<Name, int> balances, Name key) {}
        "#;
        let err = parse_module(src).expect_err("state parameters must be rejected");
        assert!(err.contains("state cannot be passed as a parameter"));
    }
    #[test]
    fn bare_helpers_are_deferred_to_name_resolution() {
        for source in [
            "fn f(StateMap<int, int> m) { let _x = get_or(m, 1, 7); }",
            "fn f(Json ev) { let _x = get_int(ev, Name::parse(\"n\")); }",
            "fn f(Option<int> value) { let _x = is_some(value); }",
        ] {
            parse_module(source).expect("bare names may refer to declared private helpers");
        }
    }
    #[test]
    fn state_map_get_method_preserves_call_form_for_resolution() {
        let program = parse_module(
            "fn get(int value) -> int { return value; } \
             fn use_get(StateMap<int, int> map) { \
                 let optional = map.get(1); \
                 let ordinary = get(1); \
             }",
        )
        .expect("method and free calls should parse");
        let Item::Function(function) = &program.items[1] else {
            panic!("expected use_get function");
        };
        let Statement::Let {
            value: method_call, ..
        } = function.body.statements[0].kind()
        else {
            panic!("expected StateMap.get call");
        };
        let Expr::Call { name: method, .. } = method_call.kind() else {
            panic!("expected StateMap.get call expression");
        };
        let Statement::Let {
            value: free_call, ..
        } = function.body.statements[1].kind()
        else {
            panic!("expected free get call");
        };
        let Expr::Call { name: free, .. } = free_call.kind() else {
            panic!("expected free get call expression");
        };
        assert_eq!(method, STATE_MAP_GET_INTRINSIC);
        assert_eq!(free, "get");
    }
    #[test]
    fn parse_rejects_removed_method_map_aliases() {
        let err = parse_module("fn f(StateMap<int, int> m) { let _x = m.has(1); }")
            .expect_err("method has should be rejected");
        assert!(err.contains("map.contains(key)"), "unexpected error: {err}");
        let err =
            parse_module("fn f(StateMap<int, int> m) { let _x = m.get_or_insert_default(1, 7); }")
                .expect_err("method get_or_insert_default should be rejected");
        assert!(
            err.contains("map.get_or_insert(key, default)"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn parse_rejects_removed_method_path_and_json_aliases() {
        let err = parse_module("fn f(Name base) { let _x = base.path_map_key(7); }")
            .expect_err("method path_map_key should be rejected");
        assert!(
            err.contains("base.path(segment)"),
            "unexpected error: {err}"
        );
        let err = parse_module("fn f(Json ev) { let _x = ev.json_get_int(Name::parse(\"n\")); }")
            .expect_err("method json_get_int should be rejected");
        assert!(err.contains("json.get_int(key)"), "unexpected error: {err}");
    }
    #[test]
    fn parse_rejects_constructor_method_aliases() {
        for source in [
            r#"module M { fn f(string value) { let _id = value.account_id(); } }"#,
            r#"module M { fn f(string value) { let _name = value.name(); } }"#,
            r#"module M { fn f(string value) { let _json = value.json(); } }"#,
            r#"module M { fn f(bytes value) { let _raw = value.norito_bytes(); } }"#,
        ] {
            let error = parse(source).expect_err("constructor method alias must be rejected");
            assert!(
                error.contains("constructor method aliases were removed"),
                "unexpected error: {error}"
            );
        }
    }
    #[test]
    fn source_localization_tables_are_not_part_of_v1() {
        for spelling in ["messages", "kotoba"] {
            let source =
                format!(r#"module Localization {{ {spelling} {{ key: {{ en: "value" }} }} }}"#);
            let error = parse(&source).expect_err("source localization tables must be rejected");
            assert!(
                error.contains("expected a declaration ("),
                "unexpected diagnostic for {spelling}: {error}"
            );
        }
    }
    #[test]
    fn parse_trigger_decl() {
        let authority = sample_account_literal();
        let src = format!(
            r#"
        seiyaku C {{ permission Run;
            kotoage fn run() authorize(Run) {{}}
            trigger wake -> run {{
                on time pre_commit;
                repeats 3;
                authority "{authority}";
                metadata {{ tag: "alpha"; count: 1; enabled: true; }}
            }}
        }}
        "#
        );
        let prog = parse(&src).expect("parse trigger decl");
        let trigger = prog
            .items
            .iter()
            .find_map(|item| match item {
                Item::Trigger(t) => Some(t),
                _ => None,
            })
            .expect("trigger present");
        assert_eq!(trigger.name, "wake");
        assert_eq!(trigger.call.entrypoint, "run");
        assert!(matches!(trigger.filter, TriggerFilter::Time(_)));
        assert_eq!(trigger.authority.as_deref(), Some(authority.as_str()));
        assert_eq!(trigger.metadata.len(), 3);
    }
    #[test]
    fn malformed_trigger_drops_schedule_expressions_on_a_small_stack() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let expression = std::iter::repeat_n("1", 4_000).collect::<Vec<_>>().join(" + ");
                let source = format!(
                    "seiyaku Clock {{ kotoage fn run() authorize(anyone) {{}} trigger tick -> run {{ on time schedule(start_ms: {expression}); invalid_field; }} }}"
                );
                assert!(parse(&source).is_err(), "malformed trigger is rejected without recursive cleanup");
            })
            .expect("spawn bounded-stack trigger parser")
            .join()
            .expect("trigger schedule cleanup is iterative");
    }
    #[test]
    fn trigger_schedule_requires_canonical_labels() {
        for arguments in [
            "0",
            "0, 1_000",
            "start_ms: 0, 1_000",
            "period_ms: 1_000",
            "start_ms: 0, start_ms: 1_000",
        ] {
            let source = format!(
                "seiyaku Clock {{ kotoage fn run() authorize(anyone) {{}} trigger wake -> run {{ on time schedule({arguments}); }} }}"
            );
            let error = parse(&source).expect_err("labels and declaration order are mandatory");
            assert!(
                error.contains("E_TRIGGER_SCHEDULE_ARGUMENT"),
                "{arguments}: {error}"
            );
        }
        for arguments in [
            "start_ms: 0",
            "start_ms: 0,",
            "start_ms: 0, period_ms: 1_000,",
        ] {
            let source = format!(
                "seiyaku Clock {{ kotoage fn run() authorize(anyone) {{}} trigger wake -> run {{ on time schedule({arguments}); }} }}"
            );
            parse(&source).unwrap_or_else(|error| panic!("{arguments}: {error}"));
        }
    }
    #[test]
    fn trigger_declarations_require_arrow_target_syntax() {
        for source in [
            "seiyaku Demo { register_trigger wake { on execute Name::parse(\"tick\"); } }",
            "seiyaku Demo { trigger wake { call run; on execute Name::parse(\"tick\"); } }",
        ] {
            parse(source).expect_err("retired trigger declaration syntax must fail");
        }
    }
    #[test]
    fn call_statement_sugar_is_rejected() {
        parse("seiyaku Demo { fn run() { call helper(); } fn helper() {} }")
            .expect_err("statement-level call sugar must fail");
    }
    #[test]
    fn parse_trigger_decl_rejects_duplicate_control_fields() {
        for (field, duplicate_line, expected) in [
            (
                "on",
                "on time pre_commit;",
                "trigger field `on` is declared more than once",
            ),
            (
                "repeats",
                "repeats 2;",
                "trigger field `repeats` is declared more than once",
            ),
            (
                "authority",
                r#"authority "alice";"#,
                "trigger field `authority` is declared more than once",
            ),
        ] {
            let src = format!(
                r#"
            seiyaku C {{ permission Run;
                kotoage fn run() authorize(Run) {{}}
                trigger wake -> run {{
                    on time pre_commit;
                    repeats 1;
                    authority "bob";
                    {duplicate_line}
                }}
            }}
            "#
            );
            let err = parse(&src).unwrap_err();
            assert!(err.contains(expected), "{field}: unexpected error: {err}");
        }
    }
    #[test]
    fn parse_trigger_decl_rejects_negative_and_overflow_repeats() {
        for (repeats, expected) in [
            (
                "-1",
                "expected a non-negative integer literal for `repeats`, found `-`",
            ),
            ("4294967296", "repeats integer literal out of range"),
        ] {
            let src = format!(
                r#"
            seiyaku C {{ permission Run;
                kotoage fn run() authorize(Run) {{}}
                trigger wake -> run {{
                    on time pre_commit;
                    repeats {repeats};
                }}
            }}
            "#
            );
            let err = parse(&src).unwrap_err();
            assert!(err.contains(expected), "unexpected error: {err}");
        }
    }
    #[test]
    fn parse_trigger_decl_with_data_filter() {
        let src = r#"
        seiyaku C { permission Run;
            kotoage fn run() authorize(Run) {}
            trigger wake -> run {
                on data any;
            }
        }
        "#;
        let prog = parse(src).expect("parse trigger decl");
        let trigger = prog
            .items
            .iter()
            .find_map(|item| match item {
                Item::Trigger(t) => Some(t),
                _ => None,
            })
            .expect("trigger present");
        assert!(matches!(trigger.filter, TriggerFilter::Data(_)));
    }
    fn sample_asset_definition_literal() -> String {
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            "rose".parse().expect("name"),
        )
        .to_string()
    }
    #[test]
    fn parse_trigger_decl_with_structured_data_filter() {
        let asset_definition = sample_asset_definition_literal();
        let src = format!(
            r#"
        seiyaku C {{ permission Run;
            kotoage fn run() authorize(Run) {{}}
            trigger wake -> run {{
                on data asset added {{
                    asset_definition "{asset_definition}";
                }}
            }}
        }}
        "#
        );
        let prog = parse(&src).expect("parse trigger decl");
        let trigger = prog
            .items
            .iter()
            .find_map(|item| match item {
                Item::Trigger(t) => Some(t),
                _ => None,
            })
            .expect("trigger present");
        let TriggerFilter::Data(TriggerDataFilter::Structured(filter)) = &trigger.filter else {
            panic!("expected structured data filter");
        };
        assert_eq!(filter.family, TriggerDataFamily::Asset);
        assert_eq!(
            filter.event,
            TriggerDataEventKind::Named("added".to_string())
        );
        assert_eq!(filter.matchers.len(), 1);
        assert_eq!(filter.matchers[0].key, "asset_definition");
        assert_eq!(filter.matchers[0].value, asset_definition);
    }
    include!("parser/tests/trigger_filter_core_families.rs");
    #[test]
    fn parse_trigger_decl_rejects_nondeterministic_pipeline_filter() {
        let src = r#"
        seiyaku C { permission Run;
            kotoage fn run() authorize(Run) {}
            trigger wake -> run {
                on pipeline merge;
            }
        }
        "#;
        let err = parse(src).expect_err("parse should reject unsupported pipeline filter");
        assert!(err.contains("transaction [approved]"));
    }
    include!("parser/tests/tail_fixtures.rs");
    mod diagnostics {
        use crate::{
            diagnostic::{Diagnostic, DiagnosticFix, DiagnosticPhase},
            source::{FrontendBudget, SourceFile, SourceId},
        };
        include!("parser/tests/diagnostics.rs");
    }
    #[test]
    fn native_events_share_product_fields_but_require_emit_record_statements() {
        let source = "誓約 Events { event Transfer { int first; int second; } 言挙げ fn run() authorize(anyone) { emit Transfer { second: 2, first: 1 }; } }";
        let program = parse(source).unwrap();
        assert!(matches!(program.items[0], Item::Event(_)));
        let Item::Function(function) = &program.items[1] else {
            panic!("event entrypoint")
        };
        assert!(matches!(
            function.body.statements[0].kind(),
            Statement::Emit(_)
        ));
        assert_eq!(program.clone(), program);
        for invalid in [
            "module Library { event Note { int value; } }",
            "seiyaku Events { event Note {} fn bad() { emit 1; } }",
            "seiyaku Events { event Note { int value; } fn bad() { emit Note { value: 1, value: 2 }; } }",
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
    }
}

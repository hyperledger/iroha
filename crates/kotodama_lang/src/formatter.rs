//! Deterministic formatter for the canonical Kotodama V1 token stream.
//!
//! The formatter re-prints the compiler's lossless tokens using the parser's own
//! syntax roles (record bodies, argument and parameter lists, list literals,
//! attributes and type positions), so layout never depends on guessing what a
//! token means from its spelling. Branded keywords keep the script the author
//! wrote at each site; `kotoage` and `言挙げ` are the same token and either may
//! appear anywhere.
use crate::{
    diagnostic::{Diagnostic, DiagnosticBundle, DiagnosticPhase, SourcePosition, SourceSpan},
    source::{FrontendBudget, MAX_SOURCE_BYTES, SourceFile, TextRange},
    syntax::{GreenElement, GreenNode, GreenToken, SyntaxKind},
};
use std::collections::{BTreeMap, BTreeSet};
const INDENT: &str = "    ";
const TARGET_COLUMNS: usize = 100;
/// Format one syntactically valid Kotodama V1 source file.
///
/// Invalid sources are returned as diagnostics rather than being partly rewritten. Comments and
/// literal spellings are preserved byte-for-byte, and each comment stays with the code it
/// annotated: a comment that followed a token on the same line remains a trailing comment of that
/// token (a line comment after the `,` or `;` that ends it, a block comment ahead of it), and a
/// block comment that leads code on its line stays in front of that code. Attributes stay on
/// their own line above the item or error variant they annotate.
/// Whitespace between tokens is canonicalized with a 100-column target: a line breaks at its
/// loosest break point first and again, one level deeper, at tighter ones while it still does not
/// fit. At most one blank line written between members or declarations is kept. The only token
/// rewrites are canonical separators: struct fields, error variants and `koto_test` entries are
/// separated by `,`; trigger fields and fixture actions end with `;` unless they end with a
/// block, which takes none; comma-delimited lists laid out over several lines end with a
/// trailing comma, single-line ones do not; and redundant parentheses around a whole `if`
/// condition are removed.
pub fn format_source(
    source: &SourceFile,
    budget: FrontendBudget,
) -> Result<String, DiagnosticBundle> {
    let crate::syntax::ProgramParseOutput {
        tree,
        program,
        diagnostics,
        ..
    } = crate::syntax::parse_source_or_fragment(source, budget);
    let Some(program) = program else {
        return Err(diagnostics);
    };
    debug_assert!(diagnostics.diagnostics.is_empty());
    crate::ast::drop_program_iterative(program);
    let type_ranges = parsed_type_ranges(source, budget)?;
    let roles = SyntaxRoles::collect(tree.root());
    let tokens = prepare_tokens(source, &tree.into_tokens(), &roles, &type_ranges);
    Printer::new(&tokens)
        .print()
        .ok_or_else(|| formatted_source_too_large(source))
}
/// Return the exact source ranges the parser accepted as type expressions.
///
/// Generic delimiters are recognized from the parser's own type grammar, so every generic type
/// (`StateCursor<Name>`, `StatePage<K, V, N>`, user paths, ...) is formatted the same way and a
/// comparison is never mistaken for a type argument list.
fn parsed_type_ranges(
    source: &SourceFile,
    budget: FrontendBudget,
) -> Result<Vec<TextRange>, DiagnosticBundle> {
    let (spanned, _) = crate::syntax::parser::parse_spanned_source_or_fragment(source, budget)?;
    let crate::spanned_ast::SpannedProgram { program, facts } = spanned;
    crate::ast::drop_program_iterative(program);
    let mut ranges = facts
        .source_map
        .nodes()
        .filter(|node| node.kind == crate::spanned_ast::AstNodeKind::Type)
        .map(|node| node.range)
        .filter(|range| !range.is_empty())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| (range.start, range.end));
    // Type arguments are nested type nodes; keep the outermost extents only.
    let mut merged: Vec<TextRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start < last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    Ok(merged)
}
fn formatted_source_too_large(source: &SourceFile) -> DiagnosticBundle {
    let range = source.full_range();
    let end = source.line_column(range.end);
    let mut diagnostic = Diagnostic::error(
        "K0001",
        DiagnosticPhase::Lex,
        format!(
            "canonical formatting would exceed the {MAX_SOURCE_BYTES}-byte Kotodama V1 source limit"
        ),
        Some(SourceSpan {
            package_identity: source.package_identity().map(str::to_owned),
            source: Some(source.name().to_owned()),
            start: SourcePosition { line: 1, column: 1 },
            end: SourcePosition {
                line: end.line,
                column: end.column,
            },
            byte_range: Some(range),
        }),
    );
    diagnostic.help = Some(
        "Split the source into typed modules so the formatted deployable source remains within the V1 limit."
            .to_owned(),
    );
    DiagnosticBundle::single(diagnostic)
}
/// Layout family of one `{ ... }` pair, taken from the enclosing syntax node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BraceKind {
    /// Statement block, source-unit body or trigger body.
    Block,
    /// Exhaustive `match` arms.
    Match,
    /// Struct literal or native JSON object.
    Record,
    /// Struct destructuring pattern; stays on one line whenever it fits.
    Pattern,
    /// `koto_test { target: "..." }` entries.
    TestTarget,
    /// Struct declaration fields.
    StructFields,
    /// Error-enum variants.
    EnumVariants,
}
impl BraceKind {
    /// Whether the members are comma separated and end with a trailing comma when multi-line.
    const fn comma_separated(self) -> bool {
        !matches!(self, Self::Block)
    }
    /// Whether the braces opened at `open` and closed at `close` may stay on one line when they
    /// fit: records and `koto_test` blocks with at most one member, and struct patterns of any
    /// size. Comments and nested braces always force the multi-line layout.
    fn may_stay_inline(self, tokens: &[Tok<'_>], open: usize, close: usize) -> bool {
        match self {
            Self::Record | Self::TestTarget => record_is_compact(tokens, open, close),
            Self::Pattern => tokens.get(open + 1..close).is_some_and(|inner| {
                !inner.iter().any(|token| {
                    token.is_comment()
                        || matches!(token.kind, SyntaxKind::LBrace | SyntaxKind::RBrace)
                })
            }),
            Self::Block | Self::Match | Self::StructFields | Self::EnumVariants => false,
        }
    }
}
/// Formatting role of one token, derived from the syntax tree and the parser's type ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// No structural role beyond the token kind.
    Plain,
    /// `<` opening a type argument list.
    GenericOpen,
    /// `>` closing a type argument list.
    GenericClose,
    /// `{` of the given layout family.
    Brace(BraceKind),
    /// `(` of a call argument list or fixture action; may break one item per line.
    BreakableParen,
    /// `(` of a declaration's parameter list; breaks before anything else in the header.
    ParamParen,
    /// `(` of a tuple expression, tuple type or tuple pattern; may break one item per line, but
    /// the grammar admits no trailing comma.
    TupleParen,
    /// `[` of a list literal, comprehension or JSON array; may break one item per line.
    List { trailing_comma: bool, json: bool },
    /// `#` starting an item or error-variant attribute.
    AttributeStart,
    /// `]` ending an item or error-variant attribute.
    AttributeEnd,
    /// `}` ending a declaration item.
    ItemBlockEnd,
}
/// Formatter-relevant syntax roles keyed by token start offset.
#[derive(Default)]
struct SyntaxRoles {
    braces: BTreeMap<u32, BraceKind>,
    breakable_parens: BTreeSet<u32>,
    parameter_lists: BTreeSet<u32>,
    lists: BTreeMap<u32, (bool, bool)>,
    attribute_starts: BTreeSet<u32>,
    attribute_ends: BTreeSet<u32>,
    item_ends: BTreeSet<u32>,
    /// Opening braces of trigger bodies.
    trigger_bodies: BTreeSet<u32>,
    /// Opening parentheses of fixture actions.
    fixture_actions: BTreeSet<u32>,
}
impl SyntaxRoles {
    fn collect(root: &GreenNode) -> Self {
        let mut roles = Self::default();
        let mut nodes = vec![root];
        while let Some(node) = nodes.pop() {
            let direct = |kind: SyntaxKind| {
                node.children.iter().find_map(|child| match child {
                    GreenElement::Token(token) if token.kind == kind => Some(token.range.start),
                    _ => None,
                })
            };
            let brace = match node.kind {
                SyntaxKind::StructLiteral
                | SyntaxKind::ArgumentRecord
                | SyntaxKind::JsonObjectExpr => Some(BraceKind::Record),
                SyntaxKind::StructPattern => Some(BraceKind::Pattern),
                SyntaxKind::TestTargetItem => Some(BraceKind::TestTarget),
                SyntaxKind::StructItem | SyntaxKind::EventItem => Some(BraceKind::StructFields),
                SyntaxKind::EnumItem => Some(BraceKind::EnumVariants),
                SyntaxKind::MatchExpr => Some(BraceKind::Match),
                _ => None,
            };
            if let Some(kind) = brace
                && let Some(start) = direct(SyntaxKind::LBrace)
            {
                roles.braces.insert(start, kind);
            }
            match node.kind {
                SyntaxKind::ArgumentList => {
                    if let Some(start) = direct(SyntaxKind::LParen) {
                        roles.breakable_parens.insert(start);
                    }
                }
                SyntaxKind::ParamList => {
                    if let Some(start) = direct(SyntaxKind::LParen) {
                        roles.parameter_lists.insert(start);
                    }
                }
                SyntaxKind::TriggerItem => {
                    if let Some(start) = direct(SyntaxKind::LBrace) {
                        roles.trigger_bodies.insert(start);
                    }
                }
                SyntaxKind::FixtureItem => {
                    // Fixture actions are call-shaped and admit a trailing comma.
                    let actions = node.children.iter().filter_map(|child| match child {
                        GreenElement::Token(token) if token.kind == SyntaxKind::LParen => {
                            Some(token.range.start)
                        }
                        _ => None,
                    });
                    for start in actions {
                        roles.breakable_parens.insert(start);
                        roles.fixture_actions.insert(start);
                    }
                }
                SyntaxKind::ListExpr
                | SyntaxKind::ListComprehension
                | SyntaxKind::JsonArrayExpr => {
                    if let Some(start) = direct(SyntaxKind::LBracket) {
                        roles.lists.insert(
                            start,
                            (
                                node.kind != SyntaxKind::ListComprehension,
                                node.kind == SyntaxKind::JsonArrayExpr,
                            ),
                        );
                    }
                }
                SyntaxKind::Attribute => {
                    if let Some(start) = direct(SyntaxKind::Hash) {
                        roles.attribute_starts.insert(start);
                    }
                    if let Some(end) = node.children.iter().rev().find_map(|child| match child {
                        GreenElement::Token(token) if token.kind == SyntaxKind::RBracket => {
                            Some(token.range.start)
                        }
                        _ => None,
                    }) {
                        roles.attribute_ends.insert(end);
                    }
                }
                _ => {}
            }
            if matches!(
                node.kind,
                SyntaxKind::FunctionItem
                    | SyntaxKind::StructItem
                    | SyntaxKind::EventItem
                    | SyntaxKind::EnumItem
                    | SyntaxKind::TriggerItem
                    | SyntaxKind::FixtureItem
                    | SyntaxKind::TestTargetItem
            ) && let Some(token) = last_significant_token(node)
                && token.kind == SyntaxKind::RBrace
            {
                roles.item_ends.insert(token.range.start);
            }
            nodes.extend(node.children.iter().filter_map(|child| match child {
                GreenElement::Node(child) => Some(child.as_ref()),
                GreenElement::Token(_) => None,
            }));
        }
        roles
    }
}
fn last_significant_token(node: &GreenNode) -> Option<&GreenToken> {
    let mut current = node;
    'descend: loop {
        for child in current.children.iter().rev() {
            match child {
                GreenElement::Token(token)
                    if token.kind.is_trivia()
                        || matches!(token.kind, SyntaxKind::Missing | SyntaxKind::Eof) => {}
                GreenElement::Token(token) => return Some(token),
                GreenElement::Node(child) => {
                    current = child.as_ref();
                    continue 'descend;
                }
            }
        }
        return None;
    }
}
/// One significant source token (or comment) as the printer sees it.
#[derive(Clone, Copy, Debug)]
struct Tok<'source> {
    kind: SyntaxKind,
    text: &'source str,
    start: u32,
    /// Source line breaks between the previous retained token and this one.
    newlines_before: usize,
    role: Role,
    /// The token is a path segment after `::`; branded keywords there are spaced like names.
    segment: bool,
}
impl Tok<'_> {
    const fn is_comment(&self) -> bool {
        matches!(
            self.kind,
            SyntaxKind::LineComment | SyntaxKind::DocComment | SyntaxKind::BlockComment
        )
    }
    fn separator(kind: SyntaxKind, at: u32) -> Self {
        Self {
            kind,
            text: if kind == SyntaxKind::Comma { "," } else { ";" },
            start: at,
            newlines_before: 0,
            role: Role::Plain,
            segment: false,
        }
    }
}
fn prepare_tokens<'source>(
    source: &'source SourceFile,
    lossless: &[GreenToken],
    roles: &SyntaxRoles,
    type_ranges: &[TextRange],
) -> Vec<Tok<'source>> {
    let text = source.text();
    let in_type = |offset: u32| {
        let index = type_ranges.partition_point(|range| range.start <= offset);
        index
            .checked_sub(1)
            .and_then(|index| type_ranges.get(index))
            .is_some_and(|range| offset < range.end)
    };
    let mut tokens = Vec::with_capacity(lossless.len() / 2);
    let mut previous_end: Option<(u32, bool)> = None;
    let mut previous_kind: Option<SyntaxKind> = None;
    let mut open_generics = 0_usize;
    for token in lossless {
        if matches!(
            token.kind,
            SyntaxKind::Whitespace | SyntaxKind::Missing | SyntaxKind::Eof
        ) {
            continue;
        }
        let token_text = source.slice(token.range).unwrap_or_default();
        let newlines_before = previous_end.map_or(0, |(end, line_comment)| {
            let gap = text
                .get(end as usize..token.range.start as usize)
                .unwrap_or_default();
            gap.matches('\n').count() + usize::from(line_comment)
        });
        let start = token.range.start;
        let role = match token.kind {
            SyntaxKind::LBrace => Role::Brace(
                roles
                    .braces
                    .get(&start)
                    .copied()
                    .unwrap_or(BraceKind::Block),
            ),
            SyntaxKind::LParen if roles.breakable_parens.contains(&start) => Role::BreakableParen,
            SyntaxKind::LParen if roles.parameter_lists.contains(&start) => Role::ParamParen,
            SyntaxKind::LBracket => {
                roles
                    .lists
                    .get(&start)
                    .map_or(Role::Plain, |&(trailing_comma, json)| Role::List {
                        trailing_comma,
                        json,
                    })
            }
            SyntaxKind::Hash if roles.attribute_starts.contains(&start) => Role::AttributeStart,
            SyntaxKind::RBracket if roles.attribute_ends.contains(&start) => Role::AttributeEnd,
            SyntaxKind::RBrace if roles.item_ends.contains(&start) => Role::ItemBlockEnd,
            SyntaxKind::Less if in_type(start) && previous_kind == Some(SyntaxKind::Ident) => {
                open_generics = open_generics.saturating_add(1);
                Role::GenericOpen
            }
            SyntaxKind::Greater if in_type(start) && open_generics != 0 => {
                open_generics = open_generics.saturating_sub(1);
                Role::GenericClose
            }
            _ => Role::Plain,
        };
        tokens.push(Tok {
            kind: token.kind,
            text: token_text,
            start,
            newlines_before,
            role,
            segment: previous_kind == Some(SyntaxKind::ColonColon)
                && !token.kind.is_line_comment()
                && token.kind != SyntaxKind::BlockComment,
        });
        previous_end = Some((
            token.range.end,
            token.kind.is_line_comment() && token_text.ends_with('\n'),
        ));
        if !token.kind.is_trivia() {
            previous_kind = Some(token.kind);
        }
    }
    demote_unbalanced_generics(&mut tokens);
    let tokens = normalize_record_separators(tokens, type_ranges, &in_type);
    let mut tokens =
        canonicalize_terminators(tokens, &roles.trigger_bodies, &roles.fixture_actions);
    bind_separators_before_comments(&mut tokens);
    let mut tokens = remove_redundant_condition_parentheses(tokens);
    mark_tuple_parentheses(&mut tokens);
    tokens
}
/// Bind every `,` and `;` to the token before it, ahead of the comments that follow that token.
///
/// Block comments written on the same line as the token stay with it, before the separator
/// (`amount /* in nanos */, fee`); a line comment or a comment on a later line follows the
/// separator (`value; // why`). Layout is then measured on the order the printer writes. The
/// token after the separator keeps a blank line that separated the comments from the separator.
fn bind_separators_before_comments(tokens: &mut [Tok<'_>]) {
    for index in 1..tokens.len() {
        if !matches!(
            tokens[index].kind,
            SyntaxKind::Comma | SyntaxKind::Semicolon
        ) {
            continue;
        }
        let first_comment = (0..index)
            .rev()
            .take_while(|&before| tokens[before].is_comment())
            .last()
            .unwrap_or(index);
        if first_comment == 0 {
            continue;
        }
        let same_line = tokens[first_comment..index]
            .iter()
            .take_while(|token| {
                token.kind == SyntaxKind::BlockComment && token.newlines_before == 0
            })
            .count();
        let target = first_comment + same_line;
        if target == index && tokens[index].newlines_before == 0 {
            continue;
        }
        let carried = tokens[index].newlines_before;
        if let Some(next) = tokens.get_mut(index + 1) {
            next.newlines_before = next.newlines_before.max(carried);
        }
        tokens[target..=index].rotate_right(1);
        tokens[target].newlines_before = 0;
    }
}
/// Mark plain parentheses that hold a comma-separated tuple (expression, type or pattern).
///
/// Parentheses that follow a name, `)`/`]`, `>` or a declaration keyword belong to call-shaped
/// grammar (trigger schedules, attributes, `authorize`) and stay on one line.
fn mark_tuple_parentheses(tokens: &mut [Tok<'_>]) {
    let partners = delimiter_partners(tokens);
    let mut previous: Option<SyntaxKind> = None;
    for index in 0..tokens.len() {
        let token = tokens[index];
        if token.is_comment() {
            continue;
        }
        let call_shaped = matches!(
            previous,
            Some(
                SyntaxKind::Ident
                    | SyntaxKind::RParen
                    | SyntaxKind::RBracket
                    | SyntaxKind::Greater
                    | SyntaxKind::KwAuthorize
                    | SyntaxKind::KwHajimari
                    | SyntaxKind::KwKaizen
            )
        );
        previous = Some(spacing_kind(&token));
        if token.kind != SyntaxKind::LParen || token.role != Role::Plain || call_shaped {
            continue;
        }
        let Some(close) = partners[index] else {
            continue;
        };
        let mut depth = 0_usize;
        let tuple = tokens[index + 1..close].iter().any(|inner| {
            match (inner.kind, inner.role) {
                (SyntaxKind::LParen | SyntaxKind::LBracket | SyntaxKind::LBrace, _)
                | (SyntaxKind::Less, Role::GenericOpen) => depth += 1,
                (SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace, _)
                | (SyntaxKind::Greater, Role::GenericClose) => depth = depth.saturating_sub(1),
                _ => {}
            }
            depth == 0 && inner.kind == SyntaxKind::Comma
        });
        if tuple {
            tokens[index].role = Role::TupleParen;
        }
    }
}
/// Treat any `<`/`>` that does not close within the same delimiter nesting as an operator.
fn demote_unbalanced_generics(tokens: &mut [Tok<'_>]) {
    let mut open: Vec<usize> = Vec::new();
    for index in 0..tokens.len() {
        let token = tokens[index];
        match (token.kind, token.role) {
            (SyntaxKind::LParen | SyntaxKind::LBracket | SyntaxKind::LBrace, _)
            | (SyntaxKind::Less, Role::GenericOpen) => open.push(index),
            (SyntaxKind::Greater, Role::GenericClose) => {
                if open
                    .last()
                    .is_some_and(|&opening| tokens[opening].role == Role::GenericOpen)
                {
                    open.pop();
                } else {
                    tokens[index].role = Role::Plain;
                }
            }
            (SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace, _) => {
                while let Some(&opening) = open.last() {
                    open.pop();
                    if tokens[opening].role == Role::GenericOpen {
                        tokens[opening].role = Role::Plain;
                    } else {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    for opening in open {
        if tokens[opening].role == Role::GenericOpen {
            tokens[opening].role = Role::Plain;
        }
    }
}
/// Match every opening delimiter with its closing delimiter.
fn delimiter_partners(tokens: &[Tok<'_>]) -> Vec<Option<usize>> {
    let mut partners = vec![None; tokens.len()];
    let mut open = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        match (token.kind, token.role) {
            (SyntaxKind::LParen | SyntaxKind::LBracket | SyntaxKind::LBrace, _)
            | (SyntaxKind::Less, Role::GenericOpen) => open.push(index),
            (SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace, _)
            | (SyntaxKind::Greater, Role::GenericClose) => {
                if let Some(opening) = open.pop() {
                    partners[opening] = Some(index);
                    partners[index] = Some(opening);
                }
            }
            _ => {}
        }
    }
    partners
}
/// Canonicalize member separators in struct declarations, error enums and `koto_test` blocks.
///
/// The grammar accepts `,`, `;` or (between struct fields) no separator at all. The canonical
/// spelling is one `,` after each member; stray extra separators are removed. The trailing comma
/// of the last member is supplied by the multi-line layout.
fn normalize_record_separators<'source>(
    tokens: Vec<Tok<'source>>,
    type_ranges: &[TextRange],
    in_type: &dyn Fn(u32) -> bool,
) -> Vec<Tok<'source>> {
    let partners = delimiter_partners(&tokens);
    let mut output = Vec::with_capacity(tokens.len());
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        let body = match token.role {
            Role::Brace(
                kind @ (BraceKind::StructFields | BraceKind::EnumVariants | BraceKind::TestTarget),
            ) => partners[index].map(|close| (kind, close)),
            _ => None,
        };
        output.push(token);
        index += 1;
        let Some((kind, close)) = body else {
            continue;
        };
        let members = &tokens[index..close];
        match kind {
            BraceKind::StructFields if !type_ranges.is_empty() => {
                normalize_struct_fields(members, in_type, &mut output);
            }
            BraceKind::EnumVariants => normalize_enum_variants(members, &mut output),
            _ => {
                output.extend(members.iter().map(|member| {
                    if member.kind == SyntaxKind::Semicolon {
                        Tok::separator(SyntaxKind::Comma, member.start)
                    } else {
                        *member
                    }
                }));
            }
        }
        index = close;
    }
    output
}
fn normalize_struct_fields<'source>(
    members: &[Tok<'source>],
    in_type: &dyn Fn(u32) -> bool,
    output: &mut Vec<Tok<'source>>,
) {
    #[derive(PartialEq, Eq)]
    enum Field {
        Expect,
        Type,
        Name,
    }
    let mut state = Field::Expect;
    let mut after_name = 0;
    for member in members {
        if member.is_comment() {
            output.push(*member);
            continue;
        }
        if in_type(member.start) {
            if state == Field::Name {
                output.insert(after_name, Tok::separator(SyntaxKind::Comma, member.start));
            }
            output.push(*member);
            state = Field::Type;
        } else if matches!(member.kind, SyntaxKind::Comma | SyntaxKind::Semicolon) {
            if state == Field::Name {
                output.push(Tok {
                    kind: SyntaxKind::Comma,
                    text: ",",
                    ..*member
                });
                state = Field::Expect;
            }
        } else {
            output.push(*member);
            if state == Field::Type && member.kind == SyntaxKind::Ident {
                state = Field::Name;
                after_name = output.len();
            }
        }
    }
}
fn normalize_enum_variants<'source>(members: &[Tok<'source>], output: &mut Vec<Tok<'source>>) {
    let mut depth = 0_usize;
    let mut after_code: Option<usize> = None;
    let mut previous = None;
    for member in members {
        if member.is_comment() {
            output.push(*member);
            continue;
        }
        let starts_variant = depth == 0
            && matches!(member.kind, SyntaxKind::Hash | SyntaxKind::Ident)
            && after_code.is_some();
        if starts_variant && let Some(at) = after_code.take() {
            output.insert(at, Tok::separator(SyntaxKind::Comma, member.start));
        }
        match member.kind {
            SyntaxKind::LBracket | SyntaxKind::LParen => depth = depth.saturating_add(1),
            SyntaxKind::RBracket | SyntaxKind::RParen => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 && matches!(member.kind, SyntaxKind::Comma | SyntaxKind::Semicolon) {
            if after_code.take().is_some() {
                output.push(Tok {
                    kind: SyntaxKind::Comma,
                    text: ",",
                    ..*member
                });
            }
        } else {
            output.push(*member);
            if depth == 0
                && member.kind == SyntaxKind::Number
                && previous == Some(SyntaxKind::Equal)
            {
                after_code = Some(output.len());
            }
        }
        previous = Some(member.kind);
    }
}
/// Canonicalize the optional `;` after trigger fields and fixture actions.
///
/// The grammar requires `;` after `repeats` and `authority` but makes it optional after an `on`
/// filter, a `metadata` block and a fixture action. The canonical spelling terminates each of
/// them with `;` unless it ends with a block, and drops the `;` after one that does, so every
/// field and action starts its own line (`on time pre_commit;`, `on data account created { ... }`,
/// `metadata { ... }`, `actor(...);`).
fn canonicalize_terminators<'source>(
    tokens: Vec<Tok<'source>>,
    trigger_bodies: &BTreeSet<u32>,
    fixture_actions: &BTreeSet<u32>,
) -> Vec<Tok<'source>> {
    if trigger_bodies.is_empty() && fixture_actions.is_empty() {
        return tokens;
    }
    let partners = delimiter_partners(&tokens);
    let mut terminate_after = BTreeSet::new();
    let mut remove = BTreeSet::new();
    // Canonicalize the terminator of a field or action whose last token is `last`.
    let mut terminate = |last: usize, end: usize| {
        let next = next_code(&tokens, last + 1, end);
        let terminated = next.is_some_and(|next| tokens[next].kind == SyntaxKind::Semicolon);
        if tokens[last].kind == SyntaxKind::RBrace {
            if terminated {
                remove.extend(next);
            }
        } else if !terminated {
            // Like a written `;`, the terminator follows block comments on the same line.
            let after = (last + 1..end)
                .take_while(|&index| {
                    tokens[index].kind == SyntaxKind::BlockComment
                        && tokens[index].newlines_before == 0
                })
                .last()
                .unwrap_or(last);
            terminate_after.insert(after);
        }
    };
    for (open, token) in tokens.iter().enumerate() {
        if token.kind == SyntaxKind::LParen && fixture_actions.contains(&token.start) {
            if let Some(close) = partners[open] {
                terminate(close, tokens.len());
            }
            continue;
        }
        if token.kind != SyntaxKind::LBrace || !trigger_bodies.contains(&token.start) {
            continue;
        }
        let Some(close) = partners[open] else {
            continue;
        };
        let mut depth = 0_usize;
        let mut previous = SyntaxKind::LBrace;
        for index in open + 1..close {
            let current = &tokens[index];
            if current.is_comment() {
                continue;
            }
            let field_start = depth == 0
                && matches!(
                    previous,
                    SyntaxKind::LBrace | SyntaxKind::Semicolon | SyntaxKind::RBrace
                );
            if field_start && current.kind == SyntaxKind::Ident {
                let last = match current.text {
                    "on" => trigger_filter_last(&tokens, &partners, index, close),
                    "metadata" => next_code(&tokens, index + 1, close)
                        .filter(|&open| tokens[open].kind == SyntaxKind::LBrace)
                        .and_then(|open| partners[open])
                        .filter(|&last| last < close),
                    _ => None,
                };
                if let Some(last) = last {
                    terminate(last, close);
                }
            }
            match current.kind {
                SyntaxKind::LParen | SyntaxKind::LBracket | SyntaxKind::LBrace => depth += 1,
                SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
            previous = current.kind;
        }
    }
    let mut output = Vec::with_capacity(tokens.len() + terminate_after.len());
    for (index, token) in tokens.into_iter().enumerate() {
        if remove.contains(&index) {
            continue;
        }
        let end = token
            .start
            .saturating_add(u32::try_from(token.text.len()).unwrap_or(0));
        output.push(token);
        if terminate_after.contains(&index) {
            output.push(Tok::separator(SyntaxKind::Semicolon, end));
        }
    }
    output
}
/// Index of the first non-comment token in `from..end`.
fn next_code(tokens: &[Tok<'_>], from: usize, end: usize) -> Option<usize> {
    (from..end).find(|&index| !tokens[index].is_comment())
}
/// Return the index of the last token of the trigger filter that follows `on` at `on`.
///
/// Mirrors the closed filter grammar: `time pre_commit`, `time schedule(...)`,
/// `execute trigger <name>`, `data any`, `data <family> <event> { ... }` and
/// `pipeline transaction|block [approved]`. Returns `None` for anything else.
fn trigger_filter_last(
    tokens: &[Tok<'_>],
    partners: &[Option<usize>],
    on: usize,
    end: usize,
) -> Option<usize> {
    let next = |index: usize| next_code(tokens, index + 1, end);
    let kind = next(on)?;
    let first = next(kind)?;
    match tokens[kind].text {
        "time" => match tokens[first].text {
            "pre_commit" => Some(first),
            "schedule" => next(first)
                .filter(|&open| tokens[open].kind == SyntaxKind::LParen)
                .and_then(|open| partners[open]),
            _ => None,
        },
        "execute" => next(first),
        "data" if tokens[first].text == "any" => Some(first),
        "data" => next(first)
            .and_then(next)
            .filter(|&open| tokens[open].kind == SyntaxKind::LBrace)
            .and_then(|open| partners[open]),
        "pipeline" => Some(
            next(first)
                .filter(|&approved| {
                    tokens[approved].kind == SyntaxKind::Ident
                        && tokens[approved].text == "approved"
                })
                .unwrap_or(first),
        ),
        _ => None,
    }
    .filter(|&last| last < end)
}
/// Remove parentheses that wrap an entire `if` condition: `if (x > 1) {` becomes `if x > 1 {`.
///
/// Conditions containing braces keep their parentheses, so the rewrite never changes how a
/// struct literal or block in the condition is parsed.
fn remove_redundant_condition_parentheses(tokens: Vec<Tok<'_>>) -> Vec<Tok<'_>> {
    let partners = delimiter_partners(&tokens);
    let mut removed = vec![false; tokens.len()];
    for (index, token) in tokens.iter().enumerate() {
        if token.kind != SyntaxKind::KwIf {
            continue;
        }
        let mut open = index + 1;
        while let Some(close) = tokens
            .get(open)
            .filter(|token| token.kind == SyntaxKind::LParen && token.role == Role::Plain)
            .and_then(|_| partners[open])
        {
            let followed_by_block = tokens.get(close + 1).is_some_and(|token| {
                token.kind == SyntaxKind::LBrace && token.role == Role::Brace(BraceKind::Block)
            }) || (open > index + 1 && removed[close + 1]);
            let inner = &tokens[open + 1..close];
            let mut depth = 0_usize;
            let plain_condition = !inner.is_empty()
                && inner.iter().all(|token| {
                    match token.kind {
                        SyntaxKind::LParen | SyntaxKind::LBracket => {
                            depth = depth.saturating_add(1);
                        }
                        SyntaxKind::RParen | SyntaxKind::RBracket => {
                            depth = depth.saturating_sub(1);
                        }
                        _ => {}
                    }
                    let separates = depth == 0 && token.kind == SyntaxKind::Comma;
                    !separates && !matches!(token.kind, SyntaxKind::LBrace | SyntaxKind::RBrace)
                });
            if !followed_by_block || !plain_condition {
                break;
            }
            removed[open] = true;
            removed[close] = true;
            open += 1;
        }
    }
    tokens
        .into_iter()
        .zip(removed)
        .filter_map(|(token, removed)| (!removed).then_some(token))
        .collect()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroupKind {
    Paren,
    Bracket,
    Generic,
    Brace(BraceKind),
}
#[derive(Clone, Copy, Debug)]
struct Group {
    kind: GroupKind,
    multiline: bool,
    trailing_comma: bool,
    close: usize,
}
/// Spacing state shared by the printer and its single-line width projection.
#[derive(Clone, Copy, Debug, Default)]
struct Spacing {
    previous: Option<SyntaxKind>,
    previous_was_prefix: bool,
}
impl Spacing {
    /// Return whether `kind` is separated from the previous token by a space, and whether it is
    /// a prefix operator at this position.
    fn before(self, kind: SyntaxKind) -> (bool, bool) {
        let is_prefix = is_prefix_operator(kind) && prefix_position(self.previous);
        (
            needs_space(self.previous, self.previous_was_prefix, kind, is_prefix),
            is_prefix,
        )
    }
    fn record(&mut self, kind: SyntaxKind, is_prefix: bool) {
        self.previous = Some(kind);
        self.previous_was_prefix = is_prefix;
    }
}
/// Token kind used for spacing; branded keyword path segments are spaced like names.
fn spacing_kind(token: &Tok<'_>) -> SyntaxKind {
    if token.segment && is_word(token.kind) {
        SyntaxKind::Ident
    } else {
        token.kind
    }
}
struct Printer<'tokens, 'source> {
    tokens: &'tokens [Tok<'source>],
    partners: Vec<Option<usize>>,
    output: String,
    indent: usize,
    at_line_start: bool,
    pending_newlines: usize,
    groups: Vec<Group>,
    spacing: Spacing,
    ternaries: Vec<usize>,
    /// Output offset just after the last significant (non-comment) token.
    anchor: usize,
    last_significant: Option<SyntaxKind>,
    last_role: Role,
    comments_after_anchor: bool,
    /// The pending line break directly follows an opening delimiter.
    group_start: bool,
    /// The current output line ends with a line comment.
    line_comment_open: bool,
    /// Statements and list members currently being printed, innermost last.
    regions: Vec<Region>,
    overflowed: bool,
}
/// One statement, condition or list member that starts a line.
///
/// When it cannot fit within the target on one line, it breaks before each of its lowest-precedence
/// top-level operators, continuing one indentation level deeper. A continuation line that still
/// exceeds the target breaks again before its own lowest-precedence operators, one level deeper
/// still.
#[derive(Clone, Debug)]
struct Region {
    /// Index of the token that ends the region (`;`, `,`, a block `{` or an enclosing closer).
    end: usize,
    /// Printer group depth at the start of the region.
    depth: usize,
    /// Tokens that begin a continuation line, sorted by index, each with the number of
    /// indentation levels its line is continued by.
    breaks: Vec<(usize, usize)>,
    /// Continuation indentation levels currently applied to the printer.
    extra: usize,
}
impl Region {
    /// Continuation level of the line starting at `index`, when a break is planned there.
    fn break_level(&self, index: usize) -> Option<usize> {
        self.breaks
            .binary_search_by_key(&index, |&(at, _)| at)
            .ok()
            .map(|position| self.breaks[position].1)
    }
}
/// Break class of the `.` before each call in a method chain of two or more calls.
///
/// Chains bind tighter than every binary operator, so they only break when the region has no
/// top-level operator to break at: one call per line, continuing one indentation level deeper.
const METHOD_CHAIN_CLASS: u8 = 6;
/// Break class of a value that moves onto its own continuation line after `=` or `=>`; used
/// only when the region has no other break point.
const ASSIGNMENT_CLASS: u8 = 7;
/// Return whether the `.` at `dot` starts a method call (`.name(`).
fn starts_method_call(tokens: &[Tok<'_>], dot: usize) -> bool {
    tokens.get(dot).map(|token| token.kind) == Some(SyntaxKind::Dot)
        && tokens.get(dot + 1).map(|token| token.kind) == Some(SyntaxKind::Ident)
        && tokens.get(dot + 2).map(|token| token.kind) == Some(SyntaxKind::LParen)
}
/// Binding strength of a binary operator; lower values bind more loosely and break first.
fn operator_class(tokens: &[Tok<'_>], index: usize, is_prefix: bool) -> Option<u8> {
    let token = &tokens[index];
    match token.kind {
        SyntaxKind::Question if question_starts_ternary_at(tokens, index) => Some(0),
        SyntaxKind::OrOr => Some(1),
        SyntaxKind::AndAnd => Some(2),
        SyntaxKind::EqualEqual
        | SyntaxKind::BangEqual
        | SyntaxKind::LessEqual
        | SyntaxKind::GreaterEqual => Some(3),
        SyntaxKind::Less | SyntaxKind::Greater if token.role == Role::Plain => Some(3),
        SyntaxKind::Plus | SyntaxKind::Minus if !is_prefix => Some(4),
        SyntaxKind::Star | SyntaxKind::Slash | SyntaxKind::Percent => Some(5),
        _ => None,
    }
}
impl<'tokens, 'source> Printer<'tokens, 'source> {
    fn new(tokens: &'tokens [Tok<'source>]) -> Self {
        Self {
            tokens,
            partners: delimiter_partners(tokens),
            output: String::new(),
            indent: 0,
            at_line_start: true,
            pending_newlines: 0,
            groups: Vec::new(),
            spacing: Spacing::default(),
            ternaries: Vec::new(),
            anchor: 0,
            last_significant: None,
            last_role: Role::Plain,
            comments_after_anchor: false,
            group_start: false,
            line_comment_open: false,
            regions: Vec::new(),
            overflowed: false,
        }
    }
    fn print(mut self) -> Option<String> {
        for index in 0..self.tokens.len() {
            let token = self.tokens[index];
            self.enter_token(index);
            match (token.kind, token.role) {
                (
                    SyntaxKind::LineComment | SyntaxKind::DocComment | SyntaxKind::BlockComment,
                    _,
                ) => self.comment(index),
                (SyntaxKind::Comma, _) => self.comma(index),
                (SyntaxKind::Semicolon, _) => self.semicolon(),
                (SyntaxKind::LBrace, _) => self.open_brace(index),
                (SyntaxKind::RBrace, _) => self.close_brace(index),
                (SyntaxKind::LParen | SyntaxKind::LBracket, _) => self.open_delimiter(index),
                (SyntaxKind::RParen | SyntaxKind::RBracket, _) => self.close_delimiter(index),
                (SyntaxKind::Less, Role::GenericOpen) => self.open_generic(index),
                (SyntaxKind::Greater, Role::GenericClose) => self.close_generic(index),
                (SyntaxKind::Question, _) if question_starts_ternary_at(self.tokens, index) => {
                    self.ternary_question(index);
                }
                (SyntaxKind::Colon, _) if self.ternaries.last() == Some(&self.groups.len()) => {
                    self.ternary_colon(index);
                }
                (SyntaxKind::Hash, Role::AttributeStart) => {
                    if !self.at_line_start && self.pending_newlines == 0 {
                        self.pending_newlines = 1;
                    }
                    self.ordinary(index);
                }
                _ => self.ordinary(index),
            }
        }
        self.trim_trailing_spaces();
        if !self.output.ends_with('\n') {
            self.push_raw("\n");
        }
        (!self.overflowed).then_some(self.output)
    }
    /// Track statement regions: finish those ending here, start one at a new line, and apply a
    /// continuation break before this token when its region requires one.
    fn enter_token(&mut self, index: usize) {
        while self
            .regions
            .last()
            .is_some_and(|region| region.end <= index)
        {
            let region = self.regions.pop().unwrap_or_else(|| unreachable!());
            if region.extra != 0 {
                self.indent = self.indent.saturating_sub(region.extra);
                let block_follows = self.tokens.get(region.end).is_some_and(|token| {
                    token.kind == SyntaxKind::LBrace && token.role == Role::Brace(BraceKind::Block)
                });
                if region.end == index && block_follows {
                    // A condition split over several lines puts its block brace on its own line.
                    self.pending_newlines = self.pending_newlines.max(1);
                }
            }
        }
        let token = self.tokens[index];
        // An own-line comment starts a line unless an inline group keeps it trailing.
        let own_line_comment = token.is_comment()
            && token.newlines_before != 0
            && self.groups.last().is_none_or(|group| group.multiline);
        let line_start = (self.at_line_start || self.pending_newlines != 0 || own_line_comment)
            && !matches!(
                token.kind,
                SyntaxKind::Comma
                    | SyntaxKind::Semicolon
                    | SyntaxKind::RParen
                    | SyntaxKind::RBracket
                    | SyntaxKind::RBrace
            );
        // A block comment that starts a line and leads code on it belongs to that code's region,
        // so the line is still measured and broken like any other member.
        let starts_line = line_start
            && (!token.is_comment()
                || (!self.comment_is_trailing(index) && self.comment_leads_code(index)));
        // A new region starts for each member of a block or multi-line list. Any other line start
        // inside a region (forced by a comment) continues that region one level deeper.
        let member = self.regions.last().is_none_or(|region| {
            self.groups.len() > region.depth
                && self.groups.last().is_none_or(|group| group.multiline)
        });
        if member {
            if starts_line || token.kind == SyntaxKind::KwElse {
                let region = self.region_at(index);
                self.regions.push(region);
            }
        } else if line_start && !self.follows_attribute(index) {
            let after_region = self.ends_region_with_comments(index);
            if let Some(region) = self.regions.last_mut() {
                if after_region {
                    // The terminator moves ahead of these comments; they follow the region at
                    // its own indentation.
                    self.indent = self.indent.saturating_sub(region.extra);
                    region.extra = 0;
                } else if region.extra == 0 {
                    region.extra = 1;
                    self.indent = self.indent.saturating_add(1);
                }
            }
        }
        if let Some(region) = self.regions.last_mut()
            && let Some(level) = region.break_level(index)
        {
            self.indent = self
                .indent
                .saturating_sub(region.extra)
                .saturating_add(level);
            region.extra = level;
            self.pending_newlines = self.pending_newlines.max(1);
        }
    }
    /// Return whether `index` closes the innermost open group and the printer will write a
    /// trailing comma before it (a multi-line comma-separated group).
    fn closer_takes_trailing_comma(&self, index: usize) -> bool {
        self.groups
            .last()
            .is_some_and(|group| group.close == index && group.multiline && group.trailing_comma)
    }
    /// Return whether the token at `index` is a comment followed only by comments up to the end
    /// of the current region.
    ///
    /// The region's terminator (`;`, `,`, or the trailing comma supplied at a closer) is written
    /// before such comments, so they follow the region rather than continue it.
    fn ends_region_with_comments(&self, index: usize) -> bool {
        self.tokens[index].is_comment()
            && self.regions.last().is_some_and(|region| {
                self.next_significant(index)
                    .is_none_or(|next| next >= region.end)
            })
    }
    /// Return whether the token before `index`, ignoring comments, ends an attribute.
    fn follows_attribute(&self, index: usize) -> bool {
        self.tokens[..index]
            .iter()
            .rev()
            .find(|token| !token.is_comment())
            .is_some_and(|token| token.role == Role::AttributeEnd)
    }
    /// Measure the region starting at `start` and choose its continuation breaks.
    fn region_at(&self, start: usize) -> Region {
        let mut depth = 0_usize;
        let mut end = self.tokens.len();
        for index in start..self.tokens.len() {
            let token = &self.tokens[index];
            match (token.kind, token.role) {
                (SyntaxKind::Semicolon | SyntaxKind::Comma, _) if depth == 0 => {
                    end = index;
                    break;
                }
                (SyntaxKind::LBrace, Role::Brace(kind)) if depth == 0 => {
                    let close = self.partners[index].unwrap_or(index);
                    if kind.may_stay_inline(self.tokens, index, close) {
                        depth += 1;
                    } else {
                        end = index;
                        break;
                    }
                }
                (SyntaxKind::LParen | SyntaxKind::LBracket | SyntaxKind::LBrace, _)
                | (SyntaxKind::Less, Role::GenericOpen) => depth += 1,
                (SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace, _) => {
                    if depth == 0 {
                        end = index;
                        break;
                    }
                    depth -= 1;
                    if depth == 0 && matches!(token.role, Role::ItemBlockEnd | Role::AttributeEnd) {
                        // A declaration ending in a one-line record (`koto_test { ... }`) has no
                        // terminator, and an attribute always ends its line; what follows starts
                        // its own region.
                        end = index + 1;
                        break;
                    }
                }
                (SyntaxKind::Greater, Role::GenericClose) => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        let mut region = Region {
            end,
            depth: self.groups.len(),
            breaks: Vec::new(),
            extra: 0,
        };
        if (start..end).any(|index| !projects_flat(self.tokens, &self.partners, index)) {
            return region;
        }
        let mut line = Projection::new(self);
        // Single-line text extent `(start, end)` of every token, in columns of the current line.
        let mut extents = Vec::with_capacity(end - start);
        for index in start..end {
            line.token(index);
            extents.push((
                line.token_start.unwrap_or(line.column),
                line.column.saturating_sub(line.trailing_spaces),
            ));
        }
        // Comments after the region's last token follow its terminator, so they never count.
        let Some(content_end) = (start..end)
            .rev()
            .find(|&index| !self.tokens[index].is_comment())
            .map(|last| last + 1)
        else {
            return region;
        };
        let terminator = self.tokens.get(end).map(|token| token.kind);
        let terminator_width = usize::from(
            matches!(terminator, Some(SyntaxKind::Semicolon | SyntaxKind::Comma))
                || self.closer_takes_trailing_comma(end),
        );
        let content_width = extents[content_end - 1 - start].1;
        let width = match terminator {
            Some(SyntaxKind::LBrace) => content_width.saturating_add(2),
            _ => content_width.saturating_add(terminator_width),
        };
        if width <= TARGET_COLUMNS {
            return region;
        }
        let mut spacing = self.spacing;
        let mut depth = 0_usize;
        let mut candidates: Vec<(u8, usize)> = Vec::new();
        // The last top-level assignment or match arrow, and whether either side holds a delimited
        // group that can break on its own.
        let mut assignment: Option<usize> = None;
        let mut group_can_break = false;
        for index in start..content_end {
            let token = &self.tokens[index];
            if token.is_comment() {
                continue;
            }
            let kind = spacing_kind(token);
            let (_, is_prefix) = spacing.before(kind);
            spacing.record(kind, is_prefix);
            match (token.kind, token.role) {
                (SyntaxKind::LParen | SyntaxKind::LBracket | SyntaxKind::LBrace, _)
                | (SyntaxKind::Less, Role::GenericOpen) => {
                    if depth == 0 && self.group_can_break(index) {
                        group_can_break = true;
                    }
                    depth += 1;
                }
                (SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace, _)
                | (SyntaxKind::Greater, Role::GenericClose) => depth = depth.saturating_sub(1),
                _ if depth != 0 || index == start => {}
                (
                    SyntaxKind::Equal
                    | SyntaxKind::PlusEqual
                    | SyntaxKind::MinusEqual
                    | SyntaxKind::StarEqual
                    | SyntaxKind::SlashEqual
                    | SyntaxKind::PercentEqual
                    | SyntaxKind::FatArrow,
                    _,
                ) => {
                    candidates.clear();
                    assignment = Some(index);
                }
                (SyntaxKind::Colon, _)
                    if candidates.iter().any(|&(class, at)| {
                        class == 0 && self.tokens[at].kind == SyntaxKind::Question
                    }) =>
                {
                    candidates.push((0, index));
                }
                (SyntaxKind::Dot, _) if starts_method_call(self.tokens, index) => {
                    candidates.push((METHOD_CHAIN_CLASS, index));
                }
                _ => {
                    if let Some(class) = operator_class(self.tokens, index, is_prefix) {
                        candidates.push((class, index));
                    }
                }
            }
        }
        // A lone method call keeps its receiver and breaks its own argument list instead.
        if candidates
            .iter()
            .filter(|&&(class, _)| class == METHOD_CHAIN_CLASS)
            .nth(1)
            .is_none()
        {
            candidates.retain(|&(class, _)| class != METHOD_CHAIN_CLASS);
        }
        // A statement with no other break point moves its value onto a continuation line after
        // `=` or `=>`.
        if candidates.is_empty()
            && !group_can_break
            && terminator != Some(SyntaxKind::LBrace)
            && let Some(value) = assignment.and_then(|at| self.next_significant(at))
            && value < content_end
        {
            candidates.push((ASSIGNMENT_CLASS, value));
        }
        region.breaks =
            self.layered_breaks(start, content_end, terminator_width, &extents, &candidates);
        region
    }
    /// Choose the continuation breaks of an over-long region spanning `start..end`.
    ///
    /// The region breaks before each of its loosest candidates, continuing one level deeper.
    /// Every resulting line that still exceeds the target breaks before the loosest candidates
    /// inside it, one level deeper again, until each line fits or has no candidate left. A lone
    /// method call never breaks away from its receiver. `extents` holds the single-line text
    /// extent of each region token on the current line; `terminator_width` is the width of the
    /// `;` or `,` that ends the region's last line.
    fn layered_breaks(
        &self,
        start: usize,
        end: usize,
        terminator_width: usize,
        extents: &[(usize, usize)],
        candidates: &[(u8, usize)],
    ) -> Vec<(usize, usize)> {
        let mut breaks = Vec::new();
        // `(from, to, level, first_level)`: break `from..to` at `level`; the line holding `from`
        // is continued by `first_level` levels (the region's first line has its own column).
        let mut pending = vec![(start, end, 1_usize, 0_usize)];
        while let Some((from, to, level, first_level)) = pending.pop() {
            let inside = || {
                candidates
                    .iter()
                    .filter(move |&&(_, at)| from < at && at < to)
            };
            let Some(loosest) = inside().map(|&(class, _)| class).min() else {
                continue;
            };
            let selected = inside()
                .filter_map(|&(class, at)| (class == loosest).then_some(at))
                .collect::<Vec<_>>();
            if loosest == METHOD_CHAIN_CLASS && selected.len() < 2 {
                continue;
            }
            breaks.extend(selected.iter().map(|&at| (at, level)));
            // The first line keeps the level it already starts at; the new lines start at `level`.
            let line_level = |first: usize| if first == from { first_level } else { level };
            let boundaries = std::iter::once(from)
                .chain(selected.iter().copied())
                .chain(std::iter::once(to))
                .collect::<Vec<_>>();
            for segment in boundaries.windows(2) {
                let (first, last) = (segment[0], segment[1] - 1);
                let text_end = extents[last - start].1;
                let width = if first == start {
                    text_end
                } else {
                    self.indent
                        .saturating_add(line_level(first))
                        .saturating_mul(INDENT.len())
                        .saturating_add(text_end.saturating_sub(extents[first - start].0))
                };
                let width = if segment[1] == end {
                    width.saturating_add(terminator_width)
                } else {
                    width
                };
                if width > TARGET_COLUMNS {
                    pending.push((
                        first,
                        segment[1],
                        level.saturating_add(1),
                        line_level(first),
                    ));
                }
            }
        }
        breaks.sort_unstable();
        breaks
    }
    /// Return whether the delimited group opened at `open` can lay its members out over several
    /// lines: a non-empty argument, parameter, tuple or list group, or a record or struct pattern.
    fn group_can_break(&self, open: usize) -> bool {
        let close = self.partners[open].unwrap_or(open);
        close > open + 1
            && matches!(
                self.tokens[open].role,
                Role::BreakableParen
                    | Role::ParamParen
                    | Role::TupleParen
                    | Role::List { .. }
                    | Role::Brace(BraceKind::Record | BraceKind::Pattern | BraceKind::TestTarget)
            )
    }
    fn next_significant(&self, index: usize) -> Option<usize> {
        (index.saturating_add(1)..self.tokens.len()).find(|&next| !self.tokens[next].is_comment())
    }
    /// Materialize pending line breaks before the token at `index`.
    fn break_before(&mut self, index: usize) {
        if self.pending_newlines == 0 {
            return;
        }
        let token = &self.tokens[index];
        let closer = matches!(
            token.kind,
            SyntaxKind::RBrace | SyntaxKind::RParen | SyntaxKind::RBracket
        );
        let mut count = self.pending_newlines;
        if token.newlines_before >= 2 {
            count = 2;
        }
        if closer || self.group_start || self.last_role == Role::AttributeEnd {
            count = 1;
        }
        self.pending_newlines = 0;
        self.newlines(count.min(2));
    }
    fn ordinary(&mut self, index: usize) {
        let token = self.tokens[index];
        let kind = spacing_kind(&token);
        let (space, is_prefix) = self.spacing.before(kind);
        self.break_before(index);
        if space {
            self.space();
        }
        self.write(token.text);
        self.significant(kind, is_prefix, token.role);
    }
    fn significant(&mut self, kind: SyntaxKind, is_prefix: bool, role: Role) {
        self.spacing.record(kind, is_prefix);
        self.anchor = self.output.len();
        self.last_significant = Some(kind);
        self.last_role = role;
        self.comments_after_anchor = false;
        self.group_start = false;
    }
    fn comment(&mut self, index: usize) {
        let token = self.tokens[index];
        let text = if token.kind.is_line_comment() {
            token.text.trim_end_matches(['\r', '\n'])
        } else {
            token.text
        };
        let inline_group = self.groups.last().is_some_and(|group| !group.multiline);
        let trailing = self.comment_is_trailing(index);
        if trailing {
            // Trailing trivia stays bound to the token before it, ahead of any pending break. A
            // block comment directly after `(` or `[` hugs the delimiter like the token it precedes.
            if token.kind.is_line_comment() || !self.output.ends_with(['(', '[']) {
                self.space();
            }
            self.write(text);
        } else {
            if !self.output.is_empty() {
                self.pending_newlines = self.pending_newlines.max(1);
            }
            self.break_before(index);
            self.write(text);
            self.group_start = false;
            self.last_role = Role::Plain;
        }
        // A same-line block comment directly before the separator that ends its member keeps
        // that separator after it (`amount /* in nanos */, fee`).
        let separator_follows =
            trailing && token.kind == SyntaxKind::BlockComment && self.separator_follows(index);
        if separator_follows {
            self.anchor = self.output.len();
        }
        self.comments_after_anchor = !separator_follows;
        if token.kind.is_line_comment() {
            self.pending_newlines = self.pending_newlines.max(1);
            self.line_comment_open = true;
        } else if self.pending_newlines == 0 {
            let next_on_new_line = self
                .tokens
                .get(index + 1)
                .is_some_and(|next| next.newlines_before != 0);
            if next_on_new_line && !inline_group {
                self.pending_newlines = 1;
            } else if !closes_tightly(self.tokens, index + 1) {
                self.space();
            }
        }
    }
    /// Return whether the comment at `index` is written after the preceding token on the same
    /// output line rather than starting a line of its own.
    ///
    /// A comment that followed a token on its source line trails it, and every comment inside a
    /// single-line group trails. The exception is a block comment that directly follows the
    /// opening delimiter of a multi-line group and leads code on its line: it starts the first
    /// member's line, ahead of the code it annotates.
    fn comment_is_trailing(&self, index: usize) -> bool {
        let token = &self.tokens[index];
        if self.line_comment_open {
            return false;
        }
        if self.groups.last().is_some_and(|group| !group.multiline) {
            return true;
        }
        index > 0
            && token.newlines_before == 0
            && !(self.group_start && self.comment_leads_code(index))
    }
    /// Return whether the comment at `index` is a block comment followed on its line by code it
    /// leads: only same-line block comments sit between them, and the code is neither a
    /// separator nor a closing delimiter.
    fn comment_leads_code(&self, index: usize) -> bool {
        if self.tokens[index].kind != SyntaxKind::BlockComment {
            return false;
        }
        for token in &self.tokens[index + 1..] {
            if token.newlines_before != 0 {
                return false;
            }
            match token.kind {
                SyntaxKind::BlockComment => {}
                SyntaxKind::LineComment
                | SyntaxKind::DocComment
                | SyntaxKind::Comma
                | SyntaxKind::Semicolon
                | SyntaxKind::RParen
                | SyntaxKind::RBracket
                | SyntaxKind::RBrace => return false,
                _ => return true,
            }
        }
        false
    }
    /// Return whether the token after the comment at `index` is the separator that ends the
    /// current member: a `,` or `;`, or a closer at which the printer writes a trailing comma.
    fn separator_follows(&self, index: usize) -> bool {
        let next = index + 1;
        match self.tokens.get(next).map(|token| token.kind) {
            Some(SyntaxKind::Comma | SyntaxKind::Semicolon) => true,
            Some(SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace) => {
                self.closer_takes_trailing_comma(next)
                    && !matches!(
                        self.last_significant,
                        Some(
                            SyntaxKind::Comma
                                | SyntaxKind::LParen
                                | SyntaxKind::LBracket
                                | SyntaxKind::LBrace
                                | SyntaxKind::DotDot
                        )
                    )
            }
            _ => false,
        }
    }
    /// Write `text` directly after the last significant token, ahead of trailing comments.
    fn separator(&mut self, text: &str) {
        let at = self.anchor.min(self.output.len());
        if self.output.len().saturating_add(text.len()) > MAX_SOURCE_BYTES {
            self.overflowed = true;
            return;
        }
        self.output.insert_str(at, text);
        self.anchor = at + text.len();
        if !self.comments_after_anchor {
            self.at_line_start = false;
        }
    }
    fn comma(&mut self, index: usize) {
        let group = self.groups.last().copied();
        let closes_group =
            group.is_some_and(|group| self.next_significant(index) == Some(group.close));
        if let Some(group) = group
            && closes_group
            && group.kind != GroupKind::Generic
            && (!group.multiline || self.last_significant == Some(SyntaxKind::DotDot))
        {
            // Single-line lists, and a struct pattern's final `..`, carry no trailing comma.
            return;
        }
        self.separator(",");
        self.spacing.record(SyntaxKind::Comma, false);
        self.last_significant = Some(SyntaxKind::Comma);
        self.last_role = Role::Plain;
        match group {
            Some(Group {
                multiline: true,
                kind:
                    GroupKind::Paren
                    | GroupKind::Bracket
                    | GroupKind::Brace(
                        BraceKind::Match
                        | BraceKind::Record
                        | BraceKind::Pattern
                        | BraceKind::TestTarget
                        | BraceKind::StructFields
                        | BraceKind::EnumVariants,
                    ),
                ..
            }) => self.pending_newlines = self.pending_newlines.max(1),
            _ if self.pending_newlines == 0 => self.space(),
            _ => {}
        }
    }
    fn semicolon(&mut self) {
        self.separator(";");
        self.spacing.record(SyntaxKind::Semicolon, false);
        self.last_significant = Some(SyntaxKind::Semicolon);
        self.last_role = Role::Plain;
        let inline_group = self.groups.last().is_some_and(|group| {
            !group.multiline && matches!(group.kind, GroupKind::Paren | GroupKind::Bracket)
        });
        if inline_group {
            if self.pending_newlines == 0 {
                self.space();
            }
        } else {
            self.pending_newlines = self.pending_newlines.max(1);
        }
    }
    fn open_brace(&mut self, index: usize) {
        let token = self.tokens[index];
        let Role::Brace(kind) = token.role else {
            unreachable!("every opening brace has a brace role")
        };
        let close = self.partners[index].unwrap_or(index);
        let compact = kind.may_stay_inline(self.tokens, index, close) && self.fits(index);
        self.ordinary(index);
        self.groups.push(Group {
            kind: GroupKind::Brace(kind),
            multiline: !compact,
            trailing_comma: kind.comma_separated(),
            close,
        });
        if compact {
            if close != index + 1 {
                self.space();
            }
        } else {
            self.indent = self.indent.saturating_add(1);
            self.pending_newlines = 1;
            self.group_start = true;
        }
    }
    fn close_brace(&mut self, index: usize) {
        let token = self.tokens[index];
        let group = self.groups.pop().unwrap_or(Group {
            kind: GroupKind::Brace(BraceKind::Block),
            multiline: true,
            trailing_comma: false,
            close: index,
        });
        let empty =
            self.last_significant == Some(SyntaxKind::LBrace) && !self.comments_after_anchor;
        if group.multiline {
            if group.trailing_comma
                && !empty
                && !matches!(
                    self.last_significant,
                    Some(SyntaxKind::Comma | SyntaxKind::LBrace | SyntaxKind::DotDot)
                )
            {
                self.separator(",");
            }
            self.indent = self.indent.saturating_sub(1);
            if empty {
                self.pending_newlines = 0;
                self.group_start = false;
            } else {
                self.pending_newlines = self.pending_newlines.max(1);
            }
            self.break_before(index);
        } else {
            self.break_before(index);
            if !empty {
                self.space();
            }
        }
        self.write(token.text);
        self.significant(SyntaxKind::RBrace, false, token.role);
        let next = self
            .next_significant(index)
            .map(|next| self.tokens[next].kind);
        if token.role == Role::ItemBlockEnd && next.is_some() {
            self.pending_newlines = 2;
        } else if group.multiline && group.kind == GroupKind::Brace(BraceKind::Block) {
            // Expression-valued braces (records, `match`) continue the surrounding expression.
            match next {
                Some(SyntaxKind::KwElse) => {}
                Some(
                    SyntaxKind::Semicolon
                    | SyntaxKind::Comma
                    | SyntaxKind::RParen
                    | SyntaxKind::RBracket
                    | SyntaxKind::Dot
                    | SyntaxKind::Question,
                )
                | None => {}
                Some(_) => self.pending_newlines = self.pending_newlines.max(1),
            }
        }
    }
    fn open_delimiter(&mut self, index: usize) {
        let token = self.tokens[index];
        let close = self.partners[index].unwrap_or(index);
        let (breakable, trailing_comma) = match token.role {
            Role::BreakableParen | Role::ParamParen => (true, true),
            Role::TupleParen => (true, false),
            Role::List { trailing_comma, .. } => (true, trailing_comma),
            _ => (false, false),
        };
        let multiline = breakable && close > index + 1 && !self.fits(index);
        if matches!(token.role, Role::List { json: true, .. }) {
            self.break_before(index);
            self.space();
        }
        self.ordinary(index);
        self.groups.push(Group {
            kind: if token.kind == SyntaxKind::LParen {
                GroupKind::Paren
            } else {
                GroupKind::Bracket
            },
            multiline,
            trailing_comma: multiline && trailing_comma,
            close,
        });
        if multiline {
            self.indent = self.indent.saturating_add(1);
            self.pending_newlines = 1;
            self.group_start = true;
        }
    }
    fn close_delimiter(&mut self, index: usize) {
        let token = self.tokens[index];
        let group = self.groups.pop();
        if let Some(group) = group.filter(|group| group.multiline) {
            if group.trailing_comma
                && !matches!(
                    self.last_significant,
                    Some(SyntaxKind::Comma | SyntaxKind::LParen | SyntaxKind::LBracket)
                )
            {
                self.separator(",");
            }
            self.indent = self.indent.saturating_sub(1);
            self.pending_newlines = self.pending_newlines.max(1);
        }
        self.ordinary(index);
        if token.role == Role::AttributeEnd {
            self.pending_newlines = self.pending_newlines.max(1);
        }
    }
    fn open_generic(&mut self, index: usize) {
        let token = self.tokens[index];
        self.break_before(index);
        self.trim_trailing_spaces();
        self.write(token.text);
        // Generic delimiters have the same spacing behavior as brackets.
        self.significant(SyntaxKind::LBracket, false, token.role);
        self.groups.push(Group {
            kind: GroupKind::Generic,
            multiline: false,
            trailing_comma: false,
            close: self.partners[index].unwrap_or(index),
        });
    }
    fn close_generic(&mut self, index: usize) {
        let token = self.tokens[index];
        self.groups.pop();
        self.break_before(index);
        self.trim_trailing_spaces();
        self.write(token.text);
        self.significant(SyntaxKind::RBracket, false, token.role);
    }
    fn ternary_question(&mut self, index: usize) {
        self.break_before(index);
        self.space();
        self.write("?");
        self.ternaries.push(self.groups.len());
        self.significant(SyntaxKind::Question, false, Role::Plain);
        self.space();
    }
    fn ternary_colon(&mut self, index: usize) {
        self.break_before(index);
        self.space();
        self.write(":");
        self.ternaries.pop();
        self.significant(SyntaxKind::Colon, false, Role::Plain);
        self.space();
    }
    /// Return whether the delimited construct opened at `open` fits on the current line, including
    /// the text that must follow it before the next possible line break.
    fn fits(&self, open: usize) -> bool {
        let Some(close) = self.partners[open] else {
            return true;
        };
        let mut line = Projection::new(self);
        for index in open..=close {
            if !line.token(index) || line.column > TARGET_COLUMNS {
                return false;
            }
        }
        // A declaration head keeps measuring through its return type and `authorize(...)`, so the
        // parameter list is the first thing to break.
        let header = self.tokens[open].role == Role::ParamParen;
        let mut depth = 0_usize;
        let region = self.regions.last();
        for index in close.saturating_add(1)..self.tokens.len() {
            let token = &self.tokens[index];
            if depth == 0 && region.is_some_and(|region| region.break_level(index).is_some()) {
                break;
            }
            if token.is_comment() {
                // Comments never decide a fit: the separator or trailing comma after them is
                // written before them, and a line comment ends the line.
                if depth == 0
                    && self.next_significant(index).is_some_and(|next| {
                        matches!(
                            self.tokens[next].kind,
                            SyntaxKind::Comma | SyntaxKind::Semicolon
                        ) || self.closer_takes_trailing_comma(next)
                    })
                {
                    line.column = line.column.saturating_add(1);
                    break;
                }
                if token.kind.is_line_comment() {
                    break;
                }
                continue;
            }
            if depth == 0 {
                match token.kind {
                    SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace => {
                        if self.closer_takes_trailing_comma(index) {
                            line.column = line.column.saturating_add(1);
                        }
                        break;
                    }
                    SyntaxKind::Greater if token.role == Role::GenericClose => break,
                    SyntaxKind::Comma | SyntaxKind::Semicolon => {
                        line.column = line.column.saturating_add(1);
                        break;
                    }
                    SyntaxKind::LBrace => {
                        line.space();
                        line.column = line.column.saturating_add(1);
                        break;
                    }
                    _ => {}
                }
                if !header
                    && matches!(
                        token.role,
                        Role::BreakableParen | Role::TupleParen | Role::List { .. }
                    )
                {
                    // The following group can break on its own; only its opening is required here.
                    let _ = line.token(index);
                    break;
                }
            }
            if !line.token(index) {
                break;
            }
            if line.column > TARGET_COLUMNS {
                return false;
            }
            match token.kind {
                SyntaxKind::LParen | SyntaxKind::LBracket | SyntaxKind::LBrace => {
                    depth = depth.saturating_add(1);
                }
                SyntaxKind::Less if token.role == Role::GenericOpen => {
                    depth = depth.saturating_add(1);
                }
                SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace => {
                    depth = depth.saturating_sub(1);
                }
                SyntaxKind::Greater if token.role == Role::GenericClose => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        line.column <= TARGET_COLUMNS
    }
    fn write(&mut self, text: &str) {
        if self.overflowed {
            return;
        }
        let indentation = if self.at_line_start {
            self.indent.saturating_mul(INDENT.len())
        } else {
            0
        };
        if self
            .output
            .len()
            .saturating_add(indentation)
            .saturating_add(text.len())
            > MAX_SOURCE_BYTES
        {
            self.overflowed = true;
            return;
        }
        if self.at_line_start {
            for _ in 0..self.indent {
                self.output.push_str(INDENT);
            }
        }
        self.output.push_str(text);
        self.at_line_start = self.output.ends_with('\n');
    }
    fn push_raw(&mut self, text: &str) {
        if self.output.len().saturating_add(text.len()) > MAX_SOURCE_BYTES {
            self.overflowed = true;
        } else {
            self.output.push_str(text);
        }
    }
    fn space(&mut self) {
        if !self.at_line_start
            && !self
                .output
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_whitespace)
        {
            self.push_raw(" ");
        }
    }
    fn newlines(&mut self, count: usize) {
        self.trim_trailing_spaces();
        let existing = self
            .output
            .as_bytes()
            .iter()
            .rev()
            .take_while(|byte| **byte == b'\n')
            .count();
        if !self.output.is_empty() {
            for _ in existing..count {
                self.push_raw("\n");
            }
        }
        self.at_line_start = true;
        self.line_comment_open = false;
    }
    fn trim_trailing_spaces(&mut self) {
        while self
            .output
            .as_bytes()
            .last()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r'))
        {
            self.output.pop();
        }
        self.anchor = self.anchor.min(self.output.len());
    }
}
/// Return whether a struct literal, pattern, JSON object or `koto_test` block stays on one line:
/// it has at most one member, no comments and no nested braces.
fn record_is_compact(tokens: &[Tok<'_>], open: usize, close: usize) -> bool {
    let inner = tokens.get(open + 1..close).unwrap_or_default();
    let mut depth = 0_usize;
    let mut separators = 0_usize;
    for (offset, token) in inner.iter().enumerate() {
        match token.kind {
            SyntaxKind::LineComment
            | SyntaxKind::DocComment
            | SyntaxKind::BlockComment
            | SyntaxKind::LBrace
            | SyntaxKind::RBrace => return false,
            SyntaxKind::LParen | SyntaxKind::LBracket => depth = depth.saturating_add(1),
            SyntaxKind::RParen | SyntaxKind::RBracket => depth = depth.saturating_sub(1),
            SyntaxKind::Less if token.role == Role::GenericOpen => depth = depth.saturating_add(1),
            SyntaxKind::Greater if token.role == Role::GenericClose => {
                depth = depth.saturating_sub(1);
            }
            SyntaxKind::Comma if depth == 0 && offset + 1 < inner.len() => {
                separators = separators.saturating_add(1);
            }
            _ => {}
        }
    }
    separators == 0
}
/// Single-line rendering of a token range, mirroring the printer's spacing exactly.
struct Projection<'printer, 'tokens, 'source> {
    printer: &'printer Printer<'tokens, 'source>,
    column: usize,
    trailing_spaces: usize,
    /// Last character of the projected line, if any.
    last_char: Option<char>,
    at_line_start: bool,
    spacing: Spacing,
    groups: Vec<usize>,
    ternaries: Vec<usize>,
    /// Column where the text of the most recently projected token starts, after any space.
    token_start: Option<usize>,
}
impl<'printer, 'tokens, 'source> Projection<'printer, 'tokens, 'source> {
    fn new(printer: &'printer Printer<'tokens, 'source>) -> Self {
        let line_start = printer.at_line_start || printer.pending_newlines != 0;
        let current_line = printer.output.rsplit('\n').next().unwrap_or_default();
        let (column, trailing_spaces) = if line_start {
            (printer.indent.saturating_mul(INDENT.len()), 0)
        } else {
            (
                current_line.chars().count(),
                current_line
                    .chars()
                    .rev()
                    .take_while(|character| matches!(character, ' ' | '\t' | '\r'))
                    .count(),
            )
        };
        Self {
            printer,
            column,
            trailing_spaces,
            last_char: if line_start {
                None
            } else {
                current_line.chars().last()
            },
            at_line_start: line_start,
            spacing: printer.spacing,
            groups: Vec::new(),
            ternaries: printer.ternaries.clone(),
            token_start: None,
        }
    }
    fn depth(&self) -> usize {
        self.printer.groups.len().saturating_add(self.groups.len())
    }
    fn write(&mut self, text: &str) {
        self.token_start.get_or_insert(self.column);
        self.column = self.column.saturating_add(text.chars().count());
        self.last_char = text.chars().last().or(self.last_char);
        self.trailing_spaces = text
            .chars()
            .rev()
            .take_while(|character| matches!(character, ' ' | '\t' | '\r'))
            .count();
        self.at_line_start = false;
    }
    fn space(&mut self) {
        if !self.at_line_start && self.trailing_spaces == 0 {
            self.column = self.column.saturating_add(1);
            self.trailing_spaces = 1;
            self.last_char = Some(' ');
        }
    }
    fn trim_trailing_spaces(&mut self) {
        self.column = self.column.saturating_sub(self.trailing_spaces);
        if self.trailing_spaces != 0 {
            // Only spaces are ever trimmed; the character before them is no longer tracked.
            self.last_char = None;
        }
        self.trailing_spaces = 0;
    }
    fn ordinary(&mut self, token: &Tok<'_>) {
        let kind = spacing_kind(token);
        let (space, is_prefix) = self.spacing.before(kind);
        if space {
            self.space();
        }
        self.write(token.text);
        self.spacing.record(kind, is_prefix);
    }
    /// Project one token; returns `false` when the token cannot be laid out on a single line.
    fn token(&mut self, index: usize) -> bool {
        let tokens = self.printer.tokens;
        let token = tokens[index];
        self.token_start = None;
        if !projects_flat(tokens, &self.printer.partners, index) {
            return false;
        }
        match (token.kind, token.role) {
            (SyntaxKind::BlockComment, _) => {
                if !matches!(self.last_char, Some('(' | '[')) {
                    self.space();
                }
                self.write(token.text);
                if !closes_tightly(tokens, index + 1) {
                    self.space();
                }
            }
            (SyntaxKind::Comma, _) => {
                let next = (index + 1..tokens.len()).find(|&next| !tokens[next].is_comment());
                if self.groups.last().copied() != next || next.is_none() {
                    self.trim_trailing_spaces();
                    self.write(",");
                    self.space();
                    self.spacing.record(SyntaxKind::Comma, false);
                }
            }
            (SyntaxKind::LBrace, _) => {
                let close = self.printer.partners[index].unwrap_or(index);
                self.ordinary(&token);
                if close != index + 1 {
                    self.space();
                }
                self.groups.push(close);
            }
            (SyntaxKind::RBrace, _) => {
                if self.spacing.previous != Some(SyntaxKind::LBrace) {
                    self.space();
                }
                self.write(token.text);
                self.spacing.record(SyntaxKind::RBrace, false);
                self.groups.pop();
            }
            (SyntaxKind::LParen | SyntaxKind::LBracket, role) => {
                if matches!(role, Role::List { json: true, .. }) {
                    self.space();
                }
                self.ordinary(&token);
                self.groups
                    .push(self.printer.partners[index].unwrap_or(index));
            }
            (SyntaxKind::RParen | SyntaxKind::RBracket, _) => {
                self.groups.pop();
                self.ordinary(&token);
            }
            (SyntaxKind::Less, Role::GenericOpen) => {
                self.trim_trailing_spaces();
                self.write(token.text);
                self.spacing.record(SyntaxKind::LBracket, false);
                self.groups
                    .push(self.printer.partners[index].unwrap_or(index));
            }
            (SyntaxKind::Greater, Role::GenericClose) => {
                self.groups.pop();
                self.trim_trailing_spaces();
                self.write(token.text);
                self.spacing.record(SyntaxKind::RBracket, false);
            }
            (SyntaxKind::Question, _) if question_starts_ternary_at(tokens, index) => {
                self.space();
                self.write("?");
                self.space();
                self.ternaries.push(self.depth());
                self.spacing.record(SyntaxKind::Question, false);
            }
            (SyntaxKind::Colon, _) if self.ternaries.last() == Some(&self.depth()) => {
                self.space();
                self.write(":");
                self.space();
                self.ternaries.pop();
                self.spacing.record(SyntaxKind::Colon, false);
            }
            _ => self.ordinary(&token),
        }
        true
    }
}
/// Return whether the token at `index` can appear inside a single-line rendering.
///
/// Line comments, statement separators, multi-line literals or comments, and braces other than a
/// compact record always force a line break.
fn projects_flat(tokens: &[Tok<'_>], partners: &[Option<usize>], index: usize) -> bool {
    let token = &tokens[index];
    match (token.kind, token.role) {
        (SyntaxKind::LineComment | SyntaxKind::DocComment | SyntaxKind::Semicolon, _) => false,
        (SyntaxKind::LBrace, Role::Brace(kind)) => {
            let close = partners[index].unwrap_or(index);
            kind.may_stay_inline(tokens, index, close)
        }
        (SyntaxKind::LBrace, _) => false,
        _ => !token.text.contains(['\n', '\r']),
    }
}
/// Return whether the token at `next` follows a block comment without a space: a `)` or `]`,
/// or the `,` before one, which is written directly after the comment or dropped on one line.
fn closes_tightly(tokens: &[Tok<'_>], next: usize) -> bool {
    let closer = |index: usize| {
        tokens
            .get(index)
            .is_some_and(|token| matches!(token.kind, SyntaxKind::RParen | SyntaxKind::RBracket))
    };
    let comma = tokens
        .get(next)
        .is_some_and(|token| token.kind == SyntaxKind::Comma);
    closer(next) || (comma && closer(next + 1))
}
fn question_starts_ternary_at(tokens: &[Tok<'_>], question: usize) -> bool {
    if tokens.get(question).map(|token| token.kind) != Some(SyntaxKind::Question) {
        return false;
    }
    let first = tokens[question.saturating_add(1)..]
        .iter()
        .find(|token| !token.is_comment())
        .map(|token| token.kind);
    if !first.is_some_and(syntax_kind_starts_expression) {
        return false;
    }
    let mut paren_depth = 0_usize;
    let mut bracket_depth = 0_usize;
    let mut brace_depth = 0_usize;
    for token in tokens.iter().skip(question.saturating_add(1)) {
        let at_top_level = paren_depth == 0 && bracket_depth == 0 && brace_depth == 0;
        match token.kind {
            SyntaxKind::Colon if at_top_level => return true,
            SyntaxKind::LParen => paren_depth = paren_depth.saturating_add(1),
            SyntaxKind::LBracket => bracket_depth = bracket_depth.saturating_add(1),
            SyntaxKind::LBrace => brace_depth = brace_depth.saturating_add(1),
            SyntaxKind::RParen => {
                if at_top_level {
                    return false;
                }
                paren_depth = paren_depth.saturating_sub(1);
            }
            SyntaxKind::RBracket => {
                if at_top_level {
                    return false;
                }
                bracket_depth = bracket_depth.saturating_sub(1);
            }
            SyntaxKind::RBrace => {
                if at_top_level {
                    return false;
                }
                brace_depth = brace_depth.saturating_sub(1);
            }
            SyntaxKind::Semicolon | SyntaxKind::Comma if at_top_level => return false,
            _ => {}
        }
    }
    false
}
const fn is_word(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Ident
            | SyntaxKind::Number
            | SyntaxKind::Decimal
            | SyntaxKind::String
            | SyntaxKind::Bytes
            | SyntaxKind::KwFn
            | SyntaxKind::KwLet
            | SyntaxKind::KwVar
            | SyntaxKind::KwConst
            | SyntaxKind::KwReturn
            | SyntaxKind::KwBreak
            | SyntaxKind::KwContinue
            | SyntaxKind::KwState
            | SyntaxKind::KwStruct
            | SyntaxKind::KwEvent
            | SyntaxKind::KwEmit
            | SyntaxKind::KwError
            | SyntaxKind::KwEnum
            | SyntaxKind::KwAuthorize
            | SyntaxKind::KwTrigger
            | SyntaxKind::KwIf
            | SyntaxKind::KwMatch
            | SyntaxKind::KwElse
            | SyntaxKind::KwFor
            | SyntaxKind::KwIn
            | SyntaxKind::KwSeiyaku
            | SyntaxKind::KwModule
            | SyntaxKind::KwInclude
            | SyntaxKind::KwPermission
            | SyntaxKind::KwImport
            | SyntaxKind::KwAs
            | SyntaxKind::KwExport
            | SyntaxKind::KwKotoage
            | SyntaxKind::KwHajimari
            | SyntaxKind::KwKaizen
            | SyntaxKind::KwView
            | SyntaxKind::KwTrue
            | SyntaxKind::KwFalse
    )
}
const fn is_operator(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Plus
            | SyntaxKind::PlusEqual
            | SyntaxKind::Minus
            | SyntaxKind::MinusEqual
            | SyntaxKind::Arrow
            | SyntaxKind::FatArrow
            | SyntaxKind::Star
            | SyntaxKind::StarEqual
            | SyntaxKind::Slash
            | SyntaxKind::SlashEqual
            | SyntaxKind::Percent
            | SyntaxKind::PercentEqual
            | SyntaxKind::Bang
            | SyntaxKind::BangEqual
            | SyntaxKind::Equal
            | SyntaxKind::EqualEqual
            | SyntaxKind::Less
            | SyntaxKind::LessEqual
            | SyntaxKind::Greater
            | SyntaxKind::GreaterEqual
            | SyntaxKind::AndAnd
            | SyntaxKind::OrOr
    )
}
const fn is_prefix_operator(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Bang | SyntaxKind::Minus | SyntaxKind::Plus
    )
}
const fn syntax_kind_starts_expression(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Ident
            | SyntaxKind::Number
            | SyntaxKind::Decimal
            | SyntaxKind::String
            | SyntaxKind::Bytes
            | SyntaxKind::KwTrue
            | SyntaxKind::KwFalse
            | SyntaxKind::KwIf
            | SyntaxKind::KwMatch
            | SyntaxKind::LParen
            | SyntaxKind::LBracket
            | SyntaxKind::Minus
            | SyntaxKind::Bang
    )
}
const fn prefix_position(previous: Option<SyntaxKind>) -> bool {
    match previous {
        None => true,
        Some(kind) => matches!(
            kind,
            SyntaxKind::LParen
                | SyntaxKind::LBracket
                | SyntaxKind::LBrace
                | SyntaxKind::Comma
                | SyntaxKind::Colon
                | SyntaxKind::Semicolon
                | SyntaxKind::Question
                | SyntaxKind::FatArrow
                | SyntaxKind::KwReturn
                | SyntaxKind::KwLet
                | SyntaxKind::KwVar
                | SyntaxKind::KwIf
                | SyntaxKind::KwElse
                | SyntaxKind::KwMatch
                | SyntaxKind::KwIn
                | SyntaxKind::Equal
                | SyntaxKind::Plus
                | SyntaxKind::PlusEqual
                | SyntaxKind::Minus
                | SyntaxKind::MinusEqual
                | SyntaxKind::Star
                | SyntaxKind::StarEqual
                | SyntaxKind::Slash
                | SyntaxKind::SlashEqual
                | SyntaxKind::Percent
                | SyntaxKind::PercentEqual
                | SyntaxKind::Bang
                | SyntaxKind::BangEqual
                | SyntaxKind::EqualEqual
                | SyntaxKind::Less
                | SyntaxKind::LessEqual
                | SyntaxKind::Greater
                | SyntaxKind::GreaterEqual
                | SyntaxKind::AndAnd
                | SyntaxKind::OrOr
        ),
    }
}
const fn needs_space(
    previous: Option<SyntaxKind>,
    previous_was_prefix: bool,
    current: SyntaxKind,
    current_is_prefix: bool,
) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    if previous_was_prefix {
        return false;
    }
    if matches!(
        current,
        SyntaxKind::RParen
            | SyntaxKind::RBracket
            | SyntaxKind::Semicolon
            | SyntaxKind::Comma
            | SyntaxKind::Colon
            | SyntaxKind::ColonColon
            | SyntaxKind::Dot
            | SyntaxKind::Question
    ) || matches!(
        previous,
        SyntaxKind::LParen
            | SyntaxKind::LBracket
            | SyntaxKind::Hash
            | SyntaxKind::ColonColon
            | SyntaxKind::Dot
    ) {
        return false;
    }
    if matches!(current, SyntaxKind::LParen) {
        return !matches!(
            previous,
            SyntaxKind::Ident
                | SyntaxKind::RParen
                | SyntaxKind::RBracket
                | SyntaxKind::KwAuthorize
                | SyntaxKind::KwHajimari
                | SyntaxKind::KwKaizen
        );
    }
    if matches!(current, SyntaxKind::LBracket) {
        return !matches!(
            previous,
            SyntaxKind::Ident
                | SyntaxKind::RParen
                | SyntaxKind::RBracket
                | SyntaxKind::Hash
                | SyntaxKind::Question
        );
    }
    if matches!(current, SyntaxKind::LBrace) {
        return !matches!(previous, SyntaxKind::LBrace);
    }
    if matches!(previous, SyntaxKind::Colon) {
        return true;
    }
    if current_is_prefix {
        return is_word(previous) || is_operator(previous);
    }
    if is_operator(current) || is_operator(previous) {
        return true;
    }
    is_word(previous) && is_word(current)
        || matches!(
            previous,
            SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace
        ) && is_word(current)
}
#[cfg(test)]
mod tests;

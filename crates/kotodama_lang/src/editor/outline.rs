//! Outline, folding, highlights, semantic tokens and test lenses for one source.
//!
//! Every result is derived from parser-owned declaration facts, resolver identities and the
//! significant token stream, so it is available for incomplete buffers too. Branded
//! keywords are classified by token, never by script: `誓約` and `seiyaku` produce the same
//! semantic token type, and outline details echo the spelling written in the source.
use super::{
    EditorIdentity, EditorSnapshot, EditorUnit, SourceId, TextRange, Token, TokenKind, context,
};
use crate::{ast::FunctionKind, resolved::ResolvedBindingKind, spanned_ast::DeclarationKind};

/// Semantic token types, in legend order. `brandedKeyword` covers both spellings of
/// `seiyaku`/`誓約`, `kotoage`/`言挙げ`, `hajimari`/`始まり` and `kaizen`/`改善`; clients
/// that do not know it fall back to `keyword`.
pub const SEMANTIC_TOKEN_TYPES: &[&str] = &[
    "namespace",
    "type",
    "struct",
    "enum",
    "enumMember",
    "parameter",
    "variable",
    "property",
    "function",
    "method",
    "keyword",
    "brandedKeyword",
    "string",
    "number",
];
/// Semantic token modifiers, in legend bit order.
pub const SEMANTIC_TOKEN_MODIFIERS: &[&str] = &["declaration", "readonly", "defaultLibrary"];

const NAMESPACE: u32 = 0;
const TYPE: u32 = 1;
const STRUCT: u32 = 2;
const ENUM: u32 = 3;
const ENUM_MEMBER: u32 = 4;
const PARAMETER: u32 = 5;
const VARIABLE: u32 = 6;
const PROPERTY: u32 = 7;
const FUNCTION: u32 = 8;
const METHOD: u32 = 9;
const KEYWORD: u32 = 10;
const BRANDED_KEYWORD: u32 = 11;
const STRING: u32 = 12;
const NUMBER: u32 = 13;
const DECLARATION: u32 = 1;
const READONLY: u32 = 1 << 1;
const DEFAULT_LIBRARY: u32 = 1 << 2;

/// One outline entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorSymbol {
    /// Declared name as written (`increment`, `始まり`, `Counter`).
    pub name: String,
    /// Declaration keyword in the source's spelling plus type or authorization detail.
    pub detail: String,
    /// LSP `SymbolKind`.
    pub kind: u64,
    /// Whole declaration range.
    pub range: TextRange,
    /// Declared-name range.
    pub selection: TextRange,
    /// Nested declarations, fields and error variants.
    pub children: Vec<EditorSymbol>,
}
/// One foldable region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EditorFold {
    /// From the opening delimiter or first comment to the closing delimiter or last comment.
    pub range: TextRange,
    /// Whether the region is a comment block.
    pub comment: bool,
}
/// One highlighted use of the declaration under the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EditorHighlight {
    /// Exact name range.
    pub range: TextRange,
    /// LSP `DocumentHighlightKind`: 1 declaration, 2 read, 3 write.
    pub kind: u64,
}
/// One classified token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EditorSemanticToken {
    /// Exact token range.
    pub range: TextRange,
    /// Index into [`SEMANTIC_TOKEN_TYPES`].
    pub token_type: u32,
    /// Bit set over [`SEMANTIC_TOKEN_MODIFIERS`].
    pub modifiers: u32,
}
/// A runnable local `#[test]` function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorTestLens {
    /// Test function name, as accepted by `koto test run --filter <name> --exact`.
    pub name: String,
    /// Declared-name range.
    pub range: TextRange,
}

fn token_index(unit: &EditorUnit, offset: u32) -> usize {
    unit.tokens
        .partition_point(|token| token.range.start < offset)
}
/// Whether the token at `index` labels a named argument, struct-literal field, JSON key or
/// trigger metadata entry (`name: value` after `(`, `{`, `,` or `;`). The `? value :` branch
/// of a conditional is not a label.
fn is_label(unit: &EditorUnit, index: usize) -> bool {
    let next = unit.tokens.get(index + 1).map(|token| &token.kind);
    let previous = index
        .checked_sub(1)
        .and_then(|index| unit.tokens.get(index))
        .map(|token| &token.kind);
    next == Some(&TokenKind::Colon)
        && matches!(
            previous,
            Some(TokenKind::LParen | TokenKind::LBrace | TokenKind::Comma | TokenKind::Semicolon)
        )
}
fn spelled(unit: &EditorUnit, token: &Token) -> String {
    unit.file.slice(token.range).unwrap_or_default().to_owned()
}
/// Tokens of a declaration header: from its start up to its body or terminator.
fn header(unit: &EditorUnit, range: TextRange) -> &[Token] {
    let start = token_index(unit, range.start);
    let mut end = start;
    let mut depth = 0_usize;
    while let Some(token) = unit.tokens.get(end) {
        if token.range.start >= range.end {
            break;
        }
        match token.kind {
            TokenKind::LParen | TokenKind::LBracket => depth += 1,
            TokenKind::RParen | TokenKind::RBracket => depth = depth.saturating_sub(1),
            TokenKind::LBrace | TokenKind::Semicolon if depth == 0 => break,
            _ => {}
        }
        end += 1;
    }
    &unit.tokens[start..end]
}
/// Whether a `#[test]` attribute directly precedes the declaration starting at `start`.
fn has_test_attribute(unit: &EditorUnit, start: u32) -> bool {
    let mut index = token_index(unit, start);
    // The declaration range may already include its attributes.
    let mut inner = index;
    while unit.tokens.get(inner).map(|token| &token.kind) == Some(&TokenKind::Hash)
        && unit.tokens.get(inner + 1).map(|token| &token.kind) == Some(&TokenKind::LBracket)
    {
        if matches!(unit.tokens.get(inner + 2).map(|token| &token.kind), Some(TokenKind::Ident(name)) if name == "test")
        {
            return true;
        }
        let Some(close) = unit.tokens[inner..]
            .iter()
            .position(|token| token.kind == TokenKind::RBracket)
        else {
            return false;
        };
        inner += close + 1;
    }
    while index >= 2 && unit.tokens[index - 1].kind == TokenKind::RBracket {
        let Some(open) = unit.tokens[..index - 1]
            .iter()
            .rposition(|token| token.kind == TokenKind::LBracket)
        else {
            return false;
        };
        if open == 0 || unit.tokens[open - 1].kind != TokenKind::Hash {
            return false;
        }
        if matches!(&unit.tokens.get(open + 1).map(|token| &token.kind), Some(TokenKind::Ident(name)) if name == "test")
        {
            return true;
        }
        index = open - 1;
    }
    false
}
fn slice_between(unit: &EditorUnit, first: Option<&Token>, last: Option<&Token>) -> String {
    match (first, last) {
        (Some(first), Some(last)) if first.range.start <= last.range.end => unit
            .file
            .slice(TextRange::new(first.range.start, last.range.end))
            .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "))
            .unwrap_or_default(),
        _ => String::new(),
    }
}
/// Fields of a struct or variants of an error enum, read from the declaration body tokens.
fn members(unit: &EditorUnit, range: TextRange, variants: bool) -> Vec<EditorSymbol> {
    let start = token_index(unit, range.start);
    let Some(open) = unit.tokens[start..]
        .iter()
        .position(|token| token.kind == TokenKind::LBrace)
        .map(|position| start + position)
    else {
        return Vec::new();
    };
    let mut members = Vec::new();
    let mut item_start = open + 1;
    let mut depth = 0_usize;
    for index in open + 1..unit.tokens.len() {
        let token = &unit.tokens[index];
        if token.range.start >= range.end {
            break;
        }
        match token.kind {
            TokenKind::LParen | TokenKind::LBracket => depth += 1,
            TokenKind::RParen | TokenKind::RBracket => depth = depth.saturating_sub(1),
            TokenKind::Comma | TokenKind::Semicolon | TokenKind::RBrace if depth == 0 => {
                let mut item = &unit.tokens[item_start..index];
                while item.len() >= 2
                    && item[0].kind == TokenKind::Hash
                    && item[1].kind == TokenKind::LBracket
                {
                    let Some(close) = item
                        .iter()
                        .position(|token| token.kind == TokenKind::RBracket)
                    else {
                        break;
                    };
                    item = &item[close + 1..];
                }
                let name = if variants {
                    item.iter()
                        .position(|token| token.kind == TokenKind::Equal)
                        .and_then(|equal| equal.checked_sub(1))
                        .and_then(|name| item.get(name))
                } else {
                    item.last()
                };
                if let Some(name) = name.filter(|token| matches!(token.kind, TokenKind::Ident(_))) {
                    let detail = if variants {
                        item.last()
                            .filter(|token| matches!(token.kind, TokenKind::Number(_)))
                            .map(|code| format!("= {}", spelled(unit, code)))
                            .unwrap_or_default()
                    } else {
                        let type_end = item.len().saturating_sub(2);
                        slice_between(unit, item.first(), item.get(type_end))
                    };
                    members.push(EditorSymbol {
                        name: spelled(unit, name),
                        detail,
                        kind: if variants { 22 } else { 8 },
                        range: TextRange::new(
                            item.first()
                                .map_or(name.range.start, |token| token.range.start),
                            name.range
                                .end
                                .max(item.last().map_or(name.range.end, |token| token.range.end)),
                        ),
                        selection: name.range,
                        children: Vec::new(),
                    });
                }
                if token.kind == TokenKind::RBrace {
                    break;
                }
                item_start = index + 1;
            }
            _ => {}
        }
    }
    members
}

impl EditorSnapshot {
    fn declaration_symbol(
        &self,
        unit: &EditorUnit,
        kind: DeclarationKind,
        range: TextRange,
        selection: TextRange,
    ) -> Option<EditorSymbol> {
        let name = unit.file.slice(selection)?.to_owned();
        let header = header(unit, range);
        let first = |kinds: &[TokenKind]| header.iter().find(|token| kinds.contains(&token.kind));
        let name_index = header
            .iter()
            .position(|token| token.range == selection)
            .unwrap_or(header.len());
        let (kind, detail, children) = match kind {
            DeclarationKind::SourceUnit => {
                let keyword = first(&[TokenKind::Seiyaku, TokenKind::Module])?;
                (
                    if keyword.kind == TokenKind::Module {
                        2
                    } else {
                        5
                    },
                    spelled(unit, keyword),
                    Vec::new(),
                )
            }
            DeclarationKind::Function => {
                let test = has_test_attribute(unit, range.start);
                let authorization = header
                    .iter()
                    .position(|token| token.kind == TokenKind::Authorize)
                    .map(|index| slice_between(unit, header.get(index), header.get(index + 3)));
                let (kind, mut detail) =
                    if let Some(hook) = first(&[TokenKind::Hajimari, TokenKind::Kaizen]) {
                        (9, spelled(unit, hook))
                    } else if let Some(modifier) = first(&[TokenKind::Kotoage, TokenKind::View]) {
                        (6, format!("{} fn", spelled(unit, modifier)))
                    } else if test {
                        (12, "#[test] fn".to_owned())
                    } else {
                        (12, "fn".to_owned())
                    };
                if let Some(authorization) = authorization {
                    detail.push(' ');
                    detail.push_str(&authorization);
                }
                (kind, detail, Vec::new())
            }
            DeclarationKind::Struct => (23, "struct".to_owned(), members(unit, range, false)),
            DeclarationKind::Event => (24, "event".to_owned(), members(unit, range, false)),
            DeclarationKind::Enum => (10, "error enum".to_owned(), members(unit, range, true)),
            DeclarationKind::State | DeclarationKind::Const => {
                let keyword = first(&[TokenKind::State, TokenKind::Const])?;
                let keyword_index = header
                    .iter()
                    .position(|token| token.range == keyword.range)
                    .unwrap_or(0);
                let ty = slice_between(
                    unit,
                    header.get(keyword_index + 1),
                    name_index
                        .checked_sub(1)
                        .and_then(|index| header.get(index)),
                );
                (
                    if keyword.kind == TokenKind::State {
                        7
                    } else {
                        14
                    },
                    format!("{} {ty}", spelled(unit, keyword)),
                    Vec::new(),
                )
            }
            DeclarationKind::Trigger => {
                // `trigger wake -> callback`: show the callback the trigger dispatches.
                let callback = header
                    .iter()
                    .position(|token| token.kind == TokenKind::Arrow)
                    .map(|arrow| slice_between(unit, header.get(arrow + 1), header.last()))
                    .filter(|callback| !callback.is_empty());
                (
                    24,
                    callback.map_or_else(
                        || "trigger".to_owned(),
                        |callback| format!("trigger -> {callback}"),
                    ),
                    Vec::new(),
                )
            }
            DeclarationKind::Permission => (14, "permission".to_owned(), Vec::new()),
            DeclarationKind::Parameter => return None,
        };
        Some(EditorSymbol {
            name,
            detail,
            kind,
            range,
            selection,
            children,
        })
    }
    /// Outline of one source: its source unit and every declaration, nested by range.
    pub fn document_symbols(&self, source: SourceId) -> Vec<EditorSymbol> {
        let Some(unit) = self.units.get(&source) else {
            return Vec::new();
        };
        let mut symbols = unit
            .facts
            .declarations
            .iter()
            .filter_map(|declaration| {
                let range = unit.facts.source_map.node(declaration.node)?.range;
                let selection = unit.facts.source_map.node(declaration.name_node)?.range;
                self.declaration_symbol(unit, declaration.kind, range, selection)
            })
            .collect::<Vec<_>>();
        symbols.sort_by_key(|symbol| (symbol.range.start, std::cmp::Reverse(symbol.range.end)));
        let mut roots: Vec<EditorSymbol> = Vec::new();
        for symbol in symbols {
            if let Some(parent) = roots.last_mut()
                && parent.range.start <= symbol.range.start
                && symbol.range.end <= parent.range.end
                && matches!(parent.kind, 2 | 5)
            {
                parent.children.push(symbol);
            } else {
                roots.push(symbol);
            }
        }
        roots
    }
    /// Declarations across every source in the snapshot whose name contains `query`
    /// (case-insensitively), each with its source identity and container name.
    pub fn workspace_symbols(&self, query: &str) -> Vec<(SourceId, EditorSymbol, Option<String>)> {
        let query = query.to_lowercase();
        let mut found = Vec::new();
        for source in self.units.keys() {
            let mut pending = self
                .document_symbols(*source)
                .into_iter()
                .map(|symbol| (symbol, None::<String>))
                .collect::<Vec<_>>();
            while let Some((mut symbol, container)) = pending.pop() {
                let children = std::mem::take(&mut symbol.children);
                pending.extend(
                    children
                        .into_iter()
                        .map(|child| (child, Some(symbol.name.clone()))),
                );
                if symbol.name.to_lowercase().contains(&query) {
                    found.push((*source, symbol, container));
                }
            }
        }
        found.sort_by(|left, right| {
            (left.0, left.1.range.start).cmp(&(right.0, right.1.range.start))
        });
        found
    }
    /// Multi-line delimiter blocks and comment runs.
    pub fn folding_ranges(&self, source: SourceId) -> Vec<EditorFold> {
        let Some(unit) = self.units.get(&source) else {
            return Vec::new();
        };
        let line = |offset: u32| unit.file.line_column(offset).line;
        let mut stack = Vec::new();
        let mut folds = Vec::new();
        for token in &unit.tokens {
            match token.kind {
                TokenKind::LBrace | TokenKind::LParen | TokenKind::LBracket => {
                    stack.push(token.range.start);
                }
                TokenKind::RBrace | TokenKind::RParen | TokenKind::RBracket => {
                    if let Some(start) = stack.pop()
                        && line(token.range.start) > line(start) + 1
                    {
                        folds.push(EditorFold {
                            range: TextRange::new(start, token.range.start),
                            comment: false,
                        });
                    }
                }
                _ => {}
            }
        }
        let lexed = crate::syntax::lex(&unit.file, crate::source::FrontendBudget::v1());
        // Consecutive line comments: (range, first line, last line).
        let mut run: Option<(TextRange, usize, usize)> = None;
        let close_run = |run: Option<(TextRange, usize, usize)>, folds: &mut Vec<EditorFold>| {
            if let Some((range, first, last)) = run
                && last > first
            {
                folds.push(EditorFold {
                    range,
                    comment: true,
                });
            }
        };
        for token in &lexed.tokens {
            match token.kind {
                crate::syntax::SyntaxKind::BlockComment
                    if line(token.range.end) > line(token.range.start) =>
                {
                    close_run(run.take(), &mut folds);
                    folds.push(EditorFold {
                        range: token.range,
                        comment: true,
                    });
                }
                crate::syntax::SyntaxKind::LineComment | crate::syntax::SyntaxKind::DocComment => {
                    let current = line(token.range.start);
                    run = match run.take() {
                        Some((range, first, last)) if current == last + 1 => {
                            Some((TextRange::new(range.start, token.range.end), first, current))
                        }
                        previous => {
                            close_run(previous, &mut folds);
                            Some((token.range, current, current))
                        }
                    };
                }
                crate::syntax::SyntaxKind::Whitespace => {}
                _ => close_run(run.take(), &mut folds),
            }
        }
        close_run(run, &mut folds);
        folds.sort_by_key(|fold| (fold.range.start, fold.range.end));
        folds
    }
    /// Uses of the declaration under the cursor within the same source.
    pub fn highlights(&self, source: SourceId, offset: u32) -> Vec<EditorHighlight> {
        let Some(definition) = self.definition(source, offset) else {
            return Vec::new();
        };
        self.occurrences
            .iter()
            .filter(|occurrence| {
                occurrence.identity == definition.identity && occurrence.source.source == source
            })
            .map(|occurrence| EditorHighlight {
                range: occurrence.source.range,
                kind: if occurrence.declaration {
                    1
                } else if occurrence.write {
                    3
                } else {
                    2
                },
            })
            .collect()
    }
    /// Local `#[test]` functions that `koto test run --filter <name> --exact` can run.
    pub fn test_lenses(&self, source: SourceId) -> Vec<EditorTestLens> {
        let Some(unit) = self.units.get(&source) else {
            return Vec::new();
        };
        unit.facts
            .declarations
            .iter()
            .filter(|declaration| declaration.kind == DeclarationKind::Function)
            .filter_map(|declaration| {
                let range = unit.facts.source_map.node(declaration.node)?.range;
                let name = unit.facts.source_map.node(declaration.name_node)?.range;
                has_test_attribute(unit, range.start).then(|| EditorTestLens {
                    name: declaration.name.clone(),
                    range: name,
                })
            })
            .collect()
    }
    fn identity_token(&self, unit: &EditorUnit, range: TextRange) -> Option<(u32, u32)> {
        let occurrence = self.occurrences.iter().find(|occurrence| {
            occurrence.source.source == unit.file.id() && occurrence.source.range == range
        })?;
        let definition = self.definitions.get(&occurrence.identity)?;
        let declaration = if occurrence.declaration {
            DECLARATION
        } else {
            0
        };
        let token_type = match definition.identity {
            EditorIdentity::Binding(owner, binding) => {
                let parameter = self
                    .units
                    .get(&owner)
                    .and_then(|owner| owner.resolved.as_ref())
                    .and_then(|resolved| {
                        resolved
                            .bindings()
                            .find(|candidate| candidate.id == binding)
                    })
                    .is_some_and(|binding| binding.kind == ResolvedBindingKind::Parameter);
                if parameter { PARAMETER } else { VARIABLE }
            }
            EditorIdentity::Symbol(..) => match definition.kind {
                3 => match definition
                    .signature
                    .as_ref()
                    .and_then(|signature| signature.function_kind)
                {
                    Some(FunctionKind::Kotoage | FunctionKind::View) => METHOD,
                    _ => FUNCTION,
                },
                22 => STRUCT,
                13 => ENUM,
                6 => PROPERTY,
                21 => return Some((VARIABLE, declaration | READONLY)),
                _ => TYPE,
            },
        };
        Some((token_type, declaration))
    }
    fn heuristic_token(unit: &EditorUnit, index: usize, name: &str) -> Option<(u32, u32)> {
        let previous = index
            .checked_sub(1)
            .and_then(|index| unit.tokens.get(index))
            .map(|token| &token.kind);
        let next = unit.tokens.get(index + 1).map(|token| &token.kind);
        let labelled = is_label(unit, index);
        let is_type = kotodama_surface::source_policy::V1_SOURCE_TYPE_NAMES.contains(&name)
            || name == "Rounding";
        Some(match (previous, next) {
            (_, Some(TokenKind::ColonColon)) => (if is_type { TYPE } else { NAMESPACE }, 0),
            (Some(TokenKind::ColonColon), Some(TokenKind::LParen)) => (FUNCTION, DEFAULT_LIBRARY),
            (Some(TokenKind::ColonColon), _) => (ENUM_MEMBER, 0),
            (Some(TokenKind::Dot), Some(TokenKind::LParen)) => (METHOD, DEFAULT_LIBRARY),
            (Some(TokenKind::Dot), _) => (PROPERTY, 0),
            (_, Some(TokenKind::LParen))
                if kotodama_surface::builtins::Builtin::from_source_name(name).is_some() =>
            {
                (FUNCTION, DEFAULT_LIBRARY)
            }
            _ if is_type => (TYPE, DEFAULT_LIBRARY),
            _ if labelled => (PARAMETER, 0),
            _ => return None,
        })
    }
    /// Classified tokens of one source in source order. Strings spanning lines are omitted.
    pub fn semantic_tokens(&self, source: SourceId) -> Vec<EditorSemanticToken> {
        let Some(unit) = self.units.get(&source) else {
            return Vec::new();
        };
        let mut tokens = Vec::new();
        for (index, token) in unit.tokens.iter().enumerate() {
            let classified = match &token.kind {
                // `test::invoke_kotoage(kotoage: "quote")`: a keyword used as an argument label.
                kind if context::is_keyword(kind) && is_label(unit, index) => Some((PARAMETER, 0)),
                kind if context::is_branded_keyword(kind) => Some((BRANDED_KEYWORD, 0)),
                kind if context::is_keyword(kind) => Some((KEYWORD, 0)),
                TokenKind::String(_) | TokenKind::Bytes(_) => {
                    (unit.file.line_column(token.range.start).line
                        == unit.file.line_column(token.range.end).line)
                        .then_some((STRING, 0))
                }
                TokenKind::Number(_) | TokenKind::DecimalLiteral(_) => Some((NUMBER, 0)),
                TokenKind::Ident(name) => self
                    .identity_token(unit, token.range)
                    .or_else(|| Self::heuristic_token(unit, index, name)),
                _ => None,
            };
            if let Some((token_type, modifiers)) = classified {
                tokens.push(EditorSemanticToken {
                    range: token.range,
                    token_type,
                    modifiers,
                });
            }
        }
        tokens
    }
    /// Whether the resolved symbol at `range` is a source-unit declaration.
    #[cfg(test)]
    fn is_source_unit(&self, source: SourceId, range: TextRange) -> bool {
        self.units
            .get(&source)
            .and_then(|unit| unit.resolved.as_ref())
            .is_some_and(|resolved| {
                resolved.symbols().any(|symbol| {
                    symbol.source.range == range
                        && symbol.kind == super::ResolvedSymbolKind::SourceUnit
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "// Counter seiyaku.\n// Mixed spellings are one language.\n誓約 Counter { permission CanBump; permission CanReset; \n    state int value;\n    const int LIMIT = 10;\n    error enum Failure {\n        #[message(\"Too large\")]\n        TooLarge = 1,\n    }\n    struct Pair { int first; int second; }\n    始まり() {\n        value = 0;\n    }\n    改善() {\n        value = 1;\n    }\n    trigger wake -> reset {\n        on time pre_commit;\n    }\n    kotoage fn bump(int delta) authorize(CanBump) -> int {\n        value = value + delta;\n        value\n    }\n    言挙げ fn reset() authorize(CanReset) {\n        value = 0;\n    }\n    view fn read() authorize(anyone) -> int { value }\n}\n";

    fn snapshot() -> EditorSnapshot {
        EditorSnapshot::single("counter.ko", SOURCE, false)
    }

    #[test]
    fn outline_nests_declarations_and_echoes_written_spellings() {
        let snapshot = snapshot();
        let symbols = snapshot.document_symbols(SourceId(0));
        assert_eq!(symbols.len(), 1);
        let unit = &symbols[0];
        assert_eq!(
            (unit.name.as_str(), unit.detail.as_str(), unit.kind),
            ("Counter", "誓約", 5)
        );
        assert!(snapshot.is_source_unit(SourceId(0), unit.selection));
        let children = unit
            .children
            .iter()
            .map(|symbol| (symbol.name.as_str(), symbol.detail.as_str(), symbol.kind))
            .collect::<Vec<_>>();
        assert_eq!(
            children,
            vec![
                ("CanBump", "permission", 14),
                ("CanReset", "permission", 14),
                ("value", "state int", 7),
                ("LIMIT", "const int", 14),
                ("Failure", "error enum", 10),
                ("Pair", "struct", 23),
                ("始まり", "始まり", 9),
                ("改善", "改善", 9),
                ("wake", "trigger -> reset", 24),
                ("bump", "kotoage fn authorize(CanBump)", 6),
                ("reset", "言挙げ fn authorize(CanReset)", 6),
                ("read", "view fn authorize(anyone)", 6),
            ]
        );
        let failure = &unit.children[4];
        assert_eq!(failure.children[0].name, "TooLarge");
        assert_eq!(failure.children[0].detail, "= 1");
        let pair = &unit.children[5];
        assert_eq!(
            pair.children
                .iter()
                .map(|field| (field.name.as_str(), field.detail.as_str()))
                .collect::<Vec<_>>(),
            vec![("first", "int"), ("second", "int")]
        );
        for symbol in &unit.children {
            assert!(unit.range.start <= symbol.range.start && symbol.range.end <= unit.range.end);
            assert!(
                symbol.range.start <= symbol.selection.start
                    && symbol.selection.end <= symbol.range.end
            );
        }
        let workspace = snapshot.workspace_symbols("RE");
        assert_eq!(
            workspace
                .iter()
                .map(|(_, symbol, container)| (symbol.name.as_str(), container.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                ("CanReset", Some("Counter")),
                ("Failure", Some("Counter")),
                ("reset", Some("Counter")),
                ("read", Some("Counter"))
            ]
        );
    }

    #[test]
    fn branded_keywords_share_one_semantic_token_type_in_both_scripts() {
        let snapshot = snapshot();
        let tokens = snapshot.semantic_tokens(SourceId(0));
        let type_of = |needle: &str| {
            let start = u32::try_from(SOURCE.find(needle).expect(needle)).unwrap();
            tokens
                .iter()
                .find(|token| token.range.start == start)
                .map(|token| SEMANTIC_TOKEN_TYPES[token.token_type as usize])
        };
        for spelling in ["誓約", "始まり", "kotoage", "言挙げ"] {
            assert_eq!(type_of(spelling), Some("brandedKeyword"), "{spelling}");
        }
        assert_eq!(type_of("view"), Some("keyword"));
        assert_eq!(type_of("int delta"), Some("type"));
        assert_eq!(type_of("delta)"), Some("parameter"));
        assert_eq!(type_of("bump"), Some("method"));
        assert_eq!(type_of("Failure {"), Some("enum"));
        assert_eq!(type_of("CanBump;"), Some("type"));
        let mut previous = None;
        for token in &tokens {
            assert!(previous.is_none_or(|end| end <= token.range.start));
            previous = Some(token.range.end);
        }
    }

    #[test]
    fn only_labels_before_a_colon_are_parameters() {
        let source = "module M {\n    fn pick(bool c) -> bool { c ? true : false }\n    fn helper(int value) -> int { value }\n    fn call() -> int { helper(value: 1) }\n    fn branch(bool c, int a, int b) -> int { c ? a : b }\n}\n";
        let snapshot = EditorSnapshot::single("labels.ko", source, false);
        let tokens = snapshot.semantic_tokens(SourceId(0));
        let type_of = |needle: &str| {
            let start = u32::try_from(source.find(needle).expect(needle)).unwrap();
            tokens
                .iter()
                .find(|token| token.range.start == start)
                .map(|token| SEMANTIC_TOKEN_TYPES[token.token_type as usize])
        };
        assert_eq!(type_of("true :"), Some("keyword"));
        assert_eq!(type_of("value: 1"), Some("parameter"));
        assert_eq!(type_of("a : b"), Some("parameter"));
        let unit = snapshot.units.get(&SourceId(0)).expect("unit");
        let index = |needle: &str| {
            let start = u32::try_from(source.find(needle).expect(needle)).unwrap();
            unit.tokens
                .iter()
                .position(|token| token.range.start == start)
                .expect("token")
        };
        assert!(is_label(unit, index("value: 1")));
        assert!(!is_label(unit, index("true :")));
        assert!(!is_label(unit, index("a : b")));
    }

    #[test]
    fn folds_highlights_and_test_lenses_follow_source_structure() {
        let snapshot = snapshot();
        let folds = snapshot.folding_ranges(SourceId(0));
        assert!(
            folds
                .iter()
                .any(|fold| fold.comment && fold.range.start == 0)
        );
        assert!(folds.iter().any(|fold| !fold.comment
            && fold.range.start == u32::try_from(SOURCE.find("{ permission").unwrap()).unwrap()));
        let value = u32::try_from(SOURCE.find("value;").unwrap()).unwrap();
        let highlights = snapshot.highlights(SourceId(0), value);
        assert_eq!(
            highlights
                .iter()
                .filter(|highlight| highlight.kind == 1)
                .count(),
            1
        );
        assert!(highlights.iter().any(|highlight| highlight.kind == 3));
        assert!(highlights.iter().any(|highlight| highlight.kind == 2));
        let tests = EditorSnapshot::single(
            "tests.ko",
            "module T {\n    #[test]\n    fn first() {}\n    fn helper() {}\n    #[test(fixture = alice)]\n    fn second() {}\n}\n",
            false,
        );
        assert_eq!(
            tests
                .test_lenses(SourceId(0))
                .into_iter()
                .map(|lens| lens.name)
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
    }
}

//! Syntactic completion sites and the keyword vocabulary shown by completion and hover.
//!
//! Classification reads only the significant token stream before the cursor, so it works on
//! incomplete buffers. Branded keywords are offered in both spellings; neither script is
//! preferred, and hover echoes the spelling written at the hovered site.
use super::{EditorCompletion, Token, TokenKind};
use crate::glossary;

/// Kind of the innermost source unit around the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UnitKind {
    /// `seiyaku`/`誓約` body.
    Seiyaku,
    /// `module` body.
    Module,
    /// Bare declaration fragment included by a seiyaku or module.
    Fragment,
}

/// What may be written at the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompletionSite {
    /// Outside every source unit of a file that has no source unit yet.
    TopLevel {
        /// The file already holds bare fragment declarations.
        fragment: bool,
        /// No significant token precedes the cursor, so a `seiyaku`/`誓約` or `module` header
        /// may still start the file.
        unit_start: bool,
    },
    /// Start of a declaration inside a source unit or fragment.
    ItemStart(UnitKind),
    /// After `kotoage`/`言挙げ` or `view`: only `fn` may follow.
    AfterEntrypointModifier,
    /// After `export` in a module.
    AfterExport,
    /// After `error`: only `enum` may follow.
    AfterError,
    /// A type is expected.
    Type,
    /// Inside a `kotoage`/`言挙げ` or `view` header after its parameter list or return type,
    /// where `authorize(...)` may follow.
    FunctionHeader,
    /// The explicit caller policy in a public function header.
    Authorization,
    /// A declared native event name after `emit`.
    Event,
    /// Start of a statement in a function body.
    Statement,
    /// Inside an expression.
    Expression,
    /// Directly after `else`.
    AfterElse,
    /// No word completion applies (declared names, error variants, trigger metadata).
    Nothing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Block {
    Unit(UnitKind),
    Function,
    Struct,
    Other,
}

/// Whether the token is one of the V1 keywords of the generated `grammar/v1.lex` table.
pub(super) fn is_keyword(kind: &TokenKind) -> bool {
    crate::lexer::v1_keyword_spelling(kind).is_some()
}

/// Whether the token is one of the glossary's branded keywords, in either spelling. Both
/// spellings lex to one token kind, so the script never affects the answer.
pub(super) fn is_branded_keyword(kind: &TokenKind) -> bool {
    crate::lexer::v1_keyword_spelling(kind)
        .is_some_and(|spelling| glossary::by_spelling(spelling).is_some())
}

fn without_attributes<'a>(run: &'a [&'a TokenKind]) -> &'a [&'a TokenKind] {
    let mut rest = run;
    while let [TokenKind::Hash, TokenKind::LBracket, tail @ ..] = rest {
        let Some(close) = tail.iter().position(|kind| **kind == TokenKind::RBracket) else {
            return rest;
        };
        rest = &tail[close + 1..];
    }
    rest
}

fn item_block(run: &[&TokenKind]) -> Block {
    let run = without_attributes(run);
    if run.iter().any(|kind| {
        matches!(
            kind,
            TokenKind::Fn | TokenKind::Hajimari | TokenKind::Kaizen
        )
    }) {
        Block::Function
    } else if run.first() == Some(&&TokenKind::Event)
        || run.first() == Some(&&TokenKind::Struct)
        || run.starts_with(&[&TokenKind::Export, &TokenKind::Struct])
    {
        Block::Struct
    } else {
        Block::Other
    }
}

fn item_site(unit: UnitKind, run: &[&TokenKind], parens: usize) -> CompletionSite {
    let run = without_attributes(run);
    let Some(last) = run.last() else {
        return CompletionSite::ItemStart(unit);
    };
    let header = run.iter().any(|kind| {
        matches!(
            kind,
            TokenKind::Fn | TokenKind::Hajimari | TokenKind::Kaizen
        )
    });
    if parens > 0
        && run
            .iter()
            .rev()
            .take_while(|kind| !matches!(kind, TokenKind::RParen))
            .any(|kind| matches!(kind, TokenKind::Authorize))
    {
        return CompletionSite::Authorization;
    }
    if parens > 0 {
        return if header && matches!(last, TokenKind::LParen | TokenKind::Comma) {
            CompletionSite::Type
        } else {
            CompletionSite::Nothing
        };
    }
    // Only public entrypoints declare `authorize(...)`, at most once; private functions and
    // lifecycle hooks never do.
    let entrypoint = header
        && !run.contains(&&TokenKind::Authorize)
        && !run.contains(&&TokenKind::Arrow)
        && run
            .iter()
            .any(|kind| matches!(kind, TokenKind::Kotoage | TokenKind::View));
    let after_return_type = run.contains(&&TokenKind::Arrow);
    match last {
        TokenKind::Kotoage | TokenKind::View if run.len() == 1 => {
            CompletionSite::AfterEntrypointModifier
        }
        TokenKind::Export if run.len() == 1 => CompletionSite::AfterExport,
        TokenKind::Error => CompletionSite::AfterError,
        TokenKind::State | TokenKind::Const | TokenKind::Arrow => CompletionSite::Type,
        // `-> Option<|` and `-> StateMap<int, |` still expect a type argument.
        TokenKind::Less | TokenKind::Comma if header && after_return_type => CompletionSite::Type,
        // `)` closes the parameter list or a `-> ()` return type.
        TokenKind::RParen if entrypoint => CompletionSite::FunctionHeader,
        TokenKind::Ident(_) | TokenKind::Greater if entrypoint && after_return_type => {
            CompletionSite::FunctionHeader
        }
        _ => CompletionSite::Nothing,
    }
}

/// Classify the cursor using the significant tokens before it. A word that ends exactly at the
/// cursor is the completion prefix, not context.
pub(super) fn completion_site(tokens: &[Token], offset: u32) -> CompletionSite {
    let mut before = tokens
        .iter()
        .filter(|token| token.kind != TokenKind::EOF && token.range.end <= offset)
        .collect::<Vec<_>>();
    let prefix = before
        .last()
        .filter(|token| {
            token.range.end == offset
                && (matches!(token.kind, TokenKind::Ident(_)) || is_keyword(&token.kind))
        })
        .map(|token| token.range);
    if prefix.is_some() {
        before.pop();
    }
    let context_tokens = || {
        tokens
            .iter()
            .filter(move |token| token.kind != TokenKind::EOF && Some(token.range) != prefix)
    };
    let unit_start = before.is_empty();
    let mut stack = Vec::<Block>::new();
    let mut run = Vec::<&TokenKind>::new();
    let mut parens = 0_usize;
    for token in before {
        match &token.kind {
            TokenKind::LBrace => {
                let block = match stack.last() {
                    None if run.contains(&&TokenKind::Seiyaku) => Block::Unit(UnitKind::Seiyaku),
                    None if run.contains(&&TokenKind::Module) => Block::Unit(UnitKind::Module),
                    None | Some(Block::Unit(_)) => item_block(&run),
                    Some(Block::Function) => Block::Function,
                    Some(Block::Struct | Block::Other) => Block::Other,
                };
                stack.push(block);
                run.clear();
                parens = 0;
            }
            TokenKind::RBrace => {
                stack.pop();
                run.clear();
                parens = 0;
            }
            TokenKind::Semicolon if parens == 0 => run.clear(),
            kind @ (TokenKind::LParen | TokenKind::LBracket) => {
                parens += 1;
                run.push(kind);
            }
            kind @ (TokenKind::RParen | TokenKind::RBracket) => {
                parens = parens.saturating_sub(1);
                run.push(kind);
            }
            kind => run.push(kind),
        }
    }
    match stack.last() {
        None => {
            let has_unit = context_tokens()
                .any(|token| matches!(token.kind, TokenKind::Seiyaku | TokenKind::Module));
            if has_unit {
                CompletionSite::Nothing
            } else if run.is_empty() {
                CompletionSite::TopLevel {
                    fragment: context_tokens().next().is_some(),
                    unit_start,
                }
            } else {
                item_site(UnitKind::Fragment, &run, parens)
            }
        }
        Some(Block::Unit(unit)) => item_site(*unit, &run, parens),
        Some(Block::Function) => match run.last() {
            _ if parens > 0 => CompletionSite::Expression,
            None => CompletionSite::Statement,
            Some(TokenKind::Else) => CompletionSite::AfterElse,
            Some(TokenKind::Emit) => CompletionSite::Event,
            Some(TokenKind::Let | TokenKind::Var) => CompletionSite::Type,
            Some(_) => CompletionSite::Expression,
        },
        Some(Block::Struct) => match run.last() {
            None | Some(TokenKind::Comma) => CompletionSite::Type,
            Some(_) => CompletionSite::Nothing,
        },
        Some(Block::Other) => CompletionSite::Nothing,
    }
}

/// Statement keywords offered at the start of a statement.
pub(super) const STATEMENT_KEYWORDS: &[&str] = &[
    "let", "var", "if", "for", "match", "return", "break", "continue", "emit",
];
/// Keywords that are complete expressions.
pub(super) const EXPRESSION_KEYWORDS: &[&str] = &["true", "false", "if", "match"];

/// One-line documentation for ordinary (non-branded) V1 keywords.
const KEYWORD_DOCS: &[(&str, &str)] = &[
    (
        "event",
        "Declares a seiyaku-owned native event payload: `event Transfer { AccountId from; quantity amount; }`. Event payloads contain canonical public values and cannot be used as ordinary value types.",
    ),
    (
        "emit",
        "Emits one checked native event record: `emit Transfer { from: owner, amount: total };`. Fields evaluate once in source order; views cannot emit events.",
    ),
    (
        "as",
        "Names the alias of an import: `import \"./math.ko\" as math;`.",
    ),
    (
        "authorize",
        "Declares caller policy: `authorize(Admin)` uses a declared permission and `authorize(anyone)` explicitly permits every caller. Every `kotoage`/`言挙げ` fn and `view fn` declares a policy before the return type; lifecycle hooks never do.",
    ),
    (
        "break",
        "Leaves the innermost bounded `for` loop: `break;`.",
    ),
    (
        "const",
        "Declares a typed constant: `const Type NAME = expression;`.",
    ),
    (
        "continue",
        "Skips to the next iteration of the innermost bounded `for` loop: `continue;`.",
    ),
    ("else", "Introduces the alternative branch of an `if`."),
    (
        "enum",
        "Declares a closed nominal data type: `enum Name { Variant = 1 }`. Every variant has an explicit nonzero code; ordinary variants cannot reject execution.",
    ),
    (
        "error",
        "Begins an error enum: `error enum Name { Variant = 1 }`. Every variant has an explicit, non-zero numeric code used to reject execution with `require`.",
    ),
    (
        "export",
        "Makes a module declaration reachable through `import`: `export fn`, `export struct`, `export const`, `export enum` or `export error enum`.",
    ),
    ("false", "The boolean constant `false`."),
    (
        "fn",
        "Declares a function: `fn name(Type parameter) -> Type { ... }`. A plain `fn` is internal; `view fn` and `kotoage fn`/`言挙げ fn` are public entrypoints.",
    ),
    (
        "for",
        "Bounded loop: `for item in values { ... }` or `for index in range(limit) { ... }`.",
    ),
    (
        "if",
        "Conditional: `if condition { ... } else { ... }`; `if let` matches an `Option` or `Result` payload.",
    ),
    (
        "import",
        "Imports a named local module under an alias: `import \"./math.ko\" as math;`. Only its `export`ed declarations are reachable as `math::name`.",
    ),
    (
        "in",
        "Separates the binding from the iterated value in a `for` loop.",
    ),
    (
        "include",
        "Includes a declaration fragment into this source unit: `include \"./part.ko\";`. Fragment declarations share the owner's scope.",
    ),
    (
        "let",
        "Declares an immutable local binding: `let name = expression;` or `let Type name = expression;`.",
    ),
    (
        "match",
        "Matches an `Option` or `Result` value: `match value { Option::some(x) => x, Option::none => 0 }`.",
    ),
    (
        "module",
        "Declares a reusable library source unit: `module Name { ... }`. A module is not deployable; other sources `import` its `export`ed declarations.",
    ),
    (
        "permission",
        "Declares an instance permission: `permission Admin;`. Chain permissions use `import permission` with an explicit token string and alias.",
    ),
    (
        "return",
        "Returns from the current function: `return expression;` or `return;`.",
    ),
    (
        "state",
        "Declares durable seiyaku state: `state Type name;`. State persists between calls; scalar state is initialized by `hajimari`/`始まり`.",
    ),
    (
        "struct",
        "Declares a record type with named, typed fields: `struct Name { Type field; }`.",
    ),
    (
        "trigger",
        "Declares a seiyaku trigger recorded in the manifest: `trigger name -> callback { on <filter>; }`.",
    ),
    ("true", "The boolean constant `true`."),
    (
        "var",
        "Declares a mutable local binding: `var name = expression;`.",
    ),
    (
        "view",
        "Declares a read-only public function: `view fn name() authorize(anyone) -> Type { ... }`. Use a declared permission instead of `anyone` to restrict callers. Views cannot mutate durable state, emit ledger instructions or perform host side effects.",
    ),
];

/// Markdown documentation for a keyword spelling. Both spellings of a branded keyword share
/// the glossary entry.
pub(super) fn keyword_documentation(spelling: &str) -> Option<String> {
    if let Some(entry) = glossary::by_spelling(spelling) {
        return Some(entry.hover_markdown());
    }
    KEYWORD_DOCS
        .iter()
        .find(|(keyword, _)| *keyword == spelling)
        .map(|(_, text)| (*text).to_owned())
}

fn keyword_item(label: &str, detail: &str, documentation: String) -> EditorCompletion {
    EditorCompletion {
        label: label.into(),
        kind: 14,
        detail: detail.into(),
        insert_text: label.into(),
        snippet: false,
        documentation,
        filter_text: None,
        sort_text: None,
    }
}

/// A plain keyword completion documented from the keyword table.
pub(super) fn plain_keyword(keyword: &str) -> EditorCompletion {
    keyword_item(
        keyword,
        "Kotodama keyword",
        keyword_documentation(keyword).unwrap_or_default(),
    )
}

fn snippet(label: &str, detail: &str, body: String, documentation: String) -> EditorCompletion {
    EditorCompletion {
        label: label.into(),
        kind: 15,
        detail: detail.into(),
        insert_text: body,
        snippet: true,
        documentation,
        filter_text: None,
        sort_text: None,
    }
}

/// Both spellings of one branded keyword as adjacent completions. The Japanese item also
/// filters on the romanized spelling, so typing either script finds both.
fn branded_pair(
    romaji: &str,
    label_suffix: &str,
    detail: &str,
    body: impl Fn(&str) -> String,
) -> [EditorCompletion; 2] {
    let entry = glossary::by_spelling(romaji).expect("branded keyword");
    [entry.romaji, entry.kanji].map(|spelling| {
        let label = format!("{spelling}{label_suffix}");
        let mut item = snippet(&label, detail, body(spelling), entry.hover_markdown());
        item.sort_text = Some(format!(
            "{}{label_suffix} {}",
            entry.romaji,
            usize::from(spelling == entry.kanji)
        ));
        if spelling == entry.kanji {
            item.filter_text = Some(format!("{label} {}{label_suffix}", entry.romaji));
        }
        item
    })
}

/// Source-unit declarations offered at the top level of a file.
pub(super) fn source_unit_items() -> Vec<EditorCompletion> {
    let mut items = branded_pair("seiyaku", "", "deployable source unit", |spelling| {
        format!("{spelling} ${{1:Name}} {{\n\t$0\n}}")
    })
    .to_vec();
    items.push(snippet(
        "module",
        "library source unit",
        "module ${1:Name} {\n\t$0\n}".into(),
        keyword_documentation("module").unwrap_or_default(),
    ));
    items
}

/// Declarations offered at the start of an item in the given source unit.
pub(super) fn item_start_items(unit: UnitKind) -> Vec<EditorCompletion> {
    let doc = |keyword: &str| keyword_documentation(keyword).unwrap_or_default();
    let mut items = vec![
        snippet(
            "fn",
            "internal function",
            "fn ${1:name}($2) {\n\t$0\n}".into(),
            doc("fn"),
        ),
        snippet(
            "const",
            "constant",
            "const ${1:int} ${2:NAME} = $0;".into(),
            doc("const"),
        ),
        snippet(
            "struct",
            "record type",
            "struct ${1:Name} {\n\t${2:int} ${3:field};\n}".into(),
            doc("struct"),
        ),
        snippet(
            "enum",
            "nominal data variants",
            "enum ${1:Name} {\n\t${2:Variant} = ${3:1},\n}".into(),
            doc("enum"),
        ),
        snippet(
            "error enum",
            "error codes",
            "error enum ${1:Name} {\n\t${2:Variant} = ${3:1},\n}".into(),
            doc("error"),
        ),
        snippet(
            "include",
            "declaration fragment",
            "include \"${1:./part.ko}\";".into(),
            doc("include"),
        ),
        snippet(
            "import",
            "local module import",
            "import \"${1:./module.ko}\" as ${2:alias};".into(),
            doc("import"),
        ),
    ];
    if matches!(unit, UnitKind::Module | UnitKind::Fragment) {
        items.push(plain_keyword("export"));
    }
    if matches!(unit, UnitKind::Seiyaku | UnitKind::Fragment) {
        items.push(snippet(
            "event",
            "native event declaration",
            "event ${1:Name} {\n\t${2:int} ${3:field};\n}".into(),
            doc("event"),
        ));
        items.push(snippet(
            "permission",
            "instance permission",
            "permission ${1:Admin};".into(),
            doc("permission"),
        ));
        items.push(snippet(
            "import permission",
            "chain permission import",
            "import permission \"${1:CanSetParameters}\" as ${2:ChainAdmin};".into(),
            doc("permission"),
        ));
        items.push(snippet(
            "state",
            "durable state",
            "state ${1:int} ${2:name};".into(),
            doc("state"),
        ));
        items.push(snippet(
            "view fn",
            "read-only public function",
            "view fn ${1:name}($2) authorize(${3:anyone}) -> ${4:int} {\n\t$0\n}".into(),
            doc("view"),
        ));
        items.push(plain_keyword("trigger"));
        items.extend(branded_pair(
            "kotoage",
            " fn",
            "authorized public function",
            |spelling| {
                format!("{spelling} fn ${{1:name}}($2) authorize(${{3:Admin}}) {{\n\t$0\n}}")
            },
        ));
        for (romaji, detail) in [
            ("hajimari", "activation hook"),
            ("kaizen", "code-replacement migration hook"),
        ] {
            items.extend(branded_pair(romaji, "", detail, |spelling| {
                format!("{spelling}() {{\n\t$0\n}}")
            }));
        }
    }
    items
}

/// Keywords that may follow `kotoage`/`言挙げ`, `view`, `export` or `error`.
pub(super) fn modifier_items(site: CompletionSite) -> Vec<EditorCompletion> {
    match site {
        CompletionSite::AfterEntrypointModifier => vec![plain_keyword("fn")],
        CompletionSite::AfterExport => ["fn", "const", "struct", "enum", "error"]
            .into_iter()
            .map(plain_keyword)
            .collect(),
        CompletionSite::AfterError => vec![plain_keyword("enum")],
        CompletionSite::FunctionHeader => vec![snippet(
            "authorize",
            "caller authorization",
            "authorize(${1:Admin})".into(),
            keyword_documentation("authorize").unwrap_or_default(),
        )],
        CompletionSite::AfterElse => vec![plain_keyword("if")],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glossary::BRANDED_KEYWORDS;

    fn site(source: &str) -> CompletionSite {
        let marker = source.find('|').expect("cursor marker");
        let text = source.replacen('|', "", 1);
        let tokens = crate::lexer::lower_lexed_recovering(
            &crate::source::SourceFile::new(crate::source::SourceId(0), "site.ko", &text),
            crate::source::FrontendBudget::v1(),
            crate::syntax::lex(
                &crate::source::SourceFile::new(crate::source::SourceId(0), "site.ko", &text),
                crate::source::FrontendBudget::v1(),
            ),
        )
        .0;
        completion_site(&tokens, u32::try_from(marker).expect("short source"))
    }

    #[test]
    fn sites_follow_the_grammar_position() {
        let empty_file = CompletionSite::TopLevel {
            fragment: false,
            unit_start: true,
        };
        assert_eq!(site("|"), empty_file);
        assert_eq!(site("se|"), empty_file);
        assert_eq!(site("// note\n誓|"), empty_file);
        assert_eq!(
            site("seiyaku A { | }"),
            CompletionSite::ItemStart(UnitKind::Seiyaku)
        );
        assert_eq!(
            site("誓約 A { kot| }"),
            CompletionSite::ItemStart(UnitKind::Seiyaku)
        );
        assert_eq!(
            site("module M { | }"),
            CompletionSite::ItemStart(UnitKind::Module)
        );
        assert_eq!(
            site("seiyaku A { 言挙げ | }"),
            CompletionSite::AfterEntrypointModifier
        );
        assert_eq!(site("seiyaku A { state | }"), CompletionSite::Type);
        assert_eq!(site("seiyaku A { fn f(int a, | }"), CompletionSite::Type);
        assert_eq!(
            site("seiyaku A { kotoage fn f() | {} }"),
            CompletionSite::FunctionHeader
        );
        // Authorization belongs before the return type; completed guards never offer it again.
        assert_eq!(
            site("seiyaku A { 言挙げ fn f() authorize(anyone) -> int | {} }"),
            CompletionSite::Nothing
        );
        assert_eq!(
            site("seiyaku A { view fn f() authorize(anyone) -> Option<int> | {} }"),
            CompletionSite::Nothing
        );
        assert_eq!(
            site("seiyaku A { view fn f() authorize(anyone) -> () | {} }"),
            CompletionSite::Nothing
        );
        assert_eq!(
            site("seiyaku A { view fn f() authorize(anyone) -> Option<| {} }"),
            CompletionSite::Type
        );
        assert_eq!(
            site("seiyaku A { kotoage fn f() authorize(Ad|) {} }"),
            CompletionSite::Authorization
        );
        assert_eq!(site("seiyaku A { fn f() | {} }"), CompletionSite::Nothing);
        assert_eq!(
            site("seiyaku A { fn f() -> int | {} }"),
            CompletionSite::Nothing
        );
        assert_eq!(site("seiyaku A { 始まり() | {} }"), CompletionSite::Nothing);
        assert_eq!(
            site("seiyaku A { permission P;  kotoage fn f() authorize(P) | {} }"),
            CompletionSite::Nothing
        );
        assert_eq!(
            site("seiyaku A { fn f() { | } }"),
            CompletionSite::Statement
        );
        assert_eq!(
            site("seiyaku A { 始まり() { let x = 1; | } }"),
            CompletionSite::Statement
        );
        assert_eq!(
            site("seiyaku A { fn f() { let x = | } }"),
            CompletionSite::Expression
        );
        assert_eq!(
            site("seiyaku A { fn f() { require(| } }"),
            CompletionSite::Expression
        );
        assert_eq!(
            site("seiyaku A { fn f() { if true {} else | } }"),
            CompletionSite::AfterElse
        );
        assert_eq!(site("seiyaku A { struct S { | } }"), CompletionSite::Type);
        assert_eq!(
            site("seiyaku A { error enum E { | } }"),
            CompletionSite::Nothing
        );
        assert_eq!(site("seiyaku A {} |"), CompletionSite::Nothing);
        // A fragment file can no longer start with a source-unit header.
        assert_eq!(
            site("fn helper() {} |"),
            CompletionSite::TopLevel {
                fragment: true,
                unit_start: false,
            }
        );
        assert_eq!(
            site("| fn helper() {}"),
            CompletionSite::TopLevel {
                fragment: true,
                unit_start: true,
            }
        );
        assert_eq!(
            site("seiyaku A { #[test] | }"),
            CompletionSite::ItemStart(UnitKind::Seiyaku)
        );
    }

    #[test]
    fn branded_items_offer_both_spellings_with_romaji_filtering() {
        let items = item_start_items(UnitKind::Seiyaku);
        for keyword in &BRANDED_KEYWORDS[1..] {
            let romaji = items
                .iter()
                .find(|item| item.label.starts_with(keyword.romaji))
                .expect("romaji item");
            let kanji = items
                .iter()
                .find(|item| item.label.starts_with(keyword.kanji))
                .expect("kanji item");
            assert!(romaji.insert_text.starts_with(keyword.romaji));
            assert!(kanji.insert_text.starts_with(keyword.kanji));
            assert!(
                kanji
                    .filter_text
                    .as_deref()
                    .is_some_and(|text| text.contains(keyword.romaji))
            );
            assert_eq!(romaji.documentation, kanji.documentation);
            assert!(romaji.sort_text < kanji.sort_text);
        }
        let module = item_start_items(UnitKind::Module);
        assert!(
            module
                .iter()
                .all(|item| !item.label.contains("kotoage") && item.label != "state")
        );
        let units = source_unit_items();
        assert_eq!(
            units
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["seiyaku", "誓約", "module"]
        );
    }

    #[test]
    fn keyword_predicates_follow_the_generated_table_in_both_scripts() {
        for spelling in crate::lexer::V1_KEYWORDS {
            let kind = crate::lexer::v1_keyword_kind(spelling).expect("V1 keyword");
            assert!(is_keyword(&kind), "`{spelling}` is a keyword");
            assert_eq!(
                is_branded_keyword(&kind),
                glossary::by_spelling(spelling).is_some(),
                "`{spelling}` branding"
            );
        }
        for keyword in &BRANDED_KEYWORDS {
            let romaji = crate::lexer::v1_keyword_kind(keyword.romaji).expect("romaji");
            let kanji = crate::lexer::v1_keyword_kind(keyword.kanji).expect("kanji");
            assert_eq!(romaji, kanji, "both spellings are one token");
            assert!(is_branded_keyword(&kanji));
        }
        for kind in [
            TokenKind::Ident("kotoage_total".into()),
            TokenKind::Semicolon,
            TokenKind::String("seiyaku".into()),
        ] {
            assert!(!is_keyword(&kind) && !is_branded_keyword(&kind), "{kind:?}");
        }
    }

    #[test]
    fn keyword_vocabulary_is_documented_from_v1_keywords() {
        for keyword in crate::lexer::V1_KEYWORDS {
            assert!(
                keyword_documentation(keyword).is_some(),
                "keyword `{keyword}` has no editor documentation"
            );
        }
        for (keyword, _) in KEYWORD_DOCS {
            assert!(crate::lexer::V1_KEYWORDS.contains(keyword));
        }
        for keyword in STATEMENT_KEYWORDS.iter().chain(EXPRESSION_KEYWORDS) {
            assert!(crate::lexer::V1_KEYWORDS.contains(keyword));
        }
        assert_eq!(
            keyword_documentation("言挙げ"),
            keyword_documentation("kotoage")
        );
        for spelling in BRANDED_KEYWORDS
            .iter()
            .flat_map(|keyword| keyword.spellings())
        {
            assert!(
                keyword_documentation(spelling).is_some_and(|text| text.contains("mixed freely"))
            );
        }
        assert!(plain_keyword("view").documentation.contains("read-only"));
    }
}

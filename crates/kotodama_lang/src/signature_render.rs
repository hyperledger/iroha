//! Source-syntax rendering of Kotodama declarations, call signatures and builtin specs.
//!
//! Editor hover, completion and signature help, and `koto doc`, describe callables with
//! this renderer instead of compiler-internal `Debug` output. Declarations render exactly
//! as the V1 grammar spells them, using the keyword spelling written at the declaration
//! site: a `言挙げ fn` stays `言挙げ` and a `kotoage fn` stays `kotoage`. Branded keyword
//! wording comes from [`crate::glossary`]; builtin summaries come from
//! [`kotodama_surface::builtin_docs`], and effects, access and call policy are rendered
//! from the canonical builtin registry as plain words.
use crate::{ast::FunctionKind, glossary};
use kotodama_surface::builtins::{
    Builtin, BuiltinAccess, BuiltinCallPolicy, BuiltinEffects, BuiltinMode, BuiltinSurface,
};

/// One parameter in source order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenderParameter<'a> {
    /// Declared parameter name.
    pub name: &'a str,
    /// Canonical source type.
    pub ty: &'a str,
    /// Whether callers must supply the declared name.
    pub named: bool,
}

/// A source function or lifecycle declaration, as written at its declaration site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceDeclaration<'a> {
    /// Declaration kind.
    pub kind: FunctionKind,
    /// Authored Markdown from the attached `///` block.
    pub documentation: Option<&'a str>,
    /// Keyword spelling written at the declaration site (`言挙げ`, `kotoage`, `view`,
    /// `始まり`, ...). `None` renders the romanized spelling for branded kinds.
    pub keyword: Option<&'a str>,
    /// Declared function name. Lifecycle hooks have no separate name.
    pub name: &'a str,
    /// Parameters in source order.
    pub parameters: &'a [RenderParameter<'a>],
    /// Canonical return type; `()` is omitted from the rendered header.
    pub return_type: &'a str,
    /// Declared caller authorization.
    pub authorization: Option<&'a str>,
    /// Whether the function is a local `#[test]`.
    pub is_test: bool,
    /// Fixture bound by `#[test(fixture = ...)]`.
    pub fixture: Option<&'a str>,
}

/// Render a parameter list with type-first syntax; positional parameters keep their `_`.
#[must_use]
pub fn parameter_list(parameters: &[RenderParameter<'_>]) -> String {
    parameters
        .iter()
        .map(|parameter| {
            format!(
                "{} {}{}",
                parameter.ty,
                if parameter.named { "" } else { "_ " },
                parameter.name
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn keyword_spelling(kind: FunctionKind, written: Option<&str>) -> Option<String> {
    let canonical = match kind {
        FunctionKind::Private => return None,
        FunctionKind::View => "view",
        FunctionKind::Kotoage => "kotoage",
        FunctionKind::Hajimari => "hajimari",
        FunctionKind::Kaizen => "kaizen",
    };
    // Only an accepted spelling of the same keyword may be echoed back.
    let accepted = |spelling: &str| {
        spelling == canonical
            || glossary::by_spelling(spelling).is_some_and(|keyword| keyword.romaji == canonical)
    };
    Some(
        written
            .filter(|spelling| accepted(spelling))
            .unwrap_or(canonical)
            .to_owned(),
    )
}

/// Render a declaration header exactly as V1 source spells it, without its body.
///
/// `言挙げ fn increment(int delta) authorize(CanIncrementCounter) -> int`,
/// `始まり()`, `view fn total() -> int`, `#[test] fn checks_total()`.
#[must_use]
pub fn source_declaration(declaration: &SourceDeclaration<'_>) -> String {
    let keyword = keyword_spelling(declaration.kind, declaration.keyword);
    let parameters = parameter_list(declaration.parameters);
    let mut rendered = String::new();
    if declaration.is_test {
        match declaration.fixture {
            Some(fixture) => rendered.push_str(&format!("#[test(fixture = {fixture})] ")),
            None => rendered.push_str("#[test] "),
        }
    }
    match declaration.kind {
        FunctionKind::Hajimari | FunctionKind::Kaizen => {
            rendered.push_str(keyword.as_deref().unwrap_or_default());
            rendered.push('(');
            rendered.push_str(&parameters);
            rendered.push(')');
            return rendered;
        }
        FunctionKind::Kotoage | FunctionKind::View => {
            rendered.push_str(keyword.as_deref().unwrap_or_default());
            rendered.push(' ');
        }
        FunctionKind::Private => {}
    }
    rendered.push_str("fn ");
    rendered.push_str(declaration.name);
    rendered.push('(');
    rendered.push_str(&parameters);
    rendered.push(')');
    if let Some(authorization) = declaration.authorization {
        rendered.push_str(&format!(" authorize({authorization})"));
    }
    if declaration.return_type != "()" {
        rendered.push_str(" -> ");
        rendered.push_str(declaration.return_type);
    }
    rendered
}

/// Markdown prose describing a source declaration: what it is and who may call it.
#[must_use]
pub fn source_documentation(declaration: &SourceDeclaration<'_>) -> String {
    let keyword = keyword_spelling(declaration.kind, declaration.keyword);
    let branded = keyword.as_deref().and_then(glossary::by_spelling);
    let mut lines = Vec::new();
    if let Some(authored) = declaration.documentation.filter(|text| !text.is_empty()) {
        lines.push(authored.to_owned());
    }
    if declaration.is_test {
        lines.push(
            "Local `#[test]` function run by `koto test`; it is never compiled into a deployable artifact."
                .to_owned(),
        );
    }
    match (declaration.kind, branded) {
        (FunctionKind::Kotoage | FunctionKind::Hajimari | FunctionKind::Kaizen, Some(entry)) => {
            let written = keyword.as_deref().unwrap_or(entry.romaji);
            let other = if written == entry.kanji {
                entry.romaji
            } else {
                entry.kanji
            };
            lines.push(format!("**{written}** ({other}) \u{2014} {}.", entry.role));
        }
        (FunctionKind::View, _) => lines.push(
            "**view fn** \u{2014} Read-only public function. It cannot mutate durable state, emit ledger instructions or perform host side effects, directly or through the functions it calls."
                .to_owned(),
        ),
        (FunctionKind::Private, _) if !declaration.is_test => lines.push(
            "Ordinary function: callable from source (and through `import` when a module exports it), never a public entrypoint."
                .to_owned(),
        ),
        _ => {}
    }
    match declaration.kind {
        FunctionKind::Kotoage | FunctionKind::View => lines.push(match declaration.authorization {
            Some("anyone") => "Authorization: anyone may call this function.".to_owned(),
            Some(authorization) => format!("Authorization: callers need the declared permission `{authorization}`."),
            None => "Authorization: public.".to_owned(),
        }),
        FunctionKind::Hajimari | FunctionKind::Kaizen => lines.push(
            "Authorization: callers need the runtime `CanInvokeContractEntrypoint` authorization for this hook of this seiyaku; lifecycle hooks never declare `authorize`."
                .to_owned(),
        ),
        FunctionKind::Private => {}
    }
    lines.join("\n\n")
}

/// Plain-word description of a builtin's scheduler access class.
#[must_use]
pub const fn access_words(access: BuiltinAccess) -> &'static str {
    match access {
        BuiltinAccess::None => "no ledger or durable-state access",
        BuiltinAccess::StateRead => "reads seiyaku durable state",
        BuiltinAccess::StateWrite => "writes seiyaku durable state",
        BuiltinAccess::LedgerRead => "reads ledger state",
        BuiltinAccess::LedgerWrite => "writes ledger state",
        BuiltinAccess::Dynamic => {
            "dynamic access; the scheduler serializes it when the exact keys are unresolved"
        }
    }
}

/// Plain-word descriptions of a builtin's security-relevant effects.
#[must_use]
pub fn effect_words(effects: BuiltinEffects) -> Vec<&'static str> {
    let mut words = Vec::new();
    if effects.mutates_durable_state {
        words.push("mutates seiyaku durable state");
    }
    if effects.emits_instructions {
        words.push("submits an Iroha instruction or invokes another seiyaku");
    }
    if effects.host_side_effects {
        words.push("has host-managed side effects");
    }
    words
}

/// Markdown prose for a registry builtin: summary, effects, access, mode and call policy.
#[must_use]
pub fn builtin_documentation(builtin: Builtin) -> String {
    let spec = builtin.spec();
    let mut lines = Vec::new();
    if let Some(summary) = kotodama_surface::builtin_docs::builtin_doc(spec.name) {
        lines.push(summary.to_owned());
    }
    let effects = effect_words(spec.effects);
    let mut facts = vec![format!("- Access: {}", access_words(spec.access))];
    if effects.is_empty() {
        facts.push("- Effects: none; usable in `view fn`".to_owned());
    } else {
        facts.push(format!(
            "- Effects: {}; not usable in `view fn`",
            effects.join(", ")
        ));
    }
    match spec.mode {
        BuiltinMode::Any | BuiltinMode::CompilerInternal => {}
        BuiltinMode::ZkOnly => {
            facts.push("- Available only when ZK compilation is enabled".to_owned());
        }
        BuiltinMode::TestOnly => facts.push("- Available only in local test builds".to_owned()),
        BuiltinMode::TestFunctionOnly => {
            facts.push("- Available only inside `#[test]` functions".to_owned());
        }
    }
    let method = spec.surface == BuiltinSurface::MethodOnly;
    let arguments = spec
        .signature
        .parameter_names
        .len()
        .saturating_sub(usize::from(method));
    if arguments > 0 {
        let positional = match spec.call_policy {
            BuiltinCallPolicy::Named => 0,
            BuiltinCallPolicy::PositionalPrefix(count) => count.saturating_sub(usize::from(method)),
        };
        facts.push(match positional {
            0 => "- Arguments: every argument requires its declared name".to_owned(),
            count if count >= arguments => "- Arguments: positional".to_owned(),
            1 => "- Arguments: the first argument is positional; the rest require their declared names"
                .to_owned(),
            count => format!(
                "- Arguments: the first {count} arguments are positional; the rest require their declared names"
            ),
        });
    }
    lines.push(facts.join("\n"));
    lines.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration<'a>(
        kind: FunctionKind,
        keyword: Option<&'a str>,
        parameters: &'a [RenderParameter<'a>],
        authorization: Option<&'a str>,
    ) -> SourceDeclaration<'a> {
        SourceDeclaration {
            documentation: None,
            kind,
            keyword,
            name: "increment",
            parameters,
            return_type: "int",
            authorization,
            is_test: false,
            fixture: None,
        }
    }

    #[test]
    fn declarations_echo_the_written_keyword_spelling() {
        let parameters = [RenderParameter {
            name: "delta",
            ty: "int",
            named: true,
        }];
        assert_eq!(
            source_declaration(&declaration(
                FunctionKind::Kotoage,
                Some("言挙げ"),
                &parameters,
                Some("CanIncrementCounter")
            )),
            "言挙げ fn increment(int delta) authorize(CanIncrementCounter) -> int"
        );
        assert_eq!(
            source_declaration(&declaration(
                FunctionKind::Kotoage,
                Some("kotoage"),
                &parameters,
                Some("CanIncrementCounter")
            )),
            "kotoage fn increment(int delta) authorize(CanIncrementCounter) -> int"
        );
        // A spelling of a different keyword is never echoed as this declaration's keyword.
        assert!(
            source_declaration(&declaration(
                FunctionKind::Kotoage,
                Some("始まり"),
                &parameters,
                Some("P")
            ))
            .starts_with("kotoage fn")
        );
        let hook = SourceDeclaration {
            return_type: "()",
            ..declaration(FunctionKind::Hajimari, Some("始まり"), &[], None)
        };
        assert_eq!(source_declaration(&hook), "始まり()");
        let positional = [RenderParameter {
            name: "value",
            ty: "int",
            named: false,
        }];
        let private = SourceDeclaration {
            return_type: "()",
            ..declaration(FunctionKind::Private, None, &positional, None)
        };
        assert_eq!(source_declaration(&private), "fn increment(int _ value)");
        let test = SourceDeclaration {
            is_test: true,
            fixture: Some("alice"),
            return_type: "()",
            ..declaration(FunctionKind::Private, None, &[], None)
        };
        assert_eq!(
            source_declaration(&test),
            "#[test(fixture = alice)] fn increment()"
        );
    }

    #[test]
    fn documentation_uses_glossary_wording_and_never_debug_output() {
        let kanji = source_documentation(&declaration(
            FunctionKind::Kotoage,
            Some("言挙げ"),
            &[],
            Some("CanBump"),
        ));
        assert!(kanji.starts_with("**言挙げ** (kotoage)"), "{kanji}");
        assert!(kanji.contains("Authorization: callers need the declared permission `CanBump`."));
        let romaji = source_documentation(&declaration(
            FunctionKind::Kaizen,
            Some("kaizen"),
            &[],
            None,
        ));
        assert!(romaji.starts_with("**kaizen** (改善)"), "{romaji}");
        assert!(romaji.contains("CanInvokeContractEntrypoint"));
        let view = source_documentation(&declaration(FunctionKind::View, None, &[], None));
        assert!(view.contains("Authorization: public."));
        let private = source_documentation(&declaration(FunctionKind::Private, None, &[], None));
        assert!(private.contains("never a public entrypoint"), "{private}");
        assert!(!private.contains("Authorization"));
        for text in [kanji, romaji, view, private] {
            assert!(!text.contains("Some(") && !text.contains("None") && !text.contains('{'));
        }
    }

    #[test]
    fn builtin_documentation_renders_registry_metadata_as_words() {
        let transfer = Builtin::from_source_name("ledger::asset::transfer").expect("builtin");
        let text = builtin_documentation(transfer);
        assert!(text.starts_with("Transfer an asset quantity"), "{text}");
        assert!(text.contains("writes ledger state"));
        assert!(text.contains("not usable in `view fn`"));
        assert!(!text.contains("BuiltinEffects") && !text.contains("LedgerWrite"));
        let hash = Builtin::from_source_name("crypto::sha256").expect("builtin");
        assert!(builtin_documentation(hash).contains("usable in `view fn`"));
        let invoke = Builtin::from_source_name("test::invoke_kotoage").expect("builtin");
        assert!(builtin_documentation(invoke).contains("inside `#[test]` functions"));
        assert_eq!(
            access_words(BuiltinAccess::StateRead),
            "reads seiyaku durable state"
        );
        assert!(effect_words(BuiltinEffects::NONE).is_empty());
        assert_eq!(effect_words(BuiltinEffects::INSTRUCTION).len(), 1);
    }

    #[test]
    fn parameter_lists_keep_positional_markers() {
        assert_eq!(
            parameter_list(&[
                RenderParameter {
                    name: "first",
                    ty: "int",
                    named: false
                },
                RenderParameter {
                    name: "second",
                    ty: "Json",
                    named: true
                },
            ]),
            "int _ first, Json second"
        );
        assert_eq!(parameter_list(&[]), "");
    }
}

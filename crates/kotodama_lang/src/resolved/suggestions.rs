//! Name suggestions for resolver diagnostics.
//!
//! Suggestions only change diagnostic text. Every ranking is deterministic:
//! exact teaching tables first, then the same namespace, then the whole
//! builtin registry, with ties broken by edit distance and lexical order
//! (see [`crate::diagnostic::suggest`]).
use kotodama_surface::builtins::{Builtin, BuiltinSurface};
use std::collections::BTreeSet;

/// Upper bound on namespace members listed in one note.
const MAX_LISTED_MEMBERS: usize = 16;

/// Concept words newcomers type for a context capability, mapped to the
/// canonical accessor. Matching is exact on the final path segment.
const CONTEXT_SYNONYMS: &[(&str, &str)] = &[
    ("caller", "context::authority"),
    ("sender", "context::authority"),
    ("signer", "context::authority"),
    ("block_timestamp", "context::transaction_time_ms"),
    ("block_time_ms", "context::transaction_time_ms"),
    ("current_time_ms", "context::transaction_time_ms"),
    ("timestamp", "context::transaction_time_ms"),
    ("now", "context::transaction_time_ms"),
    ("block_number", "context::block_height"),
    ("height", "context::block_height"),
    ("address", "context::seiyaku_address"),
    ("self_address", "context::seiyaku_address"),
];

/// Every builtin spelling a source call may use, in lexical order.
fn source_builtin_names() -> BTreeSet<&'static str> {
    Builtin::all()
        .filter(|builtin| {
            matches!(
                builtin.surface(),
                BuiltinSurface::Function | BuiltinSurface::FunctionOrMethod
            )
        })
        .map(Builtin::source_name)
        .chain(super::INTRINSIC_CALLS.iter().copied())
        .collect()
}

/// Return the compiler-owned namespace root of a qualified name.
///
/// Import aliases may never use these roots (see
/// [`crate::linker::is_reserved_import_alias`]), so a qualified call through
/// one always names a builtin and never an import.
pub(crate) fn builtin_root(name: &str) -> Option<&str> {
    let (root, rest) = name.split_once("::")?;
    (!root.is_empty() && !rest.is_empty() && crate::linker::is_reserved_import_alias(root))
        .then_some(root)
}

/// The branded spelling of a retired English concept spelling, if any.
///
/// Builtins that carry a branded concept (`seiyaku`/誓約 or `kotoage`/言挙げ)
/// were never available under an English concept word such as `contract` or
/// `entrypoint`. The table is derived from the registry so it cannot drift.
fn branded_spelling_of(name: &str) -> Option<(&'static str, &'static str)> {
    source_builtin_names().into_iter().find_map(|branded| {
        let concept = if branded.contains("seiyaku") {
            "seiyaku"
        } else if branded.contains("kotoage") {
            "kotoage"
        } else {
            return None;
        };
        let english = branded
            .replace("seiyaku", "contract")
            .replace("kotoage", "entrypoint");
        (english == name && Builtin::from_source_name(&english).is_none())
            .then_some((branded, concept))
    })
}

/// A suggestion for an unresolved name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NameSuggestion {
    /// Replacement spelling for the unresolved name.
    pub(crate) replacement: String,
    /// Help text explaining the suggestion.
    pub(crate) help: String,
}

/// Explain an unknown qualified name under a compiler-owned namespace.
///
/// Returns the suggestion (if any) and an optional note listing the members of
/// the namespace when no close spelling exists.
pub(crate) fn unknown_builtin(name: &str) -> (Option<NameSuggestion>, Option<String>) {
    let names = source_builtin_names();
    if let Some((branded, concept)) = branded_spelling_of(name) {
        let label = crate::glossary::by_spelling(concept).map_or_else(
            || concept.to_owned(),
            crate::glossary::BrandedKeyword::label,
        );
        return (
            Some(NameSuggestion {
                replacement: branded.to_owned(),
                help: format!(
                    "`{name}` is spelled `{branded}` in Kotodama; the concept is named {label}."
                ),
            }),
            None,
        );
    }
    let (namespace, member) = name.rsplit_once("::").unwrap_or(("", name));
    let root = name.split("::").next().unwrap_or_default();
    let found = |replacement: &str| {
        Some(NameSuggestion {
            replacement: replacement.to_owned(),
            help: format!("did you mean `{replacement}`?"),
        })
    };
    if root == "context"
        && let Some((_, canonical)) = CONTEXT_SYNONYMS.iter().find(|(word, _)| *word == member)
        && names.contains(canonical)
    {
        return (found(canonical), None);
    }
    let siblings = names
        .iter()
        .filter_map(|candidate| {
            candidate
                .rsplit_once("::")
                .filter(|(candidate_namespace, _)| *candidate_namespace == namespace)
                .map(|(_, candidate_member)| (*candidate, candidate_member))
        })
        .collect::<Vec<_>>();
    // Same namespace: a close spelling, a different letter case, or an
    // abbreviation/extension of the member name.
    if let Some(member_match) = crate::diagnostic::suggest::closest(
        member,
        siblings
            .iter()
            .map(|(_, candidate_member)| *candidate_member),
    )
    .or_else(|| {
        siblings
            .iter()
            .map(|(_, candidate_member)| *candidate_member)
            .filter(|candidate_member| {
                candidate_member.len() >= 3
                    && (member.starts_with(candidate_member)
                        || candidate_member.starts_with(member))
            })
            .min()
    }) {
        return (found(&format!("{namespace}::{member_match}")), None);
    }
    // Same root and member, different sub-namespace (`ledger::account::balance`).
    if let Some(candidate) = names.iter().find(|candidate| {
        candidate.split("::").next() == Some(root)
            && candidate.rsplit("::").next() == Some(member)
            && **candidate != name
    }) {
        return (found(candidate), None);
    }
    if let Some(candidate) = crate::diagnostic::suggest::closest(
        name,
        names
            .iter()
            .copied()
            .filter(|candidate| candidate.split("::").next() == Some(root)),
    ) {
        return (found(candidate), None);
    }
    let note = (!siblings.is_empty()).then(|| {
        let mut members = siblings
            .iter()
            .map(|(_, candidate_member)| format!("`{candidate_member}`"))
            .take(MAX_LISTED_MEMBERS)
            .collect::<Vec<_>>();
        if siblings.len() > MAX_LISTED_MEMBERS {
            members.push(format!("and {} more", siblings.len() - MAX_LISTED_MEMBERS));
        }
        format!("`{namespace}` provides {}", members.join(", "))
    });
    (None, note)
}

/// Suggest a correctly spelled candidate for an unresolved local name.
pub(crate) fn closest_name<'candidate>(
    word: &str,
    candidates: impl IntoIterator<Item = &'candidate str>,
) -> Option<NameSuggestion> {
    let candidates = candidates
        .into_iter()
        .filter(|candidate| !candidate.is_empty() && *candidate != "_")
        .collect::<BTreeSet<_>>();
    crate::diagnostic::suggest::closest(word, candidates).map(|replacement| NameSuggestion {
        replacement: replacement.to_owned(),
        help: format!("did you mean `{replacement}`?"),
    })
}

/// Suggest a canonical lowercase sum or rounding path for a mis-cased one, or
/// the capitalized variant of a compiler-owned nominal enum such as
/// `Mintable::Once`.
pub(crate) fn intrinsic_value(name: &str) -> Option<NameSuggestion> {
    if let Some(constructor) = Builtin::nominal_value(name)
        .filter(|builtin| !builtin.is_nominal_path() && builtin.signature().parameters.is_empty())
    {
        let replacement = format!("{}()", constructor.source_name());
        return Some(NameSuggestion {
            help: format!(
                "did you mean `{replacement}`? `{}` values are constructor calls.",
                constructor.signature().return_type
            ),
            replacement,
        });
    }
    if let Some(nominal) = Builtin::all().find(|builtin| {
        builtin.is_nominal_path() && builtin.source_name().eq_ignore_ascii_case(name)
    }) {
        let replacement = nominal.source_name();
        return Some(NameSuggestion {
            replacement: replacement.to_owned(),
            help: format!(
                "did you mean `{replacement}`? `{}` is a compiler-owned enum with capitalized variants.",
                nominal.signature().return_type
            ),
        });
    }
    let candidates = kotodama_surface::source_policy::V1_SUM_PATHS
        .iter()
        .chain(kotodama_surface::source_policy::V1_ROUNDING_PATHS);
    let exact_case = candidates
        .clone()
        .find(|candidate| candidate.eq_ignore_ascii_case(name));
    exact_case
        .copied()
        .or_else(|| crate::diagnostic::suggest::closest(name, candidates.copied()))
        .map(|replacement| NameSuggestion {
            replacement: replacement.to_owned(),
            help: format!(
                "did you mean `{replacement}`? Kotodama sum constructors and rounding modes are lowercase."
            ),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_roots_are_compiler_owned_namespaces() {
        assert_eq!(builtin_root("context::caller"), Some("context"));
        assert_eq!(builtin_root("ledger::account::balance"), Some("ledger"));
        assert_eq!(builtin_root("Option::Some"), Some("Option"));
        assert_eq!(builtin_root("math::minimum"), Some("math"));
        assert_eq!(builtin_root("helpers::add"), None);
        assert_eq!(builtin_root("context"), None);
    }

    #[test]
    fn retired_english_spellings_point_to_branded_builtins() {
        for (retired, branded) in [
            ("context::contract_address", "context::seiyaku_address"),
            ("context::entrypoint", "context::kotoage"),
            ("test::invoke_entrypoint", "test::invoke_kotoage"),
            (
                "ledger::query::contract_manifest",
                "ledger::query::seiyaku_manifest",
            ),
        ] {
            let (suggestion, _) = unknown_builtin(retired);
            let suggestion = suggestion.expect("retired spelling has a branded replacement");
            assert_eq!(suggestion.replacement, branded);
            let concept = if branded.contains("seiyaku") {
                "誓約"
            } else {
                "言挙げ"
            };
            assert!(suggestion.help.contains(concept), "{}", suggestion.help);
        }
    }

    #[test]
    fn unknown_builtins_rank_same_namespace_then_global() {
        let replacement = |name| {
            unknown_builtin(name)
                .0
                .map(|suggestion| suggestion.replacement)
        };
        assert_eq!(
            replacement("context::caller").as_deref(),
            Some("context::authority")
        );
        assert_eq!(
            replacement("context::authorty").as_deref(),
            Some("context::authority")
        );
        assert_eq!(replacement("math::minimum").as_deref(), Some("math::min"));
        assert_eq!(
            replacement("ledger::account::balance").as_deref(),
            Some("ledger::asset::balance")
        );
        assert_eq!(
            replacement("ledger::asset::transfr").as_deref(),
            Some("ledger::asset::transfer")
        );
        let (suggestion, note) = unknown_builtin("math::zzz");
        assert!(suggestion.is_none());
        assert!(note.expect("namespace members").contains("`isqrt`"));
    }

    #[test]
    fn mis_cased_sum_paths_suggest_lowercase_constructors() {
        assert_eq!(
            intrinsic_value("Option::None").map(|suggestion| suggestion.replacement),
            Some("Option::none".to_owned())
        );
        assert_eq!(
            intrinsic_value("Option::Some").map(|suggestion| suggestion.replacement),
            Some("Option::some".to_owned())
        );
        assert!(intrinsic_value("Vault::missing").is_none());
        assert_eq!(
            intrinsic_value("Mintable::once").map(|suggestion| suggestion.replacement),
            Some("Mintable::Once".to_owned())
        );
        assert_eq!(
            intrinsic_value("SignatureScheme::ed25519").map(|suggestion| suggestion.replacement),
            Some("SignatureScheme::Ed25519".to_owned())
        );
        assert_eq!(
            intrinsic_value("NumericSpec::integer").map(|suggestion| suggestion.replacement),
            Some("NumericSpec::integer()".to_owned())
        );
    }

    #[test]
    fn local_suggestions_are_deterministic() {
        assert_eq!(
            closest_name("totl", ["total", "totals", "_"]).map(|s| s.replacement),
            Some("total".to_owned())
        );
        assert_eq!(closest_name("x", ["y"]), None);
    }
}

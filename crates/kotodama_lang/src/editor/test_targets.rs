//! Standalone test modules attached to a snapshot.
//!
//! Tests invoke public entrypoints by name (`test::invoke_kotoage(kotoage: "quote", ...)`).
//! Attaching the test modules that target a seiyaku makes each plain selector string a
//! reference to the `kotoage`/`言挙げ` or `view fn` it names, so definition, references,
//! rename and completion see it. Attached tests never decide whether the target graph is
//! complete.
use super::{
    EditorCompletion, EditorIdentity, EditorSnapshot, EditorUnit, Occurrence, SourceFile, SourceId,
    SourceRange, TextRange, Token, TokenKind, call_context, merge_duplicate_occurrences,
};
use crate::{ast::FunctionKind, linker::SourceModuleUnit};
use std::collections::BTreeSet;

/// Test helpers whose `kotoage:` argument names a target entrypoint.
const SELECTOR_HELPERS: &[&str] = &[
    "test::invoke_kotoage",
    "test::invoke_kotoage_as",
    "test::expect_reject_as",
    "test::expect_any_reject_as",
];

/// Return the target path declared by `koto_test { target: "..." }`, read from tokens so an
/// incomplete test module still names its target.
#[must_use]
pub fn declared_test_target(source: &str) -> Option<String> {
    let file = SourceFile::new(SourceId(0), "<test>", source);
    let budget = crate::source::FrontendBudget::v1();
    let (tokens, _) =
        crate::lexer::lower_lexed_recovering(&file, budget, crate::syntax::lex(&file, budget));
    tokens.windows(5).find_map(|window| match window {
        [
            Token {
                kind: TokenKind::Ident(keyword),
                ..
            },
            Token {
                kind: TokenKind::LBrace,
                ..
            },
            Token {
                kind: TokenKind::Ident(key),
                ..
            },
            Token {
                kind: TokenKind::Colon,
                ..
            },
            Token {
                kind: TokenKind::String(target),
                ..
            },
        ] if keyword == "koto_test" && key == "target" => Some(target.clone()),
        _ => None,
    })
}

/// A selector string inside one of [`SELECTOR_HELPERS`]: its literal token and quoted name.
fn selector_at(unit: &EditorUnit, index: usize) -> Option<(&Token, &str)> {
    let label = unit.tokens.get(index)?;
    if label.kind != TokenKind::Kotoage || unit.tokens.get(index + 1)?.kind != TokenKind::Colon {
        return None;
    }
    let literal = unit.tokens.get(index + 2)?;
    let TokenKind::String(name) = &literal.kind else {
        return None;
    };
    let (helper, _, _) = call_context(&unit.tokens, label.range.end)?;
    SELECTOR_HELPERS
        .contains(&helper.as_str())
        .then_some((literal, name.as_str()))
}

/// Exact range of the name inside a plain `"..."` literal; escaped or raw literals have no
/// one-to-one name range and are not treated as references.
fn selector_content(unit: &EditorUnit, literal: &Token, name: &str) -> Option<TextRange> {
    (unit.file.slice(literal.range)? == format!("\"{name}\""))
        .then(|| TextRange::new(literal.range.start + 1, literal.range.end - 1))
}

impl EditorSnapshot {
    pub(super) fn attach_test_modules(&mut self, tests: &[SourceModuleUnit], zk_enabled: bool) {
        let complete = self.complete;
        let blocking = self.blocking.clone();
        let Some(mut next) = self
            .units
            .keys()
            .map(|id| id.0)
            .max()
            .map_or(Some(0), |max| max.checked_add(1))
        else {
            return;
        };
        for test in tests {
            let id = SourceId(next);
            self.add_unit(
                SourceFile::new(id, test.source_name.as_str(), test.source.as_str()),
                vec![],
                None,
                BTreeSet::new(),
                zk_enabled,
            );
            self.test_modules.push((id, test.clone()));
            let Some(following) = next.checked_add(1) else {
                break;
            };
            next = following;
        }
        self.complete = complete;
        self.blocking = blocking;
    }
    /// Public entrypoint of the test target named by a selector string.
    fn selector_identity(&self, name: &str) -> Option<EditorIdentity> {
        let owner = self.test_target_owner?;
        self.definitions
            .values()
            .find(|definition| {
                matches!(definition.identity, EditorIdentity::Symbol(..))
                    && definition.name == name
                    && self
                        .units
                        .get(&definition.source.source)
                        .is_some_and(|unit| unit.owner == owner)
                    && definition.signature.as_ref().is_some_and(|signature| {
                        matches!(
                            signature.function_kind,
                            Some(FunctionKind::Kotoage | FunctionKind::View)
                        )
                    })
            })
            .map(|definition| definition.identity)
    }
    pub(super) fn index_test_selectors(&mut self) {
        let mut found = Vec::new();
        for (id, _) in &self.test_modules {
            let Some(unit) = self.units.get(id) else {
                continue;
            };
            for index in 0..unit.tokens.len() {
                if let Some((literal, name)) = selector_at(unit, index)
                    && let Some(content) = selector_content(unit, literal, name)
                    && let Some(identity) = self.selector_identity(name)
                {
                    found.push(Occurrence {
                        source: SourceRange::new(*id, content),
                        identity,
                        declaration: false,
                        write: false,
                    });
                }
            }
        }
        if found.is_empty() {
            return;
        }
        self.occurrences.extend(found);
        self.occurrences
            .sort_by_key(|occurrence| (occurrence.source, occurrence.identity));
        merge_duplicate_occurrences(&mut self.occurrences);
    }
    /// Entrypoint names offered inside a selector string of an attached test module.
    pub(super) fn selector_completions(
        &self,
        unit: &EditorUnit,
        offset: u32,
    ) -> Option<Vec<EditorCompletion>> {
        let index = unit.tokens.iter().position(|token| {
            matches!(token.kind, TokenKind::String(_))
                && token.range.start < offset
                && offset < token.range.end
        })?;
        selector_at(unit, index.checked_sub(2)?)?;
        let owner = self.test_target_owner?;
        Some(
            self.definitions
                .values()
                .filter(|definition| {
                    self.units
                        .get(&definition.source.source)
                        .is_some_and(|candidate| candidate.owner == owner)
                })
                .filter_map(|definition| {
                    let signature = definition.signature.as_ref()?;
                    matches!(
                        signature.function_kind,
                        Some(FunctionKind::Kotoage | FunctionKind::View)
                    )
                    .then(|| EditorCompletion {
                        label: definition.name.clone(),
                        kind: 2,
                        detail: signature.declaration.clone(),
                        insert_text: definition.name.clone(),
                        snippet: false,
                        documentation: signature.documentation.clone(),
                        filter_text: None,
                        sort_text: None,
                    })
                })
                .collect(),
        )
    }
    /// Source identities of attached standalone test modules, in attachment order.
    pub fn test_module_sources(&self) -> impl Iterator<Item = SourceId> + '_ {
        self.test_modules.iter().map(|(id, _)| *id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "seiyaku Club { fn points(int coffees) -> int { coffees * 10 } view fn quote(int coffees) authorize(anyone) -> int { points(coffees: coffees) } }";
    const TEST: &str = "module ClubTests {\n    koto_test { target: \"../contracts/club.ko\" }\n    #[test]\n    fn quotes() {\n        let points = test::invoke_kotoage(kotoage: \"quote\", arguments: {});\n        test::assert_eq(actual: points, expected: 0);\n    }\n}\n";

    fn snapshot() -> EditorSnapshot {
        EditorSnapshot::single_with_tests(
            "contracts/club.ko",
            TARGET,
            &[SourceModuleUnit {
                source_name: "tests/club.test.ko".into(),
                source: TEST.into(),
            }],
            false,
        )
    }

    #[test]
    fn declared_targets_are_read_from_complete_and_incomplete_modules() {
        assert_eq!(
            declared_test_target(TEST).as_deref(),
            Some("../contracts/club.ko")
        );
        assert_eq!(
            declared_test_target("module T { koto_test { target: \"a.ko\" } #[test] fn x() {")
                .as_deref(),
            Some("a.ko")
        );
        assert_eq!(declared_test_target(TARGET), None);
    }

    #[test]
    fn selector_strings_navigate_and_rename_with_the_target_entrypoint() {
        let snapshot = snapshot();
        assert!(
            snapshot.is_complete(),
            "attached tests never block the target"
        );
        let test = snapshot.test_module_sources().next().expect("test unit");
        let selector = u32::try_from(TEST.find("quote\"").expect("selector")).unwrap();
        let definition = snapshot
            .definition(test, selector + 1)
            .expect("selector resolves to the target entrypoint");
        assert_eq!(definition.name, "quote");
        assert_eq!(definition.source.source, SourceId(0));
        let declaration = u32::try_from(TARGET.find("quote(").unwrap()).unwrap();
        let references = snapshot.references(SourceId(0), declaration, true);
        assert!(references.iter().any(|range| range.source == test));
        let rename = snapshot
            .rename(SourceId(0), declaration, "estimate")
            .expect("rename updates the selector string");
        let test_edit = rename
            .sources
            .iter()
            .find(|range| range.source == test)
            .expect("selector edit");
        assert_eq!(
            &TEST[test_edit.range.start as usize..test_edit.range.end as usize],
            "quote"
        );
        // Internal functions are not entrypoints and are never selector targets.
        let points = u32::try_from(TARGET.find("points(int").unwrap()).unwrap();
        assert!(
            snapshot
                .references(SourceId(0), points, true)
                .iter()
                .all(|range| range.source == SourceId(0))
        );
    }

    #[test]
    fn japanese_selector_labels_are_the_same_keyword() {
        let test = TEST.replace("kotoage: \"quote\"", "言挙げ: \"quote\"");
        let snapshot = EditorSnapshot::single_with_tests(
            "contracts/club.ko",
            TARGET,
            &[SourceModuleUnit {
                source_name: "tests/club.test.ko".into(),
                source: test.clone(),
            }],
            false,
        );
        let unit = snapshot.test_module_sources().next().expect("test unit");
        let selector = u32::try_from(test.find("quote\"").expect("selector")).unwrap();
        let definition = snapshot
            .definition(unit, selector + 1)
            .expect("a `言挙げ:` label names the same selector as `kotoage:`");
        assert_eq!(definition.name, "quote");
    }

    #[test]
    fn selector_strings_complete_public_entrypoint_names() {
        let snapshot = snapshot();
        let test = snapshot.test_module_sources().next().expect("test unit");
        let offset = u32::try_from(TEST.find("quote\"").unwrap()).unwrap();
        let labels = snapshot
            .completions(test, offset + 2)
            .into_iter()
            .map(|item| item.label)
            .collect::<Vec<_>>();
        assert_eq!(labels, vec!["quote"]);
    }
}

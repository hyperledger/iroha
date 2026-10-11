#[cfg(test)]
mod tests {
    use crate::{
        compiler::{Compiler, CompilerOptions},
        lexer::{V1_KEYWORD_DOC_TABLE, V1_KEYWORDS, V1_OPERATOR_DOC_TABLE, V1_OPERATORS},
        session::{CompileRequest, CompilerSession},
    };
    use kotodama_surface::builtins::{Builtin, BuiltinSurface};
    use kotodama_surface::source_policy::{
        V1_LIST_MEMBER_NAMES, V1_ROUNDING_PATHS, V1_SOURCE_TYPE_NAMES, V1_SUM_PATHS,
    };
    use std::{fs, path::PathBuf};
    fn docs_roots() -> [PathBuf; 2] {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        [
            manifest_dir.join("../../specs"),
            manifest_dir.join("../ivm/docs"),
        ]
    }
    fn is_localized_markdown(path: &std::path::Path) -> bool {
        // Translations are informative snapshots. The English V1 grammar and
        // Current branded examples are the release-language input to CI.
        const LOCALES: &[&str] = &[
            "am", "ar", "az", "ba", "dz", "es", "fr", "he", "hy", "ja", "ka", "kk", "mn", "my",
            "pt", "ru", "ur", "uz", "zh-hans", "zh-hant",
        ];
        let Some(stem) = path.file_stem().and_then(|name| name.to_str()) else {
            return false;
        };
        stem.rsplit_once('.')
            .is_some_and(|(_, suffix)| LOCALES.contains(&suffix))
    }
    fn kotodama_doc_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for root in docs_roots() {
            let entries = fs::read_dir(&root).unwrap_or_else(|err| {
                panic!("read {}: {err}", root.display());
            });
            paths.extend(
                entries
                    .filter_map(|entry| entry.ok().map(|item| item.path()))
                    .filter(|path| {
                        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                            return false;
                        };
                        (name.starts_with("kotodama_grammar")
                            || name.starts_with("kotodama_examples"))
                            && !is_localized_markdown(path)
                    }),
            );
        }
        paths.sort();
        paths
    }
    fn collect_markdown_files(root: &std::path::Path, paths: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(root).unwrap_or_else(|err| {
            panic!("read {}: {err}", root.display());
        });
        for entry in entries {
            let path = entry.expect("documentation directory entry").path();
            if path.is_dir() {
                collect_markdown_files(&path, paths);
            } else if path.extension().is_some_and(|extension| extension == "md")
                && !is_localized_markdown(&path)
            {
                paths.push(path);
            }
        }
    }
    fn kotodama_fences(text: &str) -> Vec<(usize, String)> {
        let mut snippets = Vec::new();
        let mut start_line = None;
        let mut source = String::new();
        for (index, line) in text.lines().enumerate() {
            if start_line.is_some() {
                if line.trim() == "```" {
                    snippets.push((start_line.expect("open fence"), std::mem::take(&mut source)));
                    start_line = None;
                } else {
                    source.push_str(line);
                    source.push('\n');
                }
            } else if line.trim() == "```kotodama" {
                start_line = Some(index + 2);
            }
        }
        assert!(start_line.is_none(), "unterminated `kotodama` code fence");
        snippets
    }
    fn textmate_match<'a>(grammar: &'a norito::json::Value, section: &str) -> &'a str {
        let patterns = grammar
            .pointer(&format!("/repository/{section}/patterns"))
            .and_then(norito::json::Value::as_array)
            .unwrap_or_else(|| panic!("TextMate grammar omitted {section} patterns"));
        assert_eq!(
            patterns.len(),
            1,
            "TextMate {section} table must contain exactly one generated matcher"
        );
        patterns[0]
            .get("match")
            .and_then(norito::json::Value::as_str)
            .unwrap_or_else(|| panic!("TextMate grammar omitted {section} match pattern"))
    }
    /// Every `(match, scope)` pattern of a generated section.
    fn textmate_patterns<'a>(
        grammar: &'a norito::json::Value,
        section: &str,
    ) -> Vec<(&'a str, &'a str)> {
        grammar
            .pointer(&format!("/repository/{section}/patterns"))
            .and_then(norito::json::Value::as_array)
            .unwrap_or_else(|| panic!("TextMate grammar omitted {section} patterns"))
            .iter()
            .map(|pattern| {
                (
                    pattern
                        .get("match")
                        .and_then(norito::json::Value::as_str)
                        .unwrap_or_else(|| panic!("{section} pattern without a match")),
                    pattern
                        .get("name")
                        .and_then(norito::json::Value::as_str)
                        .unwrap_or_else(|| panic!("{section} pattern without a scope")),
                )
            })
            .collect()
    }
    /// The literal alternatives of a generated `(?:a|b|c)` matcher, with regex escapes removed.
    fn alternatives(pattern: &str, prefix: &str, suffix: &str) -> Vec<String> {
        let body = pattern
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
            .unwrap_or_else(|| panic!("unexpected generated matcher shape `{pattern}`"));
        let mut values = vec![String::new()];
        let mut characters = body.chars();
        while let Some(character) = characters.next() {
            match character {
                '\\' => values
                    .last_mut()
                    .expect("alternative")
                    .push(characters.next().expect("escaped character")),
                '|' => values.push(String::new()),
                other => values.last_mut().expect("alternative").push(other),
            }
        }
        values
    }
    fn textmate_attribute_match(grammar: &norito::json::Value) -> &str {
        let patterns = grammar
            .pointer("/repository/attributes/patterns/0/patterns")
            .and_then(norito::json::Value::as_array)
            .expect("TextMate grammar omitted attribute patterns");
        let matches = patterns
            .iter()
            .filter_map(|pattern| pattern.get("match"))
            .filter_map(norito::json::Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "TextMate attributes must contain exactly one matcher"
        );
        matches[0]
    }
    fn textmate_named_match<'a>(grammar: &'a norito::json::Value, name: &str) -> &'a str {
        grammar
            .pointer("/repository/numbers/patterns")
            .and_then(norito::json::Value::as_array)
            .expect("TextMate grammar omitted numeric patterns")
            .iter()
            .find(|pattern| pattern.get("name").and_then(norito::json::Value::as_str) == Some(name))
            .and_then(|pattern| pattern.get("match"))
            .and_then(norito::json::Value::as_str)
            .unwrap_or_else(|| panic!("TextMate grammar omitted matcher `{name}`"))
    }
    fn textmate_top_level_includes(grammar: &norito::json::Value) -> Vec<&str> {
        grammar
            .get("patterns")
            .and_then(norito::json::Value::as_array)
            .expect("TextMate grammar omitted top-level patterns")
            .iter()
            .filter_map(|pattern| pattern.get("include"))
            .filter_map(norito::json::Value::as_str)
            .collect()
    }
    fn textmate_definition_matches(grammar: &norito::json::Value) -> Vec<&str> {
        grammar
            .pointer("/repository/definitions/patterns")
            .and_then(norito::json::Value::as_array)
            .expect("TextMate grammar omitted definition patterns")
            .iter()
            .filter_map(|pattern| pattern.get("match"))
            .filter_map(norito::json::Value::as_str)
            .collect()
    }
    fn alternation_pattern(paths: &[&str]) -> String {
        format!(r"\b(?:{})\b", paths.join("|"))
    }
    fn generated_section<'a>(text: &'a str, name: &str) -> &'a str {
        let start_marker = format!("<!-- BEGIN GENERATED: {name} -->\n");
        let end_marker = format!("<!-- END GENERATED: {name} -->");
        let (_, rest) = text
            .split_once(&start_marker)
            .unwrap_or_else(|| panic!("missing generated section `{name}`"));
        let (section, _) = rest
            .split_once(&end_marker)
            .unwrap_or_else(|| panic!("unterminated generated section `{name}`"));
        section
    }
    #[test]
    fn kotodama_docs_do_not_advertise_removed_helper_spellings() {
        for path in kotodama_doc_paths() {
            let text = fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!("read {}: {err}", path.display());
            });
            for needle in [
                "get_or_insert_default(",
                ".get_or_insert_default(",
                ".json_get_",
                ".path_map_key(",
                ".path_map_key_norito(",
                ".has(",
                " json_get_",
                " path_map_key(",
                " path_map_key_norito(",
                "account!(",
                "account_id!(",
                "asset_definition!(",
                "asset_id!(",
                "domain!(",
                "domain_id!(",
                "name!(",
                "json!(",
                "json!{",
                "json![",
                "nft_id!(",
                "blob!(",
                "norito_bytes!(",
            ] {
                assert!(
                    !text.contains(needle),
                    "{} still contains removed helper spelling `{needle}`",
                    path.display()
                );
            }
        }
    }
    #[test]
    fn canonical_syntax_tables_cover_docs_and_textmate_grammar() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let specification =
            fs::read_to_string(manifest_dir.join("../../specs/kotodama_grammar.md"))
                .expect("read normative Kotodama grammar");
        let textmate =
            fs::read_to_string(manifest_dir.join(
                "../../tools/kotodama_linguist/grammar-repo/syntaxes/kotodama.tmLanguage.json",
            ))
            .expect("read TextMate grammar");
        let textmate_value: norito::json::Value =
            norito::json::from_str(&textmate).expect("parse TextMate grammar JSON");
        assert_eq!(
            generated_section(&specification, "kotodama-v1-keywords"),
            V1_KEYWORD_DOC_TABLE,
            "the normative keyword table must be regenerated from grammar/v1.lex"
        );
        assert_eq!(
            generated_section(&specification, "kotodama-v1-operators"),
            V1_OPERATOR_DOC_TABLE,
            "the normative operator table must be regenerated from grammar/v1.lex"
        );
        // Keywords are split by role; together they are exactly grammar/v1.lex, each keyword
        // appears once, and both spellings of a branded keyword share one scope.
        let mut keyword_scopes = std::collections::BTreeMap::new();
        for (pattern, scope) in textmate_patterns(&textmate_value, "keywords") {
            for keyword in alternatives(pattern, r"(?<![\p{L}\p{N}_])(?:", r")(?![\p{L}\p{N}_])") {
                assert!(
                    keyword_scopes.insert(keyword.clone(), scope).is_none(),
                    "TextMate keyword `{keyword}` is scoped twice"
                );
            }
        }
        assert_eq!(
            keyword_scopes
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            {
                let mut keywords = V1_KEYWORDS.to_vec();
                keywords.sort_unstable();
                keywords
            },
            "TextMate keyword matchers must be generated from grammar/v1.lex"
        );
        for keyword in &crate::glossary::BRANDED_KEYWORDS {
            assert_eq!(
                keyword_scopes[keyword.romaji], keyword_scopes[keyword.kanji],
                "both spellings of `{}` must share one TextMate scope",
                keyword.romaji
            );
        }
        for spelling in ["true", "false"] {
            assert_eq!(
                keyword_scopes[spelling], "constant.language.boolean.kotodama",
                "booleans are constants, not control flow"
            );
        }
        // Operators and punctuation together are exactly grammar/v1.lex; delimiters and
        // separators are punctuation, and operators are matched before the `.` accessor.
        let operator_patterns = textmate_patterns(&textmate_value, "operators");
        assert_eq!(operator_patterns[0].1, "keyword.operator.kotodama");
        let mut symbols = std::collections::BTreeMap::new();
        for (pattern, scope) in &operator_patterns {
            for symbol in alternatives(pattern, "(?:", ")") {
                assert!(
                    symbols.insert(symbol.clone(), *scope).is_none(),
                    "TextMate symbol `{symbol}` is scoped twice"
                );
            }
        }
        assert_eq!(
            symbols
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            V1_OPERATORS.iter().copied().collect(),
            "TextMate operator matchers must be generated from grammar/v1.lex"
        );
        for punctuation in ["{", "}", "(", ")", "[", "]", ";", ",", ":", "::", ".", "#"] {
            assert!(
                symbols[punctuation].starts_with("punctuation."),
                "`{punctuation}` must be punctuation, not an operator"
            );
        }
        assert_eq!(
            textmate_match(&textmate_value, "builtins"),
            r"(?:\brequire\b|(?<=::)[A-Za-z_][A-Za-z0-9_]*)(?=\s*\()",
            "TextMate builtin highlighting must remain structural and namespaced"
        );
        // The attribute matcher names exactly the attribute words the parser accepts:
        // `#[test]`, its `fixture` option, and `#[message(...)]` on error variants.
        let attribute_words =
            alternatives(textmate_attribute_match(&textmate_value), r"\b(?:", r")\b");
        assert_eq!(attribute_words, ["fixture", "message", "test"]);
        for accepted in [
            "module M { #[test] fn checks() {} }",
            "module M { #[test(fixture = alice)] fn checks() {} }",
            "module M { error enum Failure { #[message(\"Too large\")] TooLarge = 1 } }",
        ] {
            assert!(
                crate::parser::parse(accepted).is_ok(),
                "TextMate highlights an attribute the parser rejects: {accepted}"
            );
        }
        for rejected in [
            "module M { #[inline] fn checks() {} }",
            "module M { #[access(read)] fn checks() {} }",
            "module M { error enum Failure { #[doc(\"x\")] TooLarge = 1 } }",
        ] {
            assert!(
                crate::parser::parse(rejected).is_err(),
                "the parser accepts an attribute TextMate does not highlight: {rejected}"
            );
        }
        // Trigger bodies highlight exactly the contextual words of the normative trigger
        // productions, from `trigger` through `pipeline-filter`.
        let trigger_productions = specification
            .lines()
            .skip_while(|line| !line.starts_with("trigger "))
            .take_while(|line| !line.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            trigger_productions.contains("pipeline-filter ="),
            "the normative trigger productions moved"
        );
        let mut spec_trigger_words = trigger_productions
            .split('"')
            .skip(1)
            .step_by(2)
            .filter(|word| word.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
            .filter(|word| !word.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        spec_trigger_words.sort_unstable();
        spec_trigger_words.dedup();
        let trigger_body = textmate_value
            .pointer("/repository/triggerBody/patterns")
            .and_then(norito::json::Value::as_array)
            .expect("TextMate grammar omitted triggerBody patterns")
            .iter()
            .find(|pattern| {
                pattern.get("name").and_then(norito::json::Value::as_str)
                    == Some("keyword.other.trigger.kotodama")
            })
            .and_then(|pattern| pattern.get("match"))
            .and_then(norito::json::Value::as_str)
            .expect("TextMate trigger contextual words");
        let mut textmate_trigger_words = alternatives(
            trigger_body,
            r"(?<![\p{L}\p{N}_])(?:",
            r")(?![\p{L}\p{N}_])",
        );
        textmate_trigger_words.sort_unstable();
        assert_eq!(
            textmate_trigger_words, spec_trigger_words,
            "TextMate trigger words must match the normative trigger productions"
        );
        let top_level_includes = textmate_top_level_includes(&textmate_value);
        for section in [
            "#namedFields",
            "#sumVariants",
            "#roundingVariants",
            "#jsonConstruction",
            "#memberCalls",
            "#retiredNumericSuffixes",
        ] {
            assert_eq!(
                top_level_includes
                    .iter()
                    .filter(|include| **include == section)
                    .count(),
                1,
                "TextMate grammar must include V1 contextual section `{section}` exactly once"
            );
        }
        assert_eq!(
            textmate_match(&textmate_value, "namedFields"),
            r"(?<![\p{L}\p{N}_])(?<!\?)(?<!\?\s)[\p{L}_][\p{L}\p{N}_]*(?=\s*:(?!:))",
            "TextMate named labels must stop before `::` so `Type::` and `namespace::` path heads keep their own scopes, and must not capture the `? value :` branch of a conditional"
        );
        let position = |include: &str| {
            top_level_includes
                .iter()
                .position(|candidate| *candidate == include)
                .unwrap_or_else(|| panic!("TextMate grammar omitted {include}"))
        };
        for (earlier, later) in [
            ("#sumVariants", "#namedFields"),
            ("#roundingVariants", "#namedFields"),
            ("#namedFields", "#types"),
            ("#types", "#keywords"),
            ("#keywords", "#operators"),
        ] {
            assert!(
                position(earlier) < position(later),
                "TextMate {earlier} must be tried before {later}"
            );
        }
        assert!(
            !top_level_includes.contains(&"#constants"),
            "booleans are generated with the keyword roles"
        );
        assert_eq!(
            textmate_match(&textmate_value, "sumVariants"),
            alternation_pattern(V1_SUM_PATHS),
            "TextMate sum paths drifted from the active-only Option/Result surface"
        );
        assert_eq!(
            textmate_match(&textmate_value, "roundingVariants"),
            alternation_pattern(V1_ROUNDING_PATHS),
            "TextMate rounding paths drifted from the exact quantity surface"
        );
        assert_eq!(
            textmate_match(&textmate_value, "jsonConstruction"),
            r"\bjson\b(?=\s*[\{\[])",
            "TextMate must treat `json` as contextual object/array construction syntax"
        );
        let mut member_names = vec![
            "is_some",
            "is_none",
            "is_ok",
            "is_err",
            "unwrap_or",
            "unwrap_err_or",
            "expect",
            "ok_or",
            "or_err",
            "page",
        ];
        member_names.extend_from_slice(V1_LIST_MEMBER_NAMES);
        member_names.push("div_round");
        member_names.push("mul_div_round");
        member_names.push("ratio_round");
        for builtin in Builtin::all() {
            if !matches!(
                builtin.surface(),
                BuiltinSurface::MethodOnly | BuiltinSurface::FunctionOrMethod
            ) {
                continue;
            }
            let member_name = builtin.name();
            if !member_names.contains(&member_name) {
                member_names.push(member_name);
            }
        }
        assert_eq!(
            textmate_match(&textmate_value, "memberCalls"),
            format!(r"(?<=\.)(?:{})(?=\s*\()", member_names.join("|")),
            "TextMate member calls drifted from bounded List, quantity, or typed JSON APIs"
        );
        assert_eq!(
            textmate_match(&textmate_value, "retiredNumericSuffixes"),
            r"(?<![A-Za-z0-9_])(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|\d(?:[\d_]*\d)?(?:\.\d(?:[\d_]*\d)?)?(?:[eE][+-]?\d(?:[\d_]*\d)?)?)(?:amt|qty)\b",
            "TextMate retired numeric suffix highlighting drifted from amt/qty fix-it policy"
        );
        let mut type_names = V1_SOURCE_TYPE_NAMES.to_vec();
        type_names.push("Rounding");
        assert_eq!(
            textmate_match(&textmate_value, "types"),
            alternation_pattern(&type_names),
            "TextMate types drifted from the canonical V1 source surface"
        );
        assert_eq!(
            textmate_named_match(&textmate_value, "constant.numeric.decimal.kotodama"),
            r"\b(?:\d(?:[\d_]*\d)?\.\d(?:[\d_]*\d)?(?:[eE][+-]?\d(?:[\d_]*\d)?)?|\d(?:[\d_]*\d)?[eE][+-]?\d(?:[\d_]*\d)?)\b",
            "TextMate decimal literal highlighting drifted from unsuffixed V1 syntax"
        );
        let definition_matches = textmate_definition_matches(&textmate_value);
        for retired in ["contract", "entry", "init", "upgrade"] {
            assert!(
                definition_matches
                    .iter()
                    .all(|pattern| !pattern.contains(retired)),
                "TextMate definition matchers still accept retired English declaration spelling `{retired}`"
            );
        }
        for keyword in V1_KEYWORDS {
            assert!(
                !iroha_data_model::smart_contract::entrypoint::is_canonical_kotodama_identifier(
                    keyword,
                ),
                "boundary-schema identifier validation drifted from grammar/v1.lex at `{keyword}`"
            );
        }
        for retired in [
            "assert",
            "assert_eq",
            "contains",
            "get_or_insert_default",
            "transfer_asset",
            "mint_asset",
            "burn_asset",
            "subscription_bill",
            "execute_instruction",
            "execute_query",
            "create_trigger",
            "register_trigger",
            "unregister_trigger",
            "remove_trigger",
            "authority",
            "account_id",
            "asset_definition",
            "asset_id",
            "domain",
            "domain_id",
            "name",
            "json",
            "nft_id",
            "norito_bytes",
            "blob",
            "isqrt",
            "info",
            "zk_vote_verify_ballot",
            "zk_verify_transfer",
            "zk_verify_unshield",
            "sc_execute_unshield",
            "build_submit_ballot_inline",
            "build_unshield_inline",
        ] {
            assert!(
                !textmate_match(&textmate_value, "builtins").contains(retired),
                "TextMate grammar still advertises retired raw or flat builtin `{retired}`"
            );
        }
        for retired in [
            "get_numeric",
            "json_get_int",
            "json_get_numeric",
            "get_or_insert_default",
            "has",
        ] {
            assert!(
                !textmate_match(&textmate_value, "memberCalls").contains(retired),
                "TextMate grammar still advertises retired method `{retired}`"
            );
        }
    }
    #[test]
    fn every_current_kotodama_documentation_fence_compiles() {
        let mut paths = Vec::new();
        for root in docs_roots() {
            collect_markdown_files(&root, &mut paths);
        }
        paths.sort();
        let compiler = Compiler::new();
        let session = CompilerSession::new(CompilerOptions::default());
        let mut failures = Vec::new();
        for path in paths {
            let text = fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!("read {}: {err}", path.display());
            });
            for (line, source) in kotodama_fences(&text) {
                let result = if source.trim_start().starts_with("module ") {
                    session
                        .check(CompileRequest {
                            source: &source,
                            source_name: None,
                        })
                        .map_err(|diagnostics| diagnostics.render_human())
                } else {
                    compiler.compile_source_with_manifest(&source).map(|_| ())
                };
                if let Err(error) = result {
                    failures.push(format!("{}:{line}: {error}", path.display()));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "Kotodama documentation snippets failed to compile:\n{}",
            failures.join("\n")
        );
    }
}

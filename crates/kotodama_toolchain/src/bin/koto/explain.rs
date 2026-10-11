//! `koto explain`: long-form help for diagnostic codes, lint names, and branded keywords.
//!
//! Diagnostic text comes from the compiler-owned registry
//! (`kotodama_lang::diagnostic::DIAGNOSTIC_EXPLANATIONS`, generated from
//! `diagnostic_explanations_v1.tsv`), so the summary, help, and worked examples printed here are
//! the same ones the compiler attaches to diagnostics. Branded keywords use the shared glossary
//! (`kotodama_lang::glossary`); both spellings of a keyword are accepted and the heading echoes
//! the spelling the user typed.
use super::KotoError;
use clap::ValueEnum;
use kotodama_lang::{
    diagnostic::{
        DIAGNOSTIC_EXPLANATIONS, DiagnosticExplanation, DiagnosticPhase, suggest::edit_distance,
    },
    glossary::{self, BrandedKeyword},
};
use kotodama_toolchain::diagnostics::{SPEC_URL, documentation_url, heading_anchor, spec_section};
use std::fmt::Write as _;

/// Output format of `koto explain`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum ExplainFormat {
    /// Terminal text.
    #[default]
    Human,
    /// Markdown with one stable anchor per code, suitable for a published reference page.
    Markdown,
}

/// Lint names accepted by `koto explain`, with the unified diagnostic code each one reports.
fn lint_codes() -> impl Iterator<Item = (&'static str, &'static str)> {
    kotodama_lang::lint::LINT_REGISTRY
        .iter()
        .map(|(slug, code, _)| (*slug, *code))
}
/// One resolved `koto explain` topic.
enum Topic<'input> {
    Diagnostic {
        explanation: &'static DiagnosticExplanation,
        lint: Option<&'static str>,
    },
    Keyword {
        keyword: &'static BrandedKeyword,
        written: &'input str,
    },
    ForeignWord {
        keyword: &'static BrandedKeyword,
        written: &'input str,
    },
}

fn resolve(topic: &str) -> Option<Topic<'_>> {
    if let Some(explanation) = kotodama_lang::diagnostic::diagnostic_explanation(topic) {
        let lint = lint_codes()
            .find(|(_, code)| *code == explanation.code)
            .map(|(name, _)| name);
        return Some(Topic::Diagnostic { explanation, lint });
    }
    if let Some((name, code)) = lint_codes().find(|(name, _)| name.eq_ignore_ascii_case(topic)) {
        let explanation = kotodama_lang::diagnostic::diagnostic_explanation(code)?;
        return Some(Topic::Diagnostic {
            explanation,
            lint: Some(name),
        });
    }
    if let Some(keyword) = glossary::by_spelling(topic) {
        return Some(Topic::Keyword {
            keyword,
            written: topic,
        });
    }
    glossary::suggestion_for(topic).map(|keyword| Topic::ForeignWord {
        keyword,
        written: topic,
    })
}

/// Run `koto explain`.
pub(crate) fn run(
    topic: &Option<String>,
    list: bool,
    format: ExplainFormat,
) -> Result<(), KotoError> {
    if list {
        print!("{}", render_list(format));
        return Ok(());
    }
    let topic = topic
        .as_deref()
        .ok_or_else(|| KotoError::Usage("explain expects a topic or --list".to_owned()))?;
    let rendered = render_topic(topic, format).map_err(KotoError::Usage)?;
    print!("{rendered}");
    Ok(())
}

/// Render one topic, or a not-found message that echoes the input unchanged with suggestions.
pub(crate) fn render_topic(topic: &str, format: ExplainFormat) -> Result<String, String> {
    match resolve(topic) {
        Some(Topic::Diagnostic { explanation, lint }) => {
            Ok(render_diagnostic(explanation, lint, format))
        }
        Some(Topic::Keyword { keyword, written }) => Ok(render_keyword(keyword, written, format)),
        Some(Topic::ForeignWord { keyword, written }) => {
            let mut output = match format {
                ExplainFormat::Human => format!(
                    "`{written}` is not a Kotodama keyword. Kotodama spells this concept `{}` or `{}`; both spellings are the same keyword.\n\n",
                    keyword.romaji, keyword.kanji
                ),
                ExplainFormat::Markdown => format!(
                    "> `{written}` is not a Kotodama keyword. Kotodama spells this concept `{}` or `{}`; both spellings are the same keyword.\n\n",
                    keyword.romaji, keyword.kanji
                ),
            };
            output.push_str(&render_keyword(keyword, keyword.romaji, format));
            Ok(output)
        }
        None => {
            let mut message = format!("no explanation is registered for `{topic}`");
            let suggestions = suggestions(topic);
            if !suggestions.is_empty() {
                let _ = write!(
                    message,
                    "; did you mean {}?",
                    suggestions
                        .iter()
                        .map(|suggestion| format!("`{suggestion}`"))
                        .collect::<Vec<_>>()
                        .join(" or ")
                );
            }
            message.push_str(
                "\nhelp: run `koto explain --list` to see every code, lint name, and keyword",
            );
            Err(message)
        }
    }
}

fn phase_label(phase: DiagnosticPhase) -> &'static str {
    phase.as_str()
}

fn render_diagnostic(
    explanation: &DiagnosticExplanation,
    lint: Option<&str>,
    format: ExplainFormat,
) -> String {
    let section = spec_section(explanation.code);
    let url = documentation_url(explanation.code);
    let mut output = String::new();
    match format {
        ExplainFormat::Human => {
            let _ = writeln!(
                output,
                "{} [{}]: {}",
                explanation.code,
                phase_label(explanation.phase),
                explanation.summary
            );
            if let Some(lint) = lint {
                let _ = writeln!(
                    output,
                    "\nThis is the `{lint}` lint. It warns by default and the source still compiles; `koto check --deny {lint}`, `--deny-warnings`, or a `lints` level of `deny` makes it fail the check."
                );
            }
            let _ = writeln!(output, "\nhelp: {}", explanation.help);
            if let (Some(bad), Some(fixed)) = (explanation.bad_example, explanation.fixed_example) {
                let _ = writeln!(output, "\nThis source reports {}:\n", explanation.code);
                output.push_str(&indent_block(bad));
                let _ = writeln!(output, "\nFixed:\n");
                output.push_str(&indent_block(fixed));
            }
            let _ = writeln!(output, "\nSpecification: \u{201c}{section}\u{201d} ({url})");
        }
        ExplainFormat::Markdown => {
            let _ = writeln!(
                output,
                "### {} {{#{}}}\n",
                explanation.code,
                explanation.code.to_ascii_lowercase()
            );
            let _ = writeln!(
                output,
                "*{}* \u{2014} {}\n",
                phase_label(explanation.phase),
                explanation.summary
            );
            if let Some(lint) = lint {
                let _ = writeln!(
                    output,
                    "Lint `{lint}` (warns by default and the source still compiles; a `deny` level fails the check).\n"
                );
            }
            let _ = writeln!(output, "{}\n", explanation.help);
            if let (Some(bad), Some(fixed)) = (explanation.bad_example, explanation.fixed_example) {
                let _ = writeln!(output, "Reports `{}`:\n", explanation.code);
                let _ = writeln!(output, "```kotodama\n{}\n```\n", bad.trim_end());
                output.push_str("Fixed:\n\n");
                let _ = writeln!(output, "```kotodama\n{}\n```\n", fixed.trim_end());
            }
            let _ = writeln!(output, "Specification: [{section}]({url})\n");
        }
    }
    output
}

fn render_keyword(keyword: &BrandedKeyword, written: &str, format: ExplainFormat) -> String {
    let other = if written == keyword.kanji {
        keyword.romaji
    } else {
        keyword.kanji
    };
    let hover = keyword.hover_markdown();
    match format {
        ExplainFormat::Human => {
            let mut output = format!("{written} ({other}): {}\n\n", keyword.role);
            output.push_str(&markdown_to_terminal(&hover));
            output.push('\n');
            let _ = writeln!(
                output,
                "\nSpecification: \u{201c}Declarations\u{201d} ({SPEC_URL}#{})",
                heading_anchor("Declarations")
            );
            output
        }
        ExplainFormat::Markdown => {
            let mut output = format!("### {written} / {other} {{#{}}}\n\n", keyword.romaji);
            output.push_str(&hover);
            output.push_str("\n\n");
            output
        }
    }
}

/// Render the glossary's hover Markdown for a terminal: drop emphasis markers and indent code.
fn markdown_to_terminal(markdown: &str) -> String {
    let mut output = String::new();
    let mut in_code = false;
    for line in markdown.lines() {
        if line.starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if in_code {
            let _ = writeln!(output, "    {line}");
        } else {
            let _ = writeln!(output, "{}", line.replace("**", ""));
        }
    }
    output.trim_end().to_owned()
}

fn indent_block(source: &str) -> String {
    source
        .trim_end()
        .lines()
        .map(|line| {
            if line.is_empty() {
                "\n".to_owned()
            } else {
                format!("    {line}\n")
            }
        })
        .collect()
}

fn render_list(format: ExplainFormat) -> String {
    let mut output = String::new();
    match format {
        ExplainFormat::Human => {
            output.push_str("Branded keywords (either spelling; they may be mixed freely):\n");
            for keyword in &glossary::BRANDED_KEYWORDS {
                let _ = writeln!(
                    output,
                    "  {:<10} {:<8} {}",
                    keyword.romaji, keyword.kanji, keyword.role
                );
            }
            output.push_str("\nLint names:\n");
            for (name, code) in lint_codes() {
                let _ = writeln!(output, "  {name:<28} {code}");
            }
            output.push_str("\nDiagnostic codes:\n");
            for explanation in DIAGNOSTIC_EXPLANATIONS {
                let _ = writeln!(
                    output,
                    "  {:<36} {:<9} {}",
                    explanation.code,
                    phase_label(explanation.phase),
                    explanation.summary
                );
            }
            output.push_str("\nRun `koto explain <TOPIC>` for details.\n");
        }
        ExplainFormat::Markdown => {
            output.push_str("# Kotodama diagnostics\n\n");
            output.push_str(
                "Generated by `koto explain --list --format markdown` from the compiler's diagnostic registry. \
                 Every code below is also available offline through `koto explain <CODE>`.\n\n",
            );
            output.push_str("## Branded keywords\n\n");
            for keyword in &glossary::BRANDED_KEYWORDS {
                output.push_str(&render_keyword(keyword, keyword.romaji, format));
            }
            output.push_str("## Diagnostic codes\n\n");
            for explanation in DIAGNOSTIC_EXPLANATIONS {
                let lint = lint_codes()
                    .find(|(_, code)| *code == explanation.code)
                    .map(|(name, _)| name);
                output.push_str(&render_diagnostic(explanation, lint, format));
            }
        }
    }
    output
}

/// Registered codes, lint names, and keyword spellings closest to an unknown topic (at most two
/// edits away, by the compiler's suggestion distance).
fn suggestions(topic: &str) -> Vec<String> {
    let distance = |candidate: &str| edit_distance(topic, candidate, 2);
    let mut candidates = DIAGNOSTIC_EXPLANATIONS
        .iter()
        .map(|explanation| explanation.code)
        .chain(lint_codes().map(|(name, _)| name))
        .chain(
            glossary::BRANDED_KEYWORDS
                .iter()
                .flat_map(|keyword| keyword.spellings()),
        )
        .filter_map(|candidate| distance(candidate).map(|distance| (distance, candidate)))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates
        .into_iter()
        .take(3)
        .map(|(_, candidate)| candidate.to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotodama_lang::session::{CompileRequest, CompilerSession};

    #[test]
    fn every_documentation_link_targets_an_existing_specification_heading() {
        let spec = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/kotodama_grammar.md"),
        )
        .expect("read Kotodama specification");
        let anchors = spec
            .lines()
            .filter_map(|line| line.strip_prefix("## "))
            .map(heading_anchor)
            .collect::<std::collections::BTreeSet<_>>();
        for explanation in DIAGNOSTIC_EXPLANATIONS {
            let url = documentation_url(explanation.code);
            let anchor = url.rsplit_once('#').expect("anchored URL").1;
            assert!(
                anchors.contains(anchor),
                "{} links to missing specification anchor `{anchor}`",
                explanation.code
            );
        }
        assert!(anchors.contains(&heading_anchor("Declarations")));
        assert_eq!(heading_anchor("Local test mode"), "local-test-mode");
        assert_eq!(
            heading_anchor("Secrets and ZK seiyaku"),
            "secrets-and-zk-seiyaku"
        );
    }

    #[test]
    fn topics_resolve_codes_lints_and_both_keyword_spellings() {
        let code = render_topic("k2003", ExplainFormat::Human).expect("case-insensitive code");
        assert!(code.starts_with("K2003 [semantic]: "), "{code}");
        assert!(code.contains("help: "));
        assert!(code.contains("#types"));
        let lint = render_topic("unused-parameter", ExplainFormat::Human).expect("lint slug");
        assert!(lint.starts_with("K5003 "), "{lint}");
        assert!(lint.contains("`unused-parameter` lint"));
        let romaji = render_topic("kotoage", ExplainFormat::Human).expect("romanized keyword");
        assert!(romaji.starts_with("kotoage (言挙げ): "), "{romaji}");
        let kanji = render_topic("言挙げ", ExplainFormat::Human).expect("Japanese keyword");
        assert!(kanji.starts_with("言挙げ (kotoage): "), "{kanji}");
        for rendered in [&romaji, &kanji] {
            assert!(rendered.contains("mixed freely"));
            assert!(
                !rendered.contains("**"),
                "terminal output keeps no Markdown emphasis"
            );
        }
        let guess = render_topic("contract", ExplainFormat::Human).expect("English guess");
        assert!(guess.contains("`seiyaku` or `誓約`"), "{guess}");
    }

    #[test]
    fn unknown_topics_echo_the_input_and_suggest_close_matches() {
        let error = render_topic("K2033", ExplainFormat::Human).expect_err("unknown code");
        assert!(
            error.contains("no explanation is registered for `K2033`"),
            "{error}"
        );
        assert!(error.contains("`K2003`"), "{error}");
        let error = render_topic("unused-paramter", ExplainFormat::Human).expect_err("typo");
        assert!(error.contains("`unused-paramter`"));
        assert!(error.contains("`unused-parameter`"), "{error}");
        assert!(error.contains("koto explain --list"));
        // A confusable spelling resolves to the keyword; a near miss is suggested in its script.
        let confusable = render_topic("言挙", ExplainFormat::Human).expect("confusable");
        assert!(confusable.contains("`kotoage` or `言挙げ`"), "{confusable}");
        let error = render_topic("改膳", ExplainFormat::Human).expect_err("misspelt keyword");
        assert!(error.contains("`改善`"), "{error}");
        let error = render_topic("kotoag", ExplainFormat::Human).expect_err("misspelt keyword");
        assert!(error.contains("`kotoage`"), "{error}");
    }

    #[test]
    fn list_and_markdown_cover_every_registered_code_with_stable_anchors() {
        let human = render_list(ExplainFormat::Human);
        let markdown = render_list(ExplainFormat::Markdown);
        for explanation in DIAGNOSTIC_EXPLANATIONS {
            assert!(human.contains(explanation.code));
            assert!(markdown.contains(&format!(
                "### {} {{#{}}}",
                explanation.code,
                explanation.code.to_ascii_lowercase()
            )));
        }
        for keyword in &glossary::BRANDED_KEYWORDS {
            assert!(human.contains(keyword.romaji) && human.contains(keyword.kanji));
            assert!(markdown.contains(&format!("{{#{}}}", keyword.romaji)));
        }
    }

    #[test]
    fn lint_names_match_the_codes_the_compiler_reports() {
        let session = CompilerSession::default();
        for (source, lint) in [(
            "seiyaku Lint { fn helper(int unused) -> int { return 1; } view fn value() authorize(anyone) -> int { return helper(unused: 0); } }",
            "unused-parameter",
        )] {
            let warnings = session
                .check_with_lints(CompileRequest {
                    source,
                    source_name: Some("lint.ko"),
                })
                .expect("lint fixture compiles");
            let warning = warnings
                .iter()
                .find(|warning| warning.code == lint)
                .unwrap_or_else(|| panic!("lint `{lint}` did not fire"));
            let expected = lint_codes()
                .find(|(name, _)| *name == lint)
                .map(|(_, code)| code);
            assert_eq!(Some(warning.diagnostic_code()), expected, "{lint}");
        }
        for (_, code) in lint_codes() {
            assert!(
                kotodama_lang::diagnostic::diagnostic_explanation(code).is_some(),
                "{code} must be registered"
            );
        }
    }
}

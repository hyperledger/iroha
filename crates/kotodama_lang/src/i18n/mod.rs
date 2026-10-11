pub use iroha_i18n::Language;
use iroha_i18n::wrap_placeholder;
const TRANSLATION_LANGUAGE_COUNT: usize = 76;
const TRANSLATION_MESSAGE_COUNT: usize = 15;
const TRANSLATION_OFFSET_WIDTH: usize = std::mem::size_of::<u32>() * 2;
const TRANSLATION_TEXT: &str = include_str!("translations/messages.v1.tsv");
const TRANSLATION_OFFSETS: &[u8; TRANSLATION_LANGUAGE_COUNT
     * TRANSLATION_MESSAGE_COUNT
     * TRANSLATION_OFFSET_WIDTH] =
    include_bytes!(concat!(env!("OUT_DIR"), "/kotodama_i18n_v1_offsets.bin"));
#[repr(usize)]
enum MessageIndex {
    NoFunctions,
    UnsupportedBinaryOp,
    UnknownParam,
    ReadFile,
    ParserError,
    SemanticError,
    LintUnusedState,
    LintStateShadowedParam,
    LintStateShadowedBinding,
    LintStateShadowedMapBinding,
    LintUnusedParameter,
    LintUnreachableAfterReturn,
    LintOk,
    LintUsage,
    LintUsageHelp,
}
const fn language_index(lang: Language) -> usize {
    match lang {
        Language::English => 0,
        Language::Japanese => 1,
        Language::SimplifiedChinese => 2,
        Language::TraditionalChinese => 3,
        Language::Thai => 4,
        Language::Khmer => 5,
        Language::Vietnamese => 6,
        Language::Korean => 7,
        Language::Arabic => 8,
        Language::Hebrew => 9,
        Language::Russian => 10,
        Language::Burmese => 11,
        Language::Hindi => 12,
        Language::Urdu => 13,
        Language::Sinhala => 14,
        Language::Tamil => 15,
        Language::French => 16,
        Language::Ukrainian => 17,
        Language::Polish => 18,
        Language::Swedish => 19,
        Language::German => 20,
        Language::Greek => 21,
        Language::Italian => 22,
        Language::Kazakh => 23,
        Language::Mongolian => 24,
        Language::Javanese => 25,
        Language::Madurese => 26,
        Language::Balinese => 27,
        Language::Minangkabau => 28,
        Language::AncientEgyptianHieroglyph => 29,
        Language::Dzongkha => 30,
        Language::Serbian => 31,
        Language::Turkish => 32,
        Language::Armenian => 33,
        Language::Amharic => 34,
        Language::Hausa => 35,
        Language::Tibetan => 36,
        Language::Kashmiri => 37,
        Language::Nepali => 38,
        Language::Afrikaans => 39,
        Language::Spanish => 40,
        Language::Farsi => 41,
        Language::OldAkkadian => 42,
        Language::Quechua => 43,
        Language::Aymara => 44,
        Language::Bengali => 45,
        Language::Balochi => 46,
        Language::Bashkir => 47,
        Language::Brahui => 48,
        Language::Portuguese => 49,
        Language::Punjabi => 50,
        Language::Sindhi => 51,
        Language::Pashto => 52,
        Language::Saraiki => 53,
        Language::Tatar => 54,
        Language::Somali => 55,
        Language::Sundanese => 56,
        Language::Shona => 57,
        Language::Swahili => 58,
        Language::Oromo => 59,
        Language::Igbo => 60,
        Language::Yoruba => 61,
        Language::Zulu => 62,
        Language::Dutch => 63,
        Language::Danish => 64,
        Language::Norse => 65,
        Language::Finnish => 66,
        Language::Estonian => 67,
        Language::Latvian => 68,
        Language::Hungarian => 69,
        Language::Czech => 70,
        Language::Lao => 71,
        Language::Indonesian => 72,
        Language::Pijin => 73,
        Language::Divehi => 74,
        Language::Manchurian => 75,
    }
}
fn translation_offset(index: usize) -> usize {
    let start = index * std::mem::size_of::<u32>();
    u32::from_le_bytes([
        TRANSLATION_OFFSETS[start],
        TRANSLATION_OFFSETS[start + 1],
        TRANSLATION_OFFSETS[start + 2],
        TRANSLATION_OFFSETS[start + 3],
    ]) as usize
}
fn message_for(lang: Language, message: MessageIndex) -> &'static str {
    let offset_index = (language_index(lang) * TRANSLATION_MESSAGE_COUNT + message as usize) * 2;
    let start = translation_offset(offset_index);
    let end = translation_offset(offset_index + 1);
    &TRANSLATION_TEXT[start..end]
}
/// Detect the best-fit language from overrides and environment.
pub fn detect_language() -> Language {
    iroha_i18n::detect_language(None)
}
/// Attach a translated message to a diagnostic whose `message` is the
/// canonical English text.
///
/// Machine-readable output keeps the English message; the translation is
/// shown to humans only when it covers all of the diagnostic's prose (see
/// [`crate::diagnostic::Diagnostic::presented_text`]). Nothing is attached for
/// English or when the translation fell back to the English text.
#[must_use]
pub fn with_translation(
    diagnostic: crate::diagnostic::Diagnostic,
    language: Language,
    translated: String,
) -> crate::diagnostic::Diagnostic {
    if language == Language::English || translated == diagnostic.message {
        return diagnostic;
    }
    diagnostic.with_localized(language.tag(), translated, None)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateShadowContext {
    Parameter,
    Binding,
    MapBinding,
}
pub enum Message<'a> {
    NoFunctions,
    UnsupportedBinaryOp(&'a str),
    UnknownParam(&'a str),
    ReadFile(&'a str, &'a str),
    ParserError(&'a str),
    SemanticError(&'a str),
    LintUnusedState {
        name: &'a str,
    },
    LintStateShadowed {
        func: &'a str,
        name: &'a str,
        context: StateShadowContext,
    },
    LintUnusedParameter {
        func: &'a str,
        name: &'a str,
    },
    LintUnreachableAfterReturn {
        context: &'a str,
    },
    LintOk,
    LintUsage,
    LintUsageHelp,
}
fn render_template(
    template: &str,
    replacements: &[(&str, &str)],
    language: Language,
) -> Option<String> {
    let mut result = template.to_string();
    let mut template_remainder = template.to_string();
    for (key, value) in replacements {
        let marker = format!("{{{key}}}");
        if !template_remainder.contains(&marker) {
            return None;
        }
        let replacement = wrap_placeholder(language, value);
        result = result.replace(&marker, replacement.as_ref());
        template_remainder = template_remainder.replace(&marker, "");
    }
    if !replacements.is_empty()
        && !template_remainder.contains('{')
        && !template_remainder.contains('}')
    {
        Some(result)
    } else {
        None
    }
}
pub fn translate(lang: Language, msg: Message) -> String {
    match msg {
        Message::NoFunctions => message_for(lang, MessageIndex::NoFunctions).to_string(),
        Message::UnsupportedBinaryOp(op) => {
            let template = message_for(lang, MessageIndex::UnsupportedBinaryOp);
            render_template(template, &[("op", op)], lang)
                .unwrap_or_else(|| format!("{} {}", template, wrap_placeholder(lang, op)))
        }
        Message::UnknownParam(name) => {
            let template = message_for(lang, MessageIndex::UnknownParam);
            render_template(template, &[("name", name)], lang)
                .unwrap_or_else(|| format!("{} {}", template, wrap_placeholder(lang, name)))
        }
        Message::ReadFile(path, err) => {
            let template = message_for(lang, MessageIndex::ReadFile);
            render_template(template, &[("path", path), ("error", err)], lang).unwrap_or_else(
                || {
                    format!(
                        "{} {}: {}",
                        template,
                        wrap_placeholder(lang, path),
                        wrap_placeholder(lang, err)
                    )
                },
            )
        }
        Message::ParserError(error) => {
            let template = message_for(lang, MessageIndex::ParserError);
            render_template(template, &[("error", error)], lang)
                .unwrap_or_else(|| format!("{}: {}", template, wrap_placeholder(lang, error)))
        }
        Message::SemanticError(error) => {
            let template = message_for(lang, MessageIndex::SemanticError);
            render_template(template, &[("error", error)], lang)
                .unwrap_or_else(|| format!("{}: {}", template, wrap_placeholder(lang, error)))
        }
        Message::LintUnusedState { name } => {
            let template = message_for(lang, MessageIndex::LintUnusedState);
            render_template(template, &[("name", name)], lang).unwrap_or_else(|| {
                format!(
                    "state {} is declared but never used",
                    wrap_placeholder(lang, name)
                )
            })
        }
        Message::LintStateShadowed {
            func,
            name,
            context,
        } => {
            let message_index = match context {
                StateShadowContext::Parameter => MessageIndex::LintStateShadowedParam,
                StateShadowContext::Binding => MessageIndex::LintStateShadowedBinding,
                StateShadowContext::MapBinding => MessageIndex::LintStateShadowedMapBinding,
            };
            let template = message_for(lang, message_index);
            render_template(template, &[("func", func), ("name", name)], lang).unwrap_or_else(
                || {
                    format!(
                        "state shadowed: {} in {}",
                        wrap_placeholder(lang, name),
                        wrap_placeholder(lang, func),
                    )
                },
            )
        }
        Message::LintUnusedParameter { func, name } => {
            let template = message_for(lang, MessageIndex::LintUnusedParameter);
            render_template(template, &[("func", func), ("name", name)], lang).unwrap_or_else(
                || {
                    format!(
                        "unused parameter {} in {}",
                        wrap_placeholder(lang, name),
                        wrap_placeholder(lang, func)
                    )
                },
            )
        }
        Message::LintUnreachableAfterReturn { context } => {
            let template = message_for(lang, MessageIndex::LintUnreachableAfterReturn);
            render_template(template, &[("context", context)], lang).unwrap_or_else(|| {
                format!(
                    "unreachable statement after return in {}",
                    wrap_placeholder(lang, context)
                )
            })
        }
        Message::LintOk => message_for(lang, MessageIndex::LintOk).to_string(),
        Message::LintUsage => message_for(lang, MessageIndex::LintUsage).to_string(),
        Message::LintUsageHelp => message_for(lang, MessageIndex::LintUsageHelp).to_string(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{Diagnostic, DiagnosticBundle, DiagnosticPhase};
    #[test]
    fn translations_never_replace_the_canonical_message_or_mix_languages() {
        let english = translate(
            Language::English,
            Message::LintUnusedParameter {
                func: "run",
                name: "unused",
            },
        );
        let japanese = translate(
            Language::Japanese,
            Message::LintUnusedParameter {
                func: "run",
                name: "unused",
            },
        );
        assert_ne!(english, japanese);
        let base = Diagnostic::warning("K5003", DiagnosticPhase::Semantic, english.clone(), None);
        let localized = with_translation(base.clone(), Language::Japanese, japanese.clone());
        assert_eq!(localized.message, english);
        assert_eq!(
            localized
                .localized
                .as_ref()
                .map(|text| text.language.as_str()),
            Some(Language::Japanese.tag())
        );
        // The registry help is English and untranslated, so humans see the
        // English pair rather than a Japanese message with English help.
        assert_eq!(localized.presented_text().0, english);
        let without_help = Diagnostic {
            help: None,
            ..localized.clone()
        };
        assert_eq!(without_help.presented_text(), (japanese.as_str(), None));
        let rendered = DiagnosticBundle::single(without_help)
            .render_json()
            .expect("JSON");
        assert!(rendered.contains(&format!("\"message\": \"{english}\"")));
        assert!(rendered.contains("\"localized\""));
        assert!(
            with_translation(base.clone(), Language::English, japanese)
                .localized
                .is_none()
        );
        assert!(
            with_translation(base, Language::Japanese, english)
                .localized
                .is_none()
        );
    }
    #[test]
    fn semantic_error_templates_preserve_braces_in_replacement_values() {
        let rendered = translate(
            Language::English,
            Message::SemanticError(r#"invalid JSON literal `{"owner":1}`"#),
        );
        assert_eq!(
            rendered,
            r#"semantic error: invalid JSON literal `{"owner":1}`"#
        );
        assert!(!rendered.contains("{error}"));
    }
    #[test]
    fn template_rendering_rejects_missing_or_unknown_markers() {
        assert!(
            render_template(
                "semantic error",
                &[("error", "invalid JSON")],
                Language::English,
            )
            .is_none()
        );
        assert!(
            render_template(
                "semantic error: {error} {unknown}",
                &[("error", "invalid JSON")],
                Language::English,
            )
            .is_none()
        );
    }
}

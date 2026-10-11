//! Canonical glossary for Kotodama's branded declaration keywords.
//!
//! Kotodama brands the four points where a seiyaku meets ledger authority: the
//! deployable unit itself, its authorized state-changing declarations, and its
//! two consensus-staged lifecycle hooks. Each concept has a romanized spelling
//! and an exact Japanese spelling. Both spellings lex to the same keyword token
//! and may be mixed freely within one source file; tooling must never require
//! or prefer one script over the other.
//!
//! Diagnostics, LSP hover and completion, `koto explain`, `koto doc`, and the
//! rendered documentation derive their wording from [`BRANDED_KEYWORDS`] so the
//! vocabulary cannot drift between surfaces.

/// One branded Kotodama keyword with both accepted spellings and its meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrandedKeyword {
    /// Romanized (Hepburn) spelling accepted by the lexer.
    pub romaji: &'static str,
    /// Japanese spelling accepted by the lexer.
    pub kanji: &'static str,
    /// Hiragana reading of the Japanese spelling.
    pub reading: &'static str,
    /// Literal English gloss of the word.
    pub literal: &'static str,
    /// What the keyword declares in Kotodama.
    pub role: &'static str,
    /// One-paragraph explanation used by hover, completion and `koto explain`.
    pub summary: &'static str,
    /// Minimal declaration shape that demonstrates the keyword.
    pub example: &'static str,
    /// English words newcomers commonly type for this concept. Diagnostics use
    /// them to suggest the branded keyword; they are never accepted as syntax.
    pub english_guesses: &'static [&'static str],
    /// Near-miss Japanese spellings (IME confusions) that diagnostics map back
    /// to this keyword. They are never accepted as syntax.
    pub confusables: &'static [&'static str],
}

impl BrandedKeyword {
    /// Both accepted spellings, romanized first.
    #[must_use]
    pub const fn spellings(&self) -> [&'static str; 2] {
        [self.romaji, self.kanji]
    }

    /// Short label of the form `kotoage (言挙げ)`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} ({})", self.romaji, self.kanji)
    }

    /// Markdown hover text shared by the LSP and `koto explain`.
    #[must_use]
    pub fn hover_markdown(&self) -> String {
        format!(
            "**{romaji}** / **{kanji}** ({reading}, \u{201c}{literal}\u{201d})\n\n{role}.\n\n{summary}\n\n```kotodama\n{example}\n```\n\nBoth spellings are the same keyword and can be mixed freely.",
            romaji = self.romaji,
            kanji = self.kanji,
            reading = self.reading,
            literal = self.literal,
            role = self.role,
            summary = self.summary,
            example = self.example,
        )
    }
}

/// The four branded keywords, in declaration-lifecycle order.
pub const BRANDED_KEYWORDS: [BrandedKeyword; 4] = [
    BrandedKeyword {
        romaji: "seiyaku",
        kanji: "誓約",
        reading: "せいやく",
        literal: "solemn pledge",
        role: "Declares the deployable unit compiled to one IVM `.to` artifact",
        summary: "A source file contains exactly one seiyaku or one module. The seiyaku owns \
                  durable state, kotoage and view declarations, lifecycle hooks and triggers; \
                  its declared name is preserved through the signed interface and diagnostics.",
        example: "seiyaku Counter {\n    state int value;\n}",
        english_guesses: &["contract", "program", "actor"],
        confusables: &["契約", "制約", "誓い", "せいやく", "セイヤク"],
    },
    BrandedKeyword {
        romaji: "kotoage",
        kanji: "言挙げ",
        reading: "ことあげ",
        literal: "raising one's words",
        role: "Declares an authorized, state-changing public function of a seiyaku",
        summary: "A kotoage is submitted in a transaction, may write durable state and the \
                  ledger, and always states who may invoke it with `authorize(...)`. Read-only \
                  public functions are `view fn` instead.",
        example: "permission CanIncrement; kotoage fn increment(int delta) authorize(CanIncrement) {\n    value += delta;\n}",
        english_guesses: &["entry", "entrypoint", "pub", "public", "external", "action"],
        confusables: &["事挙げ", "言挙", "言上げ", "ことあげ", "コトアゲ"],
    },
    BrandedKeyword {
        romaji: "hajimari",
        kanji: "始まり",
        reading: "はじまり",
        literal: "beginning",
        role: "Declares the one-shot activation hook that initializes durable state",
        summary: "Activating newly deployed code stages exactly one hajimari transition. It \
                  must initialize every scalar state declaration on every successful path and \
                  runs before any other kotoage or view is accepted.",
        example: "hajimari() {\n    value = 0;\n}",
        english_guesses: &["init", "initialize", "constructor", "setup", "instantiate"],
        confusables: &["始り", "初まり", "はじまり", "ハジマリ"],
    },
    BrandedKeyword {
        romaji: "kaizen",
        kanji: "改善",
        reading: "かいぜん",
        literal: "improvement",
        role: "Declares the migration hook run once when an active seiyaku's code is replaced in place",
        summary: "Rebinding an active seiyaku address to new verified code stages one kaizen \
                  transition when the new artifact declares it. Use it to migrate durable state \
                  to the new layout; it is not a recurring hook.",
        example: "kaizen() {\n    schema_version = 2;\n}",
        english_guesses: &["upgrade", "migrate", "migration", "update"],
        confusables: &["改繕", "かいぜん", "カイゼン"],
    },
];

/// Looks up a branded keyword by either accepted spelling.
#[must_use]
pub fn by_spelling(spelling: &str) -> Option<&'static BrandedKeyword> {
    BRANDED_KEYWORDS
        .iter()
        .find(|keyword| keyword.romaji == spelling || keyword.kanji == spelling)
}

/// Finds the branded keyword a newcomer most likely meant by an English word
/// or a near-miss Japanese spelling. Matching is exact and case-insensitive
/// for ASCII guesses.
#[must_use]
pub fn suggestion_for(word: &str) -> Option<&'static BrandedKeyword> {
    BRANDED_KEYWORDS.iter().find(|keyword| {
        keyword
            .english_guesses
            .iter()
            .any(|guess| guess.eq_ignore_ascii_case(word))
            || keyword.confusables.contains(&word)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_spellings_resolve_to_the_same_entry() {
        for keyword in &BRANDED_KEYWORDS {
            assert_eq!(by_spelling(keyword.romaji), Some(keyword));
            assert_eq!(by_spelling(keyword.kanji), Some(keyword));
        }
        assert_eq!(by_spelling("contract"), None);
    }

    #[test]
    fn spellings_match_the_lexical_grammar() {
        let lex = include_str!("../grammar/v1.lex");
        for keyword in &BRANDED_KEYWORDS {
            for spelling in keyword.spellings() {
                let token = lex
                    .lines()
                    .filter_map(|line| line.strip_prefix("keyword\t"))
                    .find_map(|rest| rest.split_once('\t').filter(|(s, _)| *s == spelling))
                    .map(|(_, token)| token);
                assert!(token.is_some(), "{spelling} missing from v1.lex");
            }
        }
    }

    #[test]
    fn guesses_and_confusables_map_back_without_collisions() {
        assert_eq!(
            suggestion_for("contract").map(|k| k.romaji),
            Some("seiyaku")
        );
        assert_eq!(suggestion_for("Init").map(|k| k.romaji), Some("hajimari"));
        assert_eq!(suggestion_for("upgrade").map(|k| k.romaji), Some("kaizen"));
        assert_eq!(suggestion_for("契約").map(|k| k.romaji), Some("seiyaku"));
        assert_eq!(suggestion_for("事挙げ").map(|k| k.romaji), Some("kotoage"));
        let mut seen = std::collections::BTreeSet::new();
        for keyword in &BRANDED_KEYWORDS {
            for word in keyword.english_guesses.iter().chain(keyword.confusables) {
                assert!(
                    seen.insert(word.to_ascii_lowercase()),
                    "duplicate guess {word}"
                );
                assert!(
                    by_spelling(word).is_none(),
                    "{word} must not be a real spelling"
                );
            }
        }
    }

    #[test]
    fn hover_markdown_names_both_spellings() {
        let hover = BRANDED_KEYWORDS[1].hover_markdown();
        assert!(hover.contains("**kotoage**") && hover.contains("**言挙げ**"));
        assert!(hover.contains("mixed freely"));
        assert_eq!(BRANDED_KEYWORDS[2].label(), "hajimari (始まり)");
    }
}

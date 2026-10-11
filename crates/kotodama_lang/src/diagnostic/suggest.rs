//! Bounded, deterministic "did you mean" suggestions for diagnostics.
//!
//! Suggestions only change compiler output text, never compiled behaviour.
//! They are still fully deterministic so goldens and editor output are stable:
//! candidates are ranked by case-insensitive edit distance, then by lexical
//! order of the candidate.

/// Longest word (in Unicode scalars) the edit-distance matcher considers.
///
/// Longer words are compared only for case-insensitive equality, which keeps
/// the quadratic distance computation bounded for adversarial identifiers.
pub const MAX_SUGGESTION_WORD_CHARS: usize = 64;

/// Largest edit distance accepted for a word of `chars` Unicode scalars.
///
/// Short words only match case-insensitively; four- and five-character words
/// allow one edit, longer words two.
#[must_use]
pub const fn max_distance_for(chars: usize) -> usize {
    match chars {
        0..=3 => 0,
        4..=5 => 1,
        _ => 2,
    }
}

/// Optimal-string-alignment (restricted Damerau-Levenshtein) distance between
/// `left` and `right`, compared case-insensitively for ASCII letters.
///
/// Returns `None` when the distance exceeds `limit` or either word is longer
/// than [`MAX_SUGGESTION_WORD_CHARS`].
#[must_use]
pub fn edit_distance(left: &str, right: &str, limit: usize) -> Option<usize> {
    let left = left
        .chars()
        .map(|character| character.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let right = right
        .chars()
        .map(|character| character.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if left.len() > MAX_SUGGESTION_WORD_CHARS || right.len() > MAX_SUGGESTION_WORD_CHARS {
        return (left == right).then_some(0);
    }
    if left.len().abs_diff(right.len()) > limit {
        return None;
    }
    let width = right.len() + 1;
    let mut rows = vec![0_usize; (left.len() + 1) * width];
    for (column, cell) in rows.iter_mut().enumerate().take(width) {
        *cell = column;
    }
    for row in 1..=left.len() {
        rows[row * width] = row;
        let mut row_minimum = row;
        for column in 1..=right.len() {
            let substitution = usize::from(left[row - 1] != right[column - 1]);
            let mut best = (rows[(row - 1) * width + column] + 1)
                .min(rows[row * width + column - 1] + 1)
                .min(rows[(row - 1) * width + column - 1] + substitution);
            if row > 1
                && column > 1
                && left[row - 1] == right[column - 2]
                && left[row - 2] == right[column - 1]
            {
                best = best.min(rows[(row - 2) * width + column - 2] + 1);
            }
            rows[row * width + column] = best;
            row_minimum = row_minimum.min(best);
        }
        if row_minimum > limit {
            return None;
        }
    }
    let distance = rows[left.len() * width + right.len()];
    (distance <= limit).then_some(distance)
}

/// The closest candidate to `word`, if one lies within the length-dependent
/// bound of [`max_distance_for`].
///
/// An exact match is never a suggestion; a candidate differing only in ASCII
/// case is (distance 0). Ties at the same distance go to the lexically
/// smallest candidate.
#[must_use]
pub fn closest<'candidate>(
    word: &str,
    candidates: impl IntoIterator<Item = &'candidate str>,
) -> Option<&'candidate str> {
    let limit = max_distance_for(word.chars().count());
    candidates
        .into_iter()
        .filter(|candidate| *candidate != word)
        .filter_map(|candidate| {
            edit_distance(word, candidate, limit).map(|distance| (distance, candidate))
        })
        .min_by(|(left_distance, left), (right_distance, right)| {
            left_distance
                .cmp(right_distance)
                .then_with(|| left.cmp(right))
        })
        .map(|(_, candidate)| candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_counts_insertions_deletions_substitutions_and_transpositions() {
        assert_eq!(edit_distance("kaizan", "kaizen", 2), Some(1));
        assert_eq!(edit_distance("seiyak", "seiyaku", 2), Some(1));
        assert_eq!(edit_distance("autorize", "authorize", 2), Some(1));
        assert_eq!(edit_distance("kotaoge", "kotoage", 2), Some(1));
        assert_eq!(edit_distance("Seiyaku", "seiyaku", 0), Some(0));
        assert_eq!(edit_distance("hajime", "kaizen", 2), None);
        assert_eq!(edit_distance("", "fn", 2), Some(2));
    }

    #[test]
    fn closest_is_bounded_and_breaks_ties_lexically() {
        let keywords = [
            "kaizen", "kotoage", "hajimari", "seiyaku", "state", "struct",
        ];
        assert_eq!(closest("kaizan", keywords), Some("kaizen"));
        assert_eq!(closest("hajimai", keywords), Some("hajimari"));
        assert_eq!(closest("Kotoage", keywords), Some("kotoage"));
        assert_eq!(closest("stat", ["state", "start"]), Some("start"));
        assert_eq!(closest("fn", ["fn"]), None);
        assert_eq!(closest("xyz", keywords), None);
        assert_eq!(closest("helper", keywords), None);
    }

    #[test]
    fn oversized_words_only_match_case_insensitively() {
        let long = "a".repeat(MAX_SUGGESTION_WORD_CHARS + 1);
        let upper = long.to_ascii_uppercase();
        assert_eq!(edit_distance(&long, &upper, 2), Some(0));
        assert_eq!(edit_distance(&long, &long[1..], 2), None);
    }
}

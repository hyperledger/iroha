//! Structure-aware fuzzing for production V1 artifact admission and preparation.

#![no_main]

#[path = "../artifact_admission_support.rs"]
mod support;

use libfuzzer_sys::{Corpus, fuzz_target};
use support::{exercise_admission, finish_iteration};

const CANONICAL_ARTIFACT: &[u8] =
    include_bytes!("../../../kotodama_lang/src/samples/zk_vote_ballot.to");
const MAX_MUTATIONS: usize = 64;
const MAX_INSERTED_BYTES: usize = 256;

fuzz_target!(|data: &[u8]| -> Corpus {
    match data.split_first() {
        Some((&b'R', raw)) => {
            return finish_iteration(exercise_admission(raw));
        }
        Some((&b'S', _)) => {
            return finish_iteration(exercise_admission(CANONICAL_ARTIFACT));
        }
        _ => {}
    }

    let candidate = mutate_canonical_artifact(data);
    finish_iteration(exercise_admission(&candidate))
});

fn mutate_canonical_artifact(data: &[u8]) -> Vec<u8> {
    let mut artifact = CANONICAL_ARTIFACT.to_vec();
    let Some((&mode, payload)) = data.split_first() else {
        return artifact;
    };

    match mode % 7 {
        0 => {}
        1 => {
            for mutation in payload.chunks(3).take(MAX_MUTATIONS) {
                if artifact.is_empty() {
                    break;
                }
                let high = usize::from(mutation[0]);
                let low = usize::from(*mutation.get(1).unwrap_or(&0));
                let index = ((high << 8) | low) % artifact.len();
                artifact[index] ^= *mutation.get(2).unwrap_or(&0xff);
            }
        }
        2 => {
            let keep = bounded_index(payload, artifact.len() + 1);
            artifact.truncate(keep);
        }
        3 => artifact.extend(payload.iter().copied().take(MAX_INSERTED_BYTES)),
        4 => {
            if !artifact.is_empty() {
                let start = bounded_index(payload, artifact.len());
                let available = artifact.len() - start;
                let remove = bounded_index(payload.get(2..).unwrap_or_default(), available + 1);
                artifact.drain(start..start + remove);
            }
        }
        5 => {
            let index = bounded_index(payload, artifact.len() + 1);
            artifact.splice(
                index..index,
                payload.iter().copied().skip(2).take(MAX_INSERTED_BYTES),
            );
        }
        6 => {
            for (byte, replacement) in artifact
                .iter_mut()
                .zip(payload.iter().copied())
                .take(MAX_INSERTED_BYTES)
            {
                *byte = replacement;
            }
        }
        _ => unreachable!("modulo seven is exhaustive"),
    }
    artifact
}

fn bounded_index(bytes: &[u8], bound: usize) -> usize {
    debug_assert!(bound > 0);
    let high = usize::from(bytes.first().copied().unwrap_or(0));
    let low = usize::from(bytes.get(1).copied().unwrap_or(0));
    ((high << 8) | low) % bound
}

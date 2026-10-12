//! Bounded typed privacy instruction projection for Kotlin ordered-intent hashing.

use super::*;

/// Decode one complete canonical instruction and produce only its proof-free preimage.
fn project_instruction(archive: &[u8]) -> Option<Vec<u8>> {
    let maximum = SubmitPrivacyProofV1::canonical_frame_byte_limit_v1();
    if archive.is_empty() || archive.len() > maximum {
        return None;
    }
    let base = norito::canonical_decode_limits(archive.len());
    let limits = norito::DecodeLimits::new(
        base.max_sequence_elements(),
        base.max_field_bytes(),
        base.max_total_elements(),
        base.max_total_allocated_bytes(),
        64,
    );
    let instruction =
        norito::decode_canonical_with_limits::<SubmitPrivacyProofV1>(archive, limits).ok()?;
    let projection = instruction.ordered_intent_projection_bytes_v1().ok()?;
    (projection.len() <= maximum).then_some(projection)
}

/// Return an intent-only instruction projection; null means malformed or unavailable input.
pub(super) fn java_native_submit_proof_intent_projection(
    env: &mut jni::JNIEnv<'_>,
    archive: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    if archive.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(length) = env.get_array_length(&archive) else {
        return std::ptr::null_mut();
    };
    if length <= 0
        || usize::try_from(length).map_or(true, |length| {
            length > SubmitPrivacyProofV1::canonical_frame_byte_limit_v1()
        })
    {
        return std::ptr::null_mut();
    }
    let Ok(mut input) = env.convert_byte_array(&archive) else {
        return std::ptr::null_mut();
    };
    let projection = project_instruction(&input);
    input.fill(0);
    let Some(mut projection) = projection else {
        return std::ptr::null_mut();
    };
    let result = env
        .byte_array_from_slice(&projection)
        .map_or(std::ptr::null_mut(), |array| array.into_raw());
    projection.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_exact12_projections_match_the_typed_model_and_reject_malformed_frames() {
        let fixtures =
            iroha_data_model::privacy::privacy_exact12_fixture_bundle_v1().expect("fixtures");
        for row in fixtures.rows {
            let input = row.submit_proof_instruction_norito;
            let typed = norito::decode_canonical::<SubmitPrivacyProofV1>(&input)
                .expect("typed instruction");
            assert_eq!(
                project_instruction(&input),
                Some(
                    typed
                        .ordered_intent_projection_bytes_v1()
                        .expect("projection")
                )
            );
            assert!(project_instruction(&input[..input.len() - 1]).is_none());
            let mut trailing = input.clone();
            trailing.push(0);
            assert!(project_instruction(&trailing).is_none());
            let mut damaged = input;
            *damaged.last_mut().expect("frame") ^= 1;
            assert!(project_instruction(&damaged).is_none());
            assert!(project_instruction(&row.envelope_norito).is_none());
        }
        assert!(project_instruction(&[]).is_none());
        assert!(
            project_instruction(&vec![
                0;
                SubmitPrivacyProofV1::canonical_frame_byte_limit_v1()
                    + 1
            ])
            .is_none()
        );
    }

    #[test]
    fn instruction_wrapper_accepts_a_ceiling_envelope_and_rejects_one_over() {
        let fixtures =
            iroha_data_model::privacy::privacy_exact12_fixture_bundle_v1().expect("fixtures");
        let instruction: SubmitPrivacyProofV1 =
            norito::decode_canonical(&fixtures.rows[0].submit_proof_instruction_norito)
                .expect("typed instruction");
        let mut envelope = instruction.envelope().clone();
        let envelope_limit = iroha_data_model::privacy::TAIRA_PRIVACY_MAX_ACTION_BYTES_V1 as usize;
        envelope.proof.bytes_mut().bytes = vec![0x5a; envelope_limit];
        let overhead = norito::canonical_frame_len(&envelope).expect("frame") - envelope_limit;
        envelope
            .proof
            .bytes_mut()
            .bytes
            .truncate(envelope_limit - overhead);
        assert_eq!(
            norito::canonical_frame_len(&envelope).unwrap(),
            envelope_limit
        );
        let instruction = SubmitPrivacyProofV1::new(envelope.clone());
        let exact = norito::encode_canonical(&instruction).expect("ceiling instruction");
        assert_eq!(
            exact.len(),
            SubmitPrivacyProofV1::canonical_frame_byte_limit_v1()
        );
        assert!(project_instruction(&exact).is_some());
        envelope.proof.bytes_mut().bytes.push(0x5a);
        let one_over = norito::encode_canonical(&SubmitPrivacyProofV1::new(envelope))
            .expect("one-over instruction");
        assert_eq!(one_over.len(), exact.len() + 1);
        assert!(project_instruction(&one_over).is_none());
    }
}

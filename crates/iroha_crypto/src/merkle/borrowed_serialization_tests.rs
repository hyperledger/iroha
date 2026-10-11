//! Original materialized wire, cache refusal and physical borrowed-payload controls.

use super::*;
use crate::test_allocations::{allocations_during, without_allocations};
use norito::core::{DecodeFlagsGuard, SerializePayload, header_flags::COMPACT_LEN};

const COUNTS: [u8; 7] = [0, 1, 2, 3, 7, 31, 127];

fn tree(scheme: MerkleHashScheme, count: u8) -> MerkleTree<()> {
    let leaves = (0..count)
        .map(|index| HashOf::from_untyped_unchecked(Hash::prehashed([index; Hash::LENGTH])));
    match scheme {
        MerkleHashScheme::ApplicationV1 => MerkleTree::from_application_leaf_nodes(leaves),
        MerkleHashScheme::Sha256V1 => MerkleTree::from_sha256_leaf_nodes(leaves),
    }
}
fn schemes() -> [MerkleHashScheme; 2] {
    [MerkleHashScheme::ApplicationV1, MerkleHashScheme::Sha256V1]
}

#[test]
fn borrowed_merkle_wire_matches_original_materialized_tuple_and_complete_declared_frames() {
    for scheme in schemes() {
        for count in COUNTS {
            let source = tree(scheme, count);
            let original_nodes = source.nodes.as_ptr();
            let original_capacity = source.nodes.capacity();
            let original_root = source.root();
            for flags in [0, COMPACT_LEN] {
                let _flags = DecodeFlagsGuard::enter(flags);
                // The independent test-only original oracle collects its leaves
                // and reconstructs its complete cache before serializing the tuple.
                let original = source.serialized_parts().unwrap();
                let mut expected = Vec::new();
                norito::core::serialize_to_buffer(&original, &mut expected).unwrap();
                let mut actual = Vec::new();
                norito::core::serialize_to_buffer(&source, &mut actual).unwrap();
                assert_eq!(
                    actual, expected,
                    "scheme {scheme:?}, count {count}, flags {flags}"
                );
                assert_eq!(source.encoded_len_hint(), original.encoded_len_hint());
                assert_eq!(source.encoded_len_exact(), original.encoded_len_exact());
                assert_eq!(source.encoded_len_exact(), Some(expected.len()));
                let (decoded, used) =
                    <MerkleTree<()> as norito::core::DecodeFromSlice>::decode_from_slice(&actual)
                        .unwrap();
                assert_eq!(used, actual.len());
                assert_eq!(decoded, source);
                // The expected frame uses the original MerkleTree identity and
                // exactly these declared tuple flags; no alternate schema exists.
                let expected_frame =
                    norito::core::frame_bare_with_header_flags::<MerkleTree<()>>(&expected, flags)
                        .unwrap();
                let mut actual_frame = Vec::new();
                norito::core::write_frame_to_writer(&source, &mut actual_frame).unwrap();
                assert_eq!(actual_frame, expected_frame);
                assert_eq!(
                    norito::decode_from_bytes::<MerkleTree<()>>(&actual_frame).unwrap(),
                    source
                );
            }
            assert_eq!(source.nodes.as_ptr(), original_nodes);
            assert_eq!(source.nodes.capacity(), original_capacity);
            assert_eq!(source.root(), original_root);
        }
    }
}

#[test]
fn borrowed_merkle_valid_payload_measurement_hints_and_original_destinations_allocate_nothing() {
    for scheme in schemes() {
        for count in COUNTS {
            let source = tree(scheme, count);
            for flags in [0, COMPACT_LEN] {
                let _flags = DecodeFlagsGuard::enter(flags);
                let original = source.serialized_parts().unwrap();
                let mut expected = Vec::new();
                norito::core::serialize_to_buffer(&original, &mut expected).unwrap();
                let (_, original_allocations) =
                    allocations_during(|| source.serialized_parts().unwrap());
                if count > 0 {
                    assert!(
                        original_allocations >= 3,
                        "the actual original leaf vector, queue and cache allocate"
                    );
                }
                let (scheme_id, borrowed) =
                    without_allocations(|| source.serialized_view().unwrap());
                assert_eq!(scheme_id, scheme.wire_id());
                assert_eq!(borrowed.iter().count(), usize::from(count));
                assert_eq!(
                    without_allocations(|| source.encoded_len_hint()),
                    Some(expected.len())
                );
                assert_eq!(
                    without_allocations(|| source.encoded_len_exact()),
                    Some(expected.len())
                );
                assert_eq!(
                    without_allocations(|| norito::core::encoded_payload_len(&source).unwrap()),
                    expected.len()
                );
                // Destinations are genuine physical owners created before the
                // observed operation. Neither the tree nor a leaf/cache copy is staged.
                let mut buffered = Vec::with_capacity(expected.len());
                let backing = buffered.as_ptr();
                let capacity = buffered.capacity();
                without_allocations(|| {
                    norito::core::serialize_to_buffer(&source, &mut buffered).unwrap()
                });
                assert_eq!(buffered, expected);
                assert_eq!(buffered.as_ptr(), backing);
                assert_eq!(buffered.capacity(), capacity);
                let mut fixed = vec![0_u8; 65_536].into_boxed_slice();
                assert!(expected.len() <= fixed.len());
                let mut writer = std::io::Cursor::new(fixed.as_mut());
                without_allocations(|| {
                    norito::core::serialize_to_writer(&source, &mut writer).unwrap()
                });
                let used = usize::try_from(writer.position()).unwrap();
                assert_eq!(used, expected.len());
                assert_eq!(&fixed[..used], expected);
            }
        }
    }
    // Framed schema-identity construction and caller destination allocation
    // remain separate original owners; this test qualifies only bare payload work.
}

fn assert_original_refusal(source: &MerkleTree<()>) {
    let original = source
        .serialized_parts()
        .expect_err("original malformed-cache refusal");
    assert_eq!(source.serialized_view().err(), Some(original.clone()));
    assert_eq!(source.encoded_len_hint(), None);
    assert_eq!(source.encoded_len_exact(), None);
    let mut destination = Vec::new();
    let error = norito::core::serialize_to_buffer(source, &mut destination).unwrap_err();
    assert_eq!(error.to_string(), original.to_string());
    assert!(
        destination.is_empty(),
        "no malformed cache reaches the wire writer"
    );
    #[cfg(feature = "json")]
    {
        let fallback = r#"{"hash_scheme":0,"leaves":[]}"#;
        assert_eq!(norito::json::to_json(source).unwrap(), fallback);
        assert_eq!(
            norito::json::to_json_bounded(source, fallback.len()).unwrap(),
            fallback
        );
    }
}

#[test]
fn borrowed_merkle_refuses_every_original_cached_node_corruption_and_retains_error_identity() {
    let different = HashOf::from_untyped_unchecked(Hash::new(b"different original cached node"));
    for scheme in schemes() {
        // Five and six also exercise the original absent internal padding.
        for count in [2, 3, 5, 6, 7, 31, 127] {
            let source = tree(scheme, count);
            for index in 0..source.nodes.len() {
                let mut altered = source.clone();
                altered.nodes[index] = Some(different);
                assert_original_refusal(&altered);
                if source.nodes[index].is_some() {
                    let mut absent = source.clone();
                    absent.nodes[index] = None;
                    assert_original_refusal(&absent);
                }
            }
            let mut changed_scheme = source.clone();
            changed_scheme.hash_scheme = match scheme {
                MerkleHashScheme::ApplicationV1 => MerkleHashScheme::Sha256V1,
                MerkleHashScheme::Sha256V1 => MerkleHashScheme::ApplicationV1,
            };
            assert_original_refusal(&changed_scheme);
        }
        for nodes in [
            vec![None],
            vec![Some(different), Some(different)],
            vec![Some(different), None, Some(different)],
        ] {
            assert_original_refusal(&MerkleTree {
                hash_scheme: scheme,
                nodes,
            });
        }
        // A sole leaf has no derived parent. Replacing that authenticated wire
        // leaf is another valid tree, rather than a fabricated cache mismatch.
        let single = MerkleTree::from_leaf_nodes_with(scheme, [different], |left, _| left.copied());
        assert_eq!(single.serialized_view().unwrap().0, scheme.wire_id());
        assert_eq!(single.serialized_parts().unwrap().1, [different]);
    }
}

#[test]
fn borrowed_merkle_retains_original_leaf_bound_before_cache_copy_or_output() {
    let leaf = HashOf::from_untyped_unchecked(Hash::prehashed([0x5d; Hash::LENGTH]));
    for scheme in schemes() {
        // A real original canonical tree is built outside serialization. This
        // is neither a declared count nor unbacked allocation credit.
        let leaves = std::iter::repeat_n(leaf, SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1 + 1);
        let source = match scheme {
            MerkleHashScheme::ApplicationV1 => MerkleTree::from_application_leaf_nodes(leaves),
            MerkleHashScheme::Sha256V1 => MerkleTree::from_sha256_leaf_nodes(leaves),
        };
        assert_eq!(
            source.leaf_count(),
            SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1 + 1
        );
        assert!(matches!(source.serialized_view().err(),
            Some(MerkleError::SerializedTreeTooManyLeaves { actual, maximum })
                if actual == SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1 + 1
                    && maximum == SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1));
        assert_original_refusal(&source);
    }
}

#[cfg(feature = "json")]
fn original_json(source: &MerkleTree<()>, out: &mut String) {
    let Ok((scheme, leaves)) = source.serialized_parts() else {
        out.push_str(r#"{"hash_scheme":0,"leaves":[]}"#);
        return;
    };
    out.push('{');
    json::write_json_string("hash_scheme", out);
    out.push(':');
    scheme.json_serialize(out);
    out.push(',');
    json::write_json_string("leaves", out);
    out.push(':');
    leaves.json_serialize(out);
    out.push('}');
}

#[cfg(feature = "json")]
#[test]
fn borrowed_merkle_json_preserves_original_bytes_caps_and_removes_only_cache_reconstruction() {
    for scheme in schemes() {
        for count in COUNTS {
            let source = tree(scheme, count);
            let mut expected = String::new();
            original_json(&source, &mut expected);
            let mut original_destination = String::with_capacity(expected.len());
            let ((), original_allocations) =
                allocations_during(|| original_json(&source, &mut original_destination));
            let mut borrowed_destination = String::with_capacity(expected.len());
            let ((), borrowed_allocations) =
                allocations_during(|| source.json_serialize(&mut borrowed_destination));
            assert_eq!(original_destination, expected);
            assert_eq!(borrowed_destination, expected);
            assert!(borrowed_allocations <= original_allocations);
            if count > 0 {
                assert!(
                    original_allocations >= borrowed_allocations + 3,
                    "original response-sized leaf vector/queue/cache have been removed"
                );
            }
            assert_eq!(
                norito::json::to_json_bounded(&source, expected.len()).unwrap(),
                expected
            );
            assert_eq!(
                norito::json::to_json_bounded(&source, expected.len() - 1),
                Err(json::BoundedJsonError::BodyTooLarge)
            );
            assert_eq!(
                norito::json::from_str::<MerkleTree<()>>(&expected).unwrap(),
                source
            );
            without_allocations(|| {
                source.serialized_view().unwrap();
            });
            // Existing canonical per-hash JSON literal scratch is still real;
            // no zero-allocation claim is made for the complete JSON writer.
        }
    }
}

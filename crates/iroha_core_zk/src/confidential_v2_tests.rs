#[cfg(test)]
mod tests {
    fn relabel_native_fixture(
        proof: &iroha_data_model::proof::ProofBox,
        key: &iroha_data_model::proof::VerifyingKeyBox,
        backend: &str,
    ) -> (
        iroha_data_model::proof::ProofBox,
        iroha_data_model::proof::VerifyingKeyBox,
    ) {
        let key = iroha_data_model::proof::VerifyingKeyBox::new(backend.into(), key.bytes.clone());
        let mut envelope: iroha_data_model::zk::OpenVerifyEnvelope =
            norito::decode_canonical(&proof.bytes).unwrap();
        envelope.vk_hash = crate::hash_vk(&key);
        (
            iroha_data_model::proof::ProofBox::new(
                backend.into(),
                norito::encode_canonical(&envelope).unwrap(),
            ),
            key,
        )
    }

    pub(super) fn full_tree_input_path_v3<const DEPTH: usize>(
        commitment: [u8; 32],
    ) -> super::ConfidentialMerklePathV2 {
        // Leaf zero is the input note. Every other leaf is a nonzero filler
        // commitment, so this root has no unused zero leaf. Repeated filler
        // subtrees let the capacity boundary be exercised in O(DEPTH) work.
        let mut node = super::confidential_commitment_leaf_v3(commitment, 0)
            .expect("canonical input commitment");
        let mut sibling = super::confidential_commitment_leaf_v3(scalar_bytes(7), 1)
            .expect("canonical nonzero filler commitment");
        let mut siblings = Vec::with_capacity(DEPTH);
        let mut witness_nodes = Vec::with_capacity(DEPTH);
        for _ in 0..DEPTH {
            siblings.push(super::scalar_to_repr_bytes(sibling));
            node = super::merkle_parent_v3(node, sibling);
            witness_nodes.push(super::scalar_to_repr_bytes(node));
            sibling = super::merkle_parent_v3(sibling, sibling);
        }
        super::ConfidentialMerklePathV2 {
            siblings,
            directions: vec![0; DEPTH],
            witness_nodes,
            root: super::scalar_to_repr_bytes(node),
        }
    }

    #[test]
    fn single_input_paths_accept_full_capacity_and_reject_surplus_or_foreign_paths() {
        let commitment = scalar_bytes(41);
        let path = full_tree_input_path_v3::<{ super::CONFIDENTIAL_TREE_DEPTH_V2 }>(commitment);
        let dummy =
            super::confidential_absent_input_path_v3::<{ super::CONFIDENTIAL_TREE_DEPTH_V2 }>();
        assert_eq!(dummy.root, super::poseidon_empty_root_v2());
        assert_ne!(path.root, dummy.root);
        let input = super::ConfidentialUnshieldInputV2 {
            amount: 9,
            rho: [1; 32],
            diversifier: scalar_bytes(1),
            leaf_index: 0,
        };
        for normalize in [
            super::normalize_confidential_unshield_full_paths_v3,
            super::normalize_confidential_unshield_change_paths_v4,
        ] {
            let (actual, absent) = normalize(
                std::slice::from_ref(&path),
                path.root,
                &input,
                None,
                commitment,
                [0; 32],
            )
            .expect("one-note unshield needs no empty leaf in a full tree");
            assert_eq!(actual.root, path.root);
            assert_eq!(absent.root, dummy.root);
            assert_eq!(absent.siblings, dummy.siblings);
            assert_eq!(absent.directions, dummy.directions);
            assert_eq!(absent.witness_nodes, dummy.witness_nodes);
            for supplied in [vec![], vec![path.clone(), dummy.clone()]] {
                assert!(
                    normalize(&supplied, path.root, &input, None, commitment, [0; 32]).is_err()
                );
            }
            assert!(
                normalize(
                    std::slice::from_ref(&path),
                    dummy.root,
                    &input,
                    None,
                    commitment,
                    [0; 32],
                )
                .is_err()
            );
            assert!(
                normalize(
                    &[path.clone(), dummy.clone()],
                    path.root,
                    &input,
                    Some(&input),
                    commitment,
                    commitment,
                )
                .is_err()
            );
        }
        let transfer_input = super::ConfidentialTransferInputV2 {
            amount: input.amount,
            rho: input.rho,
            diversifier: input.diversifier,
            leaf_index: input.leaf_index,
        };
        let (actual, absent) = super::normalize_confidential_transfer_paths_v3(
            std::slice::from_ref(&path),
            path.root,
            &transfer_input,
            None,
            commitment,
            [0; 32],
        )
        .expect("one-note transfer needs no empty leaf in a full tree");
        assert_eq!(actual.root, path.root);
        assert_eq!(absent.root, dummy.root);
        assert!(
            super::normalize_confidential_transfer_paths_v3(
                &[path.clone(), dummy],
                path.root,
                &transfer_input,
                None,
                commitment,
                [0; 32],
            )
            .is_err()
        );
    }

    #[test]
    fn tree_list_optional_input_accepts_full_capacity_without_empty_membership() {
        let tree = vec![scalar_bytes(7); super::CONFIDENTIAL_TREE_CAPACITY_V2];
        super::reset_confidential_commitment_leaf_hash_calls_v3();
        let absent = super::confidential_optional_input_path_v3(&tree, None)
            .expect("a full populated tree still allows an absent second input");
        assert_eq!(absent.root, super::poseidon_empty_root_v2());
        assert_eq!(super::confidential_commitment_leaf_hash_calls_v3(), 0);
        assert!(super::confidential_optional_input_path_v3(&tree, Some(tree.len())).is_err());
        assert_eq!(super::confidential_commitment_leaf_hash_calls_v3(), 0);
        let present = super::confidential_optional_input_path_v3(&tree[..1], Some(0))
            .expect("a present input resolves its actual tree membership");
        assert_eq!(
            present.root,
            super::compute_confidential_root_v2(&tree[..1]).unwrap()
        );
        assert_ne!(present.root, absent.root);
    }

    #[test]
    fn tree_builders_reject_impossible_public_shapes_before_hashing_or_keys() {
        let network = network_id("tree-shape-preflight");
        let key = iroha_data_model::proof::VerifyingKeyBox::new(
            crate::ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
            Vec::new(),
        );
        let transfer_output = super::ConfidentialTransferOutputV2 {
            amount: 1,
            rho: [1; 32],
            owner_tag: scalar_bytes(1),
        };
        let check = |result: Result<(), String>, expected: &str| {
            let error =
                result.expect_err("public shape must reject before the invalid verifier key");
            assert!(error.contains(expected), "unexpected error: {error}");
            assert_eq!(super::confidential_commitment_leaf_hash_calls_v3(), 0);
        };
        for (tree_len, indices, expected) in [
            (
                super::CONFIDENTIAL_TREE_CAPACITY_V2,
                vec![],
                "one or two inputs",
            ),
            (
                super::CONFIDENTIAL_TREE_CAPACITY_V2,
                vec![0, 1, 2],
                "one or two inputs",
            ),
            (super::CONFIDENTIAL_TREE_CAPACITY_V2 + 1, vec![0], "at most"),
            (1, vec![1], "leaf_index"),
        ] {
            let tree = vec![scalar_bytes(7); tree_len];
            let transfer_inputs: Vec<_> = indices
                .iter()
                .map(|&leaf_index| super::ConfidentialTransferInputV2 {
                    amount: 1,
                    rho: [1; 32],
                    diversifier: scalar_bytes(1),
                    leaf_index,
                })
                .collect();
            let unshield_inputs: Vec<_> = indices
                .iter()
                .map(|&leaf_index| super::ConfidentialUnshieldInputV2 {
                    amount: 1,
                    rho: [1; 32],
                    diversifier: scalar_bytes(1),
                    leaf_index,
                })
                .collect();
            super::reset_confidential_commitment_leaf_hash_calls_v3();
            check(
                super::build_confidential_transfer_proof_v2(
                    &network,
                    "asset",
                    &[1; 32],
                    &tree,
                    &transfer_inputs,
                    std::slice::from_ref(&transfer_output),
                    [0; 32],
                    super::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
                    &key,
                )
                .map(|_| ()),
                expected,
            );
            check(
                super::build_confidential_unshield_proof_v2(
                    &network,
                    "asset",
                    &[1; 32],
                    &tree,
                    &unshield_inputs,
                    1,
                    [0; 32],
                    super::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID,
                    &key,
                )
                .map(|_| ()),
                expected,
            );
            check(
                super::build_confidential_unshield_proof_v3(
                    &network,
                    "asset",
                    &[1; 32],
                    &tree,
                    &unshield_inputs,
                    &[],
                    1,
                    [0; 32],
                    super::CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID,
                    &key,
                )
                .map(|_| ()),
                expected,
            );
        }
        let transfer_input = super::ConfidentialTransferInputV2 {
            amount: 1,
            rho: [1; 32],
            diversifier: scalar_bytes(1),
            leaf_index: 0,
        };
        let tree = [scalar_bytes(7)];
        for outputs in [vec![], vec![transfer_output; 3]] {
            check(
                super::build_confidential_transfer_proof_v2(
                    &network,
                    "asset",
                    &[1; 32],
                    &tree,
                    std::slice::from_ref(&transfer_input),
                    &outputs,
                    [0; 32],
                    super::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
                    &key,
                )
                .map(|_| ()),
                "one or two outputs",
            );
        }
        let unshield_input = super::ConfidentialUnshieldInputV2 {
            amount: 1,
            rho: [1; 32],
            diversifier: scalar_bytes(1),
            leaf_index: 0,
        };
        let outputs = vec![
            super::ConfidentialUnshieldOutputV3 {
                amount: 1,
                rho: [1; 32]
            };
            2
        ];
        check(
            super::build_confidential_unshield_proof_v3(
                &network,
                "asset",
                &[1; 32],
                &tree,
                &[unshield_input],
                &outputs,
                1,
                [0; 32],
                super::CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID,
                &key,
            )
            .map(|_| ()),
            "at most one private change output",
        );
    }

    fn assert_redacted_debug(value: &dyn core::fmt::Debug, name: &str) {
        for rendered in [format!("{value:?}"), format!("{value:#?}")] {
            let fields = rendered.strip_prefix(name).expect("type name is retained");
            assert!(fields.contains(".."), "debug must indicate omitted fields");
            assert!(
                fields
                    .bytes()
                    .all(|byte| matches!(byte, b' ' | b'\n' | b'{' | b'}' | b'.')),
                "secret debug must expose only its type and an omission marker",
            );
        }
    }
    #[test]
    fn confidential_merkle_path_debug_redacts_private_authentication_data() {
        let path = super::ConfidentialMerklePathV2 {
            siblings: vec![[0xA5; 32]],
            directions: vec![1],
            witness_nodes: vec![[0xB6; 32]],
            root: [0xC7; 32],
        };
        assert_redacted_debug(&path, "ConfidentialMerklePathV2");
    }
    #[test]
    fn confidential_opening_debug_redacts_amounts_nonces_and_ownership() {
        let transfer_input = super::ConfidentialTransferInputV2 {
            amount: 123_456_789,
            rho: [0xA5; 32],
            diversifier: [0xB6; 32],
            leaf_index: 37,
        };
        let transfer_output = super::ConfidentialTransferOutputV2 {
            amount: 987_654_321,
            rho: [0xC7; 32],
            owner_tag: [0xD8; 32],
        };
        let unshield_input = super::ConfidentialUnshieldInputV2 {
            amount: 234_567_891,
            rho: [0xE9; 32],
            diversifier: [0xFA; 32],
            leaf_index: 53,
        };
        let unshield_output = super::ConfidentialUnshieldOutputV3 {
            amount: 345_678_912,
            rho: [0xAB; 32],
        };
        let private_values: [(&dyn core::fmt::Debug, &str); 4] = [
            (&transfer_input, "ConfidentialTransferInputV2"),
            (&transfer_output, "ConfidentialTransferOutputV2"),
            (&unshield_input, "ConfidentialUnshieldInputV2"),
            (&unshield_output, "ConfidentialUnshieldOutputV3"),
        ];
        for (value, name) in private_values {
            assert_redacted_debug(value, name);
        }
        let public = super::ConfidentialUnshieldProofV2 {
            nullifiers: vec![[0xBC; 32]],
            root: [0xCD; 32],
            proof: iroha_data_model::proof::ProofBox::new(
                crate::ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
                vec![0xDE],
            ),
        };
        let public_debug = format!("{public:?}");
        for field in ["nullifiers", "root", "proof"] {
            assert!(
                public_debug.contains(field),
                "public proof output remains inspectable"
            );
        }
    }

    fn network_id(seed: impl AsRef<[u8]>) -> iroha_data_model::NetworkId {
        iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::new(seed)
        ))
    }
    fn schema_public_input_order(schema: &[u8]) -> Vec<String> {
        let value: norito::json::Value =
            norito::json::from_slice(schema).expect("public-input schema must be valid JSON");
        let norito::json::Value::Object(fields) = value else {
            panic!("public-input schema must be a JSON object");
        };
        fields
            .get("public_inputs")
            .and_then(norito::json::Value::as_array)
            .expect("public-input schema must carry a public_inputs array")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("public-input column names must be strings")
                    .to_owned()
            })
            .collect()
    }
    #[test]
    fn unshield_named_binding_orders_match_pinned_schemas() {
        for (schema, assigned_order) in [
            (
                super::CONFIDENTIAL_UNSHIELD_V2_PUBLIC_INPUTS_SCHEMA_V1,
                super::CONFIDENTIAL_UNSHIELD_V2_PUBLIC_INPUT_ORDER_V1,
            ),
            (
                super::CONFIDENTIAL_UNSHIELD_V3_PUBLIC_INPUTS_SCHEMA_V1,
                super::CONFIDENTIAL_UNSHIELD_V3_PUBLIC_INPUT_ORDER_V1,
            ),
        ] {
            let schema_order = schema_public_input_order(schema);
            assert!(
                schema_order
                    .iter()
                    .map(String::as_str)
                    .eq(assigned_order.iter().copied()),
                "named circuit binding order drifted from the authenticated schema"
            );
        }
    }
    #[test]
    fn public_input_extraction_requires_exact_native_outer_and_nested_layout() {
        use iroha_data_model::zk::{BackendTag, NativePipaRProofV1, OpenVerifyEnvelope};
        let wrapper = NativePipaRProofV1 {
            public_inputs: (1_u64..=9).map(scalar_bytes).collect(),
            proof: vec![0xA5; super::native::proof_length(super::native::Kind::Transfer).unwrap()],
        };
        let envelope = OpenVerifyEnvelope {
            backend: BackendTag::NativePipaRPasta,
            circuit_id: super::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID.into(),
            vk_hash: [0x42; 32],
            public_inputs: super::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1.to_vec(),
            proof_bytes: norito::encode_canonical(&wrapper).unwrap(),
            aux: vec![],
        };
        let encoded = norito::encode_canonical(&envelope).unwrap();
        assert_eq!(
            super::parse_transfer_public_inputs(&encoded).unwrap().0[0],
            scalar_bytes(1)
        );
        let flags = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate_outer = {
            let _guard = norito::core::DecodeFlagsGuard::enter(flags);
            norito::to_bytes(&envelope).unwrap()
        };
        norito::decode_from_bytes::<OpenVerifyEnvelope>(&alternate_outer).unwrap();
        assert!(super::parse_transfer_public_inputs(&alternate_outer).is_err());
        let alternate_nested = {
            let _guard = norito::core::DecodeFlagsGuard::enter(flags);
            norito::to_bytes(&wrapper).unwrap()
        };
        norito::decode_from_bytes::<NativePipaRProofV1>(&alternate_nested).unwrap();
        let mut bad = envelope.clone();
        bad.proof_bytes = alternate_nested;
        assert!(
            super::parse_transfer_public_inputs(&norito::encode_canonical(&bad).unwrap()).is_err()
        );
        assert!(super::parse_transfer_public_inputs(&envelope.proof_bytes).is_err());
        assert!(super::parse_transfer_public_inputs(b"ZK1\0").is_err());
        for change in 0..6 {
            let mut bad = envelope.clone();
            let mut inner = wrapper.clone();
            match change {
                0 => inner.public_inputs.push(scalar_bytes(10)),
                1 => inner.public_inputs[0] = [255; 32],
                2 => {
                    inner.proof.pop();
                }
                3 => {
                    inner.proof = b"ZK1\0PROF\x00\x00\x00\x00".to_vec();
                }
                4 => {
                    bad.backend = BackendTag::Stark;
                }
                _ => {
                    bad.circuit_id = super::CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID.into();
                }
            }
            bad.proof_bytes = norito::encode_canonical(&inner).unwrap();
            assert!(
                super::parse_transfer_public_inputs(&norito::encode_canonical(&bad).unwrap())
                    .is_err(),
                "mutation{change}"
            );
        }
    }
    fn scalar_bytes(value: u64) -> [u8; 32] {
        use ff::PrimeField as _;
        use iroha_pasta::Fp;
        Fp::from(value)
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Pallas scalar representation")
    }
    fn dense_confidential_tree_layers_v3_reference(
        commitments: &[[u8; 32]],
        tree_width: usize,
        empty_leaf: super::Scalar,
    ) -> Vec<Vec<super::Scalar>> {
        assert!(tree_width.is_power_of_two());
        assert!(commitments.len() <= tree_width);
        let mut layers = vec![
            (0..tree_width)
                .map(|index| {
                    commitments.get(index).map_or(empty_leaf, |commitment| {
                        super::confidential_commitment_leaf_v3(*commitment, index)
                            .expect("canonical reference commitment")
                    })
                })
                .collect::<Vec<_>>(),
        ];
        while layers.last().expect("dense reference leaf layer").len() > 1 {
            let next = layers
                .last()
                .expect("dense reference layer")
                .chunks_exact(2)
                .map(|pair| super::merkle_parent_v3(pair[0], pair[1]))
                .collect();
            layers.push(next);
        }
        layers
    }
    #[test]
    fn canonical_empty_root_constant_matches_poseidon_profile() {
        let computed = super::scalar_to_repr_bytes(
            super::confidential_empty_subtree_roots_v3()[super::CONFIDENTIAL_TREE_DEPTH_V2],
        );
        assert_eq!(
            computed,
            iroha_data_model::zk::CONFIDENTIAL_TREE_POSEIDON_PASTA_V1_EMPTY_ROOT
        );
        assert_eq!(super::poseidon_empty_root_v2(), computed);
        assert_eq!(
            super::compute_confidential_root_v2(&[]).expect("empty profile root"),
            computed
        );
    }
    #[test]
    fn incremental_prefix_roots_match_recursive_profile() {
        let commitments = (1_u64..=64).map(scalar_bytes).collect::<Vec<_>>();
        let prefix_roots = super::compute_confidential_prefix_roots_v2(&commitments)
            .expect("canonical prefix roots");
        let empty_roots = super::confidential_empty_subtree_roots_v3();
        for prefix_len in 1..=commitments.len() {
            let recursive = super::confidential_subtree_root_v3(
                &commitments[..prefix_len],
                0,
                super::CONFIDENTIAL_TREE_DEPTH_V2,
                &empty_roots,
            )
            .map(super::scalar_to_repr_bytes)
            .expect("recursive profile root");
            assert_eq!(prefix_roots[prefix_len - 1], recursive);
        }
    }
    #[test]
    fn sparse_confidential_subtree_roots_match_dense_reference() {
        let all_commitments = (1_u64..=64).map(scalar_bytes).collect::<Vec<_>>();
        let empty_roots = super::confidential_empty_subtree_roots_v3();
        for len in [0_usize, 1, 2, 3, 7, 16, 37, 64] {
            let commitments = &all_commitments[..len];
            let dense_layers = dense_confidential_tree_layers_v3_reference(
                commitments,
                all_commitments.len(),
                empty_roots[0],
            );
            for height in 0..=6 {
                let width = 1_usize << height;
                for start in (0..64).step_by(width) {
                    let sparse = super::confidential_subtree_root_v3(
                        commitments,
                        start,
                        height,
                        &empty_roots,
                    )
                    .expect("sparse subtree root");
                    let dense = dense_layers[height][start / width];
                    assert_eq!(sparse, dense, "len={len} start={start} height={height}");
                }
            }
        }
    }
    #[test]
    fn compact_projection_matches_legacy_paths_and_incremental_frontier() {
        let commitments = (1_u64..=64).map(scalar_bytes).collect::<Vec<_>>();
        let projection = super::ConfidentialTreeProjectionV2::build(&commitments)
            .expect("compact confidential projection");
        let prefix_roots = super::compute_confidential_prefix_roots_v2(&commitments)
            .expect("canonical prefix roots");
        assert_eq!(projection.root(), prefix_roots[commitments.len() - 1]);
        let append = super::append_confidential_tree_frontier_v2(
            0,
            [None; super::CONFIDENTIAL_TREE_DEPTH_V2],
            super::poseidon_empty_root_v2(),
            &commitments,
        )
        .expect("incremental append");
        assert_eq!(
            projection.frontier().expect("projection frontier"),
            append.frontier
        );
        assert_eq!(projection.root(), append.current_root);
        assert_eq!(append.appended_roots, prefix_roots);
        for leaf_index in [0_usize, 1, 2, 31, 63, 64] {
            let projected = projection
                .compute_path(leaf_index)
                .expect("projected authentication path");
            let legacy = super::compute_confidential_merkle_path_v3(&commitments, leaf_index)
                .expect("legacy authentication path");
            assert_eq!(projected.siblings, legacy.siblings);
            assert_eq!(projected.directions, legacy.directions);
            assert_eq!(projected.witness_nodes, legacy.witness_nodes);
            assert_eq!(projected.root, legacy.root);
        }
    }
    #[test]
    fn incremental_frontier_preserves_prefix_shape_and_full_tree_transition() {
        let commitments = (1_u64..=3).map(scalar_bytes).collect::<Vec<_>>();
        let expected_roots = super::compute_confidential_prefix_roots_v2(&commitments)
            .expect("canonical prefix roots");
        let mut frontier = [None; super::CONFIDENTIAL_TREE_DEPTH_V2];
        let mut current_root = super::poseidon_empty_root_v2();
        for (index, commitment) in commitments.iter().enumerate() {
            let append = super::append_confidential_tree_frontier_v2(
                index,
                frontier,
                current_root,
                core::slice::from_ref(commitment),
            )
            .expect("single prefix append");
            frontier = append.frontier;
            current_root = append.current_root;
            assert_eq!(append.appended_roots.as_slice(), &[expected_roots[index]]);
            let projection = super::ConfidentialTreeProjectionV2::build(&commitments[..=index])
                .expect("canonical prefix projection");
            assert_eq!(
                frontier,
                projection.frontier().expect("canonical prefix frontier")
            );
            assert_eq!(current_root, projection.root());
            super::validate_confidential_tree_frontier_v2(index + 1, &frontier, current_root)
                .expect("prefix frontier remains self-consistent");
        }
        let full_frontier_scalars: [super::Scalar; super::CONFIDENTIAL_TREE_DEPTH_V2] =
            core::array::from_fn(|level| {
                super::Scalar::from(u64::try_from(level + 1).expect("tree level fits u64"))
            });
        let full_frontier =
            full_frontier_scalars.map(|node| Some(super::scalar_to_repr_bytes(node)));
        let empty_roots = super::confidential_empty_subtree_roots_v3();
        let mut prior_root = empty_roots[0];
        for left in full_frontier_scalars {
            prior_root = super::merkle_parent_v3(left, prior_root);
        }
        let final_commitment = scalar_bytes(0xA5);
        let mut expected_full_root = super::confidential_commitment_leaf_v3(
            final_commitment,
            super::CONFIDENTIAL_TREE_CAPACITY_V2 - 1,
        )
        .expect("canonical final commitment");
        for left in full_frontier_scalars {
            expected_full_root = super::merkle_parent_v3(left, expected_full_root);
        }
        let expected_full_root = super::scalar_to_repr_bytes(expected_full_root);
        let full = super::append_confidential_tree_frontier_v2(
            super::CONFIDENTIAL_TREE_CAPACITY_V2 - 1,
            full_frontier,
            super::scalar_to_repr_bytes(prior_root),
            &[final_commitment],
        )
        .expect("final-capacity append");
        assert!(full.frontier.iter().all(Option::is_none));
        assert_eq!(full.current_root, expected_full_root);
        assert_eq!(full.appended_roots.as_slice(), &[expected_full_root]);
        super::validate_confidential_tree_frontier_v2(
            super::CONFIDENTIAL_TREE_CAPACITY_V2,
            &full.frontier,
            full.current_root,
        )
        .expect("full tree retains its separately persisted root");
    }
    #[test]
    fn compact_projection_hashes_each_commitment_once_for_many_paths() {
        let commitments = (1_u64..=128).map(scalar_bytes).collect::<Vec<_>>();
        let expected_root =
            super::compute_confidential_root_v2(&commitments).expect("canonical confidential root");
        super::reset_confidential_commitment_leaf_hash_calls_v3();
        let projection = super::ConfidentialTreeProjectionV2::build(&commitments)
            .expect("compact confidential projection");
        assert_eq!(
            super::confidential_commitment_leaf_hash_calls_v3(),
            commitments.len(),
            "projection construction must hash each commitment exactly once"
        );
        for leaf_index in 0..=commitments.len() {
            projection
                .compute_path(leaf_index)
                .expect("requested or next-zero authentication path");
        }
        assert_eq!(projection.root(), expected_root);
        assert_eq!(
            super::confidential_commitment_leaf_hash_calls_v3(),
            commitments.len(),
            "path count must not cause another commitment scan"
        );
    }
    #[test]
    fn incremental_frontier_append_work_depends_only_on_batch_and_depth() {
        let commitments = (1_u64..=128).map(scalar_bytes).collect::<Vec<_>>();
        let expected_roots = super::compute_confidential_prefix_roots_v2(&commitments)
            .expect("canonical prefix roots");
        super::reset_confidential_commitment_leaf_hash_calls_v3();
        super::reset_confidential_frontier_append_parent_hash_calls_v2();
        let append = super::append_confidential_tree_frontier_v2(
            0,
            [None; super::CONFIDENTIAL_TREE_DEPTH_V2],
            super::poseidon_empty_root_v2(),
            &commitments,
        )
        .expect("incremental append");
        assert_eq!(append.appended_roots, expected_roots);
        assert_eq!(
            super::confidential_commitment_leaf_hash_calls_v3(),
            commitments.len()
        );
        assert_eq!(
            super::confidential_frontier_append_parent_hash_calls_v2(),
            commitments.len() * super::CONFIDENTIAL_TREE_DEPTH_V2
        );
        super::validate_confidential_tree_frontier_v2(
            commitments.len(),
            &append.frontier,
            append.current_root,
        )
        .expect("appended frontier remains self-consistent");
    }
    #[test]
    fn production_circuit_selectors_reject_noncanonical_aliases() {
        let selectors: [(&str, fn(&str) -> bool); 3] = [
            (
                super::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
                super::is_confidential_transfer_v2_circuit_id,
            ),
            (
                super::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID,
                super::is_confidential_unshield_v2_circuit_id,
            ),
            (
                super::CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID,
                super::is_confidential_unshield_v3_circuit_id,
            ),
        ];
        for (canonical, accepts) in selectors {
            assert!(accepts(canonical));
            assert!(!accepts(&format!(" {canonical}")));
            assert!(!accepts(&format!("{canonical} ")));
            let bare = canonical
                .strip_prefix("pipa-r/pasta/")
                .expect("production circuit IDs use the canonical native prefix");
            assert!(!accepts(bare));
            assert!(!accepts(&format!("halo2/pasta/{bare}")));
        }
    }
    #[test]
    fn retired_single_expression_poseidon_pair_has_constructive_collisions() {
        use ff::Field;
        use iroha_pasta::{Fp, Fq};
        fn fifth_power<F: Field>(value: F) -> F {
            let square = value.square();
            square.square() * value
        }
        fn broken_pair<F>(lhs: F, rhs: F) -> F
        where
            F: Field + From<u64>,
        {
            F::from(2) * fifth_power(lhs + F::from(7)) + F::from(3) * fifth_power(rhs + F::from(13))
        }
        fn assert_constructive_collision<F>(inverse_five: [u64; 4])
        where
            F: Field + From<u64> + PartialEq + core::fmt::Debug,
        {
            let lhs = F::from(5);
            let rhs = F::from(9);
            let replacement_shifted_rhs = F::from(31);
            let shifted_lhs = lhs + F::from(7);
            let shifted_rhs = rhs + F::from(13);
            let half = F::from(2).invert().unwrap();
            let replacement_shifted_lhs_fifth = fifth_power(shifted_lhs)
                + F::from(3)
                    * half
                    * (fifth_power(shifted_rhs) - fifth_power(replacement_shifted_rhs));
            let replacement_shifted_lhs = replacement_shifted_lhs_fifth.pow_vartime(inverse_five);
            let replacement = (
                replacement_shifted_lhs - F::from(7),
                replacement_shifted_rhs - F::from(13),
            );
            assert_ne!((lhs, rhs), replacement);
            assert_eq!(
                broken_pair(lhs, rhs),
                broken_pair(replacement.0, replacement.1)
            );
        }
        assert_constructive_collision::<Fp>([
            0xe0f0_f3f0_cccc_cccd,
            0x4e9e_e0c9_a10a_60e2,
            0x3333_3333_3333_3333,
            0x3333_3333_3333_3333,
        ]);
        assert_constructive_collision::<Fq>([
            0xd69f_2280_cccc_cccd,
            0x4e9e_e0c9_a143_ba4a,
            0x3333_3333_3333_3333,
            0x3333_3333_3333_3333,
        ]);
    }
    #[test]
    fn native_confidential_poseidon_matches_captured_oracle_on_both_pasta_fields() {
        let fixture: norito::json::Value = norito::json::from_str(include_str!(
            "../../../fixtures/native_prover/confidential_poseidon_v1.json"
        ))
        .expect("captured independent oracle vectors");
        assert_eq!(
            fixture.get("schema").and_then(norito::json::Value::as_str),
            Some("iroha.native_prover.confidential_poseidon.v1")
        );
        fn check<F: iroha_pasta::poseidon::PoseidonField>(
            fixture: &norito::json::Value,
            field: &str,
        ) {
            let outputs = fixture.get("fields").unwrap().get(field).unwrap();
            let domain_outputs = outputs.get("domain_outputs").unwrap().as_array().unwrap();
            let uses = [
                (super::CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3, &[3, 5][..]),
                (super::CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3, &[3, 5, 8, 13]),
                (
                    super::CONFIDENTIAL_POSEIDON_NULLIFIER_DOMAIN_V3,
                    &[3, 5, 8, 13],
                ),
                (super::CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3, &[3]),
                (super::CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3, &[3, 5]),
                (super::CONFIDENTIAL_POSEIDON_ASSET_DOMAIN_V3, &[3]),
                (super::CONFIDENTIAL_POSEIDON_NETWORK_DOMAIN_V3, &[3]),
            ];
            let cases = fixture.get("domain_cases").unwrap().as_array().unwrap();
            assert_eq!(cases.len(), uses.len());
            assert_eq!(domain_outputs.len(), uses.len());
            for (index, (domain, inputs)) in uses.into_iter().enumerate() {
                assert_eq!(
                    cases[index]
                        .get("tag")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .as_bytes(),
                    domain.to_le_bytes()
                );
                assert_eq!(
                    cases[index]
                        .get("inputs")
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap())
                        .collect::<Vec<_>>(),
                    inputs
                );
                let native = super::confidential_poseidon_hash_v3(
                    domain,
                    &inputs.iter().copied().map(F::from).collect::<Vec<_>>(),
                );
                assert_eq!(
                    hex::encode(native.to_repr()),
                    domain_outputs[index].as_str().unwrap(),
                    "{field} domain={domain:#018x}"
                );
            }
            let domains = [0, u64::MAX, super::CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3];
            assert_eq!(
                fixture
                    .get("boundary_domains")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap())
                    .collect::<Vec<_>>(),
                domains
            );
            let boundary_outputs = outputs.get("boundary_outputs").unwrap().as_array().unwrap();
            assert_eq!(boundary_outputs.len(), 34);
            // Preserve the full pre-retirement differential corpus: all seven
            // domains plus empty/even/odd framing and modulus-boundary inputs.
            for (len, expected) in boundary_outputs.iter().enumerate() {
                let expected = expected.as_array().unwrap();
                assert_eq!(expected.len(), domains.len());
                let inputs: Vec<_> = (0..len)
                    .map(|i| match i % 4 {
                        0 => F::ZERO,
                        1 => F::ONE,
                        2 => -F::ONE,
                        _ => F::from(i as u64),
                    })
                    .collect();
                for (index, domain) in domains.into_iter().enumerate() {
                    assert_eq!(
                        hex::encode(
                            super::confidential_poseidon_hash_v3(domain, &inputs).to_repr()
                        ),
                        expected[index].as_str().unwrap(),
                        "{field} len={len} domain={domain:#018x}"
                    );
                }
            }
        }
        check::<iroha_pasta::Fp>(&fixture, "fp");
        check::<iroha_pasta::Fq>(&fixture, "fq");
    }
    #[test]
    fn secure_confidential_poseidon_kats_pin_both_pasta_fields_and_domains() {
        use iroha_pasta::{Fp, Fq};
        fn repr<F>(domain: u64) -> [u8; 32]
        where
            F: iroha_pasta::poseidon::PoseidonField,
        {
            repr_inputs::<F>(domain, &[3, 5, 8, 13])
        }
        fn repr_inputs<F>(domain: u64, inputs: &[u64]) -> [u8; 32]
        where
            F: iroha_pasta::poseidon::PoseidonField,
        {
            let inputs = inputs.iter().copied().map(F::from).collect::<Vec<_>>();
            let value = super::confidential_poseidon_hash_v3(domain, &inputs);
            value
                .to_repr()
                .as_ref()
                .try_into()
                .expect("32-byte Pasta repr")
        }
        fn hex32(value: &str) -> [u8; 32] {
            assert_eq!(value.len(), 64);
            std::array::from_fn(|index| {
                u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                    .expect("valid KAT hex byte")
            })
        }
        let vectors = [
            (
                super::CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3,
                [
                    0xce, 0x9c, 0x57, 0xdb, 0x56, 0x29, 0x51, 0xd1, 0xdd, 0x72, 0xe8, 0x34, 0xbf,
                    0xac, 0xcc, 0x74, 0xa9, 0xe2, 0x5f, 0x5c, 0xa2, 0xc1, 0xcd, 0x7d, 0xa1, 0xec,
                    0x5c, 0x3c, 0xaf, 0x45, 0x45, 0x3d,
                ],
                [
                    0x83, 0x82, 0xed, 0x00, 0xbb, 0x4b, 0xcb, 0xf7, 0x7d, 0x0c, 0x9b, 0xcc, 0x8e,
                    0xf1, 0x22, 0xac, 0x6f, 0x67, 0xa8, 0x8f, 0x68, 0xce, 0x46, 0x51, 0xce, 0x23,
                    0x7b, 0x67, 0x33, 0x4a, 0x65, 0x30,
                ],
            ),
            (
                super::CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
                [
                    0xcd, 0xb8, 0x44, 0xf8, 0xa4, 0x78, 0xeb, 0xf3, 0x14, 0x54, 0x6c, 0xc9, 0xa8,
                    0x14, 0x5b, 0xbc, 0xa0, 0x5b, 0x42, 0x21, 0xa3, 0x1a, 0x9c, 0xee, 0x2a, 0x34,
                    0xa6, 0xb2, 0xd8, 0x98, 0x86, 0x2c,
                ],
                [
                    0x22, 0x2f, 0xe8, 0xdf, 0xb1, 0x1b, 0x68, 0xb9, 0x38, 0x47, 0xd2, 0x86, 0x94,
                    0xdb, 0x28, 0xc5, 0x63, 0x6c, 0x5b, 0xbf, 0x78, 0xa7, 0xb7, 0xdb, 0x73, 0xc6,
                    0x2b, 0x3e, 0x38, 0x9a, 0xc0, 0x2d,
                ],
            ),
            (
                super::CONFIDENTIAL_POSEIDON_NULLIFIER_DOMAIN_V3,
                [
                    0x00, 0x76, 0x08, 0x32, 0xfe, 0x2d, 0x8d, 0x60, 0x37, 0x3d, 0x15, 0xeb, 0x76,
                    0x43, 0x6a, 0x21, 0x6d, 0xec, 0x7d, 0xef, 0xaa, 0xf1, 0xda, 0x69, 0xd5, 0x23,
                    0x3c, 0xce, 0x5c, 0x98, 0xab, 0x06,
                ],
                [
                    0xb4, 0x6a, 0x51, 0x8a, 0x68, 0x0c, 0xdf, 0x75, 0x06, 0x9e, 0x35, 0x78, 0x4d,
                    0x7f, 0xd5, 0x80, 0x3c, 0x8d, 0xbf, 0xc1, 0xa3, 0xb8, 0x66, 0xc1, 0xff, 0xd0,
                    0x3a, 0x2b, 0x35, 0xdf, 0x0d, 0x00,
                ],
            ),
            (
                super::CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3,
                [
                    0x66, 0x12, 0x9a, 0x24, 0xba, 0x49, 0x66, 0xae, 0xd5, 0xe6, 0xf5, 0x69, 0x56,
                    0xe8, 0x09, 0x16, 0xd5, 0x07, 0xcf, 0x6a, 0x68, 0xa6, 0xe2, 0x61, 0xb9, 0x2d,
                    0x0a, 0x9f, 0x9d, 0x13, 0x9c, 0x33,
                ],
                [
                    0x34, 0x22, 0xab, 0xe3, 0x43, 0x31, 0x71, 0x93, 0x0e, 0xb6, 0x7c, 0xa9, 0xb4,
                    0xe0, 0x5a, 0xdf, 0x27, 0xf8, 0x23, 0x62, 0xed, 0xe7, 0x8c, 0x8a, 0x65, 0x5e,
                    0x2e, 0x79, 0x85, 0xc0, 0xc5, 0x38,
                ],
            ),
            (
                super::CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3,
                [
                    0xe6, 0x44, 0x99, 0x62, 0xdd, 0xc1, 0xd2, 0x3d, 0x9d, 0x62, 0x94, 0x57, 0x72,
                    0xb9, 0x68, 0x8c, 0xea, 0x4e, 0x03, 0x82, 0x4f, 0x3c, 0xaf, 0x77, 0x3f, 0x3a,
                    0x74, 0x10, 0x4d, 0x4b, 0xb2, 0x34,
                ],
                [
                    0x1e, 0x00, 0xc2, 0xeb, 0xab, 0x3d, 0x5c, 0x05, 0x74, 0xcb, 0xc7, 0xf6, 0x47,
                    0xb5, 0xfe, 0xb4, 0xc4, 0xff, 0x27, 0x1b, 0xd8, 0x4f, 0xb7, 0x7b, 0xbb, 0x0c,
                    0xc0, 0xf3, 0xda, 0x60, 0x70, 0x39,
                ],
            ),
        ];
        for (domain, fp, fq) in vectors {
            assert_eq!(repr::<Fp>(domain), fp);
            assert_eq!(repr::<Fq>(domain), fq);
        }
        for (domain, inputs, fp, fq) in [
            (
                super::CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3,
                &[3, 5][..],
                "612ad09a40970302036fef4c16385a98a7b337143c086d7ec4c0f9fc4792610d",
                "da41767db79387f7bfb20625144da612661c38f7ea94dc3a62f330e9ddbbef10",
            ),
            (
                super::CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
                &[3, 5, 8, 13],
                "cdb844f8a478ebf314546cc9a8145bbca05b4221a31a9cee2a34a6b2d898862c",
                "222fe8dfb11b68b93847d28694db28c5636c5bbf78a7b7db73c62b3e389ac02d",
            ),
            (
                super::CONFIDENTIAL_POSEIDON_NULLIFIER_DOMAIN_V3,
                &[3, 5, 8, 13],
                "00760832fe2d8d60373d15eb76436a216dec7defaaf1da69d5233cce5c98ab06",
                "b46a518a680cdf75069e35784d7fd5803c8dbfc1a3b866c1ffd03a2b35df0d00",
            ),
            (
                super::CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3,
                &[3],
                "75b309c05d81f516d4ceadaca9640d240c24f365453f476db07b4d8e3c943713",
                "a447fb1114387ca98a59cdc3bbc721bdcf6a74b0cfe9ad7ae45125f07538a532",
            ),
            (
                super::CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3,
                &[3, 5],
                "22a66785c01757e9f8b6c401f5e1f08f6649cc52a0083bb452af4378d15b2228",
                "3f39495312f7cdfe4af7346fc00f674709cca1fce1686e2881c708ff5034842a",
            ),
            (
                super::CONFIDENTIAL_POSEIDON_ASSET_DOMAIN_V3,
                &[3],
                "e12530abfe9e4f7c1f95d510191b65c89546e4d9b8e9ed79d3e3521772f02930",
                "45591fdcac6208fef59f1955ef819d2296dab0aeba1023a3813ccf2d4e52eb03",
            ),
            (
                super::CONFIDENTIAL_POSEIDON_NETWORK_DOMAIN_V3,
                &[3],
                "971c0d57fd63afa24ea0d1c6206a4873d7be0b283848eba6fc9fd929d2747d04",
                "569c33f348ee0dd7714f5b10a50f797ada3f0b49f373de606445c0ddb338f737",
            ),
        ] {
            assert_eq!(repr_inputs::<Fp>(domain, inputs), hex32(fp));
            assert_eq!(repr_inputs::<Fq>(domain, inputs), hex32(fq));
        }
    }
    #[test]
    fn confidential_v3_native_derivations_are_domain_separated_and_fail_closed() {
        use std::collections::BTreeSet;
        let asset =
            super::derive_confidential_asset_tag_v3("rose#wonderland").expect("V3 asset tag");
        let exact_network = network_id(b"confidential-v3-domain-separation-network");
        let network = super::derive_confidential_network_tag_v3(&exact_network)
            .expect("V3 exact-network tag");
        assert_eq!(
            BTreeSet::from([asset, network]).len(),
            2,
            "distinct use domains must not alias the same preimage"
        );
        let spend_key = [11; 32];
        let diversifier = super::scalar_to_repr_bytes(super::Scalar::from(13));
        let owner =
            super::derive_confidential_owner_tag_v3_with_diversifier(&spend_key, diversifier)
                .expect("V3 owner");
        let rho = [17; 32];
        let note = super::derive_confidential_note_v3(asset, 19, rho, owner).expect("V3 note");
        let nullifier = super::derive_confidential_nullifier_v3(&spend_key, rho, asset, network)
            .expect("V3 nullifier");
        assert_ne!(note, nullifier);
        assert!(
            super::derive_confidential_owner_tag_v3_with_diversifier(&[0; 32], diversifier)
                .is_err()
        );
        assert!(
            super::derive_confidential_owner_tag_v3_with_diversifier(&spend_key, [0xff; 32])
                .is_err()
        );
        assert!(super::derive_confidential_asset_tag_v3("  ").is_err());
        assert!(super::derive_confidential_asset_tag_v3(" rose#wonderland").is_err());
        let other_network = network_id(b"confidential-v3-other-network");
        assert_ne!(
            network,
            super::derive_confidential_network_tag_v3(&other_network)
                .expect("different exact-network tag")
        );
        assert!(super::derive_confidential_note_v3(asset, 0, rho, owner).is_err());
        assert!(
            super::derive_confidential_nullifier_v3(&spend_key, [0; 32], asset, network).is_err()
        );
    }
    #[test]
    fn generated_confidential_v2_vk_records_parse_as_matching_circuits() {
        let transfer = super::confidential_transfer_v2_vk_record("vk_transfer", 3)
            .expect("transfer vk record");
        let unshield = super::confidential_unshield_v2_vk_record("vk_unshield", 4)
            .expect("unshield vk record");
        let unshield_v3 = super::confidential_unshield_v3_vk_record("vk_unshield_v3", 5)
            .expect("unshield v3 vk record");
        assert_eq!(
            transfer.circuit_id,
            super::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID
        );
        assert_eq!(
            unshield.circuit_id,
            super::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID
        );
        assert_eq!(
            unshield_v3.circuit_id,
            super::CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID
        );
        assert!(transfer.is_active());
        assert!(unshield.is_active());
        assert!(unshield_v3.is_active());
        assert!(transfer.max_proof_bytes > 0);
        assert!(unshield.max_proof_bytes > 0);
        assert!(unshield_v3.max_proof_bytes > 0);
        let transfer_key = transfer.key.as_ref().expect("transfer key");
        let unshield_key = unshield.key.as_ref().expect("unshield key");
        let unshield_v3_key = unshield_v3.key.as_ref().expect("unshield v3 key");
        super::native::validate_key(super::native::Kind::Transfer, transfer_key)
            .expect("transfer key must parse as confidential transfer v2");
        super::native::validate_key(super::native::Kind::Full, unshield_key)
            .expect("unshield key must parse as confidential unshield v2");
        super::native::validate_key(super::native::Kind::Change, unshield_v3_key)
            .expect("unshield v3 key must parse as confidential unshield v3");
    }
    #[test]
    fn supplied_confidential_merkle_path_recomputes_witness_nodes() {
        let commitments = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
        let path =
            super::compute_confidential_merkle_path_v2(&commitments, 2).expect("computed path");
        let mut supplied = path.clone();
        supplied.witness_nodes.clear();
        let normalized = super::normalize_supplied_confidential_merkle_path_v2(
            [0x33; 32],
            Some(2),
            &supplied,
            path.root,
            "test path",
        )
        .expect("supplied path should validate");
        assert_eq!(normalized.root, path.root);
        assert_eq!(normalized.witness_nodes, path.witness_nodes);
        let mut tampered = supplied;
        tampered.directions[0] ^= 1;
        assert!(
            super::normalize_supplied_confidential_merkle_path_v2(
                [0x33; 32],
                Some(2),
                &tampered,
                path.root,
                "test path",
            )
            .is_err()
        );
    }
    #[test]
    fn next_zero_confidential_path_matches_padded_tree_path() {
        for len in 1usize..12 {
            let commitments: Vec<[u8; 32]> = (0..len)
                .map(|index| {
                    let mut commitment = [0u8; 32];
                    commitment[0] = 0x40;
                    commitment[31] = u8::try_from(index + 1).expect("fixture index fits in u8");
                    commitment
                })
                .collect();
            let previous_index = commitments.len() - 1;
            let previous_path =
                super::compute_confidential_merkle_path_v2(&commitments, previous_index)
                    .expect("previous path");
            let expected_next_zero =
                super::compute_confidential_merkle_path_v2(&commitments, commitments.len())
                    .expect("expected zero path");
            let derived = super::derive_confidential_next_zero_path_v2(
                commitments[previous_index],
                previous_index,
                &previous_path,
                previous_path.root,
            )
            .expect("derived next zero path");
            assert_eq!(derived.root, expected_next_zero.root, "len={len}");
            assert_eq!(
                derived.siblings, expected_next_zero.siblings,
                "siblings len={len}"
            );
            assert_eq!(
                derived.directions, expected_next_zero.directions,
                "directions len={len}"
            );
            assert_eq!(
                derived.witness_nodes, expected_next_zero.witness_nodes,
                "witness nodes len={len}"
            );
        }
    }
    #[test]
    fn sequential_append_paths_match_complete_tree_recomputation() {
        for initial_len in 0usize..10 {
            let initial: Vec<[u8; 32]> = (0..initial_len)
                .map(|index| scalar_bytes(u64::try_from(800 + index).expect("fixture fits")))
                .collect();
            for output_count in 1usize..=2 {
                let outputs: Vec<[u8; 32]> = (0..output_count)
                    .map(|index| scalar_bytes(u64::try_from(900 + index).expect("fixture fits")))
                    .collect();
                let initial_frontier =
                    super::compute_confidential_merkle_path_v3(&initial, initial.len())
                        .expect("initial next-zero frontier");
                let derived = super::derive_confidential_sequential_append_paths_v3(
                    initial.len(),
                    &initial_frontier,
                    &outputs,
                )
                .expect("sequential append paths");
                let mut final_commitments = initial.clone();
                final_commitments.extend_from_slice(&outputs);
                let expected_final_root =
                    super::compute_confidential_root_v3(&final_commitments).expect("final root");
                assert_eq!(derived.initial_root, initial_frontier.root);
                assert_eq!(derived.final_root, expected_final_root);
                assert_eq!(derived.leaves.len(), output_count);
                for (offset, leaf) in derived.leaves.iter().enumerate() {
                    let mut before = initial.clone();
                    before.extend_from_slice(&outputs[..offset]);
                    let expected_update =
                        super::compute_confidential_merkle_path_v3(&before, initial.len() + offset)
                            .expect("expected update path");
                    let expected_membership = super::compute_confidential_merkle_path_v3(
                        &final_commitments,
                        initial.len() + offset,
                    )
                    .expect("expected final membership path");
                    assert_eq!(leaf.leaf_index, initial.len() + offset);
                    assert_eq!(leaf.update_path.root, expected_update.root);
                    assert_eq!(leaf.update_path.siblings, expected_update.siblings);
                    assert_eq!(leaf.update_path.directions, expected_update.directions);
                    assert_eq!(leaf.membership_path.root, expected_membership.root);
                    assert_eq!(leaf.membership_path.siblings, expected_membership.siblings);
                    assert_eq!(
                        leaf.membership_path.directions,
                        expected_membership.directions
                    );
                }
                let expected_frontier = super::compute_confidential_merkle_path_v3(
                    &final_commitments,
                    final_commitments.len(),
                )
                .expect("expected final frontier");
                assert_eq!(derived.next_zero_leaf_index, final_commitments.len());
                assert_eq!(derived.next_zero_path.root, expected_frontier.root);
                assert_eq!(derived.next_zero_path.siblings, expected_frontier.siblings);
                assert_eq!(
                    derived.next_zero_path.directions,
                    expected_frontier.directions
                );
            }
        }
    }
    #[test]
    fn sequential_append_paths_reject_tamper_and_invalid_cardinality() {
        let commitments = vec![scalar_bytes(1001), scalar_bytes(1002)];
        let frontier = super::compute_confidential_merkle_path_v3(&commitments, commitments.len())
            .expect("frontier");
        let output = scalar_bytes(1003);
        let mut wrong_root = frontier.clone();
        wrong_root.root[0] ^= 1;
        assert!(
            super::derive_confidential_sequential_append_paths_v3(
                commitments.len(),
                &wrong_root,
                &[output],
            )
            .is_err()
        );
        let mut wrong_direction = frontier.clone();
        wrong_direction.directions[0] ^= 1;
        assert!(
            super::derive_confidential_sequential_append_paths_v3(
                commitments.len(),
                &wrong_direction,
                &[output],
            )
            .is_err()
        );
        assert!(
            super::derive_confidential_sequential_append_paths_v3(
                commitments.len(),
                &frontier,
                &[],
            )
            .is_err()
        );
        assert!(
            super::derive_confidential_sequential_append_paths_v3(
                commitments.len(),
                &frontier,
                &[output, scalar_bytes(1004), scalar_bytes(1005)],
            )
            .is_err()
        );
        assert!(
            super::derive_confidential_sequential_append_paths_v3(
                commitments.len(),
                &frontier,
                &[[0; 32]],
            )
            .is_err()
        );
    }
    #[test]
    fn canonical_unshield_vk_digests_match_reviewed_goldens() {
        let full = super::confidential_unshield_v2_vk_box().expect("canonical full-unshield vk");
        let change =
            super::confidential_unshield_v3_vk_box().expect("canonical change-unshield vk");
        assert_eq!(
            [
                hex::encode(crate::hash_vk(&full)),
                hex::encode(crate::hash_vk(&change)),
            ],
            [
                hex::encode(super::CONFIDENTIAL_UNSHIELD_V2_VK_DIGEST_V1),
                hex::encode(super::CONFIDENTIAL_UNSHIELD_V3_VK_DIGEST_V1),
            ],
            "canonical verifier-key layout changed; review the circuit/schema version before updating these goldens",
        );
    }
    #[test]
    fn confidential_transfer_v2_canonical_vk_guard_rejects_self_consistent_key_substitution() {
        use iroha_data_model::proof::VerifyingKeyBox;
        let canonical = super::confidential_transfer_v2_vk_box().expect("canonical transfer vk");
        let cached = super::confidential_transfer_v2_vk_box().expect("cached transfer vk");
        assert_eq!(
            canonical, cached,
            "confidential transfer v2 verifier key generation should be cached and deterministic"
        );
        super::ensure_confidential_transfer_v2_canonical_vk_box(&canonical)
            .expect("canonical transfer verifier key should pass");
        let mut mutated = canonical.clone();
        let last = mutated
            .bytes
            .last_mut()
            .expect("canonical transfer verifier key bytes");
        *last ^= 0x01;
        let err = super::ensure_confidential_transfer_v2_canonical_vk_box(&mutated)
            .expect_err("mutated self-consistent verifier key must reject");
        assert!(
            err.contains("foreign native confidential compiled key"),
            "unexpected mutated-key error: {err}"
        );
        let wrong_backend =
            VerifyingKeyBox::new("halo2/ipa:kzg".to_owned(), canonical.bytes.clone());
        let err = super::ensure_confidential_transfer_v2_canonical_vk_box(&wrong_backend)
            .expect_err("wrong backend must reject before canonical bytes are considered");
        assert!(err.contains("backend"), "unexpected backend error: {err}");
        let empty = VerifyingKeyBox::new(crate::ZK_BACKEND_NATIVE_PIPA_R.to_owned(), Vec::new());
        let err = super::ensure_confidential_transfer_v2_canonical_vk_box(&empty)
            .expect_err("empty verifier key must reject");
        assert!(err.contains("length"), "unexpected empty-key error: {err}");
    }
    #[test]
    fn confidential_transfer_v2_canonical_vk_guard_rejects_malformed_key_preflight() {
        use iroha_data_model::proof::VerifyingKeyBox;
        let malformed =
            VerifyingKeyBox::new(crate::ZK_BACKEND_NATIVE_PIPA_R.to_owned(), vec![0xC9; 32]);
        let err = super::ensure_confidential_transfer_v2_canonical_vk_box(&malformed)
            .expect_err("malformed verifier key must reject before canonical key generation");
        assert!(
            err.contains("compiled key"),
            "unexpected malformed-key error: {err}"
        );
    }
    #[test]
    fn confidential_unshield_v2_v3_canonical_caches_reject_key_substitution() {
        use iroha_data_model::proof::VerifyingKeyBox;
        let v2 = super::confidential_unshield_v2_vk_box().expect("canonical unshield v2 vk");
        let v2_cached = super::confidential_unshield_v2_vk_box().expect("cached unshield v2 vk");
        assert_eq!(v2, v2_cached);
        super::ensure_confidential_unshield_v2_canonical_vk_box(&v2)
            .expect("canonical unshield v2 verifier key should pass");
        let v3 = super::confidential_unshield_v3_vk_box().expect("canonical unshield v3 vk");
        let v3_cached = super::confidential_unshield_v3_vk_box().expect("cached unshield v3 vk");
        assert_eq!(v3, v3_cached);
        super::ensure_confidential_unshield_v3_canonical_vk_box(&v3)
            .expect("canonical unshield v3 verifier key should pass");
        fn assert_rejects_key_substitution(
            label: &str,
            canonical: &VerifyingKeyBox,
            ensure: fn(&VerifyingKeyBox) -> Result<(), String>,
        ) {
            let mut mutated = canonical.clone();
            *mutated
                .bytes
                .last_mut()
                .expect("canonical unshield verifier key bytes") ^= 0x01;
            let err = match ensure(&mutated) {
                Ok(()) => panic!("{label} mutated verifier key must reject"),
                Err(err) => err,
            };
            assert!(
                err.contains("foreign native confidential compiled key"),
                "unexpected {label} mutated-key error: {err}"
            );
            let wrong_backend =
                VerifyingKeyBox::new("halo2/ipa:kzg".to_owned(), canonical.bytes.clone());
            let err = match ensure(&wrong_backend) {
                Ok(()) => panic!("{label} wrong backend must reject"),
                Err(err) => err,
            };
            assert!(
                err.contains("backend"),
                "unexpected {label} backend error: {err}"
            );
        }
        assert_rejects_key_substitution(
            "unshield v2",
            &v2,
            super::ensure_confidential_unshield_v2_canonical_vk_box,
        );
        assert_rejects_key_substitution(
            "unshield v3",
            &v3,
            super::ensure_confidential_unshield_v3_canonical_vk_box,
        );
        let err = super::ensure_confidential_unshield_v3_canonical_vk_box(&v2)
            .expect_err("unshield v2 key must not satisfy unshield v3 canonical guard");
        assert!(
            err.contains("compiled key"),
            "unexpected v2-as-v3 canonical-guard error: {err}"
        );
        let err = super::ensure_confidential_unshield_v2_canonical_vk_box(&v3)
            .expect_err("unshield v3 key must not satisfy unshield v2 canonical guard");
        assert!(
            err.contains("compiled key"),
            "unexpected v3-as-v2 canonical-guard error: {err}"
        );
    }
    #[test]
    fn generated_confidential_transfer_v2_one_input_one_output_verifies_against_generated_vk() {
        use ff::Field as _;
        use iroha_pasta::Fp;
        let network_id = network_id(b"generated-confidential-transfer-network");
        let asset_definition_id = "xor#universal";
        let spend_key = [0x11_u8; 32];
        let input_rho = [0x22_u8; 32];
        let input_diversifier = super::derive_confidential_diversifier_v2(b"input");
        let input_owner_tag =
            super::derive_confidential_owner_tag_v2_with_diversifier(&spend_key, input_diversifier)
                .expect("input owner tag");
        let input_commitment =
            super::derive_confidential_note_v2(asset_definition_id, 7, input_rho, input_owner_tag)
                .expect("input commitment");
        let tree_commitments = vec![input_commitment];
        let root = super::compute_confidential_root_v2(&tree_commitments).expect("root");
        let recipient_key = [0x33_u8; 32];
        let output_rho = [0x44_u8; 32];
        let output_diversifier = super::derive_confidential_diversifier_v2(b"recipient");
        let output_owner_tag = super::derive_confidential_owner_tag_v2_with_diversifier(
            &recipient_key,
            output_diversifier,
        )
        .expect("output owner tag");
        let transfer_vk =
            super::confidential_transfer_v2_vk_record("vk_transfer", 3).expect("transfer vk");
        let transfer_key = transfer_vk.key.as_ref().expect("inline transfer vk");
        let input_path =
            super::compute_confidential_merkle_path_v2(&tree_commitments, 0).expect("input path");
        let empty_path =
            super::compute_confidential_merkle_path_v2(&tree_commitments, tree_commitments.len())
                .expect("empty input path");
        let output_commitment = super::derive_confidential_note_v2(
            asset_definition_id,
            7,
            output_rho,
            output_owner_tag,
        )
        .expect("output commitment");
        let asset_tag = super::derive_confidential_asset_tag_v2(asset_definition_id);
        let network_tag = super::derive_confidential_network_tag_v2(&network_id);
        let nullifier = super::derive_confidential_nullifier_v2(
            &network_id,
            asset_definition_id,
            &spend_key,
            input_rho,
        );
        let witness = super::ConfidentialTransferWitnessV2 {
            include_input_1: false,
            include_output_1: false,
            input_0_amount: 7,
            input_1_amount: 0,
            output_0_amount: 7,
            output_1_amount: 0,
            input_0_rho: input_rho,
            input_1_rho: [0u8; 32],
            output_0_rho: output_rho,
            output_1_rho: [0u8; 32],
            spend_scalar: super::scalar_to_repr_bytes(super::hash_to_scalar(
                b"iroha.confidential.v3.spend_scalar",
                &[&spend_key],
            )),
            input_0_diversifier: input_diversifier,
            input_1_diversifier: [0u8; 32],
            output_0_owner_tag: output_owner_tag,
            output_1_owner_tag: [0u8; 32],
            asset_tag,
            network_tag,
            input_0_path: input_path,
            input_1_path: empty_path,
        };
        let instance_columns = vec![
            vec![super::scalar_from_repr(input_commitment).expect("input commitment")],
            vec![Fp::ZERO],
            vec![super::scalar_from_repr(nullifier).expect("nullifier")],
            vec![Fp::ZERO],
            vec![super::scalar_from_repr(output_commitment).expect("output commitment")],
            vec![Fp::ZERO],
            vec![super::scalar_from_repr(root).expect("root")],
            vec![super::scalar_from_repr(asset_tag).expect("asset tag")],
            vec![super::scalar_from_repr(network_tag).expect("network tag")],
        ];
        assert!(super::native::check_transfer::<
            { super::CONFIDENTIAL_TREE_DEPTH_V2 },
        >(&witness, instance_columns));
        let proof = super::build_confidential_transfer_proof_v2(
            &network_id,
            asset_definition_id,
            &spend_key,
            &tree_commitments,
            &[super::ConfidentialTransferInputV2 {
                amount: 7,
                rho: input_rho,
                diversifier: input_diversifier,
                leaf_index: 0,
            }],
            &[super::ConfidentialTransferOutputV2 {
                amount: 7,
                rho: output_rho,
                owner_tag: output_owner_tag,
            }],
            root,
            &transfer_vk.circuit_id,
            transfer_key,
        )
        .expect("transfer proof");
        assert!(
            crate::verify_backend(
                crate::ZK_BACKEND_NATIVE_PIPA_R,
                &proof.proof,
                Some(transfer_key),
            ),
            "generated one-input one-output confidential transfer v2 proof should verify against the generated VK"
        );
        {
            const EXACT_BACKEND: &str = "pipa-r/pasta/confidential-transfer-v1";
            let (exact_proof, exact_vk) =
                relabel_native_fixture(&proof.proof, transfer_key, EXACT_BACKEND);
            assert!(
                crate::verify_backend(EXACT_BACKEND, &exact_proof, Some(&exact_vk)),
                "exact confidential-transfer registry label should reach the transfer verifier"
            );
        }
        // A self-consistent carrier for another native relation must not
        // substitute for the transfer's exact compiled descriptor/key.
        let wrong_cid_key = super::confidential_unshield_v2_vk_box().unwrap();
        assert_ne!(crate::hash_vk(transfer_key), crate::hash_vk(&wrong_cid_key));
        let wrong_cid_error = super::build_confidential_transfer_proof_v2(
            &network_id,
            asset_definition_id,
            &spend_key,
            &tree_commitments,
            &[super::ConfidentialTransferInputV2 {
                amount: 7,
                rho: input_rho,
                diversifier: input_diversifier,
                leaf_index: 0,
            }],
            &[super::ConfidentialTransferOutputV2 {
                amount: 7,
                rho: output_rho,
                owner_tag: output_owner_tag,
            }],
            root,
            &transfer_vk.circuit_id,
            &wrong_cid_key,
        )
        .expect_err("proof builder must reject a verifier key for another circuit");
        assert!(
            wrong_cid_error.contains("compiled key"),
            "{wrong_cid_error}"
        );
        assert!(
            !crate::verify_backend(
                crate::ZK_BACKEND_NATIVE_PIPA_R,
                &proof.proof,
                Some(&wrong_cid_key),
            ),
            "verifier must reject a cryptographically valid proof whose compiled key names another relation"
        );
    }
    #[test]
    fn generated_confidential_transfer_v2_proof_verifies_against_generated_vk() {
        let network_id = network_id(b"confidential-transfer-v2-test-network");
        let asset_definition_id = "zcoin#wonderland";
        let spend_key = [0x11_u8; 32];
        let input_0_rho = [0x21_u8; 32];
        let input_1_rho = [0x22_u8; 32];
        let output_0_rho = [0x31_u8; 32];
        let output_1_rho = [0x32_u8; 32];
        let input_0_diversifier = super::default_confidential_diversifier_v2();
        let input_1_diversifier = super::derive_confidential_diversifier_v2(b"input-1");
        let output_0_owner_tag = super::derive_confidential_owner_tag_v2_with_diversifier(
            &spend_key,
            input_0_diversifier,
        )
        .expect("owner tag");
        let recipient_diversifier = super::derive_confidential_diversifier_v2(b"recipient");
        let output_1_owner_tag = super::derive_confidential_owner_tag_v2_with_diversifier(
            &[0x44_u8; 32],
            recipient_diversifier,
        )
        .expect("recipient owner tag");
        let input_0_commitment = super::derive_confidential_note_v2(
            asset_definition_id,
            7,
            input_0_rho,
            output_0_owner_tag,
        )
        .expect("input 0 commitment");
        let input_1_owner_tag = super::derive_confidential_owner_tag_v2_with_diversifier(
            &spend_key,
            input_1_diversifier,
        )
        .expect("input 1 owner tag");
        let input_1_commitment = super::derive_confidential_note_v2(
            asset_definition_id,
            5,
            input_1_rho,
            input_1_owner_tag,
        )
        .expect("input 1 commitment");
        let mut tree_commitments = Vec::new();
        tree_commitments.push(input_0_commitment);
        tree_commitments.push(super::scalar_to_repr_bytes(super::Scalar::from(0x99_u64)));
        tree_commitments.push(input_1_commitment);
        let root_hint =
            super::compute_confidential_root_v2(&tree_commitments).expect("confidential root");
        let vk_record =
            super::confidential_transfer_v2_vk_record("vk_transfer", 3).expect("transfer vk");
        let vk_box = vk_record.key.clone().expect("inline transfer vk");
        let proof = super::build_confidential_transfer_proof_v2(
            &network_id,
            asset_definition_id,
            &spend_key,
            &tree_commitments,
            &[
                super::ConfidentialTransferInputV2 {
                    amount: 7,
                    rho: input_0_rho,
                    diversifier: input_0_diversifier,
                    leaf_index: 0,
                },
                super::ConfidentialTransferInputV2 {
                    amount: 5,
                    rho: input_1_rho,
                    diversifier: input_1_diversifier,
                    leaf_index: 2,
                },
            ],
            &[
                super::ConfidentialTransferOutputV2 {
                    amount: 8,
                    rho: output_0_rho,
                    owner_tag: output_0_owner_tag,
                },
                super::ConfidentialTransferOutputV2 {
                    amount: 4,
                    rho: output_1_rho,
                    owner_tag: output_1_owner_tag,
                },
            ],
            root_hint,
            &vk_record.circuit_id,
            &vk_box,
        )
        .expect("build transfer proof");
        assert!(
            crate::verify_backend(crate::ZK_BACKEND_NATIVE_PIPA_R, &proof.proof, Some(&vk_box)),
            "generated confidential transfer v2 proof should verify against the generated VK"
        );
    }
    #[test]
    fn generated_confidential_transfer_v2_one_input_two_outputs_verifies_against_generated_vk() {
        let network_id = network_id(b"confidential-transfer-v2-one-input-test-network");
        let asset_definition_id = "zcoin#wonderland";
        let spend_key = [0x61_u8; 32];
        let input_rho = [0x71_u8; 32];
        let recipient_output_rho = [0x81_u8; 32];
        let change_output_rho = [0x82_u8; 32];
        let input_diversifier = super::default_confidential_diversifier_v2();
        let sender_owner_tag =
            super::derive_confidential_owner_tag_v2_with_diversifier(&spend_key, input_diversifier)
                .expect("sender owner tag");
        let recipient_diversifier = super::derive_confidential_diversifier_v2(b"recipient");
        let recipient_owner_tag = super::derive_confidential_owner_tag_v2_with_diversifier(
            &[0x72_u8; 32],
            recipient_diversifier,
        )
        .expect("recipient owner tag");
        let input_commitment =
            super::derive_confidential_note_v2(asset_definition_id, 2, input_rho, sender_owner_tag)
                .expect("input commitment");
        let tree_commitments = vec![input_commitment];
        let root_hint =
            super::compute_confidential_root_v2(&tree_commitments).expect("confidential root");
        let vk_record =
            super::confidential_transfer_v2_vk_record("vk_transfer", 3).expect("transfer vk");
        let vk_box = vk_record.key.clone().expect("inline transfer vk");
        let proof = super::build_confidential_transfer_proof_v2(
            &network_id,
            asset_definition_id,
            &spend_key,
            &tree_commitments,
            &[super::ConfidentialTransferInputV2 {
                amount: 2,
                rho: input_rho,
                diversifier: input_diversifier,
                leaf_index: 0,
            }],
            &[
                super::ConfidentialTransferOutputV2 {
                    amount: 1,
                    rho: recipient_output_rho,
                    owner_tag: recipient_owner_tag,
                },
                super::ConfidentialTransferOutputV2 {
                    amount: 1,
                    rho: change_output_rho,
                    owner_tag: sender_owner_tag,
                },
            ],
            root_hint,
            &vk_record.circuit_id,
            &vk_box,
        )
        .expect("build transfer proof");
        assert!(
            crate::verify_backend(crate::ZK_BACKEND_NATIVE_PIPA_R, &proof.proof, Some(&vk_box)),
            "generated one-input confidential transfer v2 proof should verify against the generated VK"
        );
    }
    include!("confidential_v2_builder_tests.rs");
}

// Structural HTTP fixtures; execution/finality authority is established separately below.
fn canonical_executed_block_fixture() -> (NonZeroU64, SignedBlock, CommittedTransaction) {
    canonical_executed_network_fixture(1, false, 0)
}

fn canonical_executed_network_fixture(
    inputs: u32,
    include_internal: bool,
    selected: u32,
) -> (NonZeroU64, SignedBlock, CommittedTransaction) {
    use crate::crypto::{PrivateKey, PublicKey};
    use iroha_data_model::block::{
        builder::BlockBuilder,
        execution_output::{ExecutionOutputV1, TimeInvocationV1, TriggerUseV1},
    };
    use iroha_data_model::events::time::{TimeEvent, TimeInterval};
    let public_key: PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .unwrap();
    let private_key: PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    let authority = AccountId::new(public_key);
    let height = NonZeroU64::new(1).unwrap();
    let header = BlockHeader::new(height, None, None, 10, 0);
    let mut builder = BlockBuilder::new(header);
    for index in 0..inputs {
        let mut transaction = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        transaction.set_creation_time(Duration::from_millis(u64::from(index) + 1));
        builder.push_transaction(transaction.try_sign(&private_key).unwrap());
    }
    let mut block = builder.try_build_with_signature(0, &private_key).unwrap();
    let mut outputs = (0..inputs)
        .map(|index| {
            client_fixture_network_output(
                index,
                Ok(iroha_data_model::transaction::DataTriggerSequence::default()).into(),
            )
        })
        .collect::<Vec<_>>();
    if include_internal {
        let invocation = TimeInvocationV1 {
            schedule_index: 0,
            event: TimeEvent {
                interval: TimeInterval {
                    since_ms: 9,
                    length_ms: 1,
                },
            },
            trigger: TriggerUseV1 {
                trigger_id: "client-internal-output".parse().unwrap(),
                registered_at_height: 0,
                action_hash: Hash::new(b"client exact action fixture"),
            },
        };
        outputs.push(ExecutionOutputV1::Time(
            iroha_data_model::block::execution_output::TimeExecutionOutputV1 {
                result: Ok(vec![iroha_data_model::trigger::DataTriggerStep {
                    id: invocation.trigger.trigger_id.clone(),
                    instructions: iroha_data_model::transaction::ExecutionStep(Vec::new().into()),
                }])
                .into(),
                invocation,
                failure_root: None,
                completions: Vec::new(),
            },
        ));
    }
    attach_client_fixture_outputs(&mut block, outputs, u64::from(inputs));
    let (output_index, row) = block.network_output_at(selected).unwrap();
    let output = ExecutionOutputV1::Network(row.clone());
    let committed = CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: block
            .network_entrypoint_at(selected as usize)
            .unwrap()
            .hash(),
        entrypoint_proof: block.network_input_proof(selected).unwrap(),
        entrypoint: block
            .network_entrypoint_at(selected as usize)
            .unwrap()
            .clone(),
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(output_index).unwrap(),
        output,
    };
    assert!(committed.verify_inclusion_in_block(&block));
    let commitment = synthetic_executed_commitment(&block);
    assert!(
        committed.verify_inclusion_in_authenticated_execution(&block, &commitment),
        "fixture commitment must bind its source block"
    );
    let decoded = decode_framed_signed_block(&block.encode_wire().unwrap()).unwrap();
    assert_eq!(decoded.header(), block.header());
    assert_eq!(decoded.execution_outputs(), block.execution_outputs());
    assert_eq!(
        decoded.network_input_merkle_commitment(),
        commitment.transaction_input_commitment
    );
    assert_eq!(
        decoded.output_merkle_commitment(),
        commitment.transaction_output_commitment
    );
    assert!(committed.verify_inclusion_in_block(&decoded));
    assert!(
        committed.verify_inclusion_in_authenticated_execution(&decoded, &commitment),
        "fixture commitment must bind its decoded wire"
    );
    if include_internal {
        assert_eq!(
            block
                .network_input_merkle_commitment()
                .unwrap()
                .leaf_count()
                .get(),
            u64::from(inputs)
        );
        assert_eq!(
            block.output_merkle_commitment().unwrap().leaf_count().get(),
            u64::from(inputs) + 1
        );
    }
    (height, block, committed)
}

fn synthetic_executed_commitment(
    block: &SignedBlock,
) -> iroha_data_model::sumeragi_finality::ExecutionCommitment {
    let wire = block.encode_wire().expect("fixture executed wire");
    // HTTP tests supply an independent root; this does not grant consensus authority.
    iroha_data_model::sumeragi_finality::ExecutionCommitment {
        parent_state_root: Hash::new(b"fixture parent state"),
        post_state_root: Hash::new(b"fixture post state"),
        ordinary_writes_root: Hash::new(b"fixture ordinary writes"),
        parent_world_state_root: Hash::new(b"fixture parent world state"),
        world_state_root: Hash::new(b"fixture world state"),
        event_commitment: None,
        executed_block_wire_len: wire.len() as u64,
        executed_block_wire_hash: Hash::new(&wire),
        transaction_input_commitment: block.network_input_merkle_commitment(),
        transaction_output_commitment: block.output_merkle_commitment(),
    }
}

#[test]
fn canonical_executed_block_reader_requires_authenticated_execution_commitment() {
    let client = client_with_base_url(base_url());
    for (height, block, committed) in [
        canonical_executed_block_fixture(),
        canonical_executed_network_fixture(2, true, 1),
    ] {
        let expected = synthetic_executed_commitment(&block);
        let wire = block.encode_wire().expect("fixture wire");
        let received = wire.clone();
        let received_address = received.as_ptr();
        let received_capacity = received.capacity();
        let response_slot = Mutex::new(Some(mk_response(
            StatusCode::OK,
            received,
            Some(APPLICATION_NORITO),
        )));
        let response = with_mock_http(
            move |_| {
                Ok(response_slot
                    .lock()
                    .expect("response slot")
                    .take()
                    .expect("exactly one HTTP request"))
            },
            |transport| {
                let client = client.clone().with_test_http_transport(transport);
                mark_data_model_compatible(&client);
                client.get_canonical_executed_block_wire(height, &committed, &expected)
            },
        )
        .expect("exact Network sources and separate output trees verify");
        assert_eq!(response, wire);
        assert_eq!(response.as_ptr(), received_address);
        assert_eq!(response.capacity(), received_capacity);
        for wrong_length in [false, true] {
            let mut wrong = expected;
            if wrong_length {
                wrong.executed_block_wire_len += 1;
            } else {
                wrong.executed_block_wire_hash = Hash::new(b"wrong wire");
            }
            let response = capture_request(
                mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO)),
                |transport| {
                    let client = client.clone().with_test_http_transport(transport);
                    mark_data_model_compatible(&client);
                    client.get_canonical_executed_block_wire(height, &committed, &wrong)
                },
            )
            .0;
            assert!(
                response
                    .expect_err("wrong exact execution commitment must fail")
                    .to_string()
                    .contains("authenticated execution commitment")
            );
        }
    }
    let (height, accepted, committed) = canonical_executed_block_fixture();
    let mut actually_rejected = accepted.clone();
    attach_client_fixture_outputs(
        &mut actually_rejected,
        vec![client_fixture_network_output(
            0,
            Err(
                iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                    iroha_data_model::ValidationFail::NotPermitted(
                        "authenticated rejected execution".into(),
                    ),
                ),
            )
            .into(),
        )],
        0,
    );
    assert_eq!(accepted.header(), actually_rejected.header());
    assert_eq!(
        accepted.hash(),
        actually_rejected.hash(),
        "outputs do not rewrite the proposal"
    );
    assert_ne!(
        accepted.output_merkle_commitment(),
        actually_rejected.output_merkle_commitment()
    );
    let expected = synthetic_executed_commitment(&actually_rejected);
    let response = capture_request(
        mk_response(
            StatusCode::OK,
            accepted.encode_wire().unwrap(),
            Some(APPLICATION_NORITO),
        ),
        |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_canonical_executed_block_wire(height, &committed, &expected)
        },
    )
    .0;
    assert!(
        response
            .expect_err("forged successful result with unchanged consensus hash must fail")
            .to_string()
            .contains("authenticated execution commitment")
    );
}

#[test]
fn canonical_executed_block_reader_rejects_a_transaction_from_another_network() {
    let (height, block, committed) = canonical_executed_block_fixture();
    let wire = block.encode_wire().expect("canonical executed block wire");
    let commitment = synthetic_executed_commitment(&block);
    let mut client = client_with_base_url(base_url());
    client.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"another network for executed block reader",
    )));
    let response = capture_request(
        mk_response(StatusCode::OK, wire, Some(APPLICATION_NORITO)),
        |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_canonical_executed_block_wire(height, &committed, &commitment)
        },
    )
    .0;
    assert!(
        response
            .expect_err("a valid committed transaction from another network must fail")
            .to_string()
            .contains("authenticated client network")
    );
}

#[test]
fn canonical_executed_block_reader_binds_route_wire_and_committed_evidence() {
    let mut client = client_with_base_url(base_url());

    client
        .headers
        .insert("Accept".to_owned(), APPLICATION_JSON.to_owned());
    client
        .headers
        .insert("Content-Type".to_owned(), APPLICATION_JSON.to_owned());
    let (height, block, committed) = canonical_executed_block_fixture();
    let wire = block.encode_wire().expect("canonical executed block wire");
    let (actual, snapshot) = capture_request(
        mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO)),
        |mock_transport| {
            let client = client
                .clone()
                .with_test_http_transport(mock_transport.clone());
            mark_data_model_compatible(&client);
            client.get_canonical_executed_block_wire(
                height,
                &committed,
                &synthetic_executed_commitment(&block),
            )
        },
    );
    assert_eq!(actual.expect("verified executed block wire"), wire);
    assert_eq!(snapshot.method, HttpMethod::GET);
    assert_eq!(snapshot.url.path(), "/v1/ledger/block/1");
    assert!(snapshot.url.query().is_none());
    assert!(snapshot.body.is_empty());
    super::tests::assert_canonical_account_signed_request(&client, &snapshot);
    assert_eq!(
        snapshot.max_response_bytes,
        AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1
    );
    assert_single_accept_header(&snapshot, APPLICATION_NORITO);
    assert!(
        snapshot
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("content-type")),
        "GET must not carry Content-Type: {:?}",
        snapshot.headers
    );
}

#[test]
fn canonical_executed_block_reader_retries_with_fresh_account_signature() {
    let client = client_with_base_url(base_url());
    let (height, block, committed) = canonical_executed_block_fixture();
    let commitment = synthetic_executed_commitment(&block);
    let wire = block.encode_wire().expect("canonical executed block wire");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&requests);
    let result = with_mock_http(
        move |request| {
            let mut requests = observed.lock().expect("captured requests");
            requests.push(request);
            if requests.len() == 1 {
                let mut response = empty_response(StatusCode::TOO_MANY_REQUESTS);
                response
                    .headers_mut()
                    .insert("retry-after", "0".parse().unwrap());
                Ok(response)
            } else {
                Ok(mk_response(
                    StatusCode::OK,
                    wire.clone(),
                    Some(APPLICATION_NORITO),
                ))
            }
        },
        |transport| {
            let client = client
                .clone()
                .with_test_http_transport(transport)
                .with_request_deadline(std::time::Instant::now() + Duration::from_secs(5));
            mark_data_model_compatible(&client);
            client.get_canonical_executed_block_wire(height, &committed, &commitment)
        },
    );
    assert_eq!(
        result.expect("signed retry verifies canonical wire"),
        block.encode_wire().unwrap()
    );
    let requests = requests.lock().expect("captured requests");
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        super::tests::assert_canonical_account_signed_request(&client, request);
        assert_single_accept_header(request, APPLICATION_NORITO);
        assert_eq!(
            request.max_response_bytes,
            AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1
        );
    }
    let nonce = |request: &RequestSnapshot| {
        request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(HEADER_NONCE))
            .expect("canonical request nonce")
            .1
            .clone()
    };
    assert_ne!(nonce(&requests[0]), nonce(&requests[1]));
}

#[test]
fn canonical_executed_block_reader_rejects_trailing_wire_and_wrong_carrier_hash() {
    let client = client_with_base_url(base_url());

    let (height, block, committed) = canonical_executed_block_fixture();
    let mut trailing = block.encode_wire().expect("canonical executed block wire");
    trailing.push(0);
    let error = capture_request(
        mk_response(StatusCode::OK, trailing, Some(APPLICATION_NORITO)),
        |mock_transport| {
            let client = client
                .clone()
                .with_test_http_transport(mock_transport.clone());
            mark_data_model_compatible(&client);
            client.get_canonical_executed_block_wire(
                height,
                &committed,
                &synthetic_executed_commitment(&block),
            )
        },
    )
    .0
    .expect_err("trailing executed-block bytes must fail");
    assert!(
        error
            .to_string()
            .contains("decode canonical executed block wire")
            || error
                .to_string()
                .contains("exact canonical SignedBlock wire")
    );

    let mut wrong_carrier = committed;
    wrong_carrier.block_hash =
        HashOf::from_untyped_unchecked(Hash::prehashed([0x91; Hash::LENGTH]));
    let wire = block.encode_wire().expect("canonical executed block wire");
    let error = capture_request(
        mk_response(StatusCode::OK, wire, Some(APPLICATION_NORITO)),
        |mock_transport| {
            let client = client
                .clone()
                .with_test_http_transport(mock_transport.clone());
            mark_data_model_compatible(&client);
            client.get_canonical_executed_block_wire(
                height,
                &wrong_carrier,
                &synthetic_executed_commitment(&block),
            )
        },
    )
    .0
    .expect_err("wrong carrier hash must fail");
    assert!(error.to_string().contains("carrier hash"));
}

#[test]
fn canonical_executed_block_reader_rejects_rehashed_source_and_internal_substitutions() {
    use iroha_data_model::block::execution_output::ExecutionOutputV1;
    let client = client_with_base_url(base_url());
    let (height, block, committed) = canonical_executed_network_fixture(2, true, 1);
    let commitment = synthetic_executed_commitment(&block);
    let wire = block.encode_wire().unwrap();
    for mutation in 0..5 {
        let mut changed = committed.clone();
        match mutation {
            0 => {
                let ExecutionOutputV1::Network(row) = &mut changed.output else {
                    unreachable!()
                };
                row.input_index = 0;
            }
            1 => changed.entrypoint_proof = block.network_input_proof(0).unwrap(),
            2 => {
                changed.entrypoint = block.network_entrypoint_at(0).unwrap().clone();
                changed.entrypoint_hash = changed.entrypoint.hash();
                changed.entrypoint_proof = block.network_input_proof(0).unwrap();
            }
            3 => {
                changed.output = block.execution_outputs()[2].clone();
                changed.output_proof = block.output_proof(2).unwrap();
                assert!(
                    changed.result().is_ok(),
                    "internal success is still no Network result"
                );
            }
            4 => changed.output_proof = block.output_proof(0).unwrap(),
            _ => unreachable!(),
        }
        changed.output_hash = HashOf::new(&changed.output);
        let error = capture_request(
            mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO)),
            |transport| {
                let client = client.clone().with_test_http_transport(transport);
                mark_data_model_compatible(&client);
                client.get_canonical_executed_block_wire(height, &changed, &commitment)
            },
        )
        .0
        .expect_err(
            "a complete self-consistent claim must still have exact authenticated inclusion",
        );
        assert!(
            error
                .to_string()
                .contains("authenticated execution commitment"),
            "mutation {mutation}: {error}"
        );
    }
}

//! Independent destination finality, exact relay execution and complete World balance evidence.

use super::*;
use iroha::client::{
    canonical_network_request_signature_message, canonical_request_account_header_value,
    canonical_request_signature_header_value,
};
use iroha_data_model::{
    asset::AssetValue,
    block::SignedBlock,
    query::CommittedTransaction,
    sumeragi_amx::{
        AmxForeignInstanceV1, AmxRecordV1, approval_proof::MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1,
    },
    sumeragi_finality::{
        CertifiedResultScope, SumeragiFinalityProof, VerifiedSumeragiBlock, authenticated_genesis,
    },
    transaction::{Executable, TransactionEntrypoint},
};
use std::sync::atomic::{AtomicU64, Ordering};

// Initial approval reads previously had this one-request bound. Retries share it.
const APPROVAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

async fn read_approval_at_until<T, F, Fut>(
    height: u64,
    deadline: tokio::time::Instant,
    mut read: F,
) -> Result<T>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last = None;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(approval_deadline_error(
                last,
                "initial AMX approval read deadline exhausted".into(),
            ));
        }
        let result = match tokio::time::timeout_at(deadline, read(height)).await {
            Ok(result) => result,
            Err(_) => {
                return Err(approval_deadline_error(
                    last,
                    "initial AMX approval read deadline exhausted".into(),
                ));
            }
        };
        match result {
            Ok(value) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(approval_deadline_error(
                        last,
                        "initial AMX approval read deadline exhausted".into(),
                    ));
                }
                return Ok(value);
            }
            Err(error) if retryable_approval_error(&error) => {
                let delay = approval_retry_delay(&error);
                last = Some(error);
                if tokio::time::Instant::now() >= deadline {
                    return Err(approval_deadline_error(
                        last,
                        "initial AMX approval read deadline exhausted".into(),
                    ));
                }
                let wake = tokio::time::Instant::now()
                    .checked_add(delay)
                    .unwrap_or(deadline)
                    .min(deadline);
                // Only the bounded timer bypasses cooperative accounting. It returns
                // the original cause at a shared outer deadline; HTTP remains bounded.
                tokio::task::unconstrained(tokio::time::sleep_until(wake)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn retryable_approval_error(error: &eyre::Report) -> bool {
    error
        .downcast_ref::<iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1>()
        .is_some_and(|failure| failure.is_valid())
}

pub(crate) fn approval_retry_delay(error: &eyre::Report) -> Duration {
    Duration::from_millis(
        error
            .downcast_ref::<iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1>()
            .and_then(|failure| failure.retry_after_ms)
            .unwrap_or(0),
    )
    .max(Duration::from_millis(200))
}

pub(crate) fn approval_deadline_error(
    original: Option<eyre::Report>,
    context: String,
) -> eyre::Report {
    match original {
        Some(error) => error.wrap_err(context),
        None => eyre!(context),
    }
}

#[cfg(test)]
mod approval_error_tests {
    use super::*;

    fn observation(
        reason: iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1,
        observed_height: Option<u64>,
        retry_after_ms: Option<u64>,
    ) -> eyre::Report {
        iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1 {
            approval_hash: iroha_crypto::Hash::new(b"exact approval"),
            relay_header_hash: iroha_crypto::Hash::new(b"exact relay"),
            requested_height: 2,
            reason,
            observed_height,
            retry_after_ms,
        }
        .into()
    }

    #[tokio::test(start_paused = true)]
    async fn initial_approval_retries_capacity_and_genesis_lag_at_only_original_height() {
        use iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1::{
            Capacity, CutChanged,
        };
        let calls = std::cell::Cell::new(0);
        let start = tokio::time::Instant::now();
        let value = read_approval_at_until(2, start + Duration::from_secs(2), |height| {
            assert_eq!(height, 2);
            let call = calls.get();
            calls.set(call + 1);
            async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                match call {
                    0 => Err(observation(Capacity, None, Some(300))),
                    1 => Err(observation(CutChanged, Some(1), None)),
                    _ => Ok("original independently verified cut"),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(value, "original independently verified cut");
        assert_eq!(calls.get(), 3);
        assert_eq!(
            tokio::time::Instant::now() - start,
            Duration::from_millis(800)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn initial_approval_newer_cut_is_never_promoted_to_success() {
        use iroha_torii_shared::amx_approval_read::{
            AmxApprovalReadFailureV1, AmxApprovalReadReasonV1,
        };
        let calls = std::cell::Cell::new(0);
        let start = tokio::time::Instant::now();
        let error =
            read_approval_at_until::<(), _, _>(2, start + Duration::from_millis(300), |height| {
                assert_eq!(
                    height, 2,
                    "unsigned observed height must never select another request"
                );
                calls.set(calls.get() + 1);
                std::future::ready(Err(observation(
                    AmxApprovalReadReasonV1::CutChanged,
                    Some(3),
                    None,
                )))
            })
            .await
            .unwrap_err();
        let cause = error.downcast_ref::<AmxApprovalReadFailureV1>().unwrap();
        assert_eq!(cause.requested_height, 2);
        assert_eq!(cause.observed_height, Some(3));
        assert_eq!(calls.get(), 2);
        assert_eq!(
            tokio::time::Instant::now() - start,
            Duration::from_millis(300)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn initial_approval_deadline_bounds_later_http_and_retains_original_cause() {
        use iroha_torii_shared::amx_approval_read::{
            AmxApprovalReadFailureV1, AmxApprovalReadReasonV1,
        };
        let calls = std::cell::Cell::new(0);
        let start = tokio::time::Instant::now();
        let error = read_approval_at_until::<(), _, _>(2, start + Duration::from_secs(2), |_| {
            let call = calls.get();
            calls.set(call + 1);
            async move {
                if call == 0 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Err(
                        observation(AmxApprovalReadReasonV1::Capacity, None, Some(300))
                            .wrap_err("original HTTP refusal"),
                    )
                } else {
                    std::future::pending().await
                }
            }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.get(), 2);
        assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(2));
        assert!(error.downcast_ref::<AmxApprovalReadFailureV1>().is_some());
        assert!(format!("{error:?}").contains("original HTTP refusal"));
    }

    #[tokio::test(start_paused = true)]
    async fn initial_approval_nested_deadline_retains_cause_after_coop_exhaustion() {
        use iroha_torii_shared::amx_approval_read::{
            AmxApprovalReadFailureV1, AmxApprovalReadReasonV1,
        };
        let start = tokio::time::Instant::now();
        let deadline = start + Duration::from_secs(2);
        let calls = std::cell::Cell::new(0);
        let error = tokio::time::timeout_at(
            deadline,
            read_approval_at_until::<(), _, _>(2, deadline, |_| {
                calls.set(calls.get() + 1);
                async {
                    tokio::time::sleep_until(deadline).await;
                    while tokio::task::coop::has_budget_remaining() {
                        tokio::task::consume_budget().await;
                    }
                    Err(
                        observation(AmxApprovalReadReasonV1::Capacity, None, Some(30_000))
                            .wrap_err("final typed read cause"),
                    )
                }
            }),
        )
        .await
        .expect("inner deadline must retain the typed cause before outer timeout")
        .unwrap_err();
        assert_eq!(calls.get(), 1);
        assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(2));
        assert_eq!(
            error
                .downcast_ref::<AmxApprovalReadFailureV1>()
                .unwrap()
                .retry_after_ms,
            Some(30_000)
        );
        assert!(format!("{error:?}").contains("final typed read cause"));
    }

    #[tokio::test(start_paused = true)]
    async fn initial_approval_retry_after_cannot_extend_original_deadline() {
        use iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1;
        let start = tokio::time::Instant::now();
        let calls = std::cell::Cell::new(0);
        let error = read_approval_at_until::<(), _, _>(2, start + Duration::from_secs(2), |_| {
            calls.set(calls.get() + 1);
            std::future::ready(Err(observation(
                AmxApprovalReadReasonV1::Capacity,
                None,
                Some(30_000),
            )))
        })
        .await
        .unwrap_err();
        assert!(retryable_approval_error(&error));
        assert_eq!(calls.get(), 1);
        assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn initial_approval_auth_proof_and_unclassified_errors_are_terminal() {
        let failures: Vec<eyre::Report> = vec![
            iroha::Error::Http {
                operation: "amx.approval",
                status: 401,
                retry_after: None,
                body: vec![],
            }
            .into(),
            iroha::Error::Http {
                operation: "amx.approval",
                status: 403,
                retry_after: None,
                body: vec![],
            }
            .into(),
            iroha::Error::Http {
                operation: "amx.approval",
                status: 429,
                retry_after: Some(Duration::from_secs(1)),
                body: vec![],
            }
            .into(),
            iroha::Error::Http {
                operation: "amx.approval",
                status: 503,
                retry_after: None,
                body: vec![],
            }
            .into(),
            iroha_data_model::sumeragi_finality::FinalityError("wrong original World root".into())
                .into(),
            eyre!("malformed proof or request binding"),
        ];
        for original in failures {
            let expected = format!("{original:?}");
            let mut original = Some(original);
            let calls = std::cell::Cell::new(0);
            let start = tokio::time::Instant::now();
            let error =
                read_approval_at_until::<(), _, _>(2, start + Duration::from_secs(2), |_| {
                    calls.set(calls.get() + 1);
                    std::future::ready(Err(original.take().expect("terminal error retried")))
                })
                .await
                .unwrap_err();
            assert_eq!(format!("{error:?}"), expected);
            assert_eq!(calls.get(), 1);
            assert_eq!(tokio::time::Instant::now(), start);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn initial_approval_newer_valid_proof_cannot_replace_original_verified_block() {
        use iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1;
        let (mut chain, approval, signer) =
            iroha_core::sumeragi::test_chain::native_amx_approval_route_fixture();
        let relay = AccountId::new(signer.public_key().clone());
        let mut verifier = SumeragiFinalityVerifier::new(
            chain.genesis(),
            chain.state().chain_id_ref().as_str(),
            chain
                .validators()
                .iter()
                .map(
                    |(peer, pop)| iroha_data_model::sumeragi_finality::FinalityValidator {
                        public_key: peer.public_key().clone(),
                        proof_of_possession: pop.clone(),
                    },
                )
                .collect(),
        )
        .unwrap();
        let mut original = None;
        for height in 1..=2 {
            original = Some(
                verifier
                    .verify(
                        &iroha_core::sumeragi::finality::build_proof(&chain.state().view(), height)
                            .unwrap(),
                    )
                    .unwrap(),
            );
        }
        let original = original.unwrap();
        let transaction = chain.sign(
            &signer,
            [iroha_data_model::isi::Log::new(
                iroha_logger::Level::INFO,
                "actual later approval proof".into(),
            )
            .into()],
            2_999,
        );
        assert_eq!(chain.commit_at(3_000, vec![transaction]), [true]);
        let newer = verifier
            .verify(&iroha_core::sumeragi::finality::build_proof(&chain.state().view(), 3).unwrap())
            .unwrap();
        let pool = iroha_allocation::AllocationBudget::new(256 * 1024 * 1024);
        let proof = chain
            .state()
            .with_native_amx_debit_approval_snapshot_v1(
                &chain.committed(3),
                &approval,
                &relay,
                &pool,
                |world, permissions| {
                    Ok(AmxDebitApprovalProofV1 {
                        world: world.clone(),
                        relay_permissions: permissions.clone(),
                    })
                },
            )
            .unwrap();
        let schema = iroha_core::state::State::native_world_schema_hash_v1().unwrap();
        proof.verify(&approval, &relay, schema, &newer).unwrap();
        assert!(proof.verify(&approval, &relay, schema, &original).is_err());
        let calls = std::cell::Cell::new(0);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let error = read_approval_at_until(original.height(), deadline, |height| {
            assert_eq!(height, original.height());
            let call = calls.get();
            calls.set(call + 1);
            std::future::ready(if call == 0 {
                Err(observation(
                    AmxApprovalReadReasonV1::CutChanged,
                    Some(newer.height()),
                    None,
                ))
            } else {
                proof
                    .verify(&approval, &relay, schema, &original)
                    .map(|_| ())
                    .map_err(Into::into)
            })
        })
        .await
        .unwrap_err();
        assert_eq!(calls.get(), 2, "only the typed observation may retry");
        assert!(
            !retryable_approval_error(&error),
            "wrong selected proof remains terminal"
        );
        assert_eq!(original.height(), 2);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn approval_deadline_keeps_original_typed_cause_and_retry_after() {
        use iroha_torii_shared::amx_approval_read::{
            AmxApprovalReadFailureV1, AmxApprovalReadReasonV1,
        };
        let original = AmxApprovalReadFailureV1 {
            approval_hash: iroha_crypto::Hash::new(b"exact approval"),
            relay_header_hash: iroha_crypto::Hash::new(b"exact relay"),
            requested_height: 2,
            reason: AmxApprovalReadReasonV1::Capacity,
            observed_height: None,
            retry_after_ms: Some(7_000),
        };
        let report: eyre::Report = original.clone().into();
        assert_eq!(approval_retry_delay(&report), Duration::from_secs(7));
        let error = approval_deadline_error(Some(report), "absolute approval deadline".into());
        assert_eq!(
            error.downcast_ref::<AmxApprovalReadFailureV1>(),
            Some(&original)
        );
    }

    #[test]
    fn approval_read_does_not_retry_auth_integrity_or_unclassified_failure() {
        let failures: Vec<eyre::Report> = vec![
            iroha::Error::Http {
                operation: "amx.approval",
                status: 401,
                retry_after: None,
                body: vec![],
            }
            .into(),
            iroha::Error::Http {
                operation: "amx.approval",
                status: 403,
                retry_after: None,
                body: vec![],
            }
            .into(),
            iroha::Error::Http {
                operation: "amx.approval",
                status: 429,
                retry_after: Some(Duration::from_secs(1)),
                body: vec![],
            }
            .into(),
            iroha::Error::Http {
                operation: "amx.approval",
                status: 503,
                retry_after: None,
                body: vec![],
            }
            .into(),
            iroha_data_model::sumeragi_finality::FinalityError("wrong certified World root".into())
                .into(),
            eyre!("malformed canonical proof"),
        ];
        for error in failures {
            assert!(
                !retryable_approval_error(&error),
                "terminal error was retried: {error:?}"
            );
        }
    }
}

fn verify_balance_tuple(
    world: &iroha_data_model::sumeragi_finality::VerifiedWorldStateSnapshotV1,
    assets: &[AssetId; 3],
    balances: [u32; 3],
) -> Result<()> {
    for (asset, expected) in assets.iter().zip(balances) {
        if expected == 0 {
            world.verify_asset_absent(asset)?;
        } else {
            world.verify_table_value(
                "world.assets",
                asset,
                &AssetValue::new(Quantity::from(expected)),
            )?;
        }
    }
    Ok(())
}

fn balance_observation_from_proof(
    proof: &AmxDebitApprovalProofV1,
    tip: &VerifiedSumeragiBlock,
    assets: &[AssetId; 3],
    expected: [u32; 3],
    pending: &[[u32; 3]],
) -> Result<bool> {
    // Authenticate once before inspecting any allowed business-state preimage.
    // An invalid proof can never become a pending payment observation.
    let world = proof.world.authenticate(tip)?;
    match verify_balance_tuple(&world, assets, expected) {
        Ok(()) => Ok(true),
        Err(original) => {
            for before in pending {
                if verify_balance_tuple(&world, assets, *before).is_ok() {
                    return Ok(false);
                }
            }
            Err(original)
        }
    }
}

pub(crate) struct Observer {
    verifier: SumeragiFinalityVerifier,
    global: AmxForeignInstanceV1,
    pub decision: Option<AmxOutcomeV1>,
    pub delivery: Option<(
        u64,
        iroha_crypto::HashOf<iroha_data_model::transaction::SignedTransaction>,
    )>,
    pub decision_source: Option<iroha_data_model::sumeragi_amx::AmxCertifiedBlockV1>,
    pub delivery_result:
        Option<iroha_crypto::HashOf<iroha_data_model::block::execution_output::ExecutionOutputV1>>,
    pub delivery_fee: Option<iroha_data_model::block::consensus::NexusFeeReceipt>,
    pub tip: Option<VerifiedSumeragiBlock>,
    pub proof: Option<SumeragiFinalityProof>,
}
impl Observer {
    pub fn new(root: &Root, global: &Root) -> Result<Self> {
        Ok(Self {
            verifier: root.verifier()?,
            global: AmxForeignInstanceV1::new(
                global.instance,
                authenticated_genesis(&global.network.genesis().0)?
                    .into_parts()
                    .0,
                CertifiedResultScope::TairaGlobal,
            )?,
            decision: None,
            delivery: None,
            decision_source: None,
            delivery_result: None,
            delivery_fee: None,
            tip: None,
            proof: None,
        })
    }
    pub async fn refresh(
        &mut self,
        root: &Root,
        tx: [u8; 32],
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let client = root.client(&relay(root.index));
        let height = status_poll::read_until(deadline, || async {
            client.client().status().get().await.map_err(Into::into)
        })
        .await?
        .blocks;
        let next = self.verifier.authenticated_height().unwrap_or(0) + 1;
        ensure!(
            height.saturating_sub(next) < 128,
            "unexpected unbounded source traffic"
        );
        for height in next..=height {
            let proof = client
                .client()
                .get_sumeragi_finality_proof_async(NonZeroU64::new(height).unwrap(), root.scope)
                .await?;
            let block = self.verifier.verify(&proof)?;
            for (index, entry) in block.block().network_entrypoints().enumerate() {
                let TransactionEntrypoint::External(signed) = entry else {
                    continue;
                };
                let Executable::Instructions(instructions) = signed.instructions() else {
                    continue;
                };
                for instruction in instructions {
                    let Some(settle) = instruction.as_any().downcast_ref::<SettleAmxV1>() else {
                        continue;
                    };
                    let AmxRecordV1::Decision(decision) = &settle.decision.record else {
                        continue;
                    };
                    if decision.tx != tx {
                        continue;
                    }
                    ensure!(settle.dataspace == root.scope.dataspace_id());
                    self.global.verify_record(&settle.decision)?;
                    let carrier = evidence(block.block(), index.try_into()?);
                    let carrier = carrier?;
                    block.verify_transaction_execution(&root.network.network_id(), &carrier)?;
                    if carrier.output.result().is_ok() {
                        ensure!(
                            signed.authority() == &account(&relay(root.index)),
                            "the actual funded service account must deliver the decision"
                        );
                        let fee = carrier.output.result().nexus_fee_receipt().ok_or_else(|| {
                            eyre!("successful service carrier has no authenticated fee receipt")
                        })?;
                        ensure!(
                            fee.debit_source
                                == iroha_data_model::nexus::FeeDebitSource::Account(account(
                                    &relay(root.index)
                                ))
                        );
                        ensure!(fee.fee_asset_id == fee_asset() && !fee.fee_amount.is_zero());
                        ensure!(
                            fee.dataspace_id == root.scope.dataspace_id()
                                && fee.block_height == block.height()
                        );
                        if let Some(original) = self.decision {
                            ensure!(original == decision.outcome, "conflicting Global decision");
                        }
                        self.decision = Some(decision.outcome);
                        record_unique_delivery(
                            &mut self.delivery,
                            (block.height(), signed.hash()),
                        )?;
                        self.decision_source = Some(settle.decision.block.clone());
                        self.delivery_result = Some(iroha_crypto::HashOf::new(&carrier.output));
                        self.delivery_fee = Some(fee.clone());
                    }
                }
            }
            self.tip = Some(block);
            self.proof = Some(proof);
        }
        Ok(())
    }
    pub async fn world(
        &self,
        root: &Root,
        approval: &AmxDebitApprovalV1,
        deadline: tokio::time::Instant,
    ) -> Result<AmxDebitApprovalProofV1> {
        let tip = self
            .tip
            .as_ref()
            .ok_or_else(|| eyre!("no authenticated private cut"))?;
        let proof = tokio::time::timeout_at(deadline, approval_proof(root, approval, tip.height()))
            .await??;
        proof.verify(
            approval,
            &account(&relay(root.index)),
            iroha_core::state::State::native_world_schema_hash_v1().map_err(|e| eyre!(e))?,
            tip,
        )?;
        Ok(proof)
    }
    pub fn balance_observation(
        &self,
        proof: &AmxDebitApprovalProofV1,
        bank: usize,
        expected: [u32; 3],
        pending: &[[u32; 3]],
    ) -> Result<bool> {
        let tip = self
            .tip
            .as_ref()
            .ok_or_else(|| eyre!("no authenticated balance cut"))?;
        let custody = AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
            b"iroha-native-amx-custody-v1",
            &[tip.commitment().schedule.current.network_id.as_bytes()],
        ));
        let assets = [account(&payer(bank)), account(&payer(1 - bank)), custody].map(|owner| {
            AssetId::with_scope(
                currency(bank),
                owner,
                AssetBalanceScope::Dataspace(DATASPACES[bank]),
            )
        });
        balance_observation_from_proof(proof, tip, &assets, expected, pending)
    }
}

pub(crate) fn evidence(block: &SignedBlock, index: u32) -> Result<CommittedTransaction> {
    let entrypoint = block
        .network_entrypoint_at(index as usize)
        .ok_or_else(|| eyre!("input absent"))?
        .clone();
    let (output_index, _) = block
        .network_output_at(index)
        .ok_or_else(|| eyre!("output absent"))?;
    let output = block.execution_outputs()[output_index as usize].clone();
    Ok(CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint,
        entrypoint_proof: block
            .network_input_proof(index)
            .ok_or_else(|| eyre!("input proof absent"))?,
        output_hash: iroha_crypto::HashOf::new(&output),
        output,
        output_proof: block
            .output_proof(output_index)
            .ok_or_else(|| eyre!("output proof absent"))?,
    })
}

pub(crate) async fn assert_privileged_bank_approval(
    root: &Root,
    approval: &AmxDebitApprovalV1,
    block: &VerifiedSumeragiBlock,
) -> Result<()> {
    use iroha_data_model::{
        Registrable,
        role::{Role, RoleIdWithOwner},
    };
    let deadline = tokio::time::Instant::now()
        .checked_add(APPROVAL_REQUEST_TIMEOUT)
        .ok_or_else(|| eyre!("initial AMX approval deadline cannot be represented"))?;
    read_approval_at_until(block.height(), deadline, |height| async move {
        let proof = approval_proof(root, approval, height).await?;
        let relay = account(&relay(root.index));
        proof.verify(
            approval,
            &relay,
            iroha_core::state::State::native_world_schema_hash_v1().map_err(|e| eyre!(e))?,
            block,
        )?;
        let broad: iroha_data_model::permission::Permission =
            iroha_executor_data_model::permission::query::CanReadAllLedgerData.into();
        ensure!(
            !proof.relay_permissions.contains(&broad),
            "no direct read grant may survive deletion of the service's dedicated role"
        );
        let mut matched = false;
        for permission in &proof.relay_permissions {
            matched |= approval.matches_permission(permission)?;
        }
        ensure!(
            matched,
            "the exact direct payer-issued debit approval remains independent"
        );
        let mut role = Role::new(service_read_role(), relay.clone())
            .add_permission(broad)
            .build(&account(&genesis_key(root.index)));
        role.ensure_permission_epochs(1);
        let world = proof.world.authenticate(block)?;
        world.verify_table_value("world.roles", &service_read_role(), &role)?;
        world.verify_table_value(
            "world.account_roles",
            &RoleIdWithOwner::new(relay, service_read_role()),
            &(),
        )?;
        Ok(())
    })
    .await
}

// The SDK opaque permission result intentionally exposes no unauthenticated World DTO. This
// test also authenticates the complete response to verify monetary rows at that same cut.
pub(crate) async fn approval_response(
    root: &Root,
    approval: &AmxDebitApprovalV1,
    height: u64,
) -> Result<reqwest::Response> {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let body = norito::encode_canonical(approval)?;
    let url: reqwest::Url = format!(
        "{}/v1/amx/debit-approval/{height}",
        root.network.validators()[0]
            .torii_url()
            .trim_end_matches('/')
    )
    .parse()?;
    let timestamp = now_ms()?;
    let nonce = format!("amx-bank-cut-{}", NONCE.fetch_add(1, Ordering::Relaxed));
    let message = canonical_network_request_signature_message(
        &root.network.network_id(),
        &reqwest::Method::POST,
        &url,
        &body,
        timestamp,
        &nonce,
    )?;
    let signature = iroha_crypto::Signature::new(relay(root.index).private_key(), &message);
    let response = root
        .authenticate_http(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?
                .post(url),
        )
        .header("Content-Type", "application/x-norito")
        .header("Accept", "application/x-norito")
        .header(
            "x-iroha-account",
            canonical_request_account_header_value(&account(&relay(root.index)))?,
        )
        .header(
            "x-iroha-signature",
            canonical_request_signature_header_value(&signature)?,
        )
        .header("x-iroha-timestamp-ms", timestamp.to_string())
        .header("x-iroha-nonce", nonce)
        .body(body)
        .timeout(APPROVAL_REQUEST_TIMEOUT)
        .send()
        .await?;
    Ok(response)
}

async fn approval_proof(
    root: &Root,
    approval: &AmxDebitApprovalV1,
    height: u64,
) -> Result<AmxDebitApprovalProofV1> {
    let mut response = approval_response(root, approval, height).await?;
    let status = response.status();
    let media_values = response.headers().get_all("content-type");
    let mut media_values = media_values.iter();
    let media = media_values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| eyre!("AMX proof response omitted a valid Content-Type"))?
        .to_owned();
    ensure!(
        media_values.next().is_none(),
        "AMX proof response repeated Content-Type"
    );
    let maximum = if status.is_success() {
        MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1
    } else {
        iroha_torii_shared::amx_approval_read::AMX_APPROVAL_READ_FAILURE_MAX_BYTES
    };
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes
                .len()
                .checked_add(chunk.len())
                .is_some_and(|len| len <= maximum)
        );
        bytes.extend_from_slice(&chunk);
    }
    if matches!(
        status,
        reqwest::StatusCode::CONFLICT | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) {
        let failure =
            iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1::decode_response(
                status.as_u16(),
                &media,
                &bytes,
                approval,
                &account(&relay(root.index)),
                height,
            )
            .map_err(|error| eyre!(error))?;
        return Err(failure.into());
    }
    ensure!(
        status == reqwest::StatusCode::OK,
        "AMX proof read failed with terminal HTTP {status}"
    );
    ensure!(
        media == "application/x-norito",
        "AMX proof response has invalid media type"
    );
    Ok(AmxDebitApprovalProofV1::decode_frame(&bytes)?)
}

fn record_unique_delivery(
    retained: &mut Option<(
        u64,
        iroha_crypto::HashOf<iroha_data_model::transaction::SignedTransaction>,
    )>,
    candidate: (
        u64,
        iroha_crypto::HashOf<iroha_data_model::transaction::SignedTransaction>,
    ),
) -> Result<()> {
    ensure!(
        retained.is_none(),
        "one AMX obligation has more than one authenticated successful Settle carrier"
    );
    *retained = Some(candidate);
    Ok(())
}

#[test]
fn successful_delivery_inventory_refuses_a_second_success_without_replacing_original() {
    let identity = |byte| {
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([byte; 32]))
    };
    let original = (2, identity(0x11));
    let mut retained = None;
    record_unique_delivery(&mut retained, original).unwrap();
    for candidate in [original, (3, identity(0x22))] {
        assert!(record_unique_delivery(&mut retained, candidate).is_err());
        assert_eq!(retained, Some(original));
    }
}

#[cfg(test)]
mod balance_observation_tests {
    use super::*;

    #[test]
    fn balances_only_wait_on_an_authenticated_named_previous_state() {
        let (chain, approval, signer) =
            iroha_core::sumeragi::test_chain::native_amx_approval_route_fixture();
        let mut verifier = SumeragiFinalityVerifier::new(
            chain.genesis(),
            chain.state().chain_id_ref().as_str(),
            chain
                .validators()
                .iter()
                .map(
                    |(peer, pop)| iroha_data_model::sumeragi_finality::FinalityValidator {
                        public_key: peer.public_key().clone(),
                        proof_of_possession: pop.clone(),
                    },
                )
                .collect(),
        )
        .unwrap();
        let mut tip = None;
        for height in 1..=chain.height() {
            tip = Some(
                verifier
                    .verify(
                        &iroha_core::sumeragi::finality::build_proof(&chain.state().view(), height)
                            .unwrap(),
                    )
                    .unwrap(),
            );
        }
        let tip = tip.unwrap();
        let pool = iroha_allocation::AllocationBudget::new(256 * 1024 * 1024);
        let relay = AccountId::new(signer.public_key().clone());
        let proof = chain
            .state()
            .with_native_amx_debit_approval_snapshot_v1(
                &chain.committed(chain.height()),
                &approval,
                &relay,
                &pool,
                |world, permissions| {
                    Ok(AmxDebitApprovalProofV1 {
                        world: world.clone(),
                        relay_permissions: permissions.clone(),
                    })
                },
            )
            .unwrap();
        let custody = AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
            b"iroha-native-amx-custody-v1",
            &[chain.network_id().as_bytes()],
        ));
        let assets = [
            approval.debited_asset.clone(),
            AssetId::with_scope(
                approval.debited_asset.definition().clone(),
                relay,
                AssetBalanceScope::Dataspace(approval.dataspace),
            ),
            AssetId::with_scope(
                approval.debited_asset.definition().clone(),
                custody,
                AssetBalanceScope::Dataspace(approval.dataspace),
            ),
        ];
        assert!(balance_observation_from_proof(&proof, &tip, &assets, [1_000, 0, 0], &[]).unwrap());
        assert!(
            !balance_observation_from_proof(&proof, &tip, &assets, [875, 125, 0], &[[1_000, 0, 0]])
                .unwrap()
        );
        assert!(
            balance_observation_from_proof(&proof, &tip, &assets, [875, 125, 0], &[[900, 0, 100]])
                .is_err(),
            "an unexpected authenticated balance is not a known pending state"
        );
        let mut invalid = proof;
        invalid.world.schema_hash = iroha_crypto::Hash::new(b"substituted schema");
        assert!(
            balance_observation_from_proof(
                &invalid,
                &tip,
                &assets,
                [875, 125, 0],
                &[[1_000, 0, 0]]
            )
            .is_err(),
            "an invalid World proof must not become pending"
        );
    }
}

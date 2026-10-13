//! Shared economic workload for the two release benchmark profiles.
//!
//! This is N primary payments plus one mandatory sponsor reimbursement across
//! N exact dataspace buckets, composed with the retained benchmark session owner.

use super::*;
use iroha::data_model::{
    isi::settlement::{
        AtomicSettlementMovement, AtomicSettlementMovements, SettleAtomic, SettlementDetails,
        SettlementReceipt,
    },
    query::settlement::FindSettlementReceiptById,
};
use iroha_executor_data_model::permission::query::CanReadAllLedgerData;

#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::JsonSerialize)]
pub(super) struct BenchmarkPaymentV1 {
    pub(super) source: AssetId,
    pub(super) recipient: AccountId,
    pub(super) amount: u64,
}

#[derive(
    Clone, Debug, PartialEq, Eq, norito::Encode, norito::JsonSerialize, norito::NoritoSchema,
)]
#[norito_schema(
    name = "integration_tests::nexus::atomic_private_settlement_localnet::MatchedBenchmarkWorkloadV1"
)]
pub(super) struct MatchedBenchmarkWorkloadV1 {
    version: u8,
    participants: u16,
    seed: u64,
    session_attempt_index: u64,
    warmup: bool,
    sponsor: AccountId,
    /// Route order, independent of the canonical movement order in SettleAtomic.
    pub(super) payments: Vec<BenchmarkPaymentV1>,
    /// A separate economic movement required by the private V1 protocol.
    reimbursement: BenchmarkPaymentV1,
}

fn material(
    participants: usize,
    seed: u64,
    session_attempt_index: u64,
    warmup: bool,
    ordinal: usize,
    role: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"iroha:matched-benchmark-workload:v1\0");
    digest.update((participants as u64).to_le_bytes());
    digest.update(seed.to_le_bytes());
    digest.update(session_attempt_index.to_le_bytes());
    digest.update([u8::from(warmup)]);
    digest.update((ordinal as u64).to_le_bytes());
    digest.update(role);
    digest.finalize().into()
}

impl MatchedBenchmarkWorkloadV1 {
    pub(super) fn new(
        participants: usize,
        seed: u64,
        session_attempt_index: u64,
        warmup: bool,
    ) -> Result<Self> {
        // The release matrix is bounded by 16. In particular, N=255 plus the
        // required reimbursement cannot fit SettleAtomic's 255-movement bound.
        ensure!(
            [2, 3, 4, 8, 16].contains(&participants),
            "unsupported matched benchmark N"
        );
        let mut payments = Vec::with_capacity(participants);
        for ordinal in 0..participants {
            let key = |role: &[u8]| -> Result<KeyPair> {
                Ok(KeyPair::try_from_seed(
                    material(
                        participants,
                        seed,
                        session_attempt_index,
                        warmup,
                        ordinal,
                        role,
                    )
                    .to_vec(),
                    Algorithm::Ed25519,
                )?)
            };
            let domain = Self::domain(participants, seed, session_attempt_index, warmup, ordinal)?;
            let definition = AssetDefinitionId::derive_from_components(domain, "cbdc".parse()?);
            payments.push(BenchmarkPaymentV1 {
                source: AssetId::with_scope(
                    definition,
                    AccountId::new(key(b"payer")?.public_key().clone()),
                    AssetBalanceScope::Dataspace(DataSpaceId::new((ordinal + 1) as u64)),
                ),
                recipient: AccountId::new(key(b"recipient")?.public_key().clone()),
                amount: 42 + ordinal as u64,
            });
        }
        let reimbursement = BenchmarkPaymentV1 {
            source: payments[0].source.clone(),
            recipient: ALICE_ID.clone(),
            amount: 5,
        };
        let workload = Self {
            version: 1,
            participants: participants as u16,
            seed,
            session_attempt_index,
            warmup,
            sponsor: ALICE_ID.clone(),
            payments,
            reimbursement,
        };
        workload.validate()?;
        Ok(workload)
    }

    pub(super) fn from_request(request: &RealProcessBenchmarkRequestV1) -> Result<Self> {
        Self::new(
            request.participants,
            request.seed,
            request.session_attempt_index,
            request.payload.warmup,
        )
    }

    fn domain(
        participants: usize,
        seed: u64,
        session_attempt_index: u64,
        warmup: bool,
        ordinal: usize,
    ) -> Result<DomainId> {
        let identity = material(
            participants,
            seed,
            session_attempt_index,
            warmup,
            ordinal,
            b"asset-definition",
        );
        DomainId::try_new(
            format!("matched{}", hex::encode(&identity[..16])),
            participant_dataspace_alias(ordinal),
        )
        .map_err(Into::into)
    }

    pub(super) fn payer_key(&self, ordinal: usize) -> Result<KeyPair> {
        ensure!(ordinal < self.payments.len(), "unknown workload payer");
        Ok(KeyPair::try_from_seed(
            material(
                usize::from(self.participants),
                self.seed,
                self.session_attempt_index,
                self.warmup,
                ordinal,
                b"payer",
            )
            .to_vec(),
            Algorithm::Ed25519,
        )?)
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && [2, 3, 4, 8, 16].contains(&usize::from(self.participants))
                && self.payments.len() == usize::from(self.participants)
                && self.sponsor == *ALICE_ID,
            "invalid matched workload identity"
        );
        let mut accounts = BTreeSet::new();
        let mut definitions = BTreeSet::new();
        for (ordinal, payment) in self.payments.iter().enumerate() {
            let recipient_key = KeyPair::try_from_seed(
                material(
                    usize::from(self.participants),
                    self.seed,
                    self.session_attempt_index,
                    self.warmup,
                    ordinal,
                    b"recipient",
                )
                .to_vec(),
                Algorithm::Ed25519,
            )?;
            let definition = AssetDefinitionId::derive_from_components(
                Self::domain(
                    usize::from(self.participants),
                    self.seed,
                    self.session_attempt_index,
                    self.warmup,
                    ordinal,
                )?,
                "cbdc".parse()?,
            );
            ensure!(
                payment.source.account()
                    == &AccountId::new(self.payer_key(ordinal)?.public_key().clone())
                    && payment.recipient == AccountId::new(recipient_key.public_key().clone())
                    && payment.source.definition() == &definition
                    && payment.source.scope()
                        == &AssetBalanceScope::Dataspace(DataSpaceId::new((ordinal + 1) as u64))
                    && payment.amount == 42 + ordinal as u64
                    && payment.source.account() != &self.sponsor
                    && payment.recipient != self.sponsor
                    && accounts.insert(payment.source.account().clone())
                    && accounts.insert(payment.recipient.clone())
                    && definitions.insert(definition),
                "matched workload payment differs from deterministic identity"
            );
        }
        ensure!(
            self.reimbursement
                == (BenchmarkPaymentV1 {
                    source: self.payments[0].source.clone(),
                    recipient: self.sponsor.clone(),
                    amount: 5
                }),
            "mandatory reimbursement differs"
        );
        self.movements()?;
        Ok(())
    }

    pub(super) fn digest(&self) -> Result<String> {
        self.validate()?;
        let mut bytes = b"iroha:matched-benchmark-economic-vector:v1\0".to_vec();
        bytes.extend(norito::encode_canonical(self)?);
        Ok(sha256_hex(&bytes))
    }

    pub(super) fn movements(&self) -> Result<AtomicSettlementMovements> {
        let mut movements = self
            .payments
            .iter()
            .chain(std::iter::once(&self.reimbursement))
            .map(|payment| AtomicSettlementMovement {
                source: payment.source.clone(),
                recipient: payment.recipient.clone(),
                quantity: Quantity::from(payment.amount),
            })
            .collect::<Vec<_>>();
        movements.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
        AtomicSettlementMovements::try_from(movements).map_err(|error| eyre!(error))
    }

    pub(super) fn settlement(
        &self,
        network_id: iroha::data_model::NetworkId,
        expiry: u64,
    ) -> Result<SettleAtomic> {
        Ok(SettleAtomic::new(
            network_id,
            iroha::data_model::isi::SettlementId::new(
                self.payments
                    .first()
                    .ok_or_else(|| eyre!("empty payment vector"))?
                    .source
                    .account()
                    .clone(),
                format!("matched_{}", self.digest()?).parse()?,
            ),
            self.movements()?,
            NonZeroU64::new(expiry).ok_or_else(|| eyre!("zero settlement expiry"))?,
            Metadata::default(),
        ))
    }

    pub(super) fn private_data(&self) -> Result<Vec<PrivateSettlementLegPrivateData>> {
        self.validate()?;
        let digest = self.digest()?;
        self.payments
            .iter()
            .enumerate()
            .map(|(ordinal, payment)| {
                Ok(PrivateSettlementLegPrivateData {
                    payer: self.payer_key(ordinal)?,
                    recipient: KeyPair::try_from_seed(
                        material(
                            usize::from(self.participants),
                            self.seed,
                            self.session_attempt_index,
                            self.warmup,
                            ordinal,
                            b"recipient",
                        )
                        .to_vec(),
                        Algorithm::Ed25519,
                    )?,
                    amount: u128::from(payment.amount),
                    memo: format!("matched:{digest}:{ordinal}").into_bytes(),
                })
            })
            .collect()
    }

    pub(super) fn governance(
        &self,
        routes: &[PrivateSettlementRouteV1],
        activation: u64,
        expiry: u64,
    ) -> Result<Vec<GovernedLeg>> {
        self.validate()?;
        ensure!(
            routes.len() == self.payments.len(),
            "matched governance route count differs"
        );
        for (ordinal, route) in routes.iter().enumerate() {
            ensure!(
                route.dataspace_id == DataSpaceId::new((ordinal + 1) as u64)
                    && route.lane_id == LaneId::new((ordinal + 1) as u32),
                "matched governance route differs"
            );
        }
        let definitions = self
            .payments
            .iter()
            .map(|p| p.source.definition().clone())
            .collect::<Vec<_>>();
        let mut governed =
            governed_legs_with_asset_definitions(routes, activation, expiry, Some(&definitions))?;
        // Pool and hidden asset-binding material is unique per economic attempt;
        // the existing signed governance and proof owners validate these values.
        for (ordinal, leg) in governed.iter_mut().enumerate() {
            leg.governance = PrivateSettlementPoolGovernanceV1::from_restricted_mapping(
                leg.route,
                PrivacyPoolIdV1::new(material(
                    usize::from(self.participants),
                    self.seed,
                    self.session_attempt_index,
                    self.warmup,
                    ordinal,
                    b"pool",
                )),
                definitions[ordinal].clone(),
                material(
                    usize::from(self.participants),
                    self.seed,
                    self.session_attempt_index,
                    self.warmup,
                    ordinal,
                    b"asset-binding",
                ),
                &leg.policy,
                leg.governance.body.lifecycle,
            )?;
        }
        Ok(governed)
    }

    pub(super) fn genesis(&self) -> Result<Vec<Vec<InstructionBox>>> {
        self.validate()?;
        let mut transactions = vec![vec![
            Grant::account_permission(CanReadAllLedgerData, self.sponsor.clone()).into(),
        ]];
        for (ordinal, payment) in self.payments.iter().enumerate() {
            let domain = Self::domain(
                usize::from(self.participants),
                self.seed,
                self.session_attempt_index,
                self.warmup,
                ordinal,
            )?;
            transactions.push(vec![
                Register::domain(Domain::new(domain.clone())).into(),
                Register::asset_definition(AssetDefinition::numeric(
                    payment.source.definition().clone(),
                    format!("Matched CBDC {}", ordinal + 1),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(domain),
                ))
                .into(),
                Register::account(Account::new(payment.source.account().clone())).into(),
                Register::account(Account::new(payment.recipient.clone())).into(),
            ]);
            // Both profiles have this exact public genesis. Private value is
            // separately bootstrapped into a disjoint pool by the existing owner.
            // This is synthetic prefunding, not a claim of a public-to-private deposit.
            transactions.push(vec![
                Mint::asset_quantity(
                    payment.amount + 8 + if ordinal == 0 { 5 } else { 0 },
                    payment.source.clone(),
                )
                .into(),
            ]);
        }
        transactions.push(
            self.payments
                .iter()
                .map(|payment| {
                    Mint::asset_quantity(
                        NEXUS_FEE_SEED_BALANCE,
                        AssetId::new(
                            nexus_fee_asset_definition_id(),
                            payment.source.account().clone(),
                        ),
                    )
                    .into()
                })
                .collect(),
        );
        Ok(transactions)
    }
}

pub(super) fn matched_benchmark_builder(
    shape: TopologyShape,
    workloads: &[MatchedBenchmarkWorkloadV1],
    network_seed: &str,
) -> Result<NetworkBuilder> {
    ensure!(!workloads.is_empty(), "session workload set is empty");
    let mut post = Vec::new();
    for (index, workload) in workloads.iter().enumerate() {
        let mut genesis = workload.genesis()?;
        if index != 0 {
            genesis.remove(0);
        } // The shared AllLedger grant occurs once.
        post.extend(genesis);
    }
    Ok(localnet_builder(shape)
        .with_base_seed(network_seed.to_owned())
        .with_genesis_block_and_committee_validator_entries(move |topology, entries, committee| {
            let mut processes = topology.iter().cloned().collect::<Vec<_>>();
            processes.extend(committee.iter().map(|entry| entry.peer.clone()));
            let mut transactions = genesis_post_topology(shape, &processes, &committee);
            transactions.extend(post.clone());
            unexecuted_genesis_factory_with_post_topology(
                Vec::new(),
                transactions,
                topology,
                entries,
            )
        })
        .with_genesis_instruction(npos_override_instruction(VALIDATORS_PER_LANE))
        .with_private_settlement_route_control())
}

pub(super) fn matched_workload_record(
    request: &RealProcessBenchmarkRequestV1,
    request_sha: &str,
    network_id: iroha::data_model::NetworkId,
) -> Result<HarnessJsonValue> {
    let workload = MatchedBenchmarkWorkloadV1::from_request(request)?;
    #[derive(norito::JsonSerialize)]
    struct Record<'a> {
        version: u8,
        protocol: &'static str,
        request_id: &'a str,
        invocation_nonce: &'a str,
        request_sha256: &'a str,
        configuration_sha256: &'a str,
        network_id: iroha::data_model::NetworkId,
        economic_vector_sha256: String,
        canonical_economic_vector_hex: String,
        workload_manifest_sha256: &'a str,
        workload: &'a MatchedBenchmarkWorkloadV1,
    }
    norito::json::to_value(&Record {
        version: 1,
        protocol: "AtomicPrivateSettlementV1",
        request_id: &request.request_id,
        invocation_nonce: &request.invocation_nonce,
        request_sha256: request_sha,
        configuration_sha256: &request.configuration_sha256,
        network_id,
        economic_vector_sha256: workload.digest()?,
        canonical_economic_vector_hex: hex::encode(norito::encode_canonical(&workload)?),
        workload_manifest_sha256: &request.workload_manifest_sha256,
        workload: &workload,
    })
    .map_err(Into::into)
}

pub(super) fn publish_matched_workload(
    request: &RealProcessBenchmarkRequestV1,
    request_sha: &str,
    network: &Network,
    workload: &MatchedBenchmarkWorkloadV1,
    root: &Path,
) -> Result<()> {
    ensure!(
        *workload == MatchedBenchmarkWorkloadV1::from_request(request)?,
        "request/workload differs"
    );
    ensure!(
        root.canonicalize()? == root,
        "benchmark evidence root must be canonical"
    );
    write_smoke_evidence(
        root,
        "matched-workload.json",
        &matched_workload_record(request, request_sha, network.network_id())?,
    )?;
    Ok(())
}

pub(super) fn transparent_control_balance_expectations(
    workload: &MatchedBenchmarkWorkloadV1,
    initial: &[TransparentControlBalanceExpectation],
) -> Result<Vec<TransparentControlBalanceExpectation>> {
    workload.validate()?;
    let movements = workload.movements()?;
    let expected_ids = movements
        .as_slice()
        .iter()
        .flat_map(|m| [m.source.clone(), m.destination()])
        .collect::<BTreeSet<_>>();
    let mut balances = initial
        .iter()
        .map(|row| (row.asset_id.clone(), row.amount.clone()))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        balances.len() == initial.len()
            && balances.keys().cloned().collect::<BTreeSet<_>>() == expected_ids,
        "prestate omits or duplicates an economic bucket"
    );
    ensure!(
        initial
            .windows(2)
            .all(|pair| pair[0].asset_id < pair[1].asset_id),
        "prestate economic buckets are not in canonical order"
    );
    for movement in movements.as_slice() {
        let source = balances
            .get_mut(&movement.source)
            .expect("complete source inventory");
        *source = source
            .checked_sub(&movement.quantity)
            .wrap_err("prestate source is underfunded")?;
        let destination = balances
            .get_mut(&movement.destination())
            .expect("complete destination inventory");
        *destination = destination
            .checked_add(&movement.quantity)
            .wrap_err("destination overflow")?;
    }
    Ok(balances
        .into_iter()
        .map(|(asset_id, amount)| TransparentControlBalanceExpectation { asset_id, amount })
        .collect())
}

pub(super) fn coherent_control_balances(
    client: &Client,
    ids: &[AssetId],
) -> Result<Vec<TransparentControlBalanceExpectation>> {
    let assets = client.client().query(FindAssets::new()).execute_all()?;
    let mut values = BTreeMap::new();
    for asset in assets {
        ensure!(
            values
                .insert(asset.id.clone(), asset.value().clone())
                .is_none(),
            "duplicate coherent asset row"
        );
    }
    // FindAssets is a complete coherent WSV snapshot. Absent exact buckets have
    // zero quantity; we do not interpret a failed point query as a zero balance.
    Ok(ids
        .iter()
        .map(|id| TransparentControlBalanceExpectation {
            asset_id: id.clone(),
            amount: values.get(id).cloned().unwrap_or_else(Quantity::zero),
        })
        .collect())
}

pub(super) fn read_matched_control_prestate(
    network: &Network,
    shape: TopologyShape,
    workload: &MatchedBenchmarkWorkloadV1,
) -> Result<Vec<TransparentControlBalanceExpectation>> {
    let ids = workload
        .movements()?
        .as_slice()
        .iter()
        .flat_map(|m| [m.source.clone(), m.destination()])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let peers = network.all_peers().collect::<Vec<_>>();
    ensure!(
        peers.len() == shape.process_count(),
        "prestate omits a validator"
    );
    let first = coherent_control_balances(&peers[0].client(), &ids)?;
    for peer in &peers[1..] {
        ensure!(
            coherent_control_balances(&peer.client(), &ids)? == first,
            "validators disagree on authenticated exact prestate"
        );
    }
    transparent_control_balance_expectations(workload, &first)?;
    Ok(first)
}

pub(super) fn validate_matched_business_receipt(
    receipt: &SettlementReceipt,
    settlement: &SettleAtomic,
    carrier: &BlockHeader,
) -> Result<()> {
    let expected = settlement
        .movements
        .resolve()
        .map_err(|error| eyre!(error))?;
    ensure!(
        receipt.authority == *ALICE_ID
            && receipt.metadata == settlement.metadata
            && receipt.block_height == carrier.height().get()
            && receipt.block_hash == carrier.hash()
            && receipt.executed_at_ms == carrier.creation_time_ms,
        "business receipt authority/metadata/carrier differs"
    );
    ensure!(
        matches!(&receipt.details, SettlementDetails::Atomic(iroha_data_model::isi::AtomicSettlementDetails { movements, intent_hash })
        if *movements == expected && *intent_hash == settlement.intent_hash()?),
        "business receipt differs from complete signed matched intent"
    );
    Ok(())
}

pub(super) fn wait_for_matched_business_receipt(
    network: &Network,
    settlement: &SettleAtomic,
    carrier: &BlockHeader,
    started: Instant,
) -> Result<SettlementReceipt> {
    while started.elapsed() <= FINALITY_TIMEOUT {
        let mut observed = Vec::new();
        for peer in network.all_peers() {
            // network.client() is ALICE, the actual carrier sponsor and the
            // explicitly granted AllLedger reader; no payer-key query substitution.
            if let Ok(receipt) =
                peer.client()
                    .client()
                    .query_single(FindSettlementReceiptById::new(
                        settlement.settlement_id.clone(),
                    ))
            {
                validate_matched_business_receipt(&receipt, settlement, carrier)?;
                observed.push(receipt);
            }
        }
        if observed.len() == network.all_peers().count() {
            let first = observed.remove(0);
            ensure!(
                observed.iter().all(|receipt| receipt == &first),
                "validators disagree on immutable business receipt"
            );
            return Ok(first);
        }
        thread::sleep(POLL_INTERVAL);
    }
    // The existing canonical-carrier completion budget also bounds its joined
    // business receipt. No new deadline or retry classification is introduced.
    Err(benchmark_deadline_error(
        BenchmarkDeadlineStageV1::CanonicalCarrier,
        FINALITY_TIMEOUT,
        started.elapsed(),
    )
    .wrap_err("matched business receipt did not converge"))
}

pub(super) fn validate_matched_replay_details(
    details: &iroha_torii_shared::PipelineTransactionDetailsResponse,
    replay: &SignedTransaction,
    settlement: &SettleAtomic,
) -> Result<()> {
    use iroha::data_model::{
        ValidationFail, isi::error::InstructionExecutionError,
        transaction::error::TransactionRejectionReason,
    };
    let transaction = &details.transaction;
    let expected_entrypoint = replay.hash_as_entrypoint();
    ensure!(
        details.hash == expected_entrypoint.to_string()
            && transaction.entrypoint_hash() == &expected_entrypoint
            && transaction.entrypoint().hash() == expected_entrypoint
            && transaction.output_hash() == &iroha_crypto::HashOf::new(transaction.output()),
        "replay details substituted transaction or result binding"
    );
    let TransactionEntrypoint::External(retained) = transaction.entrypoint() else {
        return Err(eyre!("replay details are not an external transaction"));
    };
    ensure!(
        retained == replay && retained.hash() == replay.hash(),
        "replay details substituted signed transaction"
    );
    let expected = format!(
        "settlement id `{}` has already been committed",
        settlement.settlement_id
    );
    ensure!(
        matches!(&transaction.result().0,
        Err(TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::InvariantViolation(message)))) if message.as_ref() == expected),
        "replay lacks the typed committed-settlement failure"
    );
    Ok(())
}

pub(super) fn wait_for_matched_replay_rejection(
    network: &Network,
    replay: &SignedTransaction,
    settlement: &SettleAtomic,
) -> Result<()> {
    use iroha::data_model::{ValidationFail, query::error::QueryExecutionFail};
    use iroha::query::QueryError;
    let started = Instant::now();
    while started.elapsed() <= FINALITY_TIMEOUT {
        let mut retained = Vec::new();
        for peer in network.all_peers() {
            let client = peer.client();
            let details = match client
                .client()
                .get_transaction_details(replay.hash_as_entrypoint())
            {
                Ok(details) => details,
                Err(QueryError::Validation(ValidationFail::QueryFailed(
                    QueryExecutionFail::NotFound | QueryExecutionFail::CapacityLimit,
                ))) => continue,
                Err(error) => {
                    return Err(eyre::Report::new(error)
                        .wrap_err("authenticated replay details query failed"));
                }
            };
            validate_matched_replay_details(&details, replay, settlement)?;
            let blocks = client.client().query(FindBlocks::new()).execute_all()?;
            let matching = blocks
                .iter()
                .filter(|block| &block.hash() == details.transaction.block_hash())
                .collect::<Vec<_>>();
            ensure!(
                matching.len() <= 1,
                "replay containing block was duplicated"
            );
            let Some(block) = matching.first() else {
                continue;
            };
            ensure!(
                details.transaction.verify_inclusion_in_block(block),
                "replay failure lacks exact entrypoint/result inclusion in canonical block"
            );
            retained.push(norito::encode_canonical(&details.transaction)?);
        }
        if retained.len() == network.all_peers().count() {
            ensure!(
                retained.windows(2).all(|pair| pair[0] == pair[1]),
                "validators disagree on exact rejected replay record"
            );
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(benchmark_deadline_error(
        BenchmarkDeadlineStageV1::CanonicalCarrier,
        FINALITY_TIMEOUT,
        started.elapsed(),
    )
    .wrap_err("typed rejected replay did not converge on every canonical peer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network_id() -> iroha::data_model::NetworkId {
        iroha::data_model::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(hash(0xE1)),
        )
    }

    fn prestate(
        workload: &MatchedBenchmarkWorkloadV1,
        source_amount: u64,
    ) -> Vec<TransparentControlBalanceExpectation> {
        let movements = workload.movements().unwrap();
        let sources = movements
            .as_slice()
            .iter()
            .map(|m| m.source.clone())
            .collect::<BTreeSet<_>>();
        movements
            .as_slice()
            .iter()
            .flat_map(|m| [m.source.clone(), m.destination()])
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|asset_id| {
                let amount = Quantity::from(if sources.contains(&asset_id) {
                    source_amount
                } else {
                    13_u64
                });
                TransparentControlBalanceExpectation { asset_id, amount }
            })
            .collect()
    }

    #[test]
    fn matched_workload_profiles_share_exact_vector_and_genesis() {
        iroha_test_network::init_instruction_registry();
        let mut private = benchmark_terminal_request_fixture();
        private.payload.profile = "private".to_owned();
        let a = MatchedBenchmarkWorkloadV1::from_request(&private).unwrap();
        let mut control = benchmark_terminal_request_fixture();
        control.payload.profile = "transparent_control".to_owned();
        control.request_id = "d".repeat(64);
        control.invocation_nonce = "e".repeat(64);
        let b = MatchedBenchmarkWorkloadV1::from_request(&control).unwrap();
        assert_eq!(a, b);
        let frame = norito::encode_canonical(&a).unwrap();
        assert_eq!(frame, norito::encode_canonical(&b).unwrap());
        let header = norito::core::Header::read(&mut frame.as_slice()).unwrap();
        assert_eq!(
            header.schema,
            norito::core::schema_hash_for_name(
                "integration_tests::nexus::atomic_private_settlement_localnet::MatchedBenchmarkWorkloadV1"
            )
        );
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());
        assert_eq!(
            norito::encode_canonical(&a.genesis().unwrap()).unwrap(),
            norito::encode_canonical(&b.genesis().unwrap()).unwrap()
        );
        assert_ne!(private.request_id, control.request_id);
    }

    #[test]
    fn matched_workload_attempt_coordinates_are_disjoint_and_bounded() {
        let baseline = MatchedBenchmarkWorkloadV1::new(3, 8, 9, false).unwrap();
        for (n, seed, session_attempt_index, warmup) in [
            (2, 8, 9, false),
            (3, 7, 9, false),
            (3, 8, 10, false),
            (3, 8, 9, true),
        ] {
            let changed =
                MatchedBenchmarkWorkloadV1::new(n, seed, session_attempt_index, warmup).unwrap();
            assert_ne!(changed.digest().unwrap(), baseline.digest().unwrap());
            assert_ne!(changed.payments[0].source, baseline.payments[0].source);
        }
        for n in [0, 1, 5, 17, 254, 255, 256] {
            assert!(MatchedBenchmarkWorkloadV1::new(n, 8, 9, false).is_err());
        }
    }

    #[test]
    fn matched_workload_rejects_payment_scope_identity_and_reimbursement_substitution() {
        let baseline = MatchedBenchmarkWorkloadV1::new(3, 8, 9, false).unwrap();
        for field in 0..7 {
            let mut altered = baseline.clone();
            let last = altered.payments.last_mut().unwrap();
            match field {
                0 => last.amount += 1,
                1 => last.recipient = ALICE_ID.clone(),
                2 => {
                    last.source = AssetId::with_scope(
                        last.source.definition().clone(),
                        ALICE_ID.clone(),
                        *last.source.scope(),
                    )
                }
                3 => {
                    last.source = AssetId::new(
                        last.source.definition().clone(),
                        last.source.account().clone(),
                    )
                }
                4 => {
                    last.source = AssetId::with_scope(
                        cbdc_asset_definition_id(0),
                        last.source.account().clone(),
                        *last.source.scope(),
                    )
                }
                5 => altered.reimbursement.amount = 0,
                6 => altered.reimbursement.source = altered.payments[1].source.clone(),
                _ => unreachable!(),
            }
            assert!(altered.validate().is_err(), "accepted field {field}");
        }
    }

    #[test]
    fn matched_control_contains_all_primary_payments_and_mandatory_reimbursement() {
        for n in [2, 3, 4, 8, 16] {
            let workload = MatchedBenchmarkWorkloadV1::new(n, 8, 9, false).unwrap();
            let settlement = workload.settlement(network_id(), 1000).unwrap();
            let movements = settlement.movements.as_slice();
            assert_eq!(movements.len(), n + 1);
            assert_eq!(
                movements
                    .iter()
                    .map(|m| m.source.scope())
                    .collect::<BTreeSet<_>>()
                    .len(),
                n
            );
            let permissions = transparent_control_permissions(&settlement).unwrap();
            assert_eq!(permissions.len(), n);
            assert!(permissions.iter().all(|permission| permission.intent_hash
                == settlement.intent_hash().unwrap()
                && permission.settlement_id == settlement.settlement_id));
            assert!(
                movements
                    .iter()
                    .any(|m| m.source == workload.reimbursement.source
                        && m.recipient == *ALICE_ID
                        && m.quantity == Quantity::from(5_u64))
            );
            assert!(
                movements
                    .windows(2)
                    .all(|p| (&p[0].source, &p[0].recipient) < (&p[1].source, &p[1].recipient))
            );
        }
    }

    #[test]
    fn matched_balance_delta_uses_observed_prestate_not_genesis_constants() {
        let workload = MatchedBenchmarkWorkloadV1::new(3, 8, 9, false).unwrap();
        for amount in [500, 1234, 9000] {
            let initial = prestate(&workload, amount);
            let finalized = transparent_control_balance_expectations(&workload, &initial).unwrap();
            for payment in &workload.payments {
                let debit = payment.amount
                    + if payment.source == workload.reimbursement.source {
                        5
                    } else {
                        0
                    };
                assert_eq!(
                    finalized
                        .iter()
                        .find(|r| r.asset_id == payment.source)
                        .unwrap()
                        .amount,
                    Quantity::from(amount - debit)
                );
                let destination = AssetId::with_scope(
                    payment.source.definition().clone(),
                    payment.recipient.clone(),
                    *payment.source.scope(),
                );
                assert_eq!(
                    finalized
                        .iter()
                        .find(|r| r.asset_id == destination)
                        .unwrap()
                        .amount,
                    Quantity::from(13 + payment.amount)
                );
            }
        }
    }

    #[test]
    fn matched_balance_delta_rejects_incomplete_duplicate_or_underfunded_prestate() {
        let workload = MatchedBenchmarkWorkloadV1::new(3, 8, 9, false).unwrap();
        let mut omitted = prestate(&workload, 1000);
        omitted.pop();
        assert!(transparent_control_balance_expectations(&workload, &omitted).is_err());
        let mut duplicate = prestate(&workload, 1000);
        duplicate.push(duplicate[0].clone());
        assert!(transparent_control_balance_expectations(&workload, &duplicate).is_err());
        let mut reordered = prestate(&workload, 1000);
        reordered.swap(0, 1);
        assert!(transparent_control_balance_expectations(&workload, &reordered).is_err());
        assert!(
            transparent_control_balance_expectations(&workload, &prestate(&workload, 1)).is_err()
        );
    }

    #[test]
    fn matched_private_governance_and_funding_bind_the_same_payments() {
        let workload = MatchedBenchmarkWorkloadV1::new(3, 8, 9, false).unwrap();
        let routes = (0..3)
            .map(|ordinal| PrivateSettlementRouteV1 {
                dataspace_id: DataSpaceId::new(ordinal + 1),
                lane_id: LaneId::new((ordinal + 1) as u32),
                lane_incarnation: hash(0xE0 + ordinal as u8),
            })
            .collect::<Vec<_>>();
        let governed = workload.governance(&routes, 301, 1301).unwrap();
        let data = workload.private_data().unwrap();
        let manifest = proof_manifest(network_id(), 301, 1301, &governed).unwrap();
        assert_eq!(manifest.sponsor, *ALICE_ID);
        assert_eq!(manifest.public_fee_intent, bounded_nexus_fee());
        assert_eq!(manifest.reimbursement_leg_ordinal, 0);
        for ordinal in 0..3 {
            let payment = &workload.payments[ordinal];
            assert_eq!(
                &governed[ordinal].governance.body.asset_definition_id,
                payment.source.definition()
            );
            assert_eq!(
                &AccountId::new(data[ordinal].payer.public_key().clone()),
                payment.source.account()
            );
            assert_eq!(
                AccountId::new(data[ordinal].recipient.public_key().clone()),
                payment.recipient
            );
            assert_eq!(data[ordinal].amount, u128::from(payment.amount));
            let funding = private_settlement_funding(
                network_id(),
                &governed[ordinal],
                ordinal,
                &data[ordinal],
            )
            .unwrap();
            assert_eq!(
                funding.opening.value,
                u128::from(payment.amount + 7 + if ordinal == 0 { 5 } else { 0 })
            );
            assert_ne!(funding.input_commitments[0], funding.input_commitments[1]);
        }
        let mut wrong = routes;
        wrong[2].dataspace_id = DataSpaceId::new(4);
        assert!(workload.governance(&wrong, 301, 1301).is_err());
    }

    #[test]
    fn matched_business_receipt_requires_complete_intent_and_canonical_carrier() {
        let workload = MatchedBenchmarkWorkloadV1::new(3, 8, 9, false).unwrap();
        let settlement = workload.settlement(network_id(), 1000).unwrap();
        let carrier = BlockHeader::new(NonZeroU64::new(500).unwrap(), None, None, 1234, 0);
        let receipt = SettlementReceipt {
            authority: ALICE_ID.clone(),
            metadata: Metadata::default(),
            block_height: 500,
            block_hash: carrier.hash(),
            executed_at_ms: 1234,
            details: SettlementDetails::Atomic(iroha_data_model::isi::AtomicSettlementDetails {
                movements: settlement.movements.resolve().unwrap(),
                intent_hash: settlement.intent_hash().unwrap(),
            }),
        };
        validate_matched_business_receipt(&receipt, &settlement, &carrier).unwrap();
        for field in 0..6 {
            let mut altered = receipt.clone();
            match field {
                0 => altered.authority = workload.payments[0].source.account().clone(),
                1 => altered.block_height += 1,
                2 => altered.block_hash = HashOf::from_untyped_unchecked(hash(0xF1)),
                3 => altered.executed_at_ms += 1,
                4 => {
                    if let SettlementDetails::Atomic(
                        iroha_data_model::isi::AtomicSettlementDetails { intent_hash, .. },
                    ) = &mut altered.details
                    {
                        *intent_hash = hash(0xF2);
                    }
                }
                5 => {
                    let mut movements = settlement.movements.resolve().unwrap().as_slice().to_vec();
                    movements.last_mut().unwrap().quantity = Quantity::one();
                    altered.details =
                        SettlementDetails::Atomic(iroha_data_model::isi::AtomicSettlementDetails {
                            movements: movements.try_into().unwrap(),
                            intent_hash: settlement.intent_hash().unwrap(),
                        });
                }
                _ => unreachable!(),
            }
            assert!(validate_matched_business_receipt(&altered, &settlement, &carrier).is_err());
        }
    }

    #[test]
    fn matched_replay_requires_exact_authenticated_transaction_and_typed_result() {
        use iroha::data_model::{
            ValidationFail,
            isi::error::InstructionExecutionError,
            query::CommittedTransaction,
            transaction::{
                TransactionBuilder, TransactionResult, error::TransactionRejectionReason,
            },
        };
        let settlement = MatchedBenchmarkWorkloadV1::new(3, 8, 9, false)
            .unwrap()
            .settlement(network_id(), 1000)
            .unwrap();
        let replay = TransactionBuilder::new(network_id(), ALICE_ID.clone(), bounded_nexus_fee())
            .with_instructions([InstructionBox::from(settlement.clone())])
            .sign(ALICE_KEYPAIR.private_key());
        let expected = format!(
            "settlement id `{}` has already been committed",
            settlement.settlement_id
        );
        let make = |reason: &str| {
            let result = TransactionResult::new(Err(TransactionRejectionReason::Validation(
                ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(
                    reason.to_owned().into(),
                )),
            )));
            let output = iroha::data_model::block::execution_output::ExecutionOutputV1::Network(
                iroha::data_model::block::execution_output::NetworkExecutionOutputV1 {
                    input_index: 0,
                    result,
                    completions: Vec::new(),
                },
            );
            iroha_torii_shared::PipelineTransactionDetailsResponse {
                hash: replay.hash_as_entrypoint().to_string(),
                transaction: CommittedTransaction {
                    block_hash: HashOf::from_untyped_unchecked(hash(77)),
                    entrypoint_hash: replay.hash_as_entrypoint(),
                    entrypoint_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
                    entrypoint: TransactionEntrypoint::External(replay.clone()),
                    output_hash: iroha_crypto::HashOf::new(&output),
                    output_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
                    output,
                },
            }
        };
        validate_matched_replay_details(&make(&expected), &replay, &settlement).unwrap();
        assert!(
            validate_matched_replay_details(&make("other invariant"), &replay, &settlement)
                .is_err()
        );
        let mut changed = make(&expected);
        changed.hash = hash(99).to_string();
        assert!(validate_matched_replay_details(&changed, &replay, &settlement).is_err());
        let mut changed = make(&expected);
        let iroha::data_model::block::execution_output::ExecutionOutputV1::Network(output) =
            &mut changed.transaction.output
        else {
            panic!("expected Network output");
        };
        output.result = TransactionResult::new(Ok(Default::default()));
        changed.transaction.output_hash = HashOf::new(&changed.transaction.output);
        assert!(validate_matched_replay_details(&changed, &replay, &settlement).is_err());
        let mut changed = make(&expected);
        changed.transaction.output_hash = HashOf::from_untyped_unchecked(hash(98));
        assert!(validate_matched_replay_details(&changed, &replay, &settlement).is_err());
    }
}

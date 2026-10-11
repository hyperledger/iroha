//! Synthetic original complete-effect source fixtures shared by native test consumers.
//!
//! Transfer facts are fixture input only: this builds typed effects and genuinely
//! materializes their typed-key roots. It never accepts retired ordinary wire or
//! treats supplied old transfer roots, proof bytes or World roots as effect roots.
//! These public deterministic fixtures confer no execution finality authority.

use super::prover;
use iroha_allocation::AllocationBudget;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    asset::AssetBalanceScope,
    fastpq::{
        FastpqExecutionAssetV1, FastpqExecutionBalanceV1, FastpqExecutionEffectContextV1,
        FastpqExecutionEffectKindV1, FastpqExecutionEffectStatementV1, FastpqExecutionEffectV1,
        FastpqExecutionEffectsV1, FastpqExecutionTransferV1, FastpqOrdinaryCompactArtifactV1,
        FastpqOrdinarySourceStatementLeafV1, FastpqPublicTransferStatementV1,
        FastpqSourceExecutionEntryV1, FastpqSourceExecutionKindV1, FastpqSourceRouteV1,
        FastpqSourceStatementContextV1, execution_effect_statement_digest_v1,
        execution_effects_digest_v1,
    },
    nexus::AxtAssetIncarnationV1,
};
use iroha_model_base::topology::DataSpaceId;
use prover::{
    gadgets::public_transfer_statement::{
        TransferSmtBuildLimits,
        execution_effect::{
            ExecutionEffectExpectations, ExecutionEffectLimits, SourceExecutionEffectStatement,
            materialization_allocation_bytes, materialize_source_execution_effect_statement,
        },
    },
    offline_compact::{
        ExecutionEffectVerificationLimits, ExpectedExecutionEffects, ExpectedStatement,
        ProvingError, ProvingLimits, VerificationError, VerificationLimits, VerifiedArtifact,
        execution_effect_profile_id, prove_quantity_ordinary_artifact,
        quantity_ordinary_allocation_bytes, quantity_ordinary_verification_allocation_bytes,
        verify_quantity_ordinary_artifact,
    },
};

/// Independently chosen synthetic source and its genuine finite typed-key statement.
#[derive(Clone)]
pub struct EffectFixture {
    /// Independently chosen synthetic complete source leaf.
    pub source: FastpqOrdinarySourceStatementLeafV1,
    /// Statement obtained by actual finite typed-key materialization.
    pub statement: FastpqExecutionEffectStatementV1,
}
impl EffectFixture {
    /// Preserve original fixture facts and occurrence order while building the actual new relation.
    pub fn from_transfer_facts(transfer: &FastpqPublicTransferStatementV1) -> Self {
        assert_eq!(&transfer.public_inputs.dsid[8..], &[0; 8]);
        let dsid = DataSpaceId::new(u64::from_le_bytes(
            transfer.public_inputs.dsid[..8].try_into().unwrap(),
        ));
        let context = FastpqExecutionEffectContextV1 {
            source: FastpqSourceStatementContextV1 {
                network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"complete-effect native synthetic source network"),
                )),
                height: 9,
            },
            entry: FastpqSourceExecutionEntryV1 {
                // Independently selected fixture source identity binds all original headers.
                entry_hash: Hash::new(norito::encode_canonical(&transfer.transcripts).unwrap()),
                execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
                route: FastpqSourceRouteV1::Unrouted,
                dataspace_id: dsid,
            },
        };
        let mut effects = Vec::new();
        for claim in &transfer.transcripts {
            for delta in &claim.deltas {
                let asset = FastpqExecutionAssetV1 {
                    definition: delta.asset_definition.clone(),
                    incarnation: AxtAssetIncarnationV1::try_from_bytes(
                        Hash::new(b"complete-effect native synthetic lifecycle").into(),
                    )
                    .unwrap(),
                };
                effects.push(FastpqExecutionEffectV1 {
                    ordinal: u32::try_from(effects.len()).unwrap(),
                    authority_digest: claim.authority_digest,
                    authorization_context: claim.poseidon_preimage_digest.unwrap_or_else(|| {
                        Hash::new(b"complete-effect native synthetic authorization context")
                    }),
                    kind: FastpqExecutionEffectKindV1::Transfer(FastpqExecutionTransferV1 {
                        source: FastpqExecutionBalanceV1 {
                            asset: asset.clone(),
                            account: delta.from_account.clone(),
                            scope: AssetBalanceScope::Global,
                        },
                        destination: FastpqExecutionBalanceV1 {
                            asset,
                            account: delta.to_account.clone(),
                            scope: AssetBalanceScope::Global,
                        },
                        amount: delta.amount.clone(),
                        source_before: delta.from_balance_before.clone(),
                        source_after: delta.from_balance_after.clone(),
                        destination_before: delta.to_balance_before.clone(),
                        destination_after: delta.to_balance_after.clone(),
                    }),
                });
            }
        }
        assert!(!effects.is_empty());
        let effects = FastpqExecutionEffectsV1 { context, effects };
        let source = FastpqOrdinarySourceStatementLeafV1 {
            source: context.source,
            statement_index: 0,
            entry_index: 0,
            effect_count: u32::try_from(effects.effects.len()).unwrap(),
            entry_hash: context.entry.entry_hash,
            execution_kind: context.entry.execution_kind,
            route: context.entry.route,
            dataspace_id: dsid,
            effects_digest: execution_effects_digest_v1(&effects).unwrap().into(),
            slot: transfer.public_inputs.slot,
            perm_root: transfer.public_inputs.perm_root,
            tx_set_hash: transfer.public_inputs.tx_set_hash,
        };
        let limits = ExecutionEffectLimits::default();
        let tree = TransferSmtBuildLimits::for_update_limit(2 * effects.effects.len()).unwrap();
        let demand = materialization_allocation_bytes(&effects, limits, tree).unwrap();
        let budget = AllocationBudget::new(demand);
        let mut reservation = budget.try_reserve_bytes(demand).unwrap();
        let built = materialize_source_execution_effect_statement(
            &effects,
            &source,
            limits,
            tree,
            &budget,
            &mut reservation,
        )
        .unwrap();
        let frame = norito::encode_canonical(&built.statement()).unwrap();
        let statement: FastpqExecutionEffectStatementV1 = norito::decode_canonical(&frame).unwrap();
        assert_eq!(statement.effects, effects);
        assert_eq!(
            (
                statement.public_inputs.old_root,
                statement.public_inputs.new_root
            ),
            built.witnesses().roots()
        );
        drop(built);
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
        Self { source, statement }
    }
    /// Derive expected facts from this independently retained fixture.
    pub fn facts(&self) -> ExecutionEffectExpectations {
        ExecutionEffectExpectations {
            effects_digest: execution_effects_digest_v1(&self.statement.effects).unwrap(),
            statement_digest: execution_effect_statement_digest_v1(&self.statement).unwrap(),
            public_inputs: self.statement.public_inputs,
        }
    }
    /// Borrow the independent full source and its complete expected statement facts.
    pub fn expected(&self) -> ExpectedExecutionEffects<'_> {
        ExpectedExecutionEffects {
            source: &self.source,
            statement: self.facts(),
        }
    }
    /// Project verified result fields for comparison with the common result owner.
    pub fn public_expectation(&self) -> ExpectedStatement {
        ExpectedStatement {
            inputs: self.statement.public_inputs,
            ordering_hash: self.statement.ordering_hash,
            public_statement_digest: self.facts().statement_digest.into(),
        }
    }
    /// Build canonical offered model data with an explicitly supplied opaque carrier.
    pub fn artifact(&self, bundle_frame: Vec<u8>) -> FastpqOrdinaryCompactArtifactV1 {
        FastpqOrdinaryCompactArtifactV1 {
            profile_id: execution_effect_profile_id(),
            source: self.source.clone(),
            statement: self.statement.clone(),
            bundle_frame,
        }
    }
    /// Invoke the genuine complete-effect producer under finite fixture-owned credit.
    pub fn prove(
        &self,
        proving: ProvingLimits,
        policy: VerificationLimits,
    ) -> Result<Vec<u8>, ProvingError> {
        self.prove_offered(&self.statement, self.expected(), proving, policy)
    }
    /// Invoke the genuine producer with explicit offered bytes and independent expectations.
    pub fn prove_offered(
        &self,
        offered: &FastpqExecutionEffectStatementV1,
        expected: ExpectedExecutionEffects<'_>,
        proving: ProvingLimits,
        policy: VerificationLimits,
    ) -> Result<Vec<u8>, ProvingError> {
        // Test-owned finite credit is derived from the valid independent fixture,
        // leaving deliberately deficient work/public policy to the actual producer.
        let mut funding_policy = limits(VerificationLimits::default());
        funding_policy.bundle.max_segments = self.statement.effects.effects.len();
        funding_policy.bundle.max_total_statement_bytes = funding_policy
            .bundle
            .max_total_statement_bytes
            .max(policy.bundle.max_total_statement_bytes);
        let funding_work = ProvingLimits {
            private_smt: TransferSmtBuildLimits::for_update_limit(
                2 * self.statement.effects.effects.len(),
            )
            .unwrap(),
            ..proving
        };
        let demand = quantity_ordinary_allocation_bytes(
            &self.statement.effects,
            funding_work,
            &funding_policy,
        )?;
        let budget = AllocationBudget::new(demand);
        let mut reservation = budget
            .try_reserve_bytes(demand)
            .map_err(prover::Error::from)?;
        let result = prove_quantity_ordinary_artifact(
            &SourceExecutionEffectStatement::from_owned(offered),
            expected,
            proving,
            &limits(policy),
            &budget,
            &mut reservation,
        );
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
        result.map(|produced| {
            assert_eq!(
                produced.verified().identity().artifact_digest,
                Into::<[u8; 32]>::into(Hash::new(produced.bytes()))
            );
            produced.into_parts().0
        })
    }
    /// Invoke the genuine verifier using this retained independent fixture.
    pub fn verify(
        &self,
        bytes: &[u8],
        policy: VerificationLimits,
    ) -> Result<VerifiedArtifact, VerificationError> {
        self.verify_expected(bytes, self.expected(), policy)
    }
    /// Invoke the genuine verifier with independently chosen expectation mutations.
    pub fn verify_expected(
        &self,
        bytes: &[u8],
        expected: ExpectedExecutionEffects<'_>,
        policy: VerificationLimits,
    ) -> Result<VerifiedArtifact, VerificationError> {
        // Allocate fixture credit from the baseline policy, not a deliberately
        // deficient tested policy, so the actual verifier observes each cap.
        let demand = quantity_ordinary_verification_allocation_bytes(
            &self.statement.effects,
            &limits(VerificationLimits::default()),
        )?;
        let budget = AllocationBudget::new(demand);
        let mut reservation = budget
            .try_reserve_bytes(demand)
            .map_err(prover::Error::from)?;
        let result = verify_quantity_ordinary_artifact(
            bytes,
            expected,
            &limits(policy),
            &budget,
            &mut reservation,
        );
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
        result
    }
}
/// Preserve the existing test's exact physical/codec caps while selecting complete effects.
pub fn limits(policy: VerificationLimits) -> ExecutionEffectVerificationLimits {
    ExecutionEffectVerificationLimits {
        transport: policy.transport,
        bundle: policy.bundle,
        max_segment_decode_allocation_charges: policy.max_segment_decode_allocation_charges,
        total_decode: policy.total_decode,
        public_statement: ExecutionEffectLimits {
            max_effects: policy.public_statement.max_deltas,
            max_rows: policy.public_statement.max_rows,
            max_public_bytes: policy.public_statement.max_public_bytes,
            max_unique_keys: policy.public_statement.max_unique_keys,
            max_allocation_steps: policy.public_statement.max_allocation_steps,
        },
    }
}

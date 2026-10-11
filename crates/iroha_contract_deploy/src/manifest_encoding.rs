//! Original physical ownership and cumulative encoding for deployment manifests.

use eyre::{Result, eyre};
use iroha::data_model::smart_contract::manifest::ContractManifest;
use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_crypto::PublicKey;
use norito::core::DecodeBudgetContext;

/// Own one prepaid finite codec allowance and its original cumulative counters.
/// Source manifests retain their existing artifact or native transaction owner.
pub(super) struct ManifestEncodingBudget {
    context: DecodeBudgetContext,
    grant: AllocationReservation,
    max_frame_bytes: usize,
}

impl ManifestEncodingBudget {
    /// Admit this operation before any counting, sorting or output allocation.
    pub(super) fn new() -> Result<Self> {
        let canonical = usize::try_from(
            iroha::data_model::parameter::system::TransactionParameters::default()
                .max_tx_bytes
                .get(),
        )?;
        let max_frame_bytes = super::MAX_DEPLOYMENT_TRANSACTION_BYTES.min(canonical);
        // Borrowed signature views and native sequence/field/Metadata encoders
        // stream the existing graph. Prepare creates two payloads (sign then
        // verify) and one compact signer. Any codec scratch still consumes this
        // same finite allowance; a refusal never renews it.
        let cumulative = max_frame_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES + 1))
            .ok_or_else(|| eyre!("manifest cumulative allowance overflow"))?;
        let pool = AllocationBudget::new(Self::pool_bytes(cumulative)?);
        Self::from_pool(&pool, max_frame_bytes, cumulative)
    }

    fn pool_bytes(cumulative_bytes: usize) -> Result<usize> {
        cumulative_bytes
            .checked_add(DecodeBudgetContext::allocation_layout().size())
            .ok_or_else(|| eyre!("manifest physical allowance overflow"))
    }

    /// Fund all accepted cumulative codec work, including count-pass scratch,
    /// before constructing its counter. Clones grant no replacement credit.
    fn from_pool(
        pool: &AllocationBudget,
        max_frame_bytes: usize,
        cumulative_bytes: usize,
    ) -> Result<Self> {
        if max_frame_bytes == 0 {
            return Err(eyre!("manifest frame ceiling must be nonzero"));
        }
        let mut prepaid = pool.try_reserve_bytes(Self::pool_bytes(cumulative_bytes)?)?;
        let context = DecodeBudgetContext::from_reservation(
            norito::DecodeLimits::new(
                max_frame_bytes,
                max_frame_bytes,
                max_frame_bytes,
                cumulative_bytes,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            ),
            &mut prepaid,
        )?;
        Ok(Self {
            context,
            grant: prepaid,
            max_frame_bytes,
        })
    }

    /// Partition the exact canonical output before materializing it.
    /// Retain the slice until the signing or verification payload is freed.
    pub(super) fn reserve_frame(
        &mut self,
        manifest: &ContractManifest,
    ) -> Result<AllocationReservation> {
        let bytes = self.context.with(|| {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::core::encoded_frame_len_bounded(
                &manifest.signature_payload(),
                self.max_frame_bytes,
            )
        })?;
        Ok(self.grant.try_partition_bytes(bytes)?)
    }

    /// Partition the original compact signer clone's exact existing geometry.
    /// Retain it until the manifest's native transaction has been consumed.
    pub(super) fn reserve_signer(&mut self, signer: &PublicKey) -> Result<AllocationReservation> {
        Ok(self
            .grant
            .try_partition_bytes(signer.retained_allocation_layout().size())?)
    }

    /// Borrow the same operation's original cumulative accounting.
    pub(super) fn context(&self) -> &DecodeBudgetContext {
        &self.context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::data_model::{
        isi::smart_contract_code::RegisterSmartContractCode, smart_contract::ContractArtifactId,
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_model_base::topology::DataSpaceId;

    fn manifest(name: &str) -> ContractManifest {
        ContractManifest {
            seiyaku_name: Some(name.into()),
            code_hash: Some(Hash::new(b"bounded deployment code")),
            abi_hash: Some(Hash::new(b"bounded deployment abi")),
            compiler_fingerprint: None,
            features_bitmap: Some(0),
            access_set_hints: None,
            permissions: Vec::new(),
            events: Vec::new(),
            enum_types: Vec::new(),
            entrypoints: None,
            states: None,
            error_messages: None,
            error_types: None,
            kotoba: None,
            provenance: None,
        }
    }

    fn key() -> KeyPair {
        KeyPair::try_from_seed(vec![0xDB; 32], Algorithm::Ed25519).unwrap()
    }

    fn owner(cap: usize, cumulative: usize) -> (AllocationBudget, ManifestEncodingBudget) {
        let pool = AllocationBudget::new(ManifestEncodingBudget::pool_bytes(cumulative).unwrap());
        let original = ManifestEncodingBudget::from_pool(&pool, cap, cumulative).unwrap();
        (pool, original)
    }

    #[test]
    fn canonical_service_owner_preserves_retained_transaction_and_nesting_limits() {
        let mut original = ManifestEncodingBudget::new().unwrap();
        assert_eq!(
            original.max_frame_bytes,
            super::super::MAX_DEPLOYMENT_TRANSACTION_BYTES
        );
        let frame = original.reserve_frame(&manifest("first")).unwrap();
        assert!(frame.remaining_bytes() <= original.max_frame_bytes);
        assert_eq!(original.context().consumed_allocated_bytes(), 0);
    }

    #[test]
    fn borrowed_nested_manifest_fields_fit_one_sign_then_verify_allowance() {
        use iroha::data_model::{
            events::{
                EventFilterBox,
                time::{ExecutionTime, TimeEventFilter},
            },
            smart_contract::{
                entrypoint::{
                    EntrypointArgumentFieldV1, EntrypointArgumentSchemaV1, EntrypointValueKindV1,
                    EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
                },
                manifest::{
                    AccessSetHints, ContractErrorMessage, ContractErrorTypeDescriptor,
                    ContractErrorVariantDescriptor, EntryPointKind, EntrypointDescriptor,
                    EntrypointParamDescriptor, KotobaTranslation, KotobaTranslationEntry,
                    StateDescriptor, TriggerCallback, TriggerDescriptor,
                },
            },
            trigger::action::Repeats,
        };
        let key = key();
        let mut metadata = iroha_model_base::metadata::Metadata::default();
        metadata.insert(
            "callback".parse().unwrap(),
            iroha_primitives::json::Json::new("original"),
        );
        let mut source = manifest("nested");
        source.access_set_hints = Some(AccessSetHints {
            read_keys: vec!["state:points".into()],
            write_keys: vec!["state:points".into()],
            dynamic_reads: Vec::new(),
            dynamic_writes: Vec::new(),
        });
        source.entrypoints = Some(vec![EntrypointDescriptor {
            name: "points".into(),
            kind: EntryPointKind::View,
            params: vec![EntrypointParamDescriptor {
                name: "cups".into(),
                type_name: "int".into(),
            }],
            argument_schema: Some(EntrypointArgumentSchemaV1 {
                fields: vec![EntrypointArgumentFieldV1 {
                    name: "cups".into(),
                    ty: EntrypointValueTypeV1 {
                        nodes: vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)],
                    },
                }],
            }),
            return_type: Some("int".into()),
            return_schema: Some(EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)],
            }),
            authorization:
                iroha::data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: vec!["state:points".into()],
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: vec![TriggerDescriptor {
                id: "wake".parse().unwrap(),
                repeats: Repeats::Indefinitely,
                filter: EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
                authority: None,
                metadata,
                callback: TriggerCallback {
                    namespace: None,
                    entrypoint: "points".into(),
                },
            }],
        }]);
        source.states = Some(vec![StateDescriptor {
            name: "points".into(),
            type_name: "int".into(),
        }]);
        source.error_types = Some(vec![ContractErrorTypeDescriptor {
            identity: "example/Coffee::Failure".into(),
            variants: vec![ContractErrorVariantDescriptor {
                name: "Missing".into(),
                code: 1,
            }],
        }]);
        source.error_messages = Some(vec![ContractErrorMessage {
            error_type: "example/Coffee::Failure".into(),
            code: 1,
            message: "No points".into(),
        }]);
        source.kotoba = Some(vec![KotobaTranslationEntry {
            msg_id: "missing".into(),
            translations: vec![KotobaTranslation {
                lang: "ja".into(),
                text: "残高不足".into(),
            }],
        }]);
        let mut original = ManifestEncodingBudget::new().unwrap();
        let signer = original.reserve_signer(key.public_key()).unwrap();
        let frame = original.reserve_frame(&source).unwrap();
        let bytes = frame.remaining_bytes();
        assert_eq!(original.context().consumed_allocated_bytes(), 0);
        let signed = source.try_signed(original.context(), bytes, &key).unwrap();
        drop(frame);
        let verification = original.reserve_frame(&signed).unwrap();
        assert_eq!(verification.remaining_bytes(), bytes);
        let payload = signed
            .signature_payload_bytes(original.context(), bytes)
            .unwrap();
        let provenance = signed.provenance.as_ref().unwrap();
        provenance
            .signature
            .verify(&provenance.signer, &payload)
            .unwrap();
        assert_eq!(
            original.context().consumed_allocated_bytes(),
            u64::try_from(2 * bytes + signer.remaining_bytes()).unwrap()
        );
        drop(payload);
        drop(verification);
        drop(signed);
        drop(signer);
    }

    #[test]
    fn signing_and_native_encoding_retain_original_exact_backings_and_refund() {
        let key = key();
        let (pool, mut original) = owner(4096, 4096 * 40);
        let baseline = pool.reserved_bytes();
        let signer = original.reserve_signer(key.public_key()).unwrap();
        let signer_bytes = signer.remaining_bytes();
        assert_eq!(
            signer_bytes,
            key.public_key().retained_allocation_layout().size()
        );
        let frame = original.reserve_frame(&manifest("first")).unwrap();
        let frame_bytes = frame.remaining_bytes();
        let signed = manifest("first")
            .try_signed(original.context(), frame_bytes, &key)
            .unwrap();
        assert_eq!(
            original.context().consumed_allocated_bytes(),
            u64::try_from(frame_bytes + signer_bytes).unwrap()
        );
        assert_eq!(pool.reserved_bytes(), baseline); // Partition grants no new credit.
        drop(frame); // try_signed has already freed its temporary payload.
        assert_eq!(pool.reserved_bytes(), baseline - frame_bytes);
        let instruction = RegisterSmartContractCode {
            artifact_id: ContractArtifactId::new(DataSpaceId::UNIVERSAL, signed.code_hash.unwrap()),
            manifest: signed,
        };
        let encoded_bytes = original.context().with(|| {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::core::encoded_frame_len_bounded(&instruction, 4096).unwrap()
        });
        let output = original.grant.try_partition_bytes(encoded_bytes).unwrap();
        let encoded = original
            .context()
            .with(|| norito::core::to_bytes_bounded(&instruction, encoded_bytes).unwrap());
        assert_eq!(encoded.len(), encoded_bytes);
        assert!(signer.belongs_to(&pool));
        assert_eq!(pool.reserved_bytes(), baseline - frame_bytes);
        drop(encoded);
        drop(output);
        drop(instruction);
        assert_eq!(
            pool.reserved_bytes(),
            baseline - frame_bytes - encoded_bytes
        );
        drop(signer);
        assert_eq!(
            pool.reserved_bytes(),
            baseline - frame_bytes - encoded_bytes - signer_bytes
        );
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn genuine_verification_rejects_changed_content_without_releasing_its_frame_early() {
        let key = key();
        let (pool, mut original) = owner(4096, 4096 * 40);
        let signer = original.reserve_signer(key.public_key()).unwrap();
        let frame = original.reserve_frame(&manifest("first")).unwrap();
        let mut signed = manifest("first")
            .try_signed(original.context(), frame.remaining_bytes(), &key)
            .unwrap();
        drop(frame);
        for changed in [false, true] {
            if changed {
                signed.seiyaku_name = Some("other".into());
            }
            let frame = original.reserve_frame(&signed).unwrap();
            let payload = signed
                .signature_payload_bytes(original.context(), frame.remaining_bytes())
                .unwrap();
            let provenance = signed.provenance.as_ref().unwrap();
            assert_eq!(
                provenance
                    .signature
                    .verify(&provenance.signer, &payload)
                    .is_ok(),
                !changed
            );
            assert!(frame.belongs_to(&pool));
            assert!(signer.belongs_to(&pool));
            let held = pool.reserved_bytes();
            let bytes = frame.remaining_bytes();
            drop(payload);
            drop(frame);
            assert_eq!(pool.reserved_bytes(), held - bytes);
        }
        drop(signed);
        drop(signer);
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn original_counter_and_grant_capacity_refusals_preserve_the_same_pool() {
        let layout = DecodeBudgetContext::allocation_layout();
        let short = AllocationBudget::new(layout.size() - 1);
        assert!(ManifestEncodingBudget::from_pool(&short, 4096, 4096).is_err());
        assert_eq!(short.reserved_bytes(), 0);

        let (pool, original) = owner(4096, 4096 * 40);
        let held = pool.reserved_bytes();
        let refused = ManifestEncodingBudget::from_pool(&pool, 4096, 4096 * 40)
            .err()
            .unwrap();
        assert!(matches!(
            refused.downcast_ref::<iroha_allocation::AllocationRefusal>(),
            Some(iroha_allocation::AllocationRefusal::Capacity { .. })
        ));
        assert_eq!(pool.reserved_bytes(), held);
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);

        let (pool, mut short_grant) = owner(4096, 1);
        let held = pool.reserved_bytes();
        let refused = short_grant.reserve_frame(&manifest("first")).err().unwrap();
        assert!(
            refused
                .downcast_ref::<iroha_allocation::InsufficientReservation>()
                .is_some()
        );
        assert_eq!(short_grant.grant.remaining_bytes(), 1);
        assert_eq!(short_grant.context().consumed_allocated_bytes(), 0);
        assert_eq!(pool.reserved_bytes(), held);
        drop(short_grant);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn oversized_original_frame_refuses_before_output_admission_or_materialization() {
        let (pool, mut original) = owner(4096, 4096 * 40);
        let held = pool.reserved_bytes();
        let remaining = original.grant.remaining_bytes();
        assert!(
            original
                .reserve_frame(&manifest(&"x".repeat(4096)))
                .is_err()
        );
        assert_eq!(pool.reserved_bytes(), held);
        assert_eq!(original.grant.remaining_bytes(), remaining);
        assert_eq!(original.context().consumed_allocated_bytes(), 0);
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn signing_and_verification_cannot_reset_the_same_operation_cumulative_allowance() {
        let key = key();
        let (_, mut measured) = owner(4096, 4096 * 40);
        let measured_frame = measured.reserve_frame(&manifest("first")).unwrap();
        let frame_bytes = measured_frame.remaining_bytes();
        drop(measured_frame);
        drop(measured);
        let signer_bytes = key.public_key().retained_allocation_layout().size();
        let allowance = frame_bytes * 2 + signer_bytes - 1;
        let (pool, mut original) = owner(4096, allowance);
        let signer = original.reserve_signer(key.public_key()).unwrap();
        let frame = original.reserve_frame(&manifest("first")).unwrap();
        let signed = manifest("first")
            .try_signed(original.context(), frame.remaining_bytes(), &key)
            .unwrap();
        drop(frame);
        let prior = original.context().consumed_allocated_bytes();
        assert_eq!(prior, u64::try_from(frame_bytes + signer_bytes).unwrap());
        let same_context = original.context().clone();
        // A separate output grant makes this specifically a cumulative-counter
        // refusal, rather than masking it with a short prepaid partition.
        let verification_frame = pool.try_reserve_bytes(frame_bytes).unwrap();
        assert!(
            signed
                .signature_payload_bytes(&same_context, verification_frame.remaining_bytes())
                .is_err()
        );
        assert_eq!(original.context().consumed_allocated_bytes(), prior);
        drop(verification_frame);
        drop(same_context);
        drop(signed);
        drop(signer);
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

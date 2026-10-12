use super::{default_oracle, *};
use iroha_model_base::chain::ChainId;
#[cfg(test)]
use norito::codec::DecodeAll;
use norito::json::{self, JsonDeserialize, JsonSerialize};
use std::{collections::BTreeMap, marker::PhantomData};
#[cfg(test)]
std::thread_local! {
    static SNAPSHOT_NORITO_CANONICAL_PASSES: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

/// Snapshot syntax is distinct from a local refusal by the original State pool.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StateRestoreError {
    /// World authority must come from original signed-genesis and certified-history replay.
    #[error(
        "native World restoration requires fresh-State signed-genesis and certified-history replay"
    )]
    NativeExecutionReplayRequired,
    /// The snapshot does not satisfy the canonical typed schema.
    #[error(transparent)]
    Serialization(#[from] json::Error),
    /// Local resources refused restore; this does not invalidate the snapshot.
    #[error(transparent)]
    Admission(#[from] StateAdmissionError),
    /// Original finite resources refused immutable native lane signer/sample ownership.
    #[error("snapshot native lane custody admission deferred: {0}")]
    NativeLaneCustody(#[source] iroha_data_model::sumeragi_lanes::LaneStateAdmissionError),
    /// Original finite resources refused canonical native schedule ownership.
    #[error("snapshot native schedule admission deferred: {0}")]
    NativeSchedule(#[source] crate::sumeragi::schedule::ScheduleError),
    /// Original resources refused a fully authenticated retained beacon session.
    #[error("snapshot beacon session admission failed: {0}")]
    BeaconSession(#[source] crate::beacon::GlobalThresholdBeaconSessionError),
    /// Original finite resources refused the complete native participant graph.
    #[error("snapshot native AMX admission deferred: {0}")]
    NativeAmx(#[source] crate::sumeragi::amx::NativeAmxAdmissionError),
    /// Original resources refused canonical immutable evidence graph restoration.
    #[error("snapshot native evidence admission deferred: {0}")]
    Evidence(#[source] crate::sumeragi::evidence::record::EvidenceRecordRestoreError),
    /// Original resources refused SCCP generation or anchor custody during restore.
    #[error("snapshot SCCP custody admission failed: {0}")]
    Sccp(#[from] sccp_snapshot_state::SccpRestoreError),
    /// The local VM image could not be constructed before restoring State.
    #[error("snapshot State VM initialization deferred: {0}")]
    VmInitialization(#[source] ivm::VMError),
    /// An original storage reader or publication is locally unavailable during restore.
    #[error("snapshot State reader unavailable: {0}")]
    StateRead(#[source] StateViewError),
    /// Original execution resources refused this local restore attempt.
    #[error("snapshot State execution deferred: {0}")]
    ExecutionDeferred(#[source] crate::execution_attempt::ExecutionDeferred),
}
impl From<native_execution_tip::TipRestoreError> for StateRestoreError {
    fn from(error: native_execution_tip::TipRestoreError) -> Self {
        match error {
            native_execution_tip::TipRestoreError::GenesisReplayRequired => {
                Self::NativeExecutionReplayRequired
            }
            native_execution_tip::TipRestoreError::History(message) => {
                Self::Serialization(json::Error::InvalidField {
                    field: "native_execution_tip".into(),
                    message,
                })
            }
            native_execution_tip::TipRestoreError::Admission(error) => {
                Self::Admission(StateAdmissionError::Storage(error))
            }
            native_execution_tip::TipRestoreError::Deferred(original) => {
                Self::ExecutionDeferred(original)
            }
        }
    }
}

/// Validate both complete original versions before either can become a published World.
fn validate_resource_policy_versions(
    world: &World,
    committed_height: u64,
    execution_budget: &iroha_allocation::AllocationBudget,
) -> Result<(), StateRestoreError> {
    crate::resource_coherence::validate_restored_policy(&world.view(), committed_height).map_err(
        |error| json::Error::InvalidField {
            field: "state.world.resource_policy".to_owned(),
            message: error.to_string(),
        },
    )?;
    // Acquire the original undo cut atomically. Reading separate Cell predecessors
    // here would risk mixing parameter, privacy-policy, and schedule generations.
    let previous_world = world.try_block_and_revert(execution_budget)?;
    // At height zero both cuts remain pre-genesis bootstrap state; no earlier
    // committed height exists. Even that retained undo must be coherent.
    let previous_height = committed_height.checked_sub(1).unwrap_or(0);
    crate::resource_coherence::validate_restored_policy(&previous_world, previous_height).map_err(
        |error| json::Error::InvalidField {
            field: "state.world.resource_policy.revert".to_owned(),
            message: error.to_string(),
        },
    )?;
    Ok(())
}

/// Apply L1 to each complete original World cut under explicitly supplied replay policy.
/// Snapshot fields are structural claims; neither defaults nor a current-only check can
/// authenticate the genesis staking policy or an undo generation's liability window.
fn validate_sccp_policy_versions(
    world: &World,
    replay_nexus: Option<&iroha_config::parameters::actual::Nexus>,
    execution_budget: &iroha_allocation::AllocationBudget,
) -> Result<(), StateRestoreError> {
    fn validate(
        cut: &(impl WorldReadOnly + ?Sized),
        replay_nexus: Option<&iroha_config::parameters::actual::Nexus>,
        field: &str,
    ) -> Result<(), StateRestoreError> {
        use crate::smartcontracts::isi::sccp::params;
        let Some(parameters) = params::parameters(cut) else {
            return Ok(());
        };
        // TODO: authenticate genesis-pinned staking custody in the native replay owner.
        // Refuse config-free SCCP restore instead of substituting process defaults.
        let policy = replay_nexus.ok_or_else(|| json::Error::InvalidField {
            field: field.to_owned(),
            message: "SCCP restore requires explicit original replay staking policy".to_owned(),
        })?;
        params::validate_staking_policy(cut, &parameters, &policy.staking).map_err(|error| {
            json::Error::InvalidField {
                field: field.to_owned(),
                message: error.to_string(),
            }
        })?;
        Ok(())
    }
    validate(&world.view(), replay_nexus, "state.sccp.staking_policy")?;
    let previous = world.try_block_and_revert(execution_budget)?;
    validate(&previous, replay_nexus, "state.sccp.staking_policy.revert")
}

#[cfg(test)]
#[path = "sccp_policy_restore_tests.rs"]
mod sccp_policy_restore_tests;
impl From<mv::storage::AdmittedStorageError> for StateRestoreError {
    fn from(error: mv::storage::AdmittedStorageError) -> Self {
        Self::Admission(StateAdmissionError::Storage(
            StateStorageAdmissionError::World(error),
        ))
    }
}
impl From<storage_transactions::MembershipRestoreError> for StateRestoreError {
    fn from(error: storage_transactions::MembershipRestoreError) -> Self {
        match error {
            storage_transactions::MembershipRestoreError::Json(error) => Self::Serialization(error),
            storage_transactions::MembershipRestoreError::Admission(error) => {
                Self::Admission(StateAdmissionError::Membership(error))
            }
        }
    }
}
fn durable_state_restore_error(error: MergeLedgerCommitError) -> StateRestoreError {
    match error {
        MergeLedgerCommitError::NativeLaneCustodyAdmission(error) => {
            StateRestoreError::NativeLaneCustody(error)
        }
        MergeLedgerCommitError::ExecutionDeferred(reason) => {
            StateRestoreError::ExecutionDeferred(reason)
        }
        MergeLedgerCommitError::VmInitialization(reason) => {
            StateRestoreError::VmInitialization(reason)
        }
        MergeLedgerCommitError::StateStorageAdmission(error) => {
            StateRestoreError::Admission(StateAdmissionError::Storage(error))
        }
        MergeLedgerCommitError::BlockHashAdmission(error) => {
            StateRestoreError::Admission(StateAdmissionError::History(error))
        }
        MergeLedgerCommitError::MembershipAdmission(error) => {
            StateRestoreError::Admission(StateAdmissionError::Membership(error))
        }
        error => json::Error::InvalidField {
            field: "state.durable_merge_ledger".to_owned(),
            message: error.to_string(),
        }
        .into(),
    }
}

enum SnapshotJsonField<'a> {
    Borrowed {
        raw: &'a str,
    },
    #[cfg(test)]
    Owned(json::Value),
}
impl<'a> SnapshotJsonField<'a> {
    fn decode_canonical_value<T>(self) -> Result<T, json::Error>
    where
        T: JsonDeserialize + JsonSerialize,
    {
        match self {
            #[cfg(test)]
            Self::Owned(value) => json::value::from_value(value),
            Self::Borrowed { raw } => (|| {
                let value = json::from_str::<T>(raw)?;
                // TODO: Teach Norito JSON serialization to target a comparison sink so
                // canonical verification does not need one field-sized temporary String.
                let canonical = json::to_json(&value)?;
                if canonical.as_bytes() != raw.as_bytes() {
                    return Err(json::Error::Message(
                        "snapshot field is not canonically encoded".to_owned(),
                    ));
                }
                Ok(value)
            })(),
        }
    }
    fn decode_canonical<T>(self, field: &str) -> Result<T, json::Error>
    where
        T: JsonDeserialize + JsonSerialize,
    {
        self.decode_canonical_value()
            .map_err(|error| json::Error::InvalidField {
                field: field.to_owned(),
                message: error.to_string(),
            })
    }
    fn decode_transactions(
        self,
        budget: iroha_allocation::AllocationBudget,
    ) -> Result<TransactionsStorage, StateRestoreError> {
        let decoded: Result<TransactionsStorage, StateRestoreError> = (|| match self {
            Self::Borrowed { raw } => {
                let value = TransactionsStorage::from_json_with_budget(raw, budget)?;
                // As for other snapshot fields, the snapshot owner retains this
                // comparison buffer. It is not a transaction-history allocation.
                // TODO: Compare through a bounded Norito serialization sink.
                if json::to_json(&value)?.as_bytes() != raw.as_bytes() {
                    return Err(json::Error::Message(
                        "snapshot field is not canonically encoded".to_owned(),
                    )
                    .into());
                }
                Ok(value)
            }
            #[cfg(test)]
            Self::Owned(value) => {
                TransactionsStorage::from_json_with_budget(&json::to_json(&value)?, budget)
                    .map_err(StateRestoreError::from)
            }
        })();
        decoded.map_err(|error| match error {
            StateRestoreError::Serialization(error) => json::Error::InvalidField {
                field: "transactions".to_owned(),
                message: error.to_string(),
            }
            .into(),
            local => local,
        })
    }
    fn decode_evidence(
        self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Storage<iroha_crypto::Hash, RetainedEvidenceRecord>, StateRestoreError> {
        let decoded: Result<
            Storage<iroha_crypto::Hash, RetainedEvidenceRecord>,
            StateRestoreError,
        > = (|| {
            let (raw, has_original_bytes) = match &self {
                Self::Borrowed { raw } => (std::borrow::Cow::Borrowed(*raw), true),
                #[cfg(test)]
                Self::Owned(value) => (std::borrow::Cow::Owned(json::to_json(value)?), false),
            };
            let value = crate::sumeragi::evidence::record::restore_storage(&raw, budget).map_err(
                |error| match error {
                    crate::sumeragi::evidence::record::EvidenceRecordRestoreError::Json(error) => {
                        StateRestoreError::Serialization(error)
                    }
                    local => StateRestoreError::Evidence(local),
                },
            )?;
            // Production borrows the original bytes and requires their exact canonical
            // representation. The test-only DOM adapter has already discarded field
            // order, just like decode_canonical's owned path above. Neither path grants
            // authority to restored claims. Comparison scratch retains its existing TODO.
            if has_original_bytes && json::to_json(&value)?.as_bytes() != raw.as_bytes() {
                return Err(StateRestoreError::Serialization(json::Error::Message(
                    "snapshot field is not canonically encoded".into(),
                )));
            }
            Ok(value)
        })();
        decoded.map_err(|error| match error {
            StateRestoreError::Serialization(error) => json::Error::InvalidField {
                field: "consensus_evidence".into(),
                message: error.to_string(),
            }
            .into(),
            local => local,
        })
    }
    fn into_object(self, field: &str) -> Result<SnapshotJsonMap<'a>, json::Error> {
        match self {
            Self::Borrowed { raw } => SnapshotJsonMap::parse(raw, field),
            #[cfg(test)]
            Self::Owned(json::Value::Object(map)) => Ok(SnapshotJsonMap::from_owned(map)),
            #[cfg(test)]
            Self::Owned(_) => Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: "expected object".to_owned(),
            }),
        }
    }
}

struct SnapshotJsonMap<'a> {
    fields: BTreeMap<String, SnapshotJsonField<'a>>,
    source_order: Option<Vec<String>>,
}
impl<'a> SnapshotJsonMap<'a> {
    #[cfg(test)]
    fn from_owned(map: json::native::Map) -> Self {
        Self {
            fields: map
                .into_iter()
                .map(|(key, value)| (key, SnapshotJsonField::Owned(value)))
                .collect(),
            source_order: None,
        }
    }
    fn parse(input: &'a str, field: &str) -> Result<Self, json::Error> {
        let mut parser = json::Parser::new(input);
        parser
            .expect(b'{')
            .map_err(|error| json::Error::InvalidField {
                field: field.to_owned(),
                message: error.to_string(),
            })?;
        parser.skip_ws();
        let mut fields = BTreeMap::new();
        let mut source_order = Vec::new();
        if parser.peek() == Some(b'}') {
            parser.bump();
        } else {
            loop {
                let key = parser
                    .parse_string()
                    .map_err(|error| json::Error::InvalidField {
                        field: field.to_owned(),
                        message: error.to_string(),
                    })?;
                parser
                    .expect(b':')
                    .map_err(|error| json::Error::InvalidField {
                        field: field.to_owned(),
                        message: error.to_string(),
                    })?;
                parser.skip_ws();
                let start = parser.position();
                parser
                    .skip_value()
                    .map_err(|error| json::Error::InvalidField {
                        field: field.to_owned(),
                        message: error.to_string(),
                    })?;
                let end = parser.position();
                if fields
                    .insert(
                        key.clone(),
                        SnapshotJsonField::Borrowed {
                            raw: &input[start..end],
                        },
                    )
                    .is_some()
                {
                    return Err(json::Error::InvalidField {
                        field: field.to_owned(),
                        message: format!("duplicate field `{key}`"),
                    });
                }
                source_order.push(key);
                parser.skip_ws();
                match parser.bump() {
                    Some(b',') => {}
                    Some(b'}') => break,
                    _ => {
                        return Err(json::Error::InvalidField {
                            field: field.to_owned(),
                            message: "expected comma or object end".to_owned(),
                        });
                    }
                }
            }
        }
        parser.skip_ws();
        if !parser.eof() {
            return Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: "trailing bytes after snapshot object".to_owned(),
            });
        }
        Ok(Self {
            fields,
            source_order: Some(source_order),
        })
    }
    fn remove(&mut self, key: &str) -> Option<SnapshotJsonField<'a>> {
        self.fields.remove(key)
    }
    fn contains_key(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
    fn first_key(&self) -> Option<&str> {
        self.fields.keys().next().map(String::as_str)
    }
    fn require_source_order(&self, expected: &[&str], field: &str) -> Result<(), json::Error> {
        let Some(actual) = self.source_order.as_ref() else {
            return Ok(());
        };
        if let Some(unknown) = actual.iter().find(|key| !expected.contains(&key.as_str())) {
            return Err(json::Error::InvalidField {
                field: format!("{field}.{unknown}"),
                message: "unknown field is not permitted in a signed first-release snapshot"
                    .to_owned(),
            });
        }
        if actual
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
        {
            Ok(())
        } else {
            Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: "snapshot object fields are not in canonical schema order".to_owned(),
            })
        }
    }
}
fn canonical_world_field_order() -> &'static [&'static str] {
    <World as norito::json::FastJsonWrite>::json_object_field_order()
        .expect("World snapshot has a fixed derived object schema")
}
#[derive(Clone, Copy)]
pub struct IvmSeed<'e, T> {
    pub ivm: &'e IVM,
    _marker: PhantomData<T>,
}
impl<'e, T> IvmSeed<'e, T> {
    pub fn cast<U>(&self) -> IvmSeed<'e, U> {
        IvmSeed {
            ivm: self.ivm,
            _marker: PhantomData,
        }
    }
}
impl IvmSeed<'_, TriggerSet> {
    #[allow(clippy::unused_self)]
    fn parse_trigger_set(self, value: SnapshotJsonField<'_>) -> Result<TriggerSet, json::Error> {
        value.decode_canonical("triggers")
    }
}
pub struct KuraSeed {
    /// Original caller-owned execution pool retained by the restored State.
    pub execution_budget: iroha_allocation::AllocationBudget,
    pub kura: Arc<Kura>,
    /// Immutable configured manifest sources used before the first restored State view.
    pub lane_manifests: LaneManifestRegistryHandle,
    pub query_handle: LiveQueryStoreHandle,
    #[cfg(feature = "telemetry")]
    pub telemetry: StateTelemetry,
}
impl From<crate::execution_attempt::ExecutionAttemptError<json::Error>> for StateRestoreError {
    fn from(error: crate::execution_attempt::ExecutionAttemptError<json::Error>) -> Self {
        match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                Self::Serialization(error)
            }
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                Self::ExecutionDeferred(reason)
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn snapshot_format_error_for_test(error: StateRestoreError) -> json::Error {
    match error {
        StateRestoreError::Serialization(error) => error,
        local => panic!("snapshot format fixture hit a local resource failure: {local}"),
    }
}
#[cfg(test)]
mod state_snapshot_decode_error_tests {
    use super::*;

    fn commit_resource_fixture(world: &World, lower_caps: bool, lower_privacy: bool) {
        use iroha_data_model::{
            parameter::{
                Parameter,
                system::{SumeragiParameter, TransactionParameter},
            },
            privacy::{PrivacyConsensusLimitsV1, PrivacyConsensusPolicyV1},
        };
        use std::num::{NonZeroU32, NonZeroU64};
        let mut overlay = world.block();
        let parameters = overlay.parameters.get_mut();
        parameters.replace(Parameters::default()).unwrap();
        if lower_caps {
            parameters
                .set_parameter(Parameter::Transaction(TransactionParameter::MaxTxBytes(
                    NonZeroU64::new(3 * 1024 * 1024).unwrap(),
                )))
                .unwrap();
            parameters
                .set_parameter(Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
                    NonZeroU32::new(4 * 1024 * 1024).unwrap(),
                )))
                .unwrap();
        }
        let mut limits = PrivacyConsensusLimitsV1::taira_default();
        if lower_privacy {
            limits.max_proof_bytes_per_action = 2 * 1024 * 1024;
            limits.max_action_bytes = 2 * 1024 * 1024;
            limits.max_privacy_bytes_per_transaction = 2 * 1024 * 1024;
            limits.max_privacy_bytes_per_block = 3 * 1024 * 1024;
        }
        *overlay.privacy_consensus_policy.get_mut() = PrivacyConsensusPolicyV1 {
            current_limits: limits,
            pending_tightening: None,
        };
        overlay.commit();
    }

    #[test]
    fn resource_restore_validates_complete_current_and_predecessor_versions() {
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let world = World::try_with_execution_budget([], [], [], &budget).unwrap();
        commit_resource_fixture(&world, true, true);
        commit_resource_fixture(&world, false, false);
        validate_resource_policy_versions(&world, 0, &budget).unwrap();
        let previous = world.try_block_and_revert(&budget).unwrap();
        assert_eq!(
            previous.parameters().transaction().max_tx_bytes().get(),
            3 * 1024 * 1024
        );
        assert_eq!(
            previous
                .privacy_consensus_policy()
                .current_limits
                .max_action_bytes,
            2 * 1024 * 1024
        );
        assert_ne!(previous.parameters(), world.view().parameters());
    }

    #[test]
    fn resource_restore_rejects_incoherent_original_undo_before_rollback() {
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let world = World::try_with_execution_budget([], [], [], &budget).unwrap();
        commit_resource_fixture(&world, true, false);
        commit_resource_fixture(&world, false, false);
        crate::resource_coherence::validate_restored_policy(&world.view(), 0).unwrap();
        assert!(matches!(
            validate_resource_policy_versions(&world, 0, &budget),
            Err(StateRestoreError::Serialization(json::Error::InvalidField { ref field, .. }))
                if field == "state.world.resource_policy.revert"
        ));
    }

    #[test]
    fn resource_restore_keeps_original_undo_acquisition_refusal_local() {
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let world = World::try_with_execution_budget([], [], [], &budget).unwrap();
        let retained_bytes = budget.reserved_bytes();
        let undo_scope_bytes = iroha_allocation::OwnedAllocationScope::allocation_layout().size();
        assert!(retained_bytes >= undo_scope_bytes);
        crate::resource_coherence::validate_restored_policy(&world.view(), 0).unwrap();
        // The original undo scope fits this policy, but World's retained owners
        // occupy the entire pool. A zero limit would instead mean ExceedsLimit.
        budget.set_limit_bytes(retained_bytes);
        let iroha_allocation::AllocationRefusal::Capacity {
            release: original_release,
            ..
        } = budget.try_reserve_bytes(undo_scope_bytes).unwrap_err()
        else {
            panic!("original World owners occupy the undo-scope capacity");
        };
        let refused = validate_resource_policy_versions(&world, 0, &budget).unwrap_err();
        let StateRestoreError::Admission(StateAdmissionError::Storage(
            StateStorageAdmissionError::World(mv::storage::AdmittedStorageError::Allocation(
                iroha_allocation::AllocationRefusal::Capacity {
                    requested_bytes,
                    reserved_bytes,
                    limit_bytes,
                    release,
                },
            )),
        )) = refused
        else {
            panic!("expected original undo allocation capacity refusal: {refused:?}");
        };
        assert_eq!(requested_bytes, undo_scope_bytes);
        assert_eq!(reserved_bytes, retained_bytes);
        assert_eq!(limit_bytes, retained_bytes);
        assert_eq!(release, original_release);
        assert_eq!(budget.reserved_bytes(), retained_bytes);
        budget.set_limit_bytes(64 * 1024 * 1024);
        validate_resource_policy_versions(&world, 0, &budget).unwrap();
        assert_eq!(budget.reserved_bytes(), retained_bytes);
    }

    fn fee_parameters_snapshot(receiver: &str) -> String {
        let mut parameters = Parameters::default();
        parameters.set_parameter(iroha_data_model::parameter::Parameter::Custom(
            iroha_data_model::parameter::CustomParameter::new(
                "ivm_gas_tech_account_id".parse().unwrap(),
                iroha_primitives::json::Json::new(receiver),
            ),
        ));
        json::to_json(&Cell::new(parameters)).unwrap()
    }

    fn parameters_map(raw: &str) -> SnapshotJsonMap<'_> {
        SnapshotJsonMap {
            fields: BTreeMap::from([(
                "parameters".to_owned(),
                SnapshotJsonField::Borrowed { raw },
            )]),
            source_order: None,
        }
    }

    #[test]
    fn canonical_parameters_cell_restores_validated_fee_projection() {
        let receiver = iroha_test_samples::ALICE_ID.to_string();
        let canonical = fee_parameters_snapshot(&receiver);
        let restored = take_parameters_cell(&mut parameters_map(&canonical), "parameters")
            .expect("canonical original Parameters cell restores its derived fee projection");
        assert_eq!(restored.view().gas().tech_account_id, receiver);
        assert_eq!(json::to_json(&restored).unwrap(), canonical);
    }

    #[test]
    fn parameters_cell_restore_preserves_original_decode_refusal() {
        let canonical = fee_parameters_snapshot(&iroha_test_samples::ALICE_ID.to_string());
        let mut map = parameters_map(&canonical);
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let error = norito::with_decode_limits_scope(limits, || {
            take_parameters_cell(&mut map, "parameters")
                .err()
                .expect("original decode budget refuses restore")
        });
        assert!(matches!(error, StateRestoreError::ExecutionDeferred(_)));
        assert!(take_parameters_cell(&mut parameters_map(&canonical), "parameters").is_ok());
    }

    #[test]
    fn parameters_cell_restore_rejects_malformed_fee_as_serialization() {
        let malformed = fee_parameters_snapshot("alias@domain");
        let error = take_parameters_cell(&mut parameters_map(&malformed), "parameters")
            .err()
            .expect("malformed committed receiver cannot create a StateParameters owner");
        assert!(matches!(
            error,
            StateRestoreError::Serialization(json::Error::InvalidField { ref field, .. })
                if field == "parameters"
        ));
    }

    #[test]
    fn positive_fast_manifest_cannot_construct_empty_world_at_a_committed_tip() {
        for height in [1, 2, 100] {
            let kura = crate::kura::Kura::blank_kura_for_testing();
            let seed = KuraSeed {
                execution_budget: iroha_allocation::AllocationBudget::new(0),
                kura: Arc::clone(&kura),
                lane_manifests: Arc::new(
                    crate::governance::manifest::LaneManifestRegistry::default(),
                ),
                query_handle: crate::query::store::LiveQueryStore::start_test(),
                #[cfg(feature = "telemetry")]
                telemetry: crate::telemetry::StateTelemetry::default(),
            };
            let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"native-genesis"),
            ));
            let result = seed.into_state_from_emergency_fast_manifest(
                ChainId::from("native-chain"),
                network,
                height,
                None,
            );
            assert!(matches!(
                result,
                Err(StateRestoreError::NativeExecutionReplayRequired)
            ));
            assert_eq!(kura.blocks_count(), 0);
            assert_eq!(kura.exact_durable_blocks_count().unwrap(), 0);
        }
    }

    #[test]
    fn state_owner_refusals_remain_local_and_invalid_content_remains_format() {
        let deferred = crate::execution_attempt::ExecutionDeferred::from(
            ivm::error::ExecutionDeferral::AllocationUnavailable,
        );
        assert!(matches!(
            durable_state_restore_error(MergeLedgerCommitError::ExecutionDeferred(deferred)),
            StateRestoreError::ExecutionDeferred(_)
        ));
        assert!(matches!(
            durable_state_restore_error(MergeLedgerCommitError::BlockHashAdmission(
                BlockHashAdmissionError::Capacity(
                    iroha_allocation::AllocationRefusal::DemandOverflow
                )
            )),
            StateRestoreError::Admission(StateAdmissionError::History(_))
        ));
        assert!(matches!(
            durable_state_restore_error(MergeLedgerCommitError::EmptyEntry),
            StateRestoreError::Serialization(_)
        ));
    }
}
impl KuraSeed {
    #[cfg(test)]
    pub fn into_state_from_json(self, value: json::Value) -> Result<Box<State>, StateRestoreError> {
        self.into_state_from_json_with_recovery_mode(value, true)
    }
    /// Decode a canonical snapshot directly from its authenticated JSON bytes.
    ///
    /// The borrowed field map retains only schema keys and raw value slices;
    /// each field is decoded into its final typed owner before the next field,
    /// so restoration never constructs a recursive full-state JSON tree.
    /// The restored State stays on the heap through validation and handoff;
    /// nested restore calls must not reserve a full State in each stack frame.
    #[cfg(test)]
    pub(crate) fn into_state_from_json_str(
        self,
        input: &str,
    ) -> Result<Box<State>, StateRestoreError> {
        let map = SnapshotJsonMap::parse(input, "state")?;
        self.into_state_from_snapshot_map(map, true, None)
    }
    /// Decode a signed snapshot with the process's validated static Nexus policy.
    /// Snapshot-authenticated ownership and runtime catalog fields still override
    /// the configured baseline before the first State view is constructed.
    pub(crate) fn into_state_from_json_str_with_configured_nexus(
        self,
        input: &str,
        configured_nexus: iroha_config::parameters::actual::Nexus,
    ) -> Result<Box<State>, StateRestoreError> {
        let map = SnapshotJsonMap::parse(input, "state")?;
        self.into_state_from_snapshot_map(map, true, Some(configured_nexus))
    }
    /// Construct an empty State bound to an exact empty emergency manifest boundary.
    ///
    /// The caller has already authenticated the manifest signature, which authenticates an
    /// identity rather than executed World. A nonzero height therefore requires original
    /// signed-genesis and certified-history replay. At height zero, the exact empty Kura
    /// boundary retains empty World, transaction history, topology, and runtime Nexus state.
    pub(crate) fn into_state_from_emergency_fast_manifest(
        self,
        chain_id: ChainId,
        network_id: NetworkId,
        snapshot_height: usize,
        snapshot_tip: Option<HashOf<BlockHeader>>,
    ) -> Result<Box<State>, StateRestoreError> {
        // The signed manifest authenticates an identity, not an executed World.
        if snapshot_height > 0 {
            return Err(StateRestoreError::NativeExecutionReplayRequired);
        }
        let block_hashes =
            emergency_fast_block_hashes(self.kura.as_ref(), snapshot_height, snapshot_tip)?;
        let nexus = iroha_config::parameters::actual::Nexus::default();
        let lane_incarnations = derive_static_lane_incarnations(&nexus.lane_catalog);
        let lane_incarnation_activation_heights = lane_incarnations
            .keys()
            .copied()
            .map(|lane_id| (lane_id, 0))
            .collect::<BTreeMap<_, _>>();
        let lane_incarnation_lineage = lane_incarnations
            .iter()
            .map(|(&lane_id, &incarnation)| {
                (
                    lane_id,
                    LaneIncarnationLineage {
                        generation: 0,
                        incarnation,
                        activation_height: 0,
                    },
                )
            })
            .collect();
        let state = build_state(
            BuildStateInputs {
                execution_budget: self.execution_budget.clone(),
                lane_manifests: self.lane_manifests,
                world: World(Box::new(WorldData::try_new_with_execution_budget(
                    &self.execution_budget,
                )?)),
                block_hashes,
                transactions: TransactionsStorage::try_new(self.kura.transaction_history_budget())
                    .map_err(|error| {
                        StateRestoreError::Admission(StateAdmissionError::Membership(error))
                    })?,
                commit_topology: Cell::new(Vec::new()),
                prev_commit_topology: Cell::new(Vec::new()),
                ivm: IVM::try_new(0).map_err(StateRestoreError::VmInitialization)?,
                native_execution_tip: None,
                canonical_runtime: Cell::new(
                    SnapshotNexusRuntime::from_nexus_with_autoscale_history(
                        &nexus,
                        &lane_incarnations,
                        &lane_incarnation_activation_heights,
                        &VecDeque::new(),
                        &lane_incarnation_lineage,
                    ),
                ),
                nexus,
                chain_id,
                network_id,
                nexus_runtime_restored_from_snapshot: false,
                kura: self.kura,
                query_handle: self.query_handle,
                #[cfg(feature = "telemetry")]
                telemetry: self.telemetry,
            },
            false,
            true,
        )
        .map_err(durable_state_restore_error)?;
        Ok(state)
    }
    /// Decode canonical snapshot bytes without durable journal recovery for
    /// tests that intentionally omit the configured Nexus policy.
    #[cfg(test)]
    pub(crate) fn into_state_from_json_str_without_durable_recovery(
        self,
        input: &str,
    ) -> Result<Box<State>, StateRestoreError> {
        let map = SnapshotJsonMap::parse(input, "state")?;
        self.into_state_from_snapshot_map(map, false, None)
    }
    /// Validate writer-generated bytes against the same configured static policy
    /// as a real Strict restart, without recovering a durable journal.
    #[cfg(test)]
    pub(crate) fn into_state_from_json_str_with_configured_nexus_without_durable_recovery(
        self,
        input: &str,
        configured_nexus: iroha_config::parameters::actual::Nexus,
    ) -> Result<Box<State>, StateRestoreError> {
        let map = SnapshotJsonMap::parse(input, "state")?;
        self.into_state_from_snapshot_map(map, false, Some(configured_nexus))
    }
    #[cfg(test)]
    fn into_state_from_json_with_recovery_mode(
        self,
        value: json::Value,
        allow_durable_recovery: bool,
    ) -> Result<Box<State>, StateRestoreError> {
        self.into_state_from_json_with_recovery_mode_and_configured_nexus(
            value,
            allow_durable_recovery,
            None,
        )
    }
    #[cfg(test)]
    fn into_state_from_json_with_recovery_mode_and_configured_nexus(
        self,
        value: json::Value,
        allow_durable_recovery: bool,
        configured_nexus: Option<iroha_config::parameters::actual::Nexus>,
    ) -> Result<Box<State>, StateRestoreError> {
        let json::Value::Object(map) = value else {
            return Err((json::Error::InvalidField {
                field: "state".into(),
                message: "expected object".into(),
            })
            .into());
        };
        self.into_state_from_snapshot_map(
            SnapshotJsonMap::from_owned(map),
            allow_durable_recovery,
            configured_nexus,
        )
    }
    fn into_state_from_snapshot_map(
        self,
        mut map: SnapshotJsonMap<'_>,
        allow_durable_recovery: bool,
        replay_nexus: Option<iroha_config::parameters::actual::Nexus>,
    ) -> Result<Box<State>, StateRestoreError> {
        const CANONICAL_FIELDS: &[&str] = &[
            "chain_id",
            "network_id",
            "world",
            "nexus_runtime",
            "native_execution_tip",
            "block_hashes",
            "transactions",
            "public_lane_validators",
            "public_lane_stake_shares",
            "public_lane_stake_custody",
            "public_lane_stake_reserves",
            "space_directory_manifests",
            "capacity_fee_ledger",
            "capacity_disputes",
            "provider_credit_ledger",
            "sorafs_pricing",
            "soradns_directory_records",
            "soradns_directory_pending",
            "soradns_directory_history",
            "soradns_directory_prev_of",
            "soradns_directory_revocations",
            "soradns_release_signers",
            "soradns_directory_latest",
            "soradns_rotation_policy",
            "soradns_last_publish_ms",
            "soradns_history_len",
            "sccp",
            "commit_topology",
            "prev_commit_topology",
        ];
        map.require_source_order(CANONICAL_FIELDS, "state")?;
        let world_value = map
            .remove("world")
            .ok_or_else(|| json::Error::missing_field("world"))?;
        let world_map = world_value.into_object("world")?;
        if !world_map.contains_key("contract_subject_bindings") {
            return Err((json::Error::missing_field("world.contract_subject_bindings")).into());
        }
        let ivm_runtime = IVM::try_new(0).map_err(StateRestoreError::VmInitialization)?;
        let ivm_seed = IvmSeed {
            ivm: &ivm_runtime,
            _marker: PhantomData,
        };
        let mut world = parse_world(&self.execution_budget, world_map, &ivm_seed)?;
        world.public_lane_validators =
            take_required::<snapshot_storage::SnapshotStorage>(&mut map, "public_lane_validators")?
                .decode(
                    "public_lane_validators",
                    public_lane_validator_record_matches_key,
                )?;
        world.public_lane_stake_shares = take_required::<snapshot_storage::SnapshotStorage>(
            &mut map,
            "public_lane_stake_shares",
        )?
        .decode(
            "public_lane_stake_shares",
            public_lane_stake_share_matches_key,
        )?;
        world.public_lane_stake_custody = take_required::<snapshot_storage::SnapshotStorage>(
            &mut map,
            "public_lane_stake_custody",
        )?
        .decode(
            "public_lane_stake_custody",
            |_: &(LaneId, AccountId), value: &(AssetId, Quantity)| !value.1.is_zero(),
        )?;
        world.public_lane_stake_reserves = take_required::<snapshot_storage::SnapshotStorage>(
            &mut map,
            "public_lane_stake_reserves",
        )?
        .decode(
            "public_lane_stake_reserves",
            |_: &AssetId, value: &Quantity| !value.is_zero(),
        )?;
        validate_public_lane_stake_reserves_for_restore(&world.view()).map_err(|error| {
            error.map_rejection(|message| json::Error::InvalidField {
                field: "public_lane_stake_reserves.blocks".to_owned(),
                message,
            })
        })?;
        {
            let previous_world = world.try_block_and_revert(&self.execution_budget)?;
            validate_public_lane_stake_reserves_for_restore(&previous_world).map_err(|error| {
                error.map_rejection(|message| json::Error::InvalidField {
                    field: "public_lane_stake_reserves.revert".to_owned(),
                    message,
                })
            })?;
        }

        world.space_directory_manifests = take_required::<snapshot_storage::SnapshotStorage>(
            &mut map,
            "space_directory_manifests",
        )?
        .decode(
            "space_directory_manifests",
            snapshot_storage::manifest_set_matches_key,
        )?;
        snapshot_service_state::SnapshotServiceState {
            capacity_fee_ledger: take_required(&mut map, "capacity_fee_ledger")?,
            capacity_disputes: take_required(&mut map, "capacity_disputes")?,
            provider_credit_ledger: take_required(&mut map, "provider_credit_ledger")?,
            sorafs_pricing: take_required(&mut map, "sorafs_pricing")?,
            soradns_directory_records: take_required(&mut map, "soradns_directory_records")?,
            soradns_directory_pending: take_required(&mut map, "soradns_directory_pending")?,
            soradns_directory_history: take_required(&mut map, "soradns_directory_history")?,
            soradns_directory_prev_of: take_required(&mut map, "soradns_directory_prev_of")?,
            soradns_directory_revocations: take_required(
                &mut map,
                "soradns_directory_revocations",
            )?,
            soradns_release_signers: take_required(&mut map, "soradns_release_signers")?,
            soradns_directory_latest: take_required(&mut map, "soradns_directory_latest")?,
            soradns_rotation_policy: take_required(&mut map, "soradns_rotation_policy")?,
            soradns_last_publish_ms: take_required(&mut map, "soradns_last_publish_ms")?,
            soradns_history_len: take_required(&mut map, "soradns_history_len")?,
        }
        .restore(&mut world)?;
        take_required_scoped::<sccp_snapshot_state::SnapshotSccpState>(
            &mut map,
            sccp_snapshot_state::SCCP_SNAPSHOT_MEMBER,
        )?
        .restore(&mut world, &self.execution_budget)?;
        let canonical_runtime: Cell<SnapshotNexusRuntime> =
            take_required(&mut map, "nexus_runtime")?;
        let snapshot_nexus_runtime = canonical_runtime.view().get().clone();
        let chain_id: ChainId = take_required(&mut map, "chain_id")?;
        let network_id: NetworkId = take_required(&mut map, "network_id")?;
        let block_hashes: Vec<HashOf<BlockHeader>> = take_required(&mut map, "block_hashes")?;
        // A decoded World is unauthenticated until its cold-captured state root matches the
        // certified parent World state root of its successor block. TODO(S9): admit accelerated
        // restore only with that check and the State-level fields' own provenance.
        if !block_hashes.is_empty() {
            return Err(StateRestoreError::NativeExecutionReplayRequired);
        }
        let native_tip_claim: native_execution_tip::NativeExecutionTipSnapshot =
            take_required(&mut map, "native_execution_tip")?;
        let native_execution_tip = native_tip_claim
            .restore(
                &self.execution_budget,
                &chain_id,
                &network_id,
                &block_hashes,
                &self.kura,
            )
            .map_err(StateRestoreError::from)?;
        let committed_height =
            u64::try_from(block_hashes.hash_count()).map_err(|_| json::Error::InvalidField {
                field: "state.block_hashes".to_owned(),
                message: "committed height does not fit u64".to_owned(),
            })?;
        validate_sumeragi_lane_state(
            network_id,
            committed_height,
            world.sumeragi_lanes.view().get(),
        )
        .map_err(|message| json::Error::InvalidField {
            field: "world.sumeragi_lanes.blocks".to_owned(),
            message,
        })?;
        if committed_height == 0 && world.sumeragi_lanes.predecessor_view().get().is_some() {
            return Err((json::Error::InvalidField {
                field: "world.sumeragi_lanes.revert".to_owned(),
                message: "height-zero lane state cannot retain predecessor undo".to_owned(),
            })
            .into());
        }
        validate_replication_order_completion_anchors(&world, &block_hashes)?;
        validate_musubi_resolver_checkpoint_anchors(&world, &block_hashes)?;
        validator_committee::validate_committed_progress(
            &world.view(),
            &chain_id,
            network_id,
            &block_hashes,
            &self.kura,
            &self.execution_budget,
        )
        .map_err(|error| match error {
            ExecutionAttemptError::Deferred(original) => {
                StateRestoreError::ExecutionDeferred(original)
            }
            ExecutionAttemptError::Rejected(message) => json::Error::InvalidField {
                field: "world.validator_committee".to_owned(),
                message,
            }
            .into(),
        })?;
        if !block_hashes.is_empty() {
            let previous_world = world.try_block_and_revert(&self.execution_budget)?;
            // Revert the original World rather than reconstructing H-1 from the current
            // lane policy. A no-op Cell legitimately has no undo; its original value is
            // still the predecessor and must pass the predecessor height constraints.
            validate_sumeragi_lane_state(
                network_id,
                committed_height - 1,
                previous_world.sumeragi_lanes(),
            )
            .map_err(|message| json::Error::InvalidField {
                field: "world.sumeragi_lanes.revert".to_owned(),
                message,
            })?;
            validator_committee::validate_committed_progress(
                &previous_world,
                &chain_id,
                network_id,
                &block_hashes[..block_hashes.len() - 1],
                &self.kura,
                &self.execution_budget,
            )
            .map_err(|error| match error {
                ExecutionAttemptError::Deferred(original) => {
                    StateRestoreError::ExecutionDeferred(original)
                }
                ExecutionAttemptError::Rejected(message) => json::Error::InvalidField {
                    field: "world.validator_committee.revert".to_owned(),
                    message,
                }
                .into(),
            })?;
        }
        world
            .privacy_consensus_policy
            .view()
            .get()
            .validate_at_committed_height(committed_height)
            .map_err(|error| json::Error::InvalidField {
                field: "state.world.privacy_consensus_policy".to_owned(),
                message: error.to_string(),
            })?;
        validate_resource_policy_versions(&world, committed_height, &self.execution_budget)?;
        validate_sccp_policy_versions(&world, replay_nexus.as_ref(), &self.execution_budget)?;
        crate::privacy_state::validate_privacy_activations_at_committed_height_v1(
            &world.privacy_activations.view(),
            committed_height,
        )
        .map_err(|message| json::Error::InvalidField {
            field: "state.world.privacy_activations".to_owned(),
            message,
        })?;
        let (mut restored_nexus, _, _, _, _) = nexus_from_snapshot_runtime(
            snapshot_nexus_runtime,
            &block_hashes,
            replay_nexus.as_ref(),
        )?;
        let world_catalog = runtime_catalog_from_world(&world.view()).map_err(|error| {
            json::Error::InvalidField {
                field: "nexus_runtime.blocks".to_owned(),
                message: error.to_string(),
            }
        })?;
        if world_catalog.as_ref().is_some_and(|catalog| {
            catalog.baseline_manifests_hash
                != Hash::prehashed(self.lane_manifests.baseline_consensus_policy_digest())
        }) {
            return Err((json::Error::InvalidField {
                field: "state.lane_manifests".to_owned(),
                message: "manifest baseline differs from canonical World catalog".to_owned(),
            })
            .into());
        }
        // Owner policy commits to physical identity and fault tolerance, but deliberately
        // omits operator-facing descriptions. The protected runtime catalog instead binds the
        // *complete* configured baseline, descriptions included. Reconstructing that baseline
        // from owner policy loses those bytes and makes a valid post-catalog snapshot impossible
        // to restart. Strict startup supplies the validated static configuration; use its exact
        // baseline and authenticate it against the committed catalog below. The config-free
        // decoder can still reconstruct snapshots with no runtime catalog.
        restored_nexus.configured_dataspace_catalog = match replay_nexus.as_ref() {
            Some(configured) => configured.configured_dataspace_catalog.clone(),
            None if world_catalog.is_some() => return Err((json::Error::InvalidField {
                field: "nexus_runtime.blocks.owner_policy".to_owned(),
                message: "committed runtime catalog requires the complete configured dataspace baseline at snapshot restore".to_owned(),
            }).into()),
            None => restored_nexus.dataspace_catalog.clone(),
        };
        let reconstructed_dataspaces = runtime_catalog_dataspaces(
            &restored_nexus.configured_dataspace_catalog,
            world_catalog.as_ref(),
        )
        .map_err(|error| json::Error::InvalidField {
            field: "nexus_runtime.blocks.owner_policy".to_owned(),
            message: error.to_string(),
        })?;
        let retained_physical_policy =
            SnapshotNexusOwnerPolicy::from_nexus(&restored_nexus).dataspaces;
        restored_nexus.dataspace_catalog = reconstructed_dataspaces;
        if SnapshotNexusOwnerPolicy::from_nexus(&restored_nexus).dataspaces
            != retained_physical_policy
        {
            return Err((json::Error::InvalidField {
                field: "nexus_runtime.blocks.owner_policy".to_owned(),
                message: "physical ownership differs from canonical World catalog".to_owned(),
            })
            .into());
        }
        let runtime_predecessor = canonical_runtime.predecessor_view();
        // Every real carrier appends its height-bound sample, even when no
        // lifecycle policy changes. Therefore a positive-height runtime cannot
        // be a no-op Cell publication: replacement requires its actual H-1
        // record, not a reconstruction from the current policy or sample tail.
        if committed_height > 0 && runtime_predecessor.get().is_none() {
            return Err((json::Error::InvalidField {
                field: "nexus_runtime.revert".to_owned(),
                message: "committed runtime must retain its predecessor record".to_owned(),
            })
            .into());
        }
        if let Some(previous) = runtime_predecessor.get() {
            let predecessor_len = block_hashes.hash_count().checked_sub(1).ok_or_else(|| {
                json::Error::InvalidField {
                    field: "nexus_runtime.revert".to_owned(),
                    message: "height-zero runtime cannot retain predecessor undo".to_owned(),
                }
            })?;
            let (mut prior_nexus, _, _, _, _) = nexus_from_snapshot_runtime(
                previous.clone(),
                &block_hashes[..predecessor_len],
                replay_nexus.as_ref(),
            )?;
            let prior_world = world.try_block_and_revert(&self.execution_budget)?;
            let prior_catalog = runtime_catalog_from_world(&prior_world).map_err(|error| {
                json::Error::InvalidField {
                    field: "nexus_runtime.revert.owner_policy".to_owned(),
                    message: error.to_string(),
                }
            })?;
            prior_nexus.dataspace_catalog = runtime_catalog_dataspaces(
                &restored_nexus.configured_dataspace_catalog,
                prior_catalog.as_ref(),
            )
            .map_err(|error| json::Error::InvalidField {
                field: "nexus_runtime.revert.owner_policy".to_owned(),
                message: error.to_string(),
            })?;
            if SnapshotNexusOwnerPolicy::from_nexus(&prior_nexus).dataspaces
                != previous.owner_policy.dataspaces
            {
                return Err((json::Error::InvalidField {
                    field: "nexus_runtime.revert.owner_policy".to_owned(),
                    message: "predecessor physical ownership differs from reverted World catalog"
                        .to_owned(),
                })
                .into());
            }
        }
        drop(runtime_predecessor);
        let nexus_runtime_restored_from_snapshot = true;
        let transactions = map
            .remove("transactions")
            .ok_or_else(|| json::Error::missing_field("transactions"))?
            .decode_transactions(self.kura.transaction_history_budget())?;
        let commit_topology = take_topology_cell(&mut map, "commit_topology")?;
        let prev_commit_topology = take_topology_cell(&mut map, "prev_commit_topology")?;
        if let Some(qualification) = world.privacy_exact12_qualification.view().get() {
            crate::privacy_state::validate_privacy_exact12_qualification_registration_v1(
                qualification,
                &chain_id,
                network_id,
                committed_height,
                &world.privacy_activations.view(),
                commit_topology.view().get(),
            )
            .map_err(|message| json::Error::InvalidField {
                field: "state.world.privacy_exact12_qualification".to_owned(),
                message,
            })?;
        }
        reject_unknown(&map, "state")?;
        super::contract_subject_restore::rebuild(&mut world).map_err(|message| {
            json::Error::InvalidField {
                field: "contract_subject_bindings".into(),
                message,
            }
        })?;
        world
            .validate_quantity_ledger_invariants()
            .map_err(|error| {
                error.map_rejection(|message| json::Error::InvalidField {
                    field: "state.world.numeric_ledgers".to_owned(),
                    message,
                })
            })?;
        let state = build_state(
            BuildStateInputs {
                execution_budget: self.execution_budget,
                lane_manifests: self.lane_manifests,
                world,
                block_hashes: BlockHashes::try_new(
                    block_hashes,
                    self.kura.block_hash_history_budget(),
                )
                .map_err(|error| {
                    StateRestoreError::Admission(StateAdmissionError::History(error))
                })?,
                transactions,
                commit_topology,
                prev_commit_topology,
                ivm: ivm_runtime,
                canonical_runtime,
                native_execution_tip: Some(native_execution_tip),
                nexus: restored_nexus,
                chain_id,
                network_id,
                nexus_runtime_restored_from_snapshot,
                kura: self.kura,
                query_handle: self.query_handle,
                #[cfg(feature = "telemetry")]
                telemetry: self.telemetry,
            },
            allow_durable_recovery,
            false,
        )
        .map_err(durable_state_restore_error)?;
        Ok(state)
    }
}
/// Exercise exact durable Fast boundary admission without constructing native State.
#[cfg(test)]
pub(crate) fn emergency_fast_block_hashes_for_testing(
    kura: &Kura,
    snapshot_height: usize,
    snapshot_tip: Option<HashOf<BlockHeader>>,
) -> Result<BlockHashes, json::Error> {
    emergency_fast_block_hashes(kura, snapshot_height, snapshot_tip)
}
fn emergency_fast_block_hashes(
    kura: &Kura,
    snapshot_height: usize,
    snapshot_tip: Option<HashOf<BlockHeader>>,
) -> Result<BlockHashes, json::Error> {
    let (durable_height, durable_tip) = kura
        .emergency_fast_snapshot_boundary(snapshot_height)
        .map_err(|error| json::Error::InvalidField {
            field: "state.block_hashes".to_owned(),
            message: format!("failed to bind the Kura Fast boundary: {error}"),
        })?;
    if durable_height != snapshot_height || durable_tip != snapshot_tip {
        return Err(json::Error::InvalidField {
            field: "state.block_hashes".to_owned(),
            message: format!(
                "snapshot boundary ({snapshot_height}, {snapshot_tip:?}) differs from durable Kura ({durable_height}, {durable_tip:?})"
            ),
        });
    }
    Ok(
        match kura
            .emergency_fast_snapshot_hash_mapping(snapshot_height)
            .map_err(|error| json::Error::InvalidField {
                field: "state.block_hashes".to_owned(),
                message: format!("failed to map the Kura Fast hash prefix: {error}"),
            })? {
            Some(mapping) => BlockHashes::new_emergency_fast_mapped(mapping, snapshot_height),
            None if snapshot_height == 0 => BlockHashes::new_emergency_fast_empty(),
            None => {
                return Err(json::Error::InvalidField {
                    field: "state.block_hashes".to_owned(),
                    message: "nonempty Fast boundary has no durable hash mapping".to_owned(),
                });
            }
        },
    )
}
fn nexus_from_snapshot_runtime(
    runtime: SnapshotNexusRuntime,
    committed_block_hashes: &(impl crate::state::BlockHashRead + ?Sized),
    replay_nexus: Option<&iroha_config::parameters::actual::Nexus>,
) -> Result<
    (
        iroha_config::parameters::actual::Nexus,
        BTreeMap<LaneId, Hash>,
        BTreeMap<LaneId, u64>,
        BTreeMap<LaneId, LaneIncarnationLineage>,
        VecDeque<AutoscaleSampleRecord>,
    ),
    json::Error,
> {
    if runtime.version != SnapshotNexusRuntime::VERSION {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.version".to_owned(),
            message: format!(
                "unsupported Nexus runtime snapshot version {}; expected {}",
                runtime.version,
                SnapshotNexusRuntime::VERSION
            ),
        });
    }
    if runtime
        .lanes
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.lanes".to_owned(),
            message: "lanes must be in strict canonical lane-id order".to_owned(),
        });
    }
    if runtime
        .lane_incarnation_lineage
        .windows(2)
        .any(|pair| pair[0].lane_id >= pair[1].lane_id)
    {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.lane_incarnation_lineage".to_owned(),
            message: "lineage entries must be in strict canonical lane-id order".to_owned(),
        });
    }
    let autoscale_scale_out_window_blocks =
        std::num::NonZeroU16::new(runtime.autoscale_scale_out_window_blocks).ok_or_else(|| {
            json::Error::InvalidField {
                field: "nexus_runtime.autoscale_scale_out_window_blocks".to_owned(),
                message: "autoscale scale-out window must be non-zero".to_owned(),
            }
        })?;
    let autoscale_scale_in_window_blocks =
        std::num::NonZeroU16::new(runtime.autoscale_scale_in_window_blocks).ok_or_else(|| {
            json::Error::InvalidField {
                field: "nexus_runtime.autoscale_scale_in_window_blocks".to_owned(),
                message: "autoscale scale-in window must be non-zero".to_owned(),
            }
        })?;
    let autoscale_sample_history =
        validate_snapshot_autoscale_sample_history(&runtime, committed_block_hashes)?;
    let lane_count =
        std::num::NonZeroU32::new(runtime.lane_count).ok_or_else(|| json::Error::InvalidField {
            field: "nexus_runtime.lane_count".to_owned(),
            message: "lane_count must be non-zero".to_owned(),
        })?;
    let catalog =
        LaneCatalog::new(lane_count, runtime.lanes).map_err(|err| json::Error::InvalidField {
            field: "nexus_runtime.lanes".to_owned(),
            message: err.to_string(),
        })?;
    if !catalog.lanes().iter().any(|lane| lane.id == LaneId::SINGLE) {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.lanes".to_owned(),
            message: "routing default lane 0 is missing".to_owned(),
        });
    }
    let mut lane_incarnation_lineage = BTreeMap::new();
    for entry in runtime.lane_incarnation_lineage {
        if lane_incarnation_is_zero(entry.incarnation) {
            return Err(json::Error::InvalidField {
                field: "nexus_runtime.lane_incarnation_lineage".to_owned(),
                message: format!(
                    "lane {} has an all-zero incarnation commitment",
                    entry.lane_id
                ),
            });
        }
        if lane_incarnation_lineage
            .insert(
                entry.lane_id,
                LaneIncarnationLineage {
                    generation: entry.generation,
                    incarnation: entry.incarnation,
                    activation_height: entry.activation_height,
                },
            )
            .is_some()
        {
            return Err(json::Error::InvalidField {
                field: "nexus_runtime.lane_incarnation_lineage".to_owned(),
                message: format!("duplicate entry for lane {}", entry.lane_id),
            });
        }
    }
    let mut lane_incarnations = BTreeMap::new();
    let mut lane_incarnation_activation_heights = BTreeMap::new();
    for lane in catalog.lanes() {
        let entry =
            lane_incarnation_lineage
                .get(&lane.id)
                .ok_or_else(|| json::Error::InvalidField {
                    field: "nexus_runtime.lane_incarnation_lineage".to_owned(),
                    message: format!("active lane {} is missing lineage", lane.id),
                })?;
        lane_incarnations.insert(lane.id, entry.incarnation);
        lane_incarnation_activation_heights.insert(lane.id, entry.activation_height);
    }
    let committed_height = u64::try_from(committed_block_hashes.hash_count()).unwrap_or(u64::MAX);
    validate_lane_incarnation_lineage(
        &catalog,
        &lane_incarnations,
        &lane_incarnation_activation_heights,
        &lane_incarnation_lineage,
    )
    .map_err(|err| json::Error::InvalidField {
        field: "nexus_runtime.lane_incarnation_lineage".to_owned(),
        message: err.to_string(),
    })?;
    if lane_incarnation_activation_heights.get(&LaneId::SINGLE) != Some(&0) {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.lane_incarnation_lineage".to_owned(),
            message: "physical primary lane 0 must have activation height 0".to_owned(),
        });
    }
    if let Some((lane_id, activation_height)) = lane_incarnation_lineage
        .iter()
        .map(|(lane_id, entry)| (lane_id, entry.activation_height))
        .find(|(_, activation_height)| *activation_height > committed_height)
    {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.lane_incarnation_lineage".to_owned(),
            message: format!(
                "lane {lane_id} activation height {activation_height} exceeds snapshot height {committed_height}"
            ),
        });
    }
    if runtime.autoscale_last_transition_height > committed_height {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.autoscale_last_transition_height".to_owned(),
            message: format!(
                "transition height {} exceeds snapshot height {committed_height}",
                runtime.autoscale_last_transition_height
            ),
        });
    }
    let mut latest_managed_creation_height = 0_u64;
    for lane in catalog.lanes() {
        if !lane_uses_reserved_autoscale_metadata(lane) {
            continue;
        }
        ensure_autoscale_managed_lane_shape(lane)
            .and_then(|()| {
                ensure_autoscale_managed_lane_created_height_not_future(lane, committed_height)
            })
            .map_err(|err| json::Error::InvalidField {
                field: format!("nexus_runtime.lanes[{}]", lane.id.as_u32()),
                message: err.to_string(),
            })?;
        let committee = decode_autoscale_lane_committee(lane)
            .ok()
            .flatten()
            .expect("validated autoscale lane carries a canonical committee pin");
        validate_autoscale_lane_committee_pops(&committee).map_err(|reason| {
            json::Error::InvalidField {
                field: format!("nexus_runtime.lanes[{}]", lane.id.as_u32()),
                message: reason.to_owned(),
            }
        })?;
        latest_managed_creation_height = latest_managed_creation_height.max(
            lane.autoscale_created_height()
                .expect("validated managed lane carries a creation height"),
        );
    }
    if runtime.autoscale_last_transition_height < latest_managed_creation_height {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.autoscale_last_transition_height".to_owned(),
            message: format!(
                "transition height {} precedes managed lane creation height {latest_managed_creation_height}",
                runtime.autoscale_last_transition_height
            ),
        });
    }
    let mut nexus = replay_nexus.cloned().unwrap_or_default();
    restore_snapshot_nexus_owner_policy(&mut nexus, runtime.owner_policy)?;
    nexus.lane_config = iroha_config::parameters::actual::LaneConfig::from_catalog(&catalog);
    nexus.lane_catalog = catalog;
    validate_lane_authority_geometry(&nexus.lane_catalog, &nexus.dataspace_catalog).map_err(
        |error| json::Error::InvalidField {
            field: "nexus_runtime.owner_policy.dataspaces".to_owned(),
            message: error.to_string(),
        },
    )?;
    validate_nexus_routing_policy(
        &nexus.routing_policy,
        &nexus.lane_catalog,
        &nexus.dataspace_catalog,
    )
    .map_err(|error| json::Error::InvalidField {
        field: "nexus_runtime.owner_policy".to_owned(),
        message: error.to_string(),
    })?;
    // These windows determine both the serialized history cap and which retained samples
    // influence the first post-restart autoscale decision. Restore the snapshot-authenticated
    // values before canonical reserialization; substituting process defaults here makes a
    // writer-created snapshot non-canonical whenever operators tune either window.
    nexus.autoscale.scale_out_window_blocks = autoscale_scale_out_window_blocks;
    nexus.autoscale.scale_in_window_blocks = autoscale_scale_in_window_blocks;
    nexus.autoscale.last_transition_height = runtime.autoscale_last_transition_height;
    Ok((
        nexus,
        lane_incarnations,
        lane_incarnation_activation_heights,
        lane_incarnation_lineage,
        autoscale_sample_history,
    ))
}
fn restore_snapshot_nexus_owner_policy(
    nexus: &mut iroha_config::parameters::actual::Nexus,
    policy: SnapshotNexusOwnerPolicy,
) -> Result<(), json::Error> {
    let invalid = |message: String| json::Error::InvalidField {
        field: "nexus_runtime.owner_policy".to_owned(),
        message,
    };
    if policy
        .dataspaces
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(invalid(
            "dataspaces must be in strict canonical id order".to_owned(),
        ));
    }
    let dataspaces = DataSpaceCatalog::new(
        policy
            .dataspaces
            .into_iter()
            .map(|entry| {
                iroha_data_model::nexus::DataSpaceMetadata {
                    id: entry.id,
                    alias: entry.alias,
                    // Descriptions are operator-facing and excluded from the execution-policy digest.
                    description: None,
                    fault_tolerance: entry.fault_tolerance,
                }
            })
            .collect(),
    )
    .map_err(|error| invalid(error.to_string()))?;
    let nonzero = |value, field| {
        std::num::NonZeroU32::new(value).ok_or_else(|| invalid(format!("{field} must be non-zero")))
    };
    nexus.staking.max_validators = nonzero(policy.max_validators, "max_validators")?;
    nexus.autoscale.min_lane_id = nonzero(policy.autoscale_min_lane_id, "autoscale_min_lane_id")?;
    nexus.autoscale.max_lane_id_exclusive = nonzero(
        policy.autoscale_max_lane_id_exclusive,
        "autoscale_max_lane_id_exclusive",
    )?;
    ensure_autoscale_runtime_lane_bounds(&nexus.autoscale)
        .map_err(|error| invalid(error.to_string()))?;
    nexus.dataspace_catalog = dataspaces;
    nexus.staking.public_validator_mode = policy.public_validator_mode.into();
    nexus.staking.restricted_validator_mode = policy.restricted_validator_mode.into();
    nexus.routing_policy.default_lane = policy.routing_default_lane;
    nexus.routing_policy.default_dataspace = policy.routing_default_dataspace;
    nexus.autoscale.enabled = policy.autoscale_enabled;
    Ok(())
}
/// Decode typed World and external lane projection fields against an independently
/// supplied reference prefix. This test-only component validator grants no State,
/// authenticated native tip, committed root or snapshot restoration authority.
#[cfg(test)]
pub(in crate::state) fn decode_world_snapshot_projection_for_testing(
    value: json::Value,
    reference_block_hashes: &[HashOf<BlockHeader>],
) -> Result<World, StateRestoreError> {
    let execution_budget = &iroha_allocation::AllocationBudget::new(
        iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
    );
    (|| {
        let json::Value::Object(fields) = value else {
            return Err(json::Error::Message(
                "World projection requires its exact State envelope".into(),
            )
            .into());
        };
        let mut map = SnapshotJsonMap::from_owned(fields);
        let world_map = map
            .remove("world")
            .ok_or_else(|| json::Error::missing_field("world"))?
            .into_object("world")?;
        let ivm = IVM::try_new(0).map_err(StateRestoreError::VmInitialization)?;
        let seed = IvmSeed {
            ivm: &ivm,
            _marker: PhantomData,
        };
        let mut world = parse_world(execution_budget, world_map, &seed)?;
        world.public_lane_validators =
            take_required::<snapshot_storage::SnapshotStorage>(&mut map, "public_lane_validators")?
                .decode(
                    "public_lane_validators",
                    public_lane_validator_record_matches_key,
                )?;
        world.public_lane_stake_shares = take_required::<snapshot_storage::SnapshotStorage>(
            &mut map,
            "public_lane_stake_shares",
        )?
        .decode(
            "public_lane_stake_shares",
            public_lane_stake_share_matches_key,
        )?;
        world.public_lane_stake_custody = take_required::<snapshot_storage::SnapshotStorage>(
            &mut map,
            "public_lane_stake_custody",
        )?
        .decode(
            "public_lane_stake_custody",
            |_: &(LaneId, AccountId), value: &(AssetId, Quantity)| !value.1.is_zero(),
        )?;
        world.public_lane_stake_reserves = take_required::<snapshot_storage::SnapshotStorage>(
            &mut map,
            "public_lane_stake_reserves",
        )?
        .decode(
            "public_lane_stake_reserves",
            |_: &AssetId, value: &Quantity| !value.is_zero(),
        )?;
        validate_public_lane_stake_reserves_for_restore(&world.view()).map_err(|error| {
            error.map_rejection(|message| json::Error::InvalidField {
                field: "public_lane_stake_reserves.blocks".to_owned(),
                message,
            })
        })?;
        {
            let previous_world = world.try_block_and_revert(execution_budget)?;
            validate_public_lane_stake_reserves_for_restore(&previous_world).map_err(|error| {
                error.map_rejection(|message| json::Error::InvalidField {
                    field: "public_lane_stake_reserves.revert".to_owned(),
                    message,
                })
            })?;
        }

        validate_replication_order_completion_anchors(&world, reference_block_hashes)?;
        validate_musubi_resolver_checkpoint_anchors(&world, reference_block_hashes)?;
        Ok(world)
    })()
}

/// Decode and validate both Nexus runtime component cuts without constructing
/// a State or granting an authenticated native execution tip. The supplied
/// original hash prefix and World remain independently owned by the test.
#[cfg(test)]
pub(in crate::state) fn decode_nexus_runtime_component_for_testing(
    value: json::Value,
    committed_block_hashes: &[HashOf<BlockHeader>],
    world: &World,
    execution_budget: &iroha_allocation::AllocationBudget,
    baseline_manifests_hash: Hash,
    configured: Option<&iroha_config::parameters::actual::Nexus>,
) -> Result<
    (
        Cell<SnapshotNexusRuntime>,
        iroha_config::parameters::actual::Nexus,
    ),
    StateRestoreError,
> {
    let runtime: Cell<SnapshotNexusRuntime> = json::from_value(value)?;
    let (mut nexus, _, _, _, _) = nexus_from_snapshot_runtime(
        runtime.view().get().clone(),
        committed_block_hashes,
        configured,
    )?;
    let invalid = |field: &str, message: String| json::Error::InvalidField {
        field: field.to_owned(),
        message,
    };
    let catalog = runtime_catalog_from_world(&world.view())
        .map_err(|error| invalid("nexus_runtime.blocks", error.to_string()))?;
    if catalog
        .as_ref()
        .is_some_and(|catalog| catalog.baseline_manifests_hash != baseline_manifests_hash)
    {
        return Err(invalid(
            "state.lane_manifests",
            "manifest baseline differs from canonical World catalog".to_owned(),
        )
        .into());
    }
    nexus.configured_dataspace_catalog = match configured {
        Some(configured) => configured.configured_dataspace_catalog.clone(),
        None if catalog.is_some() => return Err(invalid("nexus_runtime.blocks.owner_policy",
            "committed runtime catalog requires the complete configured dataspace baseline at snapshot restore".to_owned()).into()),
        None => nexus.dataspace_catalog.clone(),
    };
    let physical_policy = SnapshotNexusOwnerPolicy::from_nexus(&nexus).dataspaces;
    nexus.dataspace_catalog =
        runtime_catalog_dataspaces(&nexus.configured_dataspace_catalog, catalog.as_ref())
            .map_err(|error| invalid("nexus_runtime.blocks.owner_policy", error.to_string()))?;
    if SnapshotNexusOwnerPolicy::from_nexus(&nexus).dataspaces != physical_policy {
        return Err(invalid(
            "nexus_runtime.blocks.owner_policy",
            "physical ownership differs from canonical World catalog".to_owned(),
        )
        .into());
    }
    let previous = runtime.predecessor_view();
    if committed_block_hashes.is_empty() && previous.get().is_some() {
        return Err(invalid(
            "nexus_runtime.revert",
            "height-zero runtime cannot retain predecessor undo".to_owned(),
        )
        .into());
    }
    if !committed_block_hashes.is_empty() && previous.get().is_none() {
        return Err(invalid(
            "nexus_runtime.revert",
            "committed runtime must retain its predecessor record".to_owned(),
        )
        .into());
    }
    if let Some(prior) = previous.get() {
        let prefix = &committed_block_hashes[..committed_block_hashes.len() - 1];
        let (mut prior_nexus, _, _, _, _) =
            nexus_from_snapshot_runtime(prior.clone(), prefix, configured)?;
        let prior_world = world.try_block_and_revert(execution_budget)?;
        let prior_catalog = runtime_catalog_from_world(&prior_world)
            .map_err(|error| invalid("nexus_runtime.revert.owner_policy", error.to_string()))?;
        prior_nexus.dataspace_catalog =
            runtime_catalog_dataspaces(&nexus.configured_dataspace_catalog, prior_catalog.as_ref())
                .map_err(|error| invalid("nexus_runtime.revert.owner_policy", error.to_string()))?;
        if SnapshotNexusOwnerPolicy::from_nexus(&prior_nexus).dataspaces
            != prior.owner_policy.dataspaces
        {
            return Err(invalid(
                "nexus_runtime.revert.owner_policy",
                "predecessor physical ownership differs from reverted World catalog".to_owned(),
            )
            .into());
        }
    }
    drop(previous);
    Ok((runtime, nexus))
}

fn validate_snapshot_autoscale_sample_history(
    runtime: &SnapshotNexusRuntime,
    committed_block_hashes: &(impl crate::state::BlockHashRead + ?Sized),
) -> Result<VecDeque<AutoscaleSampleRecord>, json::Error> {
    let field = "nexus_runtime.autoscale_sample_history";
    let cap = usize::try_from(runtime.autoscale_sample_history_cap).map_err(|_| {
        json::Error::InvalidField {
            field: "nexus_runtime.autoscale_sample_history_cap".to_owned(),
            message: "history cap does not fit this platform".to_owned(),
        }
    })?;
    if !(2..=MAX_AUTOSCALE_SAMPLE_HISTORY_ENTRIES).contains(&cap) {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.autoscale_sample_history_cap".to_owned(),
            message: format!(
                "history cap {cap} is outside the supported range 2..={MAX_AUTOSCALE_SAMPLE_HISTORY_ENTRIES}"
            ),
        });
    }
    let scale_out_window = usize::from(runtime.autoscale_scale_out_window_blocks);
    let scale_in_window = usize::from(runtime.autoscale_scale_in_window_blocks);
    if scale_out_window == 0 || scale_in_window == 0 {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.autoscale_sample_history_cap".to_owned(),
            message: "autoscale snapshot windows must be non-zero".to_owned(),
        });
    }
    let required_cap = scale_out_window.max(scale_in_window).saturating_add(1);
    if cap != required_cap {
        return Err(json::Error::InvalidField {
            field: "nexus_runtime.autoscale_sample_history_cap".to_owned(),
            message: format!(
                "history cap {cap} does not match the configured snapshot windows (required {required_cap})"
            ),
        });
    }
    let history = &runtime.autoscale_sample_history;
    if history.len() > cap {
        return Err(json::Error::InvalidField {
            field: field.to_owned(),
            message: format!(
                "history contains {} records but its declared cap is {cap}",
                history.len()
            ),
        });
    }
    if committed_block_hashes.hash_count() == 0 {
        if history.is_empty() {
            return Ok(VecDeque::new());
        }
        return Err(json::Error::InvalidField {
            field: field.to_owned(),
            message: "history must be empty at snapshot height zero".to_owned(),
        });
    }
    if history.is_empty() {
        return Err(json::Error::InvalidField {
            field: field.to_owned(),
            message: "history must retain the latest committed block".to_owned(),
        });
    }
    let committed_height = u64::try_from(committed_block_hashes.hash_count()).map_err(|_| {
        json::Error::InvalidField {
            field: field.to_owned(),
            message: "committed height does not fit u64".to_owned(),
        }
    })?;
    let history_len = u64::try_from(history.len()).map_err(|_| json::Error::InvalidField {
        field: field.to_owned(),
        message: "history length does not fit u64".to_owned(),
    })?;
    let expected_first_height = committed_height
        .checked_sub(history_len.saturating_sub(1))
        .ok_or_else(|| json::Error::InvalidField {
            field: field.to_owned(),
            message: "history is longer than the committed chain".to_owned(),
        })?;
    if expected_first_height == 0 {
        return Err(json::Error::InvalidField {
            field: field.to_owned(),
            message: "history contains a zero block height".to_owned(),
        });
    }
    let mut previous_timestamp = None;
    for (index, record) in history.iter().enumerate() {
        let offset = u64::try_from(index).map_err(|_| json::Error::InvalidField {
            field: field.to_owned(),
            message: "history index does not fit u64".to_owned(),
        })?;
        let expected_height =
            expected_first_height
                .checked_add(offset)
                .ok_or_else(|| json::Error::InvalidField {
                    field: field.to_owned(),
                    message: "history height overflow".to_owned(),
                })?;
        if record.block_height != expected_height {
            return Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: format!(
                    "record {index} has height {}; expected consecutive height {expected_height}",
                    record.block_height
                ),
            });
        }
        let hash_index = usize::try_from(record.block_height.saturating_sub(1)).map_err(|_| {
            json::Error::InvalidField {
                field: field.to_owned(),
                message: format!("record {index} height does not fit this platform"),
            }
        })?;
        if committed_block_hashes.hash_at(hash_index) != Some(&record.block_hash) {
            return Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: format!(
                    "record {index} hash does not match committed height {}",
                    record.block_height
                ),
            });
        }
        if record.creation_time_ms == 0 || record.creation_time_ms == u64::MAX {
            return Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: format!(
                    "record {index} has an invalid creation timestamp {}",
                    record.creation_time_ms
                ),
            });
        }
        if previous_timestamp.is_some_and(|previous| record.creation_time_ms <= previous) {
            return Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: format!(
                    "record {index} creation timestamp {} is not strictly increasing",
                    record.creation_time_ms
                ),
            });
        }
        if record.work_count == u64::MAX {
            return Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: format!("record {index} work count is outside the supported range"),
            });
        }
        previous_timestamp = Some(record.creation_time_ms);
    }
    Ok(history.iter().copied().collect())
}
#[cfg(test)]
fn decode_snapshot_records<T>(
    records: Vec<SnapshotNoritoBlob>,
    field: &str,
) -> Result<Vec<T>, json::Error>
where
    T: DecodeAll + Encode,
{
    records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let bytes =
                hex::decode(&record.encoded_hex).map_err(|err| json::Error::InvalidField {
                    field: field.to_owned(),
                    message: format!("record {index} hex decode failed: {err}"),
                })?;
            let mut cursor = bytes.as_slice();
            let decoded = T::decode_all(&mut cursor).map_err(|err| json::Error::InvalidField {
                field: field.to_owned(),
                message: format!("record {index} norito decode failed: {err}"),
            })?;
            #[cfg(test)]
            SNAPSHOT_NORITO_CANONICAL_PASSES.with(|passes| passes.set(passes.get() + 1));
            if decoded.encode() != bytes {
                return Err(json::Error::InvalidField {
                    field: field.to_owned(),
                    message: format!("record {index} is not canonical Norito"),
                });
            }
            Ok(decoded)
        })
        .collect()
}
#[cfg(test)]
fn validate_canonical_snapshot_record_order<T, K>(
    records: &[T],
    field: &str,
    key: impl Fn(&T) -> K,
) -> Result<(), json::Error>
where
    K: Ord,
{
    let mut previous = None;
    for (index, record) in records.iter().enumerate() {
        let current = key(record);
        if previous
            .as_ref()
            .is_some_and(|previous| previous >= &current)
        {
            return Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: format!(
                    "record {index} is duplicated or not in canonical semantic key order"
                ),
            });
        }
        previous = Some(current);
    }
    Ok(())
}
/// Preserve the original decoder scope before adding a completed schema diagnostic.
fn take_required_scoped<T>(map: &mut SnapshotJsonMap<'_>, key: &str) -> Result<T, StateRestoreError>
where
    T: JsonDeserialize + JsonSerialize,
{
    map.remove(key)
        .ok_or_else(|| json::Error::missing_field(key))?
        .decode_canonical_value()
        .map_err(|error| {
            crate::execution_attempt::json_decode_attempt_error(error, |error| {
                json::Error::InvalidField {
                    field: key.to_owned(),
                    message: error.to_string(),
                }
            })
            .into()
        })
}

fn take_required<T>(map: &mut SnapshotJsonMap<'_>, key: &str) -> Result<T, json::Error>
where
    T: JsonDeserialize + JsonSerialize,
{
    let value = map
        .remove(key)
        .ok_or_else(|| json::Error::missing_field(key))?;
    value.decode_canonical(key)
}
fn take_optional<T>(map: &mut SnapshotJsonMap<'_>, key: &str) -> Result<Option<T>, json::Error>
where
    T: JsonDeserialize + JsonSerialize,
{
    map.remove(key)
        .map(|value| value.decode_canonical(key))
        .transpose()
}
fn take_musubi_namespace_bindings(
    map: &mut SnapshotJsonMap<'_>,
) -> Result<Storage<MusubiNamespaceV1, MusubiNamespaceBindingV1>, json::Error> {
    let bindings: Storage<MusubiNamespaceV1, MusubiNamespaceBindingV1> =
        take_required(map, "musubi_namespace_bindings")?;
    for (namespace, binding) in bindings.view().iter() {
        if namespace != &binding.namespace {
            return Err(json::Error::InvalidField {
                field: "musubi_namespace_bindings".to_owned(),
                message: format!(
                    "binding key '{namespace}' does not match embedded namespace '{}'",
                    binding.namespace
                ),
            });
        }
        binding
            .validate()
            .map_err(|error| json::Error::InvalidField {
                field: "musubi_namespace_bindings".to_owned(),
                message: error.to_string(),
            })?;
    }
    Ok(bindings)
}
fn take_musubi_domain_ownership_generations(
    map: &mut SnapshotJsonMap<'_>,
) -> Result<Storage<DomainId, u64>, json::Error> {
    let generations: Storage<DomainId, u64> =
        take_required(map, "musubi_domain_ownership_generations")?;
    for (domain, generation) in generations.view().iter() {
        if *generation < 2 {
            return Err(json::Error::InvalidField {
                field: "musubi_domain_ownership_generations".to_owned(),
                message: format!(
                    "domain '{domain}' stores noncanonical generation {generation}; absent means generation 1 and persisted entries start at 2"
                ),
            });
        }
    }
    Ok(generations)
}
fn take_musubi_pin_outbox_high_waters(
    map: &mut SnapshotJsonMap<'_>,
) -> Result<Storage<AccountId, MusubiPinOutboxHighWaterV1>, json::Error> {
    let records: Storage<AccountId, MusubiPinOutboxHighWaterV1> =
        take_required(map, "musubi_pin_outbox_high_waters")?;
    for (authority, record) in records.view().iter() {
        record
            .validate()
            .map_err(|error| json::Error::InvalidField {
                field: "musubi_pin_outbox_high_waters".to_owned(),
                message: error.to_string(),
            })?;
        if authority != &record.pin_authority {
            return Err(json::Error::InvalidField {
                field: "musubi_pin_outbox_high_waters".to_owned(),
                message: "pin-outbox high-water key differs from its signer".to_owned(),
            });
        }
    }
    Ok(records)
}
fn take_musubi_registry_policy(
    map: &mut SnapshotJsonMap<'_>,
) -> Result<Cell<MusubiRegistryPolicyV1>, json::Error> {
    let policy: Cell<MusubiRegistryPolicyV1> = take_required(map, "musubi_registry_policy")?;
    policy
        .view()
        .get()
        .validate()
        .map_err(|error| json::Error::InvalidField {
            field: "musubi_registry_policy".to_owned(),
            message: error.to_string(),
        })?;
    Ok(policy)
}
fn take_musubi_resolver_index_revision(
    map: &mut SnapshotJsonMap<'_>,
) -> Result<Cell<MusubiResolverIndexRevisionV1>, json::Error> {
    let revision: Cell<MusubiResolverIndexRevisionV1> =
        take_required(map, "musubi_resolver_index_revision")?;
    if revision.view().get().get() == 0 {
        return Err(json::Error::InvalidField {
            field: "musubi_resolver_index_revision".to_owned(),
            message: "Musubi resolver-index revision must be non-zero".to_owned(),
        });
    }
    Ok(revision)
}
fn take_musubi_resolver_index_checkpoints(
    map: &mut SnapshotJsonMap<'_>,
) -> Result<Storage<MusubiResolverIndexRevisionV1, MusubiRegistrySnapshotV1>, json::Error> {
    take_required(map, "musubi_resolver_index_checkpoints")
}
fn take_musubi_replication_shortfall_releases(
    map: &mut SnapshotJsonMap<'_>,
    execution_budget: &iroha_allocation::AllocationBudget,
) -> Result<Cell<u64, iroha_allocation::AllocationCharge>, StateRestoreError> {
    // Reserve every concrete outer allocation before decoding either scalar.
    // Refusal leaves the original encoded field available for exact retry.
    let initial = mv::cell::CellInitialization::<u64>::try_reserve(execution_budget)
        .map_err(super::scalar_cell_custody::admission_error)?;
    let field = map
        .remove("musubi_replication_shortfall_releases")
        .ok_or_else(|| json::Error::missing_field("musubi_replication_shortfall_releases"))?;
    let decoded = match field {
        SnapshotJsonField::Borrowed { raw } => super::scalar_cell_custody::decode_snapshot(raw),
        #[cfg(test)]
        SnapshotJsonField::Owned(json::Value::Object(mut fields)) => {
            // Owned fixture maps have no source ordering. Render just their
            // two exact values through the same production decoder.
            let revert = fields
                .remove("revert")
                .ok_or_else(|| json::Error::missing_field("revert"))?;
            let blocks = fields
                .remove("blocks")
                .ok_or_else(|| json::Error::missing_field("blocks"))?;
            if !fields.is_empty() {
                return Err(json::Error::Message("unexpected scalar snapshot field".into()).into());
            }
            super::scalar_cell_custody::decode_snapshot(&format!(
                "{{\"revert\":{},\"blocks\":{}}}",
                json::to_json(&revert)?,
                json::to_json(&blocks)?,
            ))
        }
        #[cfg(test)]
        SnapshotJsonField::Owned(_) => Err(json::Error::Message(
            "scalar snapshot must be an object".into(),
        )),
    };
    let (blocks, revert) = decoded.map_err(|error| json::Error::InvalidField {
        field: "musubi_replication_shortfall_releases".into(),
        message: error.to_string(),
    })?;
    Ok(initial.initialize(blocks, revert))
}
fn validate_provider_ingest_completion_authorities(
    provider_owners: &Storage<ProviderId, AccountId>,
    authorities: &Storage<ProviderId, ProviderIngestCompletionAuthorityV1>,
) -> Result<(), json::Error> {
    let owners = provider_owners.view();
    for (provider_id, authority) in authorities.view().iter() {
        if !authority.is_valid() || owners.get(provider_id) != Some(&authority.provider_owner) {
            return Err(json::Error::InvalidField {
                field: "provider_ingest_completion_authorities".to_owned(),
                message: format!(
                    "provider {} has a noncanonical or owner-mismatched completion authority",
                    hex::encode(provider_id.as_bytes())
                ),
            });
        }
    }
    Ok(())
}
fn validate_capacity_declarations(
    declarations: &Storage<ProviderId, CapacityDeclarationRecord>,
    provider_owners: &Storage<ProviderId, AccountId>,
) -> Result<(), json::Error> {
    let provider_owners = provider_owners.view();
    let owner_metadata_key: Name = "sorafs.owner_account_id"
        .parse()
        .expect("static capacity owner metadata key");
    for (provider_id, record) in declarations.view().iter() {
        let provider_label = hex::encode(provider_id.as_bytes());
        if record.provider_id != *provider_id {
            return Err(json::Error::InvalidField {
                field: "world.capacity_declarations".to_owned(),
                message: format!(
                    "capacity declaration key {provider_label} does not match its stored provider"
                ),
            });
        }
        crate::smartcontracts::isi::sorafs::validate_stored_capacity_declaration(
            record,
            &provider_label,
        )
        .map_err(|error| json::Error::InvalidField {
            field: "world.capacity_declarations".to_owned(),
            message: error.to_string(),
        })?;
        let provider_owner = provider_owners.get(provider_id).ok_or_else(|| {
            json::Error::InvalidField {
                field: "world.capacity_declarations".to_owned(),
                message: format!(
                    "capacity declaration {provider_label} has no governance-established provider owner"
                ),
            }
        })?;
        let owner_literal = record.metadata.get(&owner_metadata_key).ok_or_else(|| {
            json::Error::InvalidField {
                field: "world.capacity_declarations".to_owned(),
                message: format!(
                    "capacity declaration {provider_label} omits metadata `sorafs.owner_account_id`"
                ),
            }
        })?;
        let owner_literal: String = owner_literal.try_into_any().map_err(|error| {
            json::Error::InvalidField {
                field: "world.capacity_declarations".to_owned(),
                message: format!(
                    "capacity declaration {provider_label} owner metadata must be a canonical account string: {error}"
                ),
            }
        })?;
        if owner_literal != provider_owner.to_string() {
            return Err(json::Error::InvalidField {
                field: "world.capacity_declarations".to_owned(),
                message: format!(
                    "capacity declaration {provider_label} owner metadata does not exactly match its governance-established provider owner"
                ),
            });
        }
    }
    Ok(())
}
fn validate_replication_order_completion_anchors(
    world: &World,
    block_hashes: &(impl crate::state::BlockHashRead + ?Sized),
) -> Result<(), json::Error> {
    for (order_id, order) in world.replication_orders.view().iter() {
        let order_label = hex::encode(order_id.as_bytes());
        for completion in &order.provider_completions {
            let height = completion.finalized_anchor.height;
            let index = usize::try_from(height)
                .ok()
                .and_then(|height| height.checked_sub(1))
                .ok_or_else(|| json::Error::InvalidField {
                    field: "state.world.replication_orders".to_owned(),
                    message: format!(
                        "replication order {order_label} completion for provider {} has a finalized anchor height outside the committed block prefix",
                        hex::encode(completion.provider_id.as_bytes()),
                    ),
                })?;
            let Some(committed_hash) = block_hashes.hash_at(index) else {
                return Err(json::Error::InvalidField {
                    field: "state.world.replication_orders".to_owned(),
                    message: format!(
                        "replication order {order_label} completion for provider {} anchors unavailable committed height {height}",
                        hex::encode(completion.provider_id.as_bytes()),
                    ),
                });
            };
            if *committed_hash.as_ref() != completion.finalized_anchor.block_hash {
                return Err(json::Error::InvalidField {
                    field: "state.world.replication_orders".to_owned(),
                    message: format!(
                        "replication order {order_label} completion for provider {} finalized anchor hash does not match committed block height {height}",
                        hex::encode(completion.provider_id.as_bytes()),
                    ),
                });
            }
        }
    }
    Ok(())
}
fn validate_automatic_replication_capacity_state(
    declarations: &Storage<ProviderId, CapacityDeclarationRecord>,
    provider_owners: &Storage<ProviderId, AccountId>,
    completion_authorities: &Storage<ProviderId, ProviderIngestCompletionAuthorityV1>,
    pin_manifests: &Storage<ManifestDigest, PinManifestRecord>,
    replication_orders: &Storage<ReplicationOrderId, ReplicationOrderRecord>,
) -> Result<(), json::Error> {
    let invalid = |message: String| json::Error::InvalidField {
        field: "world.replication_orders".to_owned(),
        message,
    };
    let declarations = declarations.view();
    let provider_owners = provider_owners.view();
    let completion_authorities = completion_authorities.view();
    let pin_manifests = pin_manifests.view();
    let mut allocations = BTreeMap::<(ProviderId, String), u64>::new();
    for (order_id, order) in replication_orders.view().iter() {
        if !order_id.is_auto() {
            continue;
        }
        let order_label = hex::encode(order_id.as_bytes());
        let pin = pin_manifests.get(&order.manifest_digest).ok_or_else(|| {
            invalid(format!(
                "automatic replication order {order_label} references a missing pin manifest"
            ))
        })?;
        let payload =
            crate::smartcontracts::isi::sorafs::validate_stored_automatic_replication_order(
                pin,
                order,
                &order_label,
            )
            .map_err(|error| invalid(error.to_string()))?;
        if !matches!(pin.status, PinStatus::Approved(_))
            || !matches!(
                order.status,
                ReplicationOrderStatus::Pending | ReplicationOrderStatus::Completed(_)
            )
        {
            continue;
        }
        for assignment in &payload.assignments {
            let provider_id = ProviderId::new(assignment.provider_id);
            let provider_label = hex::encode(provider_id.as_bytes());
            let declaration = declarations.get(&provider_id).ok_or_else(|| {
                invalid(format!(
                    "automatic replication order {order_label} assigns provider {provider_label} without a retained capacity declaration"
                ))
            })?;
            let Some(profile_capacity) =
                crate::smartcontracts::isi::sorafs::automatic_replication_profile_capacity_gib(
                    declaration,
                    pin,
                    order.issued_epoch,
                    order.deadline_epoch,
                )
                .map_err(|error| invalid(error.to_string()))?
            else {
                return Err(invalid(format!(
                    "automatic replication order {order_label} assigns provider {provider_label} without exact profile, storage-class, and deadline capacity"
                )));
            };
            let provider_owner = provider_owners.get(&provider_id).ok_or_else(|| {
                invalid(format!(
                    "automatic replication order {order_label} assigns provider {provider_label} without a governed owner"
                ))
            })?;
            // A retained completion is immutable self-contained evidence and remains valid across
            // a later governed owner rotation. Only an assignment that still needs completion
            // depends on the current owner-bound authority.
            if order.provider_completion(provider_id).is_none()
                && !completion_authorities
                    .get(&provider_id)
                    .is_some_and(|authority| {
                        authority.is_valid() && &authority.provider_owner == provider_owner
                    })
            {
                return Err(invalid(format!(
                    "pending automatic replication order {order_label} assigns provider {provider_label} without a valid owner-bound completion authority"
                )));
            }
            let allocated = allocations
                .entry((provider_id, payload.chunking_profile.clone()))
                .or_default();
            *allocated = allocated.checked_add(assignment.slice_gib).ok_or_else(|| {
                invalid(format!(
                    "automatic replication allocation overflowed for provider {provider_label}"
                ))
            })?;
            if *allocated > profile_capacity {
                return Err(invalid(format!(
                    "automatic replication allocations oversubscribe provider {provider_label} profile `{}`: allocated {} GiB, committed {profile_capacity} GiB",
                    payload.chunking_profile, *allocated
                )));
            }
        }
    }
    Ok(())
}
pub(super) fn validate_ram_lfe_program_policies(
    policies: &Storage<RamLfeProgramId, RamLfeProgramPolicy>,
) -> Result<(), json::Error> {
    for (program_id, policy) in policies.view().iter() {
        if program_id != &policy.program_id {
            return Err(json::Error::InvalidField {
                field: format!("world.ram_lfe_program_policies.{program_id}"),
                message: format!(
                    "RAM-LFE program policy key {program_id} does not match embedded program id {}",
                    policy.program_id
                ),
            });
        }
        crate::smartcontracts::isi::ram_lfe::validate_program_policy(policy).map_err(|err| {
            json::Error::InvalidField {
                field: format!("world.ram_lfe_program_policies.{program_id}"),
                message: err.to_string(),
            }
        })?;
    }
    Ok(())
}

fn take_ram_lfe_program_policies(
    map: &mut SnapshotJsonMap<'_>,
) -> Result<Storage<RamLfeProgramId, RamLfeProgramPolicy>, json::Error> {
    take_required(map, "ram_lfe_program_policies")
}
fn take_parameters_cell(
    map: &mut SnapshotJsonMap<'_>,
    key: &str,
) -> Result<Cell<StateParameters>, StateRestoreError> {
    let source = map
        .remove(key)
        .ok_or_else(|| json::Error::missing_field(key))?;
    source.decode_canonical_value().map_err(|error| {
        crate::execution_attempt::json_decode_attempt_error(error, |error| {
            json::Error::InvalidField {
                field: key.to_owned(),
                message: error.to_string(),
            }
        })
        .into()
    })
}
fn take_topology_cell(
    map: &mut SnapshotJsonMap<'_>,
    key: &str,
) -> Result<Cell<Vec<PeerId>>, json::Error> {
    let value = map
        .remove(key)
        .ok_or_else(|| json::Error::missing_field(key))?;
    match value {
        SnapshotJsonField::Borrowed { raw } if raw.as_bytes().first() == Some(&b'[') => {
            SnapshotJsonField::Borrowed { raw }
                .decode_canonical(key)
                .map(Cell::new)
        }
        #[cfg(test)]
        SnapshotJsonField::Owned(json::Value::Array(values)) => {
            SnapshotJsonField::Owned(json::Value::Array(values))
                .decode_canonical(key)
                .map(Cell::new)
        }
        other => other.decode_canonical(key),
    }
}
fn reject_legacy_musubi_state(
    smart_contract_state: &Storage<StatePath, Vec<u8>>,
) -> Result<(), json::Error> {
    let legacy = smart_contract_state.view().iter().find_map(|(key, _)| {
        let key = key.as_ref();
        is_legacy_musubi_state_path(key).then_some(key.to_owned())
    });
    if let Some(key) = legacy {
        return Err(json::Error::InvalidField {
            field: "smart_contract_state".to_owned(),
            message: format!(
                "legacy pre-release Musubi state `{key}` is unsupported; reset registry state"
            ),
        });
    }
    Ok(())
}
fn is_legacy_musubi_state_path(path: &str) -> bool {
    path == "musubi"
        || path.starts_with("musubi_")
        || path.starts_with("musubi/")
        || path.starts_with("musubi.")
        || path.starts_with("musubi:")
}
#[allow(clippy::too_many_lines)]
pub(crate) fn validate_musubi_location_reverse_indices(
    archives: &Storage<ArchiveId, MusubiArchiveRecordV1>,
    locations: &Storage<MusubiArchiveLocationKeyV1, MusubiArchiveLocationV1>,
    pin_manifests: &Storage<ManifestDigest, PinManifestRecord>,
    replication_orders: &Storage<ReplicationOrderId, ReplicationOrderRecord>,
    by_pin: &Storage<ManifestDigest, MusubiPinLocationReferenceV1>,
    by_order: &Storage<ReplicationOrderId, MusubiReplicationOrderLocationReferenceV1>,
    by_provider: &Storage<MusubiProviderLocationKeyV1, ()>,
) -> Result<(), json::Error> {
    let invalid = |message: String| json::Error::InvalidField {
        field: "world.musubi_location_reverse_indices".to_owned(),
        message,
    };
    let archives = archives.view();
    let locations = locations.view();
    let pin_manifests = pin_manifests.view();
    let replication_orders = replication_orders.view();
    let by_pin = by_pin.view();
    let by_order = by_order.view();
    let by_provider = by_provider.view();
    for (order, record) in replication_orders.iter() {
        let pin = pin_manifests
            .get(&record.manifest_digest)
            .ok_or_else(|| invalid("replication order targets a missing pin manifest".into()))?;
        let order_label = hex::encode(order.as_bytes());
        let approved_epoch =
            crate::smartcontracts::isi::sorafs::validate_stored_pin_approval_history(
                pin,
                &hex::encode(pin.digest.as_bytes()),
            )
            .map_err(|error| invalid(error.to_string()))?
            .ok_or_else(|| {
                invalid(format!(
                    "replication order {order_label} targets a pin that was never approved"
                ))
            })?;
        if record.issued_epoch < approved_epoch {
            return Err(invalid(format!(
                "replication order {order_label} predates its target pin approval epoch {approved_epoch}"
            )));
        }
        if let PinStatus::Retired(retired_epoch) = pin.status {
            if record.issued_epoch > retired_epoch
                || matches!(record.status, ReplicationOrderStatus::Pending)
                || matches!(record.status, ReplicationOrderStatus::Completed(epoch) | ReplicationOrderStatus::Expired(epoch) if epoch > retired_epoch)
                || order.is_auto()
                    && matches!(record.status, ReplicationOrderStatus::Completed(_))
                    && retired_epoch < pin.policy.retention_epoch
            {
                return Err(invalid(format!(
                    "replication order {order_label} lifecycle falls outside its target pin retirement epoch {retired_epoch}"
                )));
            }
        }
        let canonical_order = if order.is_auto() {
            crate::smartcontracts::isi::sorafs::validate_stored_automatic_replication_order(
                pin,
                record,
                &order_label,
            )
        } else {
            crate::smartcontracts::isi::sorafs::validate_stored_replication_order(
                record,
                &order_label,
            )
        }
        .map_err(|error| invalid(error.to_string()))?;
        if record.order_id != *order
            || pin.digest != record.manifest_digest
            || pin.root_cid != record.manifest_root_cid
            || canonical_order.chunking_profile != pin.chunker.to_handle()
            || canonical_order.target_replicas < pin.policy.min_replicas
            || record.deadline_epoch >= pin.policy.retention_epoch
        {
            return Err(invalid(
                "replication order does not match its immutable pin commitment or retention policy"
                    .into(),
            ));
        }
        if let ReplicationOrderStatus::Cancelled(cancelled_epoch) = record.status
            && !matches!(pin.status, PinStatus::Retired(retired_epoch) if retired_epoch == cancelled_epoch)
        {
            return Err(invalid(
                "cancelled replication order must exactly match its target pin retirement epoch"
                    .into(),
            ));
        }
        let reference = by_order.get(order);
        match (record.musubi_archive, reference) {
            (None, None) => {}
            (Some(archive_id), Some(reference))
                if reference.binding.replication_order == *order
                    && reference.binding.archive_id == archive_id => {}
            (Some(_), None) => {
                return Err(invalid(
                    "Musubi-purpose replication order is missing its archive binding".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(invalid(
                    "generic replication order cannot carry a Musubi archive binding".into(),
                ));
            }
            (Some(_), Some(_)) => {
                return Err(invalid(
                    "replication-order Musubi purpose does not match its archive binding".into(),
                ));
            }
        }
    }
    for (digest, reference) in by_pin.iter() {
        reference
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if digest != &reference.pin_manifest {
            return Err(invalid(
                "pin reverse-index key does not match its duplicated manifest digest".into(),
            ));
        }
        let target = locations
            .get(&reference.location)
            .ok_or_else(|| invalid("pin reverse reference targets a missing location".into()))?;
        if reference.active {
            if target.state == MusubiArchiveLocationStateV1::Retired
                || target.pin_manifest != *digest
            {
                return Err(invalid(
                    "active pin reverse reference does not match its current location".into(),
                ));
            }
        }
    }
    for (order, reference) in by_order.iter() {
        reference
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if order != &reference.binding.replication_order {
            return Err(invalid(
                "order reverse-index key does not match its duplicated order identity".into(),
            ));
        }
        let archive = archives
            .get(&reference.binding.archive_id)
            .ok_or_else(|| invalid("order binding targets a missing Musubi archive".into()))?;
        archive
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if archive.archive_id != reference.binding.archive_id
            || archive.commitment != reference.binding.commitment
        {
            return Err(invalid(
                "order binding does not match the authoritative archive commitment".into(),
            ));
        }
        let order_record = replication_orders
            .get(order)
            .ok_or_else(|| invalid("order binding targets a missing replication order".into()))?;
        if order_record.order_id != *order
            || order_record.musubi_archive != Some(reference.binding.archive_id)
            || order_record.manifest_root_cid != archive.commitment.root_cid
        {
            return Err(invalid(
                "order binding does not match its authoritative replication order".into(),
            ));
        }
        let canonical_order =
            crate::smartcontracts::isi::sorafs::validate_stored_replication_order(
                order_record,
                &hex::encode(order.as_bytes()),
            )
            .map_err(|error| invalid(error.to_string()))?;
        let pin = pin_manifests
            .get(&order_record.manifest_digest)
            .ok_or_else(|| {
                invalid("order binding replication order targets a missing pin manifest".into())
            })?;
        if pin.digest != order_record.manifest_digest
            || pin.root_cid != archive.commitment.root_cid
            || pin.chunker != archive.commitment.chunker
            || pin.chunk_digest_sha3_256 != *archive.commitment.chunk_plan_digest.as_bytes()
            || pin.por_root != *archive.commitment.por_root.as_bytes()
            || pin.content_length != archive.commitment.content_length
            || canonical_order.chunking_profile != pin.chunker.to_handle()
            || canonical_order.target_replicas
                < iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1
            || canonical_order.target_replicas < pin.policy.min_replicas
            || pin.policy.min_replicas < iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1
            || order_record.deadline_epoch >= pin.policy.retention_epoch
        {
            return Err(invalid(
                "order binding does not match its immutable pin commitment or retention policy"
                    .into(),
            ));
        }
        let mut completed_providers = order_record
            .provider_completions
            .iter()
            .map(|completion| completion.provider_id)
            .collect::<Vec<_>>();
        completed_providers.sort();
        match &reference.lifecycle {
            MusubiReplicationOrderLocationLifecycleV1::PreLocation => {}
            MusubiReplicationOrderLocationLifecycleV1::Active(location) => {
                let target = locations.get(location).ok_or_else(|| {
                    invalid("active order binding targets a missing location".into())
                })?;
                if !matches!(
                    target.state,
                    MusubiArchiveLocationStateV1::Healthy | MusubiArchiveLocationStateV1::Degraded
                ) || target.archive_id != archive.archive_id
                    || target.replication_order != *order
                    || !matches!(
                        order_record.status,
                        iroha_data_model::sorafs::pin_registry::ReplicationOrderStatus::Completed(
                            _
                        )
                    )
                    || completed_providers != target.providers
                {
                    return Err(invalid(
                        "active order binding does not match its completed provider location"
                            .into(),
                    ));
                }
            }
            MusubiReplicationOrderLocationLifecycleV1::Retired(retired) => {
                let target = locations.get(&retired.location).ok_or_else(|| {
                    invalid("retired order binding targets a missing location".into())
                })?;
                if target.archive_id != archive.archive_id
                    || (target.state != MusubiArchiveLocationStateV1::Retired
                        && target.replication_order == *order)
                    || !matches!(
                        order_record.status,
                        iroha_data_model::sorafs::pin_registry::ReplicationOrderStatus::Completed(
                            _
                        )
                    )
                    || completed_providers != retired.providers
                    || (target.state == MusubiArchiveLocationStateV1::Retired
                        && target.replication_order == *order
                        && target.providers != retired.providers)
                {
                    return Err(invalid(
                        "retired order binding does not match its completed historical location"
                            .into(),
                    ));
                }
            }
        }
    }
    for (key, ()) in by_provider.iter() {
        key.validate().map_err(|error| invalid(error.to_string()))?;
        let location = locations.get(&key.location).ok_or_else(|| {
            invalid("provider reverse reference targets a missing location".into())
        })?;
        if location.state == MusubiArchiveLocationStateV1::Retired
            || location.providers.binary_search(&key.provider_id).is_err()
        {
            return Err(invalid(
                "provider reverse reference does not match its current location".into(),
            ));
        }
    }
    for (key, location) in locations.iter() {
        location
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if key != &location.key() {
            return Err(invalid(
                "archive-location key does not match the stored record".into(),
            ));
        }
        if location.state == MusubiArchiveLocationStateV1::Retired {
            if !by_pin
                .get(&location.pin_manifest)
                .is_some_and(|reference| !reference.active && reference.location == *key)
                || !by_order
                    .get(&location.replication_order)
                    .is_some_and(|reference| reference.retired_location() == Some(*key))
            {
                return Err(invalid(
                    "retired archive location is missing an immutable reuse tombstone".into(),
                ));
            }
            continue;
        }
        if !by_pin
            .get(&location.pin_manifest)
            .is_some_and(|reference| reference.active && reference.location == *key)
            || !by_order
                .get(&location.replication_order)
                .is_some_and(|reference| reference.active_location() == Some(*key))
            || location.providers.iter().any(|provider| {
                by_provider
                    .get(&MusubiProviderLocationKeyV1::new(*provider, *key))
                    .is_none()
            })
        {
            return Err(invalid(
                "current archive location is missing an exact reverse-index entry".into(),
            ));
        }
    }
    for (manifest_digest, pin) in pin_manifests.iter() {
        if manifest_digest != &pin.digest {
            return Err(invalid(
                "pin-manifest key does not match its embedded manifest digest".into(),
            ));
        }
        let approval_epoch =
            crate::smartcontracts::isi::sorafs::validate_stored_pin_approval_history(
                pin,
                &hex::encode(manifest_digest.as_bytes()),
            )
            .map_err(|error| invalid(error.to_string()))?;
        let expected_order_id =
            iroha_data_model::sorafs::pin_registry::derive_sorafs_auto_replication_order_id_v1(
                &pin.digest,
            );
        if approval_epoch.is_none() {
            if replication_orders.get(&expected_order_id).is_some() {
                return Err(invalid(format!(
                    "never-approved pin manifest {} has an automatic replication order {}",
                    hex::encode(manifest_digest.as_bytes()),
                    hex::encode(expected_order_id.as_bytes()),
                )));
            }
            continue;
        }
        let record = replication_orders.get(&expected_order_id).ok_or_else(|| {
            invalid(format!(
                "approved pin history for manifest {} is missing its mandatory automatic replication order {}",
                hex::encode(manifest_digest.as_bytes()),
                hex::encode(expected_order_id.as_bytes()),
            ))
        })?;
        crate::smartcontracts::isi::sorafs::validate_stored_automatic_replication_order(
            pin,
            record,
            &hex::encode(expected_order_id.as_bytes()),
        )
        .map_err(|error| invalid(error.to_string()))?;
    }
    Ok(())
}
fn invalid_musubi_state(field: &str, message: impl Into<String>) -> json::Error {
    json::Error::InvalidField {
        field: format!("world.{field}"),
        message: message.into(),
    }
}
fn validate_musubi_resolver_checkpoint_structure(
    checkpoints: &Storage<MusubiResolverIndexRevisionV1, MusubiRegistrySnapshotV1>,
    current_revision: u64,
) -> Result<(), json::Error> {
    let checkpoints = checkpoints.view();
    let mut previous_height = None;
    let mut latest_revision = None;
    for (revision, checkpoint) in checkpoints.iter() {
        checkpoint.validate().map_err(|error| {
            invalid_musubi_state("musubi_resolver_index_checkpoints", error.to_string())
        })?;
        if revision.get() != checkpoint.index_revision {
            return Err(invalid_musubi_state(
                "musubi_resolver_index_checkpoints",
                "resolver checkpoint key does not match its embedded revision",
            ));
        }
        if previous_height.is_none() && checkpoint.finalized_height != 1 {
            return Err(invalid_musubi_state(
                "musubi_resolver_index_checkpoints",
                "resolver checkpoint history must begin at genesis",
            ));
        }
        if previous_height.is_some_and(|height| height >= checkpoint.finalized_height) {
            return Err(invalid_musubi_state(
                "musubi_resolver_index_checkpoints",
                "resolver checkpoint activation heights must increase strictly",
            ));
        }
        previous_height = Some(checkpoint.finalized_height);
        latest_revision = Some(revision.get());
    }
    if latest_revision.is_some_and(|revision| revision != current_revision) {
        return Err(invalid_musubi_state(
            "musubi_resolver_index_checkpoints",
            "latest resolver checkpoint does not match the current resolver-index revision",
        ));
    }
    Ok(())
}
fn validate_musubi_resolver_checkpoint_anchors(
    world: &World,
    block_hashes: &(impl crate::state::BlockHashRead + ?Sized),
) -> Result<(), json::Error> {
    let current_revision = world.musubi_resolver_index_revision.view().get().get();
    validate_musubi_resolver_checkpoint_structure(
        &world.musubi_resolver_index_checkpoints,
        current_revision,
    )?;
    let checkpoints = world.musubi_resolver_index_checkpoints.view();
    let history_is_empty = checkpoints.is_empty();
    if block_hashes.hash_count() == 0 {
        if !history_is_empty {
            return Err(invalid_musubi_state(
                "musubi_resolver_index_checkpoints",
                "pregenesis state cannot contain resolver checkpoints",
            ));
        }
        return Ok(());
    }
    if history_is_empty {
        return Err(invalid_musubi_state(
            "musubi_resolver_index_checkpoints",
            "committed state must retain the genesis resolver checkpoint",
        ));
    }
    for (_, checkpoint) in checkpoints.iter() {
        let index = checkpoint
            .finalized_height
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok());
        let canonical_hash = index
            .and_then(|index| block_hashes.hash_at(index))
            .map(|hash| *hash.as_ref());
        if canonical_hash != Some(checkpoint.finalized_block_hash) {
            return Err(invalid_musubi_state(
                "musubi_resolver_index_checkpoints",
                "resolver checkpoint is not anchored to its canonical finalized block",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
include!("deserialize_transaction_history_tests.rs");

#[cfg(test)]
mod evidence_record_restore_adapter_tests {
    use super::*;
    use crate::snapshot::TryReadError;
    use crate::state::EvidencePreparationError;
    use crate::sumeragi::evidence::record::EvidenceRecordRestoreError;
    use iroha_allocation::{AllocationBudget, AllocationRefusal};

    #[test]
    fn evidence_snapshot_requires_canonical_borrowed_bytes_but_restores_owned_projection() {
        let storage = Storage::<iroha_crypto::Hash, RetainedEvidenceRecord>::default();
        let canonical = json::to_json(&storage).unwrap();
        let projection = json::to_value(&storage).unwrap();
        let reordered = json::to_json(&projection).unwrap();
        assert_ne!(
            canonical, reordered,
            "the DOM has discarded declaration order"
        );
        let budget = AllocationBudget::new(1024);
        let restored = SnapshotJsonField::Borrowed { raw: &canonical }
            .decode_evidence(&budget)
            .expect("canonical native snapshot bytes restore");
        assert_eq!(json::to_json(&restored).unwrap(), canonical);
        let rejected = SnapshotJsonField::Borrowed { raw: &reordered }
            .decode_evidence(&budget)
            .err()
            .expect("reordered native snapshot bytes must remain rejected");
        assert!(
            matches!(rejected, StateRestoreError::Serialization(json::Error::InvalidField {ref field, ref message})
            if field == "consensus_evidence" && message.contains("not canonically encoded"))
        );
        let restored = SnapshotJsonField::Owned(projection)
            .decode_evidence(&budget)
            .expect("test DOM projection restores through the same admitted record reader");
        assert_eq!(json::to_json(&restored).unwrap(), canonical);
        let mut invalid = json::to_value(&storage).unwrap();
        let json::Value::Object(ref mut fields) = invalid else {
            panic!("native storage is an object");
        };
        fields.insert("retired_field".into(), json::Value::Null);
        assert!(
            SnapshotJsonField::Owned(invalid)
                .decode_evidence(&budget)
                .is_err(),
            "owned fixture projection still rejects unknown storage fields"
        );
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    fn partial_original_record() -> String {
        let key =
            json::to_json(&iroha_crypto::Hash::new(b"original partial restore claim")).unwrap();
        // The native byte destination is reached before this later unknown field.
        // No native certificate or attribution authority is manufactured by the fixture.
        format!(
            "{{\"revert\":{{}},\"blocks\":{{{key}:{{\"evidence\":{{\"native\":[1],\"later_unknown\":null}}}}}}}}"
        )
    }

    #[test]
    fn borrowed_evidence_restore_adapter_preserves_original_capacity_before_late_syntax() {
        let source = partial_original_record();
        let budget = AllocationBudget::new(64);
        let occupied = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
        let layout = std::alloc::Layout::array::<u8>(1).unwrap();
        let expected = budget.try_reserve(layout).unwrap_err();
        assert!(matches!(&expected, AllocationRefusal::Capacity { .. }));
        let Err(error) = SnapshotJsonField::Borrowed { raw: &source }.decode_evidence(&budget)
        else {
            panic!("the actual snapshot adapter must preserve original physical refusal");
        };
        let TryReadError::StateEvidence(EvidenceRecordRestoreError::Preparation(
            EvidencePreparationError::Admission(actual),
        )) = TryReadError::from(error)
        else {
            panic!("actual adapter must not erase original Capacity into snapshot syntax");
        };
        assert_eq!(actual, expected);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(occupied);
        let Err(error) = SnapshotJsonField::Borrowed { raw: &source }.decode_evidence(&budget)
        else {
            panic!("after original credit returns the later canonical syntax error is reached");
        };
        assert!(
            matches!(error, StateRestoreError::Serialization(json::Error::InvalidField {ref field, ref message})
            if field == "consensus_evidence" && message.contains("later_unknown"))
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn borrowed_evidence_restore_adapter_preserves_actual_active_logical_refusal() {
        let source = partial_original_record();
        let budget = AllocationBudget::new(64);
        let limits = norito::core::DecodeLimits::new(1024, 1024, 1024, 0, 32);
        let Err(error) = norito::core::with_decode_limits_scope(limits, || {
            SnapshotJsonField::Borrowed { raw: &source }.decode_evidence(&budget)
        }) else {
            panic!("active original logical scope must refuse through the real adapter");
        };
        let TryReadError::StateEvidence(EvidenceRecordRestoreError::Logical(original)) =
            TryReadError::from(error)
        else {
            panic!("actual logical origin must not become generic snapshot syntax");
        };
        assert!(original.is_decode_resource_limit());
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

impl From<sccp_forgery_custody::ForgeryStorageError> for StateRestoreError {
    fn from(error: sccp_forgery_custody::ForgeryStorageError) -> Self {
        Self::Admission(StateAdmissionError::Storage(
            StateStorageAdmissionError::SccpForgery(error),
        ))
    }
}

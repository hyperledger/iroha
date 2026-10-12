//! Bounded native gateway rows, policy history and atomic World publication.
//!
//! These reads establish integrity within one supplied World view only. They do not establish
//! current finality, independently challenged readback or signed execution. The native ISI
//! owner must derive execution and the instruction digest from its exact directly signed
//! instruction, enforce current ledger permissions, and call the pure transition owner.
//! No local journal or retained head can detect replacement of the entire World with an old cut.

use std::str::FromStr;

use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    sorafs::stream_token_gateway::native::{
        StreamTokenGatewayExecutionV1 as Execution, StreamTokenGatewayPolicyV1 as Policy,
    },
};
use iroha_model_base::state_path::StatePath;
use mv::storage::StorageReadOnly;
use norito::codec::{Decode, Encode};

use super::rows::*;
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};

use TransitionError as Error;

/// Root reserved against contract reads, writes and deletes by the native host.
pub(crate) const STATE_ROOT: &str = "sorafs_stream_token_gateway_v1";
/// Maximum canonical frame for any individual gateway row, including an original admission.
pub(crate) const MAX_ROW_BYTES: usize = 64 * 1024;
/// Aggregate encoded replacement/path bytes staged by one bounded native instruction.
const MAX_STAGED_BYTES: usize = 2 * 1024 * 1024;

/// Immutable original governance transition, distinct from the policy's own commitment.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::stream_token_gateway::GatewayPolicyRecordV1")]
pub(crate) struct GatewayPolicyRecordV1 {
    /// Complete original policy, including its own revision and policy digest.
    pub policy: Policy,
    /// Previous immutable policy-record digest, zero only at revision one.
    pub predecessor_digest: [u8; 32],
    /// Domain-separated exact instruction and signing-account commitment.
    pub instruction_digest: [u8; 32],
    /// Actual native execution supplied by the instruction owner.
    pub execution: Execution,
}

/// Small current-policy pointer; policy and history commitments have separate meanings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::stream_token_gateway::GatewayPolicyHeadV1")]
pub(crate) struct GatewayPolicyHeadV1 {
    /// Exact latest adjacent policy revision.
    pub revision: u64,
    /// Canonical policy commitment, excluding its own digest field.
    pub policy_digest: [u8; 32],
    /// Commitment to the complete immutable policy-history record.
    pub record_digest: [u8; 32],
}

/// Operational head paired with its last immutable native mutation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::stream_token_gateway::GatewayStoredHeadV1")]
pub(crate) struct GatewayStoredHeadV1 {
    /// Existing pure-transition head, unaffected by policy rotation.
    pub head: GatewayHeadV1,
    /// Last immutable mutation commitment; zero exactly before the first mutation.
    pub mutation_digest: [u8; 32],
}

/// Immutable commitment to one changed delta, including its indexed acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::stream_token_gateway::GatewayMutationRecordV1")]
pub(crate) struct GatewayMutationRecordV1 {
    /// Previous immutable mutation digest, zero only for the first mutation.
    pub predecessor_digest: [u8; 32],
    /// Exact policy revision under which this operation executed.
    pub policy_revision: u64,
    /// Exact policy commitment, distinct from the policy-history commitment.
    pub policy_digest: [u8; 32],
    /// Exact immutable policy-history commitment.
    pub policy_record_digest: [u8; 32],
    /// Domain-separated directly signed instruction and authority commitment.
    pub instruction_digest: [u8; 32],
    /// Actual native execution supplied by the instruction owner.
    pub execution: Execution,
    /// Exact operational source head.
    pub before: GatewayHeadV1,
    /// Exact operational replacement head; its revision indexes this record.
    pub after: GatewayHeadV1,
    /// Ordered commitment to canonical paths and typed before/after row frames.
    pub writes_digest: [u8; 32],
    /// Exact number of independent row CAS operations.
    pub write_count: u32,
}

/// Same-World control and operational inputs; neither wire form nor finality capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GatewayCurrentV1 {
    /// Latest immutable governance transition.
    pub policy: GatewayPolicyRecordV1,
    /// Current policy/history pointer.
    pub policy_head: GatewayPolicyHeadV1,
    /// Current operational head and immutable mutation commitment.
    pub head: GatewayStoredHeadV1,
}

/// Bound canonical encoding, checked before allocating its frame.
pub(crate) fn encode<T: norito::core::NoritoSerialize>(value: &T) -> Result<Vec<u8>, Error> {
    if norito::canonical_frame_len(value).map_err(|_| Error::Invalid)? > MAX_ROW_BYTES {
        return Err(Error::Invalid);
    }
    norito::encode_canonical(value).map_err(|_| Error::Invalid)
}

/// Bound exact canonical decoding; stored frames never choose ambient codec flags.
pub(crate) fn decode<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: norito::core::NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > MAX_ROW_BYTES {
        return Err(Error::CorruptHistory);
    }
    norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(
            MAX_ROW_BYTES,
            MAX_ROW_BYTES,
            2 * MAX_ROW_BYTES,
            256 * 1024,
            32,
        ),
    )
    .map_err(|_| Error::CorruptHistory)
}

fn commitment<T: norito::core::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], Error> {
    let frame = encode(value)?;
    let mut bytes = Vec::with_capacity(domain.len() + frame.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&frame);
    Ok(*Hash::new(bytes).as_ref())
}

/// Commitment to a complete immutable policy record, not merely to the policy.
pub(crate) fn policy_record_digest(record: &GatewayPolicyRecordV1) -> Result<[u8; 32], Error> {
    commitment(
        b"iroha.sorafs.stream-token.gateway-policy-record.v1\0",
        record,
    )
}

/// Commitment to one immutable operational mutation.
pub(crate) fn mutation_record_digest(record: &GatewayMutationRecordV1) -> Result<[u8; 32], Error> {
    commitment(b"iroha.sorafs.stream-token.gateway-mutation.v1\0", record)
}

fn scope(gateway: [u8; 32]) -> Result<String, Error> {
    if gateway == [0; 32] {
        return Err(Error::BindingMismatch);
    }
    Ok(format!("{STATE_ROOT}/{}/", hex::encode(gateway)))
}

fn path(gateway: [u8; 32], suffix: &str) -> Result<StatePath, Error> {
    StatePath::from_str(&format!("{}{suffix}", scope(gateway)?)).map_err(|_| Error::Invalid)
}

// Every prefix ends in '/'. Replacing that ASCII byte by '0' gives an exact exclusive
// lexicographic upper bound, including malformed descendants that must not be filtered away.
fn prefix_bounds(gateway: [u8; 32], suffix: &str) -> Result<(StatePath, StatePath), Error> {
    let prefix = format!("{}{suffix}", scope(gateway)?);
    let upper = format!("{}0", prefix.strip_suffix('/').ok_or(Error::Invalid)?);
    Ok((
        StatePath::from_str(&prefix).map_err(|_| Error::Invalid)?,
        StatePath::from_str(&upper).map_err(|_| Error::Invalid)?,
    ))
}

/// Canonical current-policy pointer path.
pub(crate) fn policy_head_path(gateway: [u8; 32]) -> Result<StatePath, Error> {
    path(gateway, "policy/head")
}

/// Canonical immutable policy-history path.
pub(crate) fn policy_record_path(gateway: [u8; 32], revision: u64) -> Result<StatePath, Error> {
    path(gateway, &format!("policy/revision/{revision:020}"))
}

/// Canonical operational-head path.
pub(crate) fn head_path(gateway: [u8; 32]) -> Result<StatePath, Error> {
    path(gateway, "head")
}

/// Canonical immutable operational-mutation path.
pub(crate) fn mutation_path(gateway: [u8; 32], revision: u64) -> Result<StatePath, Error> {
    path(gateway, &format!("mutation/{revision:020}"))
}

/// Canonical typed row path; expiry ordering exactly matches the engine's key order.
pub(crate) fn row_path(gateway: [u8; 32], key: &GatewayRowKey) -> Result<StatePath, Error> {
    let suffix = match key {
        GatewayRowKey::Admission(sequence) => format!("row/admission/{sequence:020}"),
        GatewayRowKey::Acknowledgement(sequence) => format!("row/acknowledgement/{sequence:020}"),
        GatewayRowKey::Context(id) => format!("row/context/{}", hex::encode(id)),
        GatewayRowKey::TokenIdentity(id) => format!("row/token/{}", hex::encode(id)),
        GatewayRowKey::QuotaLifecycle(id) => format!("row/lifecycle/{}", hex::encode(id)),
        GatewayRowKey::Quota(id) => format!("row/quota/{}", hex::encode(id)),
        GatewayRowKey::Lease(id) => format!("row/lease/{}", hex::encode(id)),
        GatewayRowKey::LeaseTerminal(id) => format!("row/terminal/{}", hex::encode(id)),
        GatewayRowKey::Expiry(key) => {
            let (kind, id) = match key.target {
                GatewayExpiryTargetV1::Lease(id) => (0, id),
                GatewayExpiryTargetV1::Quota(id) => (1, id),
            };
            format!(
                "row/expiry/{:020}/{kind}/{}",
                key.at_unix_ms,
                hex::encode(id)
            )
        }
    };
    path(gateway, &suffix)
}

fn read<T>(world: &impl WorldReadOnly, key: &StatePath) -> Result<Option<T>, Error>
where
    T: norito::core::NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de>,
{
    world
        .smart_contract_state()
        .get(key)
        .map(|bytes| decode(bytes))
        .transpose()
}

fn execution_position(value: &Execution) -> (u64, u32, u32) {
    (value.height, value.entry_index, value.instruction_index)
}

fn valid_execution(value: &Execution) -> Result<(), Error> {
    if value.height == 0
        || value.transaction_hash == [0; 32]
        || value.recorded_at_unix_ms == 0
        || value.recorded_at_unix_ms == u64::MAX
    {
        return Err(Error::CorruptHistory);
    }
    Ok(())
}

fn after_execution(value: &Execution, previous: &Execution) -> Result<(), Error> {
    valid_execution(value)?;
    valid_execution(previous)?;
    if execution_position(value) <= execution_position(previous)
        || value.recorded_at_unix_ms < previous.recorded_at_unix_ms
        || (value.height == previous.height
            && value.recorded_at_unix_ms != previous.recorded_at_unix_ms)
    {
        return Err(Error::CorruptHistory);
    }
    Ok(())
}

fn valid_head(head: GatewayHeadV1) -> Result<(), Error> {
    if head.acknowledged_through_sequence > head.high_water_sequence
        || head.revision < head.high_water_sequence
        || u64::from(head.live_tokens) > head.high_water_sequence
        || (head.revision == 0 && head != GatewayHeadV1::default())
        || (head.revision != 0
            && (head.last_execution_unix_ms == 0 || head.last_execution_unix_ms == u64::MAX))
    {
        return Err(Error::CorruptHistory);
    }
    Ok(())
}

fn namespace_empty(world: &impl WorldReadOnly, gateway: [u8; 32]) -> Result<bool, Error> {
    let (start, end) = prefix_bounds(gateway, "")?;
    let exact =
        StatePath::from_str(scope(gateway)?.trim_end_matches('/')).map_err(|_| Error::Invalid)?;
    Ok(world.smart_contract_state().get(&exact).is_none()
        && world
            .smart_contract_state()
            .range(start..end)
            .next()
            .is_none())
}

fn latest_key(
    world: &impl WorldReadOnly,
    gateway: [u8; 32],
    suffix: &str,
) -> Result<Option<StatePath>, Error> {
    let (start, end) = prefix_bounds(gateway, suffix)?;
    Ok(world
        .smart_contract_state()
        .range(start..end)
        .next_back()
        .map(|(key, _)| key.clone()))
}

fn policy_record_bare(
    world: &impl WorldReadOnly,
    network: &NetworkId,
    gateway: [u8; 32],
    revision: u64,
) -> Result<GatewayPolicyRecordV1, Error> {
    if revision == 0 {
        return Err(Error::CorruptHistory);
    }
    let record: GatewayPolicyRecordV1 =
        read(world, &policy_record_path(gateway, revision)?)?.ok_or(Error::CorruptHistory)?;
    record
        .policy
        .validate()
        .map_err(|_| Error::CorruptHistory)?;
    valid_execution(&record.execution)?;
    if record.policy.network_id != *network
        || record.policy.qualification.gateway_id != gateway
        || record.policy.qualification.revision != revision
        || record.instruction_digest == [0; 32]
        || (revision == 1) != (record.predecessor_digest == [0; 32])
    {
        return Err(Error::CorruptHistory);
    }
    Ok(record)
}

/// Read an immutable policy and verify its adjacent predecessor in this exact World view.
pub(crate) fn read_policy_record(
    world: &impl WorldReadOnly,
    network: &NetworkId,
    gateway: [u8; 32],
    revision: u64,
) -> Result<GatewayPolicyRecordV1, Error> {
    let record = policy_record_bare(world, network, gateway, revision)?;
    if revision > 1 {
        let previous = policy_record_bare(world, network, gateway, revision - 1)?;
        if policy_record_digest(&previous)? != record.predecessor_digest {
            return Err(Error::CorruptHistory);
        }
        record
            .policy
            .validate_replacement(&previous.policy)
            .map_err(|_| Error::CorruptHistory)?;
        after_execution(&record.execution, &previous.execution)?;
    }
    Ok(record)
}

fn execution_under_policy(
    world: &impl WorldReadOnly,
    network: &NetworkId,
    gateway: [u8; 32],
    policy: &GatewayPolicyRecordV1,
    execution: &Execution,
) -> Result<(), Error> {
    if !policy.policy.operators.contains(&execution.authority) {
        return Err(Error::CorruptHistory);
    }
    after_execution(execution, &policy.execution)?;
    let head: GatewayPolicyHeadV1 =
        read(world, &policy_head_path(gateway)?)?.ok_or(Error::CorruptHistory)?;
    let revision = policy.policy.qualification.revision;
    if head.revision < revision {
        return Err(Error::CorruptHistory);
    }
    if head.revision > revision {
        let next = read_policy_record(
            world,
            network,
            gateway,
            revision.checked_add(1).ok_or(Error::CorruptHistory)?,
        )?;
        // Original policy authority ends at its first successor's exact execution position.
        after_execution(&next.execution, execution)?;
    }
    Ok(())
}

fn mutation_bare(
    world: &impl WorldReadOnly,
    network: &NetworkId,
    gateway: [u8; 32],
    revision: u64,
) -> Result<GatewayMutationRecordV1, Error> {
    if revision == 0 {
        return Err(Error::CorruptHistory);
    }
    let record: GatewayMutationRecordV1 =
        read(world, &mutation_path(gateway, revision)?)?.ok_or(Error::CorruptHistory)?;
    valid_head(record.before)?;
    valid_head(record.after)?;
    valid_execution(&record.execution)?;
    if record.after.revision != revision
        || record.before.revision.checked_add(1) != Some(revision)
        || record.after.last_execution_unix_ms != record.execution.recorded_at_unix_ms
        || record.before.last_execution_unix_ms > record.execution.recorded_at_unix_ms
        || record.after.high_water_sequence < record.before.high_water_sequence
        || record.after.acknowledged_through_sequence < record.before.acknowledged_through_sequence
        || record.instruction_digest == [0; 32]
        || record.writes_digest == [0; 32]
        || record.write_count as usize > MAX_TRANSITION_WRITES
        || (revision == 1) != (record.predecessor_digest == [0; 32])
    {
        return Err(Error::CorruptHistory);
    }
    let policy = read_policy_record(world, network, gateway, record.policy_revision)?;
    if policy.policy.qualification.policy_digest != record.policy_digest
        || policy_record_digest(&policy)? != record.policy_record_digest
    {
        return Err(Error::CorruptHistory);
    }
    execution_under_policy(world, network, gateway, &policy, &record.execution)?;
    Ok(record)
}

/// Read one retained mutation and its adjacent predecessor without scanning history.
pub(crate) fn read_mutation(
    world: &impl WorldReadOnly,
    network: &NetworkId,
    gateway: [u8; 32],
    revision: u64,
) -> Result<GatewayMutationRecordV1, Error> {
    let record = mutation_bare(world, network, gateway, revision)?;
    if revision > 1 {
        let previous = mutation_bare(world, network, gateway, revision - 1)?;
        if mutation_record_digest(&previous)? != record.predecessor_digest
            || previous.after != record.before
        {
            return Err(Error::CorruptHistory);
        }
        after_execution(&record.execution, &previous.execution)?;
    }
    Ok(record)
}

/// Read exact current policy/head association within one World, rejecting partial rollback.
pub(crate) fn read_current(
    world: &impl WorldReadOnly,
    network: &NetworkId,
    gateway: [u8; 32],
) -> Result<Option<GatewayCurrentV1>, Error> {
    let Some(policy_head): Option<GatewayPolicyHeadV1> = read(world, &policy_head_path(gateway)?)?
    else {
        return if namespace_empty(world, gateway)? {
            Ok(None)
        } else {
            Err(Error::CorruptHistory)
        };
    };
    let policy = read_policy_record(world, network, gateway, policy_head.revision)?;
    if policy_head.policy_digest != policy.policy.qualification.policy_digest
        || policy_head.record_digest != policy_record_digest(&policy)?
        || latest_key(world, gateway, "policy/revision/")?
            != Some(policy_record_path(gateway, policy_head.revision)?)
    {
        return Err(Error::CorruptHistory);
    }
    let head: GatewayStoredHeadV1 =
        read(world, &head_path(gateway)?)?.ok_or(Error::CorruptHistory)?;
    valid_head(head.head)?;
    let expected_admission = if head.head.high_water_sequence == 0 {
        None
    } else {
        Some(row_path(
            gateway,
            &GatewayRowKey::Admission(head.head.high_water_sequence),
        )?)
    };
    if latest_key(world, gateway, "row/admission/")? != expected_admission {
        return Err(Error::CorruptHistory);
    }
    let expected_acknowledgement = if head.head.acknowledged_through_sequence == 0 {
        None
    } else {
        Some(row_path(
            gateway,
            &GatewayRowKey::Acknowledgement(head.head.acknowledged_through_sequence),
        )?)
    };
    if latest_key(world, gateway, "row/acknowledgement/")? != expected_acknowledgement {
        return Err(Error::CorruptHistory);
    }
    if head.head.revision == 0 {
        if head.mutation_digest != [0; 32]
            || latest_key(world, gateway, "mutation/")?.is_some()
            || latest_key(world, gateway, "row/")?.is_some()
        {
            return Err(Error::CorruptHistory);
        }
    } else {
        let mutation = read_mutation(world, network, gateway, head.head.revision)?;
        if mutation.after != head.head
            || mutation_record_digest(&mutation)? != head.mutation_digest
            || mutation.policy_revision > policy_head.revision
            || latest_key(world, gateway, "mutation/")?
                != Some(mutation_path(gateway, head.head.revision)?)
        {
            return Err(Error::CorruptHistory);
        }
        if mutation.policy_revision == policy_head.revision {
            if mutation.policy_record_digest != policy_head.record_digest {
                return Err(Error::CorruptHistory);
            }
        } else {
            after_execution(&policy.execution, &mutation.execution)?;
        }
    }
    Ok(Some(GatewayCurrentV1 {
        policy,
        policy_head,
        head,
    }))
}

/// Borrowed exact-World row source; its constructor supplies no finality or permissions.
pub(crate) struct WorldGatewayRows<'a, W: WorldReadOnly> {
    world: &'a W,
    network: NetworkId,
    gateway: [u8; 32],
}

impl<'a, W: WorldReadOnly> WorldGatewayRows<'a, W> {
    /// Bind lazy typed reads to independently selected network and gateway identities.
    pub(crate) fn new(world: &'a W, network: &NetworkId, gateway: [u8; 32]) -> Result<Self, Error> {
        read_current(world, network, gateway)?.ok_or(Error::Unavailable)?;
        Ok(Self {
            world,
            network: *network,
            gateway,
        })
    }
}

fn encode_row(key: &GatewayRowKey, row: &GatewayRow) -> Result<Vec<u8>, Error> {
    match (key, row) {
        (GatewayRowKey::Admission(sequence), GatewayRow::Admission(value))
            if *sequence != 0 && value.record.outcome.binding.gateway_sequence == *sequence =>
        {
            encode(value)
        }
        (GatewayRowKey::Acknowledgement(sequence), GatewayRow::Acknowledgement(value))
            if *sequence != 0 && value.record.outcome.binding.gateway_sequence == *sequence =>
        {
            encode(value)
        }
        (GatewayRowKey::Context(_), GatewayRow::Context(value)) => encode(value),
        (GatewayRowKey::TokenIdentity(_), GatewayRow::TokenIdentity(value)) => encode(value),
        (GatewayRowKey::QuotaLifecycle(_), GatewayRow::QuotaLifecycle(value)) => encode(value),
        (GatewayRowKey::Quota(_), GatewayRow::Quota(value)) => encode(value),
        (GatewayRowKey::Lease(_), GatewayRow::Lease(value)) => encode(value),
        (GatewayRowKey::LeaseTerminal(_), GatewayRow::LeaseTerminal(value)) => encode(value),
        (GatewayRowKey::Expiry(key), GatewayRow::Expiry(value)) if key == value => encode(value),
        _ => Err(Error::CorruptHistory),
    }
}

impl<W: WorldReadOnly> GatewayRows for WorldGatewayRows<'_, W> {
    fn read(&self, key: &GatewayRowKey) -> Result<Option<GatewayRow>, Error> {
        let Some(bytes) = self
            .world
            .smart_contract_state()
            .get(&row_path(self.gateway, key)?)
        else {
            return Ok(None);
        };
        let row = match key {
            GatewayRowKey::Admission(_) => GatewayRow::Admission(decode(bytes)?),
            GatewayRowKey::Acknowledgement(_) => GatewayRow::Acknowledgement(decode(bytes)?),
            GatewayRowKey::Context(_) => GatewayRow::Context(decode(bytes)?),
            GatewayRowKey::TokenIdentity(_) => GatewayRow::TokenIdentity(decode(bytes)?),
            GatewayRowKey::QuotaLifecycle(_) => GatewayRow::QuotaLifecycle(decode(bytes)?),
            GatewayRowKey::Quota(_) => GatewayRow::Quota(decode(bytes)?),
            GatewayRowKey::Lease(_) => GatewayRow::Lease(decode(bytes)?),
            GatewayRowKey::LeaseTerminal(_) => GatewayRow::LeaseTerminal(decode(bytes)?),
            GatewayRowKey::Expiry(_) => GatewayRow::Expiry(decode(bytes)?),
        };
        encode_row(key, &row)?;
        if let GatewayRow::Admission(value) = &row {
            let policy = read_policy_record(
                self.world,
                &self.network,
                self.gateway,
                value.record.admitted_under.revision,
            )?;
            if value.record.admitted_under != policy.policy.qualification {
                return Err(Error::CorruptHistory);
            }
            value
                .record
                .clone()
                .validate_for_request(&value.request, policy.policy.qualification)
                .map_err(|_| Error::CorruptHistory)?;
            execution_under_policy(
                self.world,
                &self.network,
                self.gateway,
                &policy,
                &value.execution,
            )?;
        }
        let historical_execution = match &row {
            GatewayRow::Acknowledgement(ack) => {
                let Some(GatewayRow::Admission(original)) = self.read(
                    &GatewayRowKey::Admission(ack.record.outcome.binding.gateway_sequence),
                )?
                else {
                    return Err(Error::CorruptHistory);
                };
                if original.record != ack.record {
                    return Err(Error::CorruptHistory);
                }
                let (_, delivery) =
                    crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::read(
                        self.world,
                        &self.network,
                        &ack.record,
                    )
                    .map_err(|_| Error::CorruptHistory)?;
                if delivery != ack.reputation_delivery {
                    return Err(Error::CorruptHistory);
                }
                after_execution(&ack.execution, &original.execution)?;
                Some((ack.policy_revision, &ack.execution))
            }
            GatewayRow::LeaseTerminal(terminal) => {
                Some((terminal.policy_revision, &terminal.execution))
            }
            _ => None,
        };
        if let Some((revision, execution)) = historical_execution {
            let policy = read_policy_record(self.world, &self.network, self.gateway, revision)?;
            execution_under_policy(self.world, &self.network, self.gateway, &policy, execution)?;
        }
        Ok(Some(row))
    }

    fn expiry_prefix(
        &self,
        now_unix_ms: u64,
        max_items: u32,
    ) -> Result<Vec<GatewayExpiryKeyV1>, Error> {
        if max_items == 0 || max_items > MAX_EXPIRY_ITEMS + 1 {
            return Err(Error::Invalid);
        }
        let (start, end) = prefix_bounds(self.gateway, "row/expiry/")?;
        let mut result = Vec::with_capacity(max_items as usize);
        for (path, bytes) in self.world.smart_contract_state().range(start..end) {
            let key: GatewayExpiryKeyV1 = decode(bytes)?;
            if row_path(self.gateway, &GatewayRowKey::Expiry(key))? != *path {
                return Err(Error::CorruptHistory);
            }
            if key.at_unix_ms > now_unix_ms {
                break;
            }
            result.push(key);
            if result.len() == max_items as usize {
                break;
            }
        }
        Ok(result)
    }
}

fn execution_in_transaction(
    tx: &StateTransaction<'_, '_>,
    network: &NetworkId,
    execution: &Execution,
    instruction_digest: [u8; 32],
) -> Result<(), Error> {
    valid_execution(execution)?;
    if tx.network_id() != network
        || execution.height != tx._curr_block.height().get()
        || execution.recorded_at_unix_ms != tx.block_unix_timestamp_ms()
        || instruction_digest == [0; 32]
    {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}

fn after_current(
    world: &impl WorldReadOnly,
    current: &GatewayCurrentV1,
    execution: &Execution,
) -> Result<(), Error> {
    after_execution(execution, &current.policy.execution)?;
    if current.head.head.revision != 0 {
        let mutation = read_mutation(
            world,
            &current.policy.policy.network_id,
            current.policy.policy.qualification.gateway_id,
            current.head.head.revision,
        )?;
        after_execution(execution, &mutation.execution)?;
    }
    Ok(())
}

/// Atomically configure or replace a policy; the native owner separately checks Manage permission.
pub(crate) fn configure(
    tx: &mut StateTransaction<'_, '_>,
    policy: &Policy,
    expected_revision: u64,
    expected_policy_digest: [u8; 32],
    execution: &Execution,
    instruction_digest: [u8; 32],
) -> Result<(), Error> {
    policy.validate().map_err(|_| Error::Invalid)?;
    execution_in_transaction(tx, &policy.network_id, execution, instruction_digest)?;
    let gateway = policy.qualification.gateway_id;
    let current = read_current(tx.world(), &policy.network_id, gateway)?;
    if let Some(current) = &current {
        after_current(tx.world(), current, execution)?;
    }
    let actual = current.as_ref().map_or((0, [0; 32]), |value| {
        (value.policy_head.revision, value.policy_head.policy_digest)
    });
    if actual != (expected_revision, expected_policy_digest) {
        if expected_revision < actual.0 {
            let original = read_policy_record(
                tx.world(),
                &policy.network_id,
                gateway,
                expected_revision.checked_add(1).ok_or(Error::Capacity)?,
            )?;
            let predecessor = if expected_revision == 0 {
                [0; 32]
            } else {
                read_policy_record(tx.world(), &policy.network_id, gateway, expected_revision)?
                    .policy
                    .qualification
                    .policy_digest
            };
            if predecessor == expected_policy_digest
                && original.policy == *policy
                && original.instruction_digest == instruction_digest
                && original.execution.authority == execution.authority
            {
                return Ok(());
            }
        }
        return Err(Error::Conflict);
    }
    let predecessor_digest = if let Some(current) = &current {
        policy
            .validate_replacement(&current.policy.policy)
            .map_err(|_| Error::Conflict)?;
        current.policy_head.record_digest
    } else {
        if policy.qualification.revision != 1 || !namespace_empty(tx.world(), gateway)? {
            return Err(Error::Conflict);
        }
        [0; 32]
    };
    let record = GatewayPolicyRecordV1 {
        policy: policy.clone(),
        predecessor_digest,
        instruction_digest,
        execution: execution.clone(),
    };
    let head = GatewayPolicyHeadV1 {
        revision: policy.qualification.revision,
        policy_digest: policy.qualification.policy_digest,
        record_digest: policy_record_digest(&record)?,
    };
    let record_key = policy_record_path(gateway, head.revision)?;
    if tx.world.smart_contract_state.get(&record_key).is_some() {
        return Err(Error::CorruptHistory);
    }
    let record_bytes = encode(&record)?;
    let head_key = policy_head_path(gateway)?;
    let head_bytes = encode(&head)?;
    let initial = if current.is_none() {
        Some((
            head_path(gateway)?,
            encode(&GatewayStoredHeadV1::default())?,
        ))
    } else {
        None
    };
    // No fallible operation follows the first overlay write.
    tx.world
        .smart_contract_state
        .insert(record_key, record_bytes);
    tx.world.smart_contract_state.insert(head_key, head_bytes);
    if let Some((key, bytes)) = initial {
        tx.world.smart_contract_state.insert(key, bytes);
    }
    Ok(())
}

/// Atomically publish a pure transition after exact policy, head and per-row CAS revalidation.
pub(crate) fn prepare_delta(
    tx: &StateTransaction<'_, '_>,
    current: &GatewayCurrentV1,
    execution: &Execution,
    instruction_digest: [u8; 32],
    delta: &TransitionDelta,
) -> Result<PreparedGatewayDelta, Error> {
    let policy = &current.policy.policy;
    execution_in_transaction(tx, &policy.network_id, execution, instruction_digest)?;
    let gateway = policy.qualification.gateway_id;
    if read_current(tx.world(), &policy.network_id, gateway)?.as_ref() != Some(current)
        || delta.before != current.head.head
    {
        return Err(Error::Conflict);
    }
    if !policy.operators.contains(&execution.authority) {
        return Err(Error::BindingMismatch);
    }
    after_current(tx.world(), current, execution)?;
    if delta.before == delta.after {
        return if delta.writes.is_empty() {
            Ok(PreparedGatewayDelta { writes: Vec::new() })
        } else {
            Err(Error::Invalid)
        };
    }
    valid_head(delta.after)?;
    if delta.after.revision
        != delta
            .before
            .revision
            .checked_add(1)
            .ok_or(Error::Capacity)?
        || delta.after.last_execution_unix_ms != execution.recorded_at_unix_ms
        || delta.after.high_water_sequence < delta.before.high_water_sequence
        || delta.after.acknowledged_through_sequence < delta.before.acknowledged_through_sequence
        || delta.writes.len() > MAX_TRANSITION_WRITES
        || !delta
            .writes
            .windows(2)
            .all(|pair| pair[0].key < pair[1].key)
    {
        return Err(Error::Invalid);
    }
    if delta.after.acknowledged_through_sequence != delta.before.acknowledged_through_sequence
        && !delta.writes.iter().any(|write| matches!(&write.after,
            Some(GatewayRow::Acknowledgement(ack))
                if ack.record.outcome.binding.gateway_sequence == delta.after.acknowledged_through_sequence))
    { return Err(Error::Invalid); }
    let rows = WorldGatewayRows::new(tx.world(), &policy.network_id, gateway)?;
    let mut staged = Vec::with_capacity(delta.writes.len());
    let mut staged_bytes = 0_usize;
    let mut writes_digest = commitment(
        b"iroha.sorafs.stream-token.gateway-writes-start.v1\0",
        &gateway,
    )?;
    for write in &delta.writes {
        if rows.read(&write.key)? != write.before {
            return Err(Error::Conflict);
        }
        let mutable = matches!(
            write.key,
            GatewayRowKey::Quota(_) | GatewayRowKey::QuotaLifecycle(_) | GatewayRowKey::Expiry(_)
        );
        if write.after.is_none()
            && !matches!(
                write.key,
                GatewayRowKey::Quota(_) | GatewayRowKey::Expiry(_)
            )
            || (!mutable && write.before.is_some())
            || write.before == write.after
        {
            return Err(Error::Invalid);
        }
        if let Some(GatewayRow::Admission(row)) = &write.after {
            if row.record.admitted_under != policy.qualification || row.execution != *execution {
                return Err(Error::BindingMismatch);
            }
            row.record
                .validate_for_request(&row.request, policy.qualification)
                .map_err(|_| Error::Invalid)?;
        }
        if let Some(GatewayRow::Acknowledgement(row)) = &write.after {
            let (_, delivery) = crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::prepare_acknowledgement(
                tx, &row.record, execution).map_err(|_| Error::CorruptHistory)?;
            if delivery != row.reputation_delivery {
                return Err(Error::CorruptHistory);
            }

            if row.execution != *execution
                || row.policy_revision != policy.qualification.revision
                || row.record.outcome.binding.gateway_sequence
                    != delta.after.acknowledged_through_sequence
                || delta.before.acknowledged_through_sequence.checked_add(1)
                    != Some(delta.after.acknowledged_through_sequence)
            {
                return Err(Error::BindingMismatch);
            }
            let Some(GatewayRow::Admission(original)) = rows.read(&GatewayRowKey::Admission(
                row.record.outcome.binding.gateway_sequence,
            ))?
            else {
                return Err(Error::CorruptHistory);
            };
            if original.record != row.record {
                return Err(Error::BindingMismatch);
            }
        }
        if let Some(GatewayRow::LeaseTerminal(row)) = &write.after {
            if row.execution != *execution || row.policy_revision != policy.qualification.revision {
                return Err(Error::BindingMismatch);
            }
        }
        let key = row_path(gateway, &write.key)?;
        let before = write
            .before
            .as_ref()
            .map(|row| encode_row(&write.key, row))
            .transpose()?;
        let after = write
            .after
            .as_ref()
            .map(|row| encode_row(&write.key, row))
            .transpose()?;
        staged_bytes = staged_bytes
            .checked_add(key.as_ref().len())
            .and_then(|size| size.checked_add(after.as_ref().map_or(0, Vec::len)))
            .filter(|size| *size <= MAX_STAGED_BYTES)
            .ok_or(Error::Capacity)?;
        writes_digest = commitment(
            b"iroha.sorafs.stream-token.gateway-write.v1\0",
            &(
                writes_digest,
                key.clone(),
                before.as_ref().map(|bytes| *Hash::new(bytes).as_ref()),
                after.as_ref().map(|bytes| *Hash::new(bytes).as_ref()),
            ),
        )?;
        staged.push((key, after));
    }
    let record = GatewayMutationRecordV1 {
        predecessor_digest: current.head.mutation_digest,
        policy_revision: current.policy_head.revision,
        policy_digest: current.policy_head.policy_digest,
        policy_record_digest: current.policy_head.record_digest,
        instruction_digest,
        execution: execution.clone(),
        before: delta.before,
        after: delta.after,
        writes_digest,
        write_count: u32::try_from(delta.writes.len()).map_err(|_| Error::Capacity)?,
    };
    let record_key = mutation_path(gateway, delta.after.revision)?;
    if tx.world.smart_contract_state.get(&record_key).is_some() {
        return Err(Error::CorruptHistory);
    }
    let record_bytes = encode(&record)?;
    let head_key = head_path(gateway)?;
    let head_bytes = encode(&GatewayStoredHeadV1 {
        head: delta.after,
        mutation_digest: mutation_record_digest(&record)?,
    })?;
    staged.push((record_key, Some(record_bytes)));
    staged.push((head_key, Some(head_bytes)));
    Ok(PreparedGatewayDelta { writes: staged })
}

/// Bounded fully validated gateway writes; publication cannot fail after another native owner writes.
pub(crate) struct PreparedGatewayDelta {
    writes: Vec<(StatePath, Option<Vec<u8>>)>,
}
impl PreparedGatewayDelta {
    /// Publish only after every participating native owner has prepared its own exact writes.
    pub(crate) fn publish(self, tx: &mut StateTransaction<'_, '_>) {
        for (key, after) in self.writes {
            if let Some(bytes) = after {
                tx.world.smart_contract_state.insert(key, bytes);
            } else {
                tx.world.smart_contract_state.remove(key);
            }
        }
    }
}

/// Apply one delta directly in storage fixtures; production prepares all owners first.
#[cfg(test)]
pub(crate) fn apply_delta(
    tx: &mut StateTransaction<'_, '_>,
    current: &GatewayCurrentV1,
    execution: &Execution,
    instruction_digest: [u8; 32],
    delta: &TransitionDelta,
) -> Result<(), Error> {
    prepare_delta(tx, current, execution, instruction_digest, delta)?.publish(tx);
    Ok(())
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;

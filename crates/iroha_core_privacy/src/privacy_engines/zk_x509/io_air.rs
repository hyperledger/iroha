//! Cross-segment private I/O copy argument for zk-X509.
//!
//! DER, SHA-256, P-256, accumulator, projection, and public-input segments exchange byte strings
//! through fixed channels. Each channel has exactly one producer and one or more fixed consumers.
//! Four independently challenged grand products bind the execution-order endpoint cells to an
//! address-sorted table; the sorted table enforces one write per byte address and identical values
//! for every read. Public-input reads are additionally fixed to verifier-supplied bytes.
//!
//! The transcript challenges must be sampled only after both endpoint and
//! address-sorted traces have been committed.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::private_table::{PrivateTableV1, zeroize_fields_v1};
use crate::privacy_engines::transparent_stark::{
    GoldilocksFieldV1 as F, TransparentStarkErrorV1, TransparentTranscriptV1,
};
use thiserror::Error;
/// Manifest descriptor for cross-segment byte-channel binding.
pub const ZK_X509_IO_AIR_DESCRIPTOR_V1: &[u8] = b"zk-x509-cross-segment-io-v1:fixed-sequential-channel-ids:fixed-producer-and-consumer-endpoints:byte-offsets-contiguous:one-write-per-channel-byte:all-reads-equal-write:public-input-reads-verifier-fixed:four-independent-lane-and-coordinate-labelled-transcript-challenged-channel-offset-value-write-grand-products:max-accesses=byte-memory-segment-capacity:first-release";
/// Exact fixed-capacity byte-memory registration in the canonical aggregate.
pub const ZK_X509_IO_FIXED_CAPACITY_ROWS_V1: usize = 1 << 18;
pub const IO_PERMUTATION_LANES_V1: usize = 4;
pub const IO_PERMUTATION_CHALLENGE_LABELS_V1: [[&[u8]; 5]; IO_PERMUTATION_LANES_V1] = [
    [
        b"zk-x509-io-copy-lane0-beta-v1",
        b"zk-x509-io-copy-lane0-channel-v1",
        b"zk-x509-io-copy-lane0-offset-v1",
        b"zk-x509-io-copy-lane0-value-v1",
        b"zk-x509-io-copy-lane0-write-v1",
    ],
    [
        b"zk-x509-io-copy-lane1-beta-v1",
        b"zk-x509-io-copy-lane1-channel-v1",
        b"zk-x509-io-copy-lane1-offset-v1",
        b"zk-x509-io-copy-lane1-value-v1",
        b"zk-x509-io-copy-lane1-write-v1",
    ],
    [
        b"zk-x509-io-copy-lane2-beta-v1",
        b"zk-x509-io-copy-lane2-channel-v1",
        b"zk-x509-io-copy-lane2-offset-v1",
        b"zk-x509-io-copy-lane2-value-v1",
        b"zk-x509-io-copy-lane2-write-v1",
    ],
    [
        b"zk-x509-io-copy-lane3-beta-v1",
        b"zk-x509-io-copy-lane3-channel-v1",
        b"zk-x509-io-copy-lane3-offset-v1",
        b"zk-x509-io-copy-lane3-value-v1",
        b"zk-x509-io-copy-lane3-write-v1",
    ],
];
/// Segment role participating in one fixed byte channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZkX509IoSegmentRoleV1 {
    /// Strict DER decoder and RFC 5280 state machine.
    StrictDer,
    /// Word-oriented SHA-256 segment.
    Sha256,
    /// P-256 field/group and ECDSA segment.
    P256,
    /// Governed CA-membership accumulator segment.
    CaAccumulator,
    /// Exact signed-CRL governance-record commitment segment.
    #[cfg(test)]
    CrlCommitment,
    /// Output projection and disclosure segment.
    Projection,
    /// Verifier-fixed public statement input.
    PublicInput,
}
/// One fixed producer or consumer endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZkX509IoEndpointV1 {
    /// Segment family.
    pub(crate) role: ZkX509IoSegmentRoleV1,
    /// Canonical instance index within that family.
    pub(crate) instance: u16,
}
/// Fixed topology and optional verifier value for one byte channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509IoChannelDeclarationV1 {
    /// Sequential channel identifier, starting at zero.
    pub(crate) channel: u32,
    /// Sole producer endpoint.
    pub(crate) producer: ZkX509IoEndpointV1,
    /// Fixed, unique consumers in canonical order.
    pub(crate) consumers: Vec<ZkX509IoEndpointV1>,
    /// Exact byte length on every endpoint.
    pub(crate) byte_len: u32,
    /// Verifier-fixed bytes when a public-input consumer is present.
    pub(crate) public_value: Option<Vec<u8>>,
}
/// Endpoint values used to generate one channel witness.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct ZkX509IoChannelWitnessV1 {
    /// Fixed topology.
    pub(crate) declaration: ZkX509IoChannelDeclarationV1,
    /// Producer bytes.
    pub(crate) producer_value: Vec<u8>,
    /// Consumer bytes in declaration order.
    pub(crate) consumer_values: Vec<Vec<u8>>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509IoChannelWitnessV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkX509IoChannelWitnessV1 { <private material redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509IoChannelWitnessV1 {
    pub(crate) fn zeroize_private_v1(&mut self) {
        use super::private_table::zeroize_words_v1;
        zeroize_words_v1(&mut self.producer_value);
        for value in &mut self.consumer_values {
            zeroize_words_v1(value);
        }
        self.producer_value.clear();
        self.consumer_values.clear();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509IoChannelWitnessV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoAccessV1 {
    pub(crate) channel: F,
    pub(crate) offset: F,
    pub(crate) value: F,
    pub(crate) is_write: F,
    pub(crate) endpoint: ZkX509IoEndpointV1,
}
/// Erase initialized private access cells while preserving public endpoint topology.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn zeroize_io_accesses_v1(accesses: &mut [IoAccessV1]) {
    for access in accesses {
        zeroize_fields_v1(core::slice::from_mut(&mut access.channel));
        zeroize_fields_v1(core::slice::from_mut(&mut access.offset));
        zeroize_fields_v1(core::slice::from_mut(&mut access.value));
        zeroize_fields_v1(core::slice::from_mut(&mut access.is_write));
    }
}
/// One independent tuple-compression lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509IoLaneChallengesV1 {
    pub(crate) beta: F,
    pub(crate) channel: F,
    pub(crate) offset: F,
    pub(crate) value: F,
    pub(crate) is_write: F,
}
/// Four independent cross-segment I/O permutation lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509IoChallengesV1 {
    pub(crate) lanes: [ZkX509IoLaneChallengesV1; IO_PERMUTATION_LANES_V1],
}
impl ZkX509IoChallengesV1 {
    /// Reject zero, non-canonical, or duplicate I/O challenge lanes.
    pub(crate) fn validate(self) -> Result<(), ZkX509IoAirErrorV1> {
        for lane in self.lanes {
            let coefficients = [
                lane.beta,
                lane.channel,
                lane.offset,
                lane.value,
                lane.is_write,
            ];
            if coefficients
                .iter()
                .any(|coefficient| F::canonical(coefficient.0).is_none() || *coefficient == F::ZERO)
            {
                return Err(ZkX509IoAirErrorV1::Challenge);
            }
        }
        if self
            .lanes
            .iter()
            .enumerate()
            .any(|(index, lane)| self.lanes[..index].contains(lane))
        {
            return Err(ZkX509IoAirErrorV1::Challenge);
        }
        Ok(())
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoPermutationRowV1 {
    pub(crate) execution: IoAccessV1,
    pub(crate) sorted: IoAccessV1,
    pub(crate) execution_product_before: [F; IO_PERMUTATION_LANES_V1],
    pub(crate) sorted_product_before: [F; IO_PERMUTATION_LANES_V1],
    pub(crate) execution_product_after: [F; IO_PERMUTATION_LANES_V1],
    pub(crate) sorted_product_after: [F; IO_PERMUTATION_LANES_V1],
}
/// Main byte-channel tables and challenge-dependent auxiliary products.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct ZkX509IoTraceV1 {
    pub(crate) declarations: Vec<ZkX509IoChannelDeclarationV1>,
    pub(crate) execution: Vec<IoAccessV1>,
    pub(crate) sorted: Vec<IoAccessV1>,
    pub(crate) permutation_rows: Vec<IoPermutationRowV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509IoTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkX509IoTraceV1 { <private material redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_io_permutation_rows_v1(rows: &mut [IoPermutationRowV1]) {
    for row in rows {
        zeroize_io_accesses_v1(core::slice::from_mut(&mut row.execution));
        zeroize_io_accesses_v1(core::slice::from_mut(&mut row.sorted));
        zeroize_fields_v1(&mut row.execution_product_before);
        zeroize_fields_v1(&mut row.sorted_product_before);
        zeroize_fields_v1(&mut row.execution_product_after);
        zeroize_fields_v1(&mut row.sorted_product_after);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509IoTraceV1 {
    fn drop(&mut self) {
        zeroize_io_accesses_v1(&mut self.execution);
        zeroize_io_accesses_v1(&mut self.sorted);
        zeroize_io_permutation_rows_v1(&mut self.permutation_rows);
    }
}
/// Cross-segment I/O construction or constraint failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509IoAirErrorV1 {
    /// A channel identifier, endpoint list, length, or public declaration is invalid.
    #[error("zk-X509 cross-segment I/O topology is invalid")]
    Topology,
    /// A byte, address, or write flag is outside its canonical range.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 cross-segment I/O range constraint is invalid")]
    Range,
    /// The address-sorted one-write/read-consistency state machine is invalid.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 cross-segment I/O sorted memory is invalid")]
    SortedMemory,
    /// A public-input read differs from verifier-supplied bytes.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 cross-segment public I/O binding is invalid")]
    PublicInput,
    /// Fiat-Shamir tuple-compression challenges are invalid.
    #[error("zk-X509 cross-segment I/O challenges are invalid")]
    Challenge,
    /// A grand-product transition or final permutation equality is invalid.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 cross-segment I/O permutation is invalid")]
    Permutation,
    /// Bounded row or allocation arithmetic failed.
    #[error("zk-X509 cross-segment I/O resource bound is exceeded")]
    Resource,
}
/// Derive I/O-copy challenges after committing endpoint and sorted traces.
pub fn derive_zk_x509_io_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<ZkX509IoChallengesV1, TransparentStarkErrorV1> {
    let mut sampled = [F::ZERO; IO_PERMUTATION_LANES_V1 * 5];
    for lane in 0..IO_PERMUTATION_LANES_V1 {
        for coordinate in 0..5 {
            sampled[lane * 5 + coordinate] =
                transcript.challenge_field(IO_PERMUTATION_CHALLENGE_LABELS_V1[lane][coordinate])?;
        }
    }
    Ok(ZkX509IoChallengesV1 {
        lanes: core::array::from_fn(|lane| ZkX509IoLaneChallengesV1 {
            beta: sampled[lane * 5],
            channel: sampled[lane * 5 + 1],
            offset: sampled[lane * 5 + 2],
            value: sampled[lane * 5 + 3],
            is_write: sampled[lane * 5 + 4],
        }),
    })
}
/// Construct and validate the complete cross-segment byte-copy trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_zk_x509_io_trace_v1(
    witnesses: &[ZkX509IoChannelWitnessV1],
    challenges: ZkX509IoChallengesV1,
) -> Result<ZkX509IoTraceV1, ZkX509IoAirErrorV1> {
    challenges.validate()?;
    let (declarations, execution, sorted) = build_zk_x509_io_base_tables_v1(witnesses)?;
    let permutation_rows = build_permutation_rows_v1(&execution, &sorted, challenges)?;
    let trace = ZkX509IoTraceV1 {
        declarations,
        execution: execution.into_vec(),
        sorted: sorted.into_vec(),
        permutation_rows: permutation_rows.into_vec(),
    };
    trace.validate(challenges)?;
    Ok(trace)
}
/// Construct the challenge-independent endpoint and address-sorted tables.
///
/// A STARK prover commits these tables before deriving the permutation challenges. Keeping this
/// phase separate prevents a caller from building a challenge-adaptive base trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn build_zk_x509_io_base_tables_v1(
    witnesses: &[ZkX509IoChannelWitnessV1],
) -> Result<
    (
        Vec<ZkX509IoChannelDeclarationV1>,
        PrivateTableV1<IoAccessV1>,
        PrivateTableV1<IoAccessV1>,
    ),
    ZkX509IoAirErrorV1,
> {
    let declarations: Vec<_> = witnesses
        .iter()
        .map(|witness| witness.declaration.clone())
        .collect();
    validate_declarations_v1(&declarations)?;
    if witnesses.len() != declarations.len() {
        return Err(ZkX509IoAirErrorV1::Topology);
    }
    let capacity = byte_memory_capacity_v1()?;
    let expected_rows = declarations
        .iter()
        .try_fold(0_usize, |rows, declaration| {
            let endpoints = declaration.consumers.len().checked_add(1)?;
            rows.checked_add(
                usize::try_from(declaration.byte_len)
                    .ok()?
                    .checked_mul(endpoints)?,
            )
        })
        .ok_or(ZkX509IoAirErrorV1::Resource)?;
    if expected_rows == 0 || expected_rows > capacity {
        return Err(ZkX509IoAirErrorV1::Resource);
    }
    let mut execution = PrivateTableV1::new(Vec::new(), zeroize_io_accesses_v1);
    execution
        .try_reserve_exact(expected_rows)
        .map_err(|_| ZkX509IoAirErrorV1::Resource)?;
    for witness in witnesses {
        append_channel_execution_v1(&mut execution, witness)?;
    }
    if execution.len() != expected_rows {
        return Err(ZkX509IoAirErrorV1::Topology);
    }
    let mut sorted = PrivateTableV1::new(Vec::new(), zeroize_io_accesses_v1);
    sorted
        .try_reserve_exact(execution.len())
        .map_err(|_| ZkX509IoAirErrorV1::Resource)?;
    sorted.extend_from_slice(&execution);
    // Canonical consumers are unique and endpoint-sorted, which is precisely
    // the prior stable tie order. The complete key lets the in-place sorter
    // preserve those bytes without an unowned private merge scratch buffer.
    sorted.sort_unstable_by_key(|access| {
        (
            access.channel.0,
            access.offset.0,
            if access.is_write == F::ONE {
                0_u8
            } else {
                1_u8
            },
            access.endpoint,
        )
    });
    validate_execution_topology_v1(&declarations, &execution)?;
    validate_sorted_v1(&declarations, &sorted)?;
    Ok((declarations, execution, sorted))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509IoTraceV1 {
    /// Number of globally bound endpoint byte accesses.
    #[cfg(test)]
    pub(crate) const fn rows(&self) -> usize {
        self.execution.len()
    }
    /// Validate topology, public values, sorted memory, and all product lanes.
    pub(crate) fn validate(
        &self,
        challenges: ZkX509IoChallengesV1,
    ) -> Result<(), ZkX509IoAirErrorV1> {
        challenges.validate()?;
        validate_declarations_v1(&self.declarations)?;
        validate_execution_topology_v1(&self.declarations, &self.execution)?;
        validate_sorted_v1(&self.declarations, &self.sorted)?;
        validate_permutation_rows_v1(
            &self.execution,
            &self.sorted,
            &self.permutation_rows,
            challenges,
        )
    }
    /// Bind one endpoint's exact bytes to another segment's constrained cells.
    #[cfg(test)]
    pub(crate) fn validate_endpoint_bytes(
        &self,
        channel: u32,
        endpoint: ZkX509IoEndpointV1,
        is_write: bool,
        expected: &[u8],
    ) -> Result<(), ZkX509IoAirErrorV1> {
        let accesses: Vec<_> = self
            .execution
            .iter()
            .filter(|access| {
                access.channel == F(u64::from(channel))
                    && access.endpoint == endpoint
                    && access.is_write == if is_write { F::ONE } else { F::ZERO }
            })
            .collect();
        if accesses.len() != expected.len()
            || accesses.iter().enumerate().any(|(offset, access)| {
                access.offset != F(offset as u64) || access.value != F(u64::from(expected[offset]))
            })
        {
            return Err(ZkX509IoAirErrorV1::Topology);
        }
        Ok(())
    }
    /// Bind all channel identifiers, lengths, and endpoint roles to the
    /// verifier-compiled topology rather than prover-selected metadata.
    #[cfg(test)]
    pub(crate) fn validate_fixed_topology(
        &self,
        expected: &[ZkX509IoChannelDeclarationV1],
    ) -> Result<(), ZkX509IoAirErrorV1> {
        validate_declarations_v1(expected)?;
        if self.declarations != expected {
            return Err(ZkX509IoAirErrorV1::Topology);
        }
        Ok(())
    }
    /// Bind one public channel to verifier-supplied statement bytes.
    #[cfg(test)]
    pub(crate) fn validate_public_channel(
        &self,
        channel: u32,
        expected: &[u8],
    ) -> Result<(), ZkX509IoAirErrorV1> {
        let declaration = self
            .declarations
            .get(usize::try_from(channel).map_err(|_| ZkX509IoAirErrorV1::Topology)?)
            .filter(|declaration| declaration.channel == channel)
            .ok_or(ZkX509IoAirErrorV1::Topology)?;
        if declaration.public_value.as_deref() != Some(expected) {
            return Err(ZkX509IoAirErrorV1::PublicInput);
        }
        let endpoint = declaration
            .consumers
            .iter()
            .copied()
            .find(|endpoint| endpoint.role == ZkX509IoSegmentRoleV1::PublicInput)
            .ok_or(ZkX509IoAirErrorV1::PublicInput)?;
        self.validate_endpoint_bytes(channel, endpoint, false, expected)
            .map_err(|_| ZkX509IoAirErrorV1::PublicInput)
    }
}
pub fn validate_declarations_v1(
    declarations: &[ZkX509IoChannelDeclarationV1],
) -> Result<(), ZkX509IoAirErrorV1> {
    if declarations.is_empty() {
        return Err(ZkX509IoAirErrorV1::Topology);
    }
    for (index, declaration) in declarations.iter().enumerate() {
        let public_consumers = declaration
            .consumers
            .iter()
            .filter(|endpoint| endpoint.role == ZkX509IoSegmentRoleV1::PublicInput)
            .count();
        if declaration.channel != u32::try_from(index).map_err(|_| ZkX509IoAirErrorV1::Resource)?
            || declaration.byte_len == 0
            || declaration.consumers.is_empty()
            || declaration.producer.role == ZkX509IoSegmentRoleV1::PublicInput
            || declaration
                .consumers
                .iter()
                .enumerate()
                .any(|(consumer, endpoint)| {
                    declaration.consumers[..consumer].contains(endpoint)
                        || *endpoint == declaration.producer
                })
            || declaration
                .consumers
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || public_consumers > 1
            || (public_consumers == 1) != declaration.public_value.is_some()
            || declaration
                .public_value
                .as_ref()
                .is_some_and(|value| value.len() != declaration.byte_len as usize)
        {
            return Err(ZkX509IoAirErrorV1::Topology);
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn append_channel_execution_v1(
    execution: &mut Vec<IoAccessV1>,
    witness: &ZkX509IoChannelWitnessV1,
) -> Result<(), ZkX509IoAirErrorV1> {
    let declaration = &witness.declaration;
    let byte_len =
        usize::try_from(declaration.byte_len).map_err(|_| ZkX509IoAirErrorV1::Resource)?;
    if witness.producer_value.len() != byte_len
        || witness.consumer_values.len() != declaration.consumers.len()
        || witness
            .consumer_values
            .iter()
            .any(|value| value.len() != byte_len)
    {
        return Err(ZkX509IoAirErrorV1::Topology);
    }
    for (offset, value) in witness.producer_value.iter().copied().enumerate() {
        execution.push(io_access_v1(
            declaration.channel,
            offset,
            value,
            true,
            declaration.producer,
        )?);
    }
    for (consumer_index, endpoint) in declaration.consumers.iter().copied().enumerate() {
        for (offset, value) in witness.consumer_values[consumer_index]
            .iter()
            .copied()
            .enumerate()
        {
            if endpoint.role == ZkX509IoSegmentRoleV1::PublicInput
                && declaration
                    .public_value
                    .as_ref()
                    .and_then(|public| public.get(offset))
                    .copied()
                    != Some(value)
            {
                return Err(ZkX509IoAirErrorV1::PublicInput);
            }
            execution.push(io_access_v1(
                declaration.channel,
                offset,
                value,
                false,
                endpoint,
            )?);
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn io_access_v1(
    channel: u32,
    offset: usize,
    value: u8,
    is_write: bool,
    endpoint: ZkX509IoEndpointV1,
) -> Result<IoAccessV1, ZkX509IoAirErrorV1> {
    Ok(IoAccessV1 {
        channel: F(u64::from(channel)),
        offset: F(u64::try_from(offset).map_err(|_| ZkX509IoAirErrorV1::Resource)?),
        value: F(u64::from(value)),
        is_write: if is_write { F::ONE } else { F::ZERO },
        endpoint,
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_execution_topology_v1(
    declarations: &[ZkX509IoChannelDeclarationV1],
    execution: &[IoAccessV1],
) -> Result<(), ZkX509IoAirErrorV1> {
    let mut cursor = 0_usize;
    for declaration in declarations {
        let byte_len =
            usize::try_from(declaration.byte_len).map_err(|_| ZkX509IoAirErrorV1::Resource)?;
        for endpoint_index in 0..=declaration.consumers.len() {
            let (endpoint, is_write) = if endpoint_index == 0 {
                (declaration.producer, F::ONE)
            } else {
                (declaration.consumers[endpoint_index - 1], F::ZERO)
            };
            for offset in 0..byte_len {
                let access = execution.get(cursor).ok_or(ZkX509IoAirErrorV1::Topology)?;
                if access.channel != F(u64::from(declaration.channel))
                    || access.offset != F(offset as u64)
                    || access.value.0 > u64::from(u8::MAX)
                    || access.is_write != is_write
                    || access.endpoint != endpoint
                {
                    return Err(ZkX509IoAirErrorV1::Topology);
                }
                if endpoint.role == ZkX509IoSegmentRoleV1::PublicInput
                    && declaration
                        .public_value
                        .as_ref()
                        .and_then(|public| public.get(offset))
                        .copied()
                        .map(u64::from)
                        != Some(access.value.0)
                {
                    return Err(ZkX509IoAirErrorV1::PublicInput);
                }
                cursor = cursor.checked_add(1).ok_or(ZkX509IoAirErrorV1::Resource)?;
            }
        }
    }
    if cursor != execution.len() {
        return Err(ZkX509IoAirErrorV1::Topology);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_sorted_v1(
    declarations: &[ZkX509IoChannelDeclarationV1],
    sorted: &[IoAccessV1],
) -> Result<(), ZkX509IoAirErrorV1> {
    let first = sorted.first().ok_or(ZkX509IoAirErrorV1::SortedMemory)?;
    if first.channel != F::ZERO || first.offset != F::ZERO || first.is_write != F::ONE {
        return Err(ZkX509IoAirErrorV1::SortedMemory);
    }
    validate_sorted_access_range_v1(*first, declarations)?;
    for pair in sorted.windows(2) {
        let previous = pair[0];
        let current = pair[1];
        validate_sorted_access_range_v1(current, declarations)?;
        if current.channel == previous.channel && current.offset == previous.offset {
            if current.is_write != F::ZERO || current.value != previous.value {
                return Err(ZkX509IoAirErrorV1::SortedMemory);
            }
        } else if current.channel == previous.channel
            && current.offset == previous.offset.add(F::ONE)
        {
            if current.is_write != F::ONE {
                return Err(ZkX509IoAirErrorV1::SortedMemory);
            }
        } else if current.channel == previous.channel.add(F::ONE)
            && current.offset == F::ZERO
            && current.is_write == F::ONE
        {
            let previous_channel = declarations
                .get(previous.channel.0 as usize)
                .ok_or(ZkX509IoAirErrorV1::SortedMemory)?;
            if previous.offset.0 + 1 != u64::from(previous_channel.byte_len) {
                return Err(ZkX509IoAirErrorV1::SortedMemory);
            }
        } else {
            return Err(ZkX509IoAirErrorV1::SortedMemory);
        }
    }
    let last = sorted.last().ok_or(ZkX509IoAirErrorV1::SortedMemory)?;
    let last_declaration = declarations
        .last()
        .ok_or(ZkX509IoAirErrorV1::SortedMemory)?;
    if last.channel != F(u64::from(last_declaration.channel))
        || last.offset.0 + 1 != u64::from(last_declaration.byte_len)
    {
        return Err(ZkX509IoAirErrorV1::SortedMemory);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_sorted_access_range_v1(
    access: IoAccessV1,
    declarations: &[ZkX509IoChannelDeclarationV1],
) -> Result<(), ZkX509IoAirErrorV1> {
    let declaration = usize::try_from(access.channel.0)
        .ok()
        .and_then(|channel| declarations.get(channel))
        .ok_or(ZkX509IoAirErrorV1::Range)?;
    if access.offset.0 >= u64::from(declaration.byte_len)
        || access.value.0 > u64::from(u8::MAX)
        || access.is_write.mul(access.is_write.sub(F::ONE)) != F::ZERO
    {
        return Err(ZkX509IoAirErrorV1::Range);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_permutation_rows_v1(
    execution: &[IoAccessV1],
    sorted: &[IoAccessV1],
    challenges: ZkX509IoChallengesV1,
) -> Result<PrivateTableV1<IoPermutationRowV1>, ZkX509IoAirErrorV1> {
    if execution.len() != sorted.len() {
        return Err(ZkX509IoAirErrorV1::Permutation);
    }
    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_io_permutation_rows_v1);
    rows.try_reserve_exact(execution.len())
        .map_err(|_| ZkX509IoAirErrorV1::Resource)?;
    let mut execution_product = [F::ONE; IO_PERMUTATION_LANES_V1];
    let mut sorted_product = [F::ONE; IO_PERMUTATION_LANES_V1];
    for (execution, sorted) in execution.iter().copied().zip(sorted.iter().copied()) {
        let execution_product_before = execution_product;
        let sorted_product_before = sorted_product;
        for lane in 0..IO_PERMUTATION_LANES_V1 {
            execution_product[lane] =
                execution_product[lane].mul(compress_access_v1(execution, challenges.lanes[lane]));
            sorted_product[lane] =
                sorted_product[lane].mul(compress_access_v1(sorted, challenges.lanes[lane]));
        }
        rows.push(IoPermutationRowV1 {
            execution,
            sorted,
            execution_product_before,
            sorted_product_before,
            execution_product_after: execution_product,
            sorted_product_after: sorted_product,
        });
    }
    Ok(rows)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_permutation_rows_v1(
    execution: &[IoAccessV1],
    sorted: &[IoAccessV1],
    rows: &[IoPermutationRowV1],
    challenges: ZkX509IoChallengesV1,
) -> Result<(), ZkX509IoAirErrorV1> {
    if execution.len() != sorted.len() || rows.len() != execution.len() || rows.is_empty() {
        return Err(ZkX509IoAirErrorV1::Permutation);
    }
    let mut execution_before = [F::ONE; IO_PERMUTATION_LANES_V1];
    let mut sorted_before = [F::ONE; IO_PERMUTATION_LANES_V1];
    for (index, row) in rows.iter().enumerate() {
        if row.execution != execution[index]
            || row.sorted != sorted[index]
            || row.execution_product_before != execution_before
            || row.sorted_product_before != sorted_before
        {
            return Err(ZkX509IoAirErrorV1::Permutation);
        }
        for lane in 0..IO_PERMUTATION_LANES_V1 {
            let execution_after = execution_before[lane]
                .mul(compress_access_v1(row.execution, challenges.lanes[lane]));
            let sorted_after =
                sorted_before[lane].mul(compress_access_v1(row.sorted, challenges.lanes[lane]));
            if row.execution_product_after[lane] != execution_after
                || row.sorted_product_after[lane] != sorted_after
            {
                return Err(ZkX509IoAirErrorV1::Permutation);
            }
        }
        execution_before = row.execution_product_after;
        sorted_before = row.sorted_product_after;
    }
    if execution_before != sorted_before {
        return Err(ZkX509IoAirErrorV1::Permutation);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compress_access_v1(access: IoAccessV1, challenge: ZkX509IoLaneChallengesV1) -> F {
    challenge
        .beta
        .add(challenge.channel.mul(access.channel))
        .add(challenge.offset.mul(access.offset))
        .add(challenge.value.mul(access.value))
        .add(challenge.is_write.mul(access.is_write))
}
pub fn byte_memory_capacity_v1() -> Result<usize, ZkX509IoAirErrorV1> {
    Ok(ZK_X509_IO_FIXED_CAPACITY_ROWS_V1)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1;
    fn endpoint(role: ZkX509IoSegmentRoleV1, instance: u16) -> ZkX509IoEndpointV1 {
        ZkX509IoEndpointV1 { role, instance }
    }
    pub(super) fn challenges() -> ZkX509IoChallengesV1 {
        ZkX509IoChallengesV1 {
            lanes: [
                ZkX509IoLaneChallengesV1 {
                    beta: F(11),
                    channel: F(13),
                    offset: F(17),
                    value: F(19),
                    is_write: F(23),
                },
                ZkX509IoLaneChallengesV1 {
                    beta: F(29),
                    channel: F(31),
                    offset: F(37),
                    value: F(41),
                    is_write: F(43),
                },
                ZkX509IoLaneChallengesV1 {
                    beta: F(47),
                    channel: F(53),
                    offset: F(59),
                    value: F(61),
                    is_write: F(67),
                },
                ZkX509IoLaneChallengesV1 {
                    beta: F(71),
                    channel: F(73),
                    offset: F(79),
                    value: F(83),
                    is_write: F(89),
                },
            ],
        }
    }
    fn witness(
        channel: u32,
        producer: ZkX509IoEndpointV1,
        consumers: Vec<ZkX509IoEndpointV1>,
        value: &[u8],
        public: bool,
    ) -> ZkX509IoChannelWitnessV1 {
        ZkX509IoChannelWitnessV1 {
            declaration: ZkX509IoChannelDeclarationV1 {
                channel,
                producer,
                consumers: consumers.clone(),
                byte_len: value.len() as u32,
                public_value: public.then(|| value.to_vec()),
            },
            producer_value: value.to_vec(),
            consumer_values: vec![value.to_vec(); consumers.len()],
        }
    }
    pub(super) fn valid_witnesses() -> Vec<ZkX509IoChannelWitnessV1> {
        vec![
            witness(
                0,
                endpoint(ZkX509IoSegmentRoleV1::StrictDer, 0),
                vec![endpoint(ZkX509IoSegmentRoleV1::Sha256, 0)],
                b"exact DER bytes",
                false,
            ),
            witness(
                1,
                endpoint(ZkX509IoSegmentRoleV1::Sha256, 0),
                vec![endpoint(ZkX509IoSegmentRoleV1::CrlCommitment, 0)],
                &[0x31; 32],
                false,
            ),
            witness(
                2,
                endpoint(ZkX509IoSegmentRoleV1::CrlCommitment, 0),
                vec![endpoint(ZkX509IoSegmentRoleV1::PublicInput, 0)],
                &[0x42; 32],
                true,
            ),
        ]
    }
    #[test]
    fn der_sha_crl_commitment_and_public_bytes_are_globally_bound() {
        let witnesses = valid_witnesses();
        let trace = build_zk_x509_io_trace_v1(&witnesses, challenges()).expect("I/O trace");
        trace.validate(challenges()).expect("valid I/O trace");
        let declarations: Vec<_> = witnesses
            .iter()
            .map(|witness| witness.declaration.clone())
            .collect();
        trace
            .validate_fixed_topology(&declarations)
            .expect("verifier-fixed topology");
        assert_eq!(trace.rows(), 158);
        trace
            .validate_endpoint_bytes(
                0,
                endpoint(ZkX509IoSegmentRoleV1::Sha256, 0),
                false,
                b"exact DER bytes",
            )
            .expect("SHA input endpoint");
        trace
            .validate_endpoint_bytes(
                1,
                endpoint(ZkX509IoSegmentRoleV1::Sha256, 0),
                true,
                &[0x31; 32],
            )
            .expect("SHA output endpoint");
        trace
            .validate_public_channel(2, &[0x42; 32])
            .expect("verifier-fixed root");
        assert_eq!(
            trace.validate_public_channel(2, &[0x43; 32]),
            Err(ZkX509IoAirErrorV1::PublicInput)
        );
        let mut wrong_topology = declarations;
        wrong_topology[1].producer.instance += 1;
        assert_eq!(
            trace.validate_fixed_topology(&wrong_topology),
            Err(ZkX509IoAirErrorV1::Topology)
        );
    }
    #[test]
    fn topology_sorted_public_and_product_mutations_fail_closed() {
        let trace = build_zk_x509_io_trace_v1(&valid_witnesses(), challenges()).expect("I/O trace");
        let mut changed = trace.clone();
        changed.execution[0].endpoint = endpoint(ZkX509IoSegmentRoleV1::P256, 0);
        assert_eq!(
            changed.validate(challenges()),
            Err(ZkX509IoAirErrorV1::Topology)
        );
        let mut changed = trace.clone();
        changed.execution[0].value = changed.execution[0].value.add(F::ONE);
        assert_eq!(
            changed.validate(challenges()),
            Err(ZkX509IoAirErrorV1::Permutation)
        );
        let mut changed = trace.clone();
        let first_group_channel = changed.sorted[0].channel;
        let first_group_offset = changed.sorted[0].offset;
        for access in changed.sorted.iter_mut().take_while(|access| {
            access.channel == first_group_channel && access.offset == first_group_offset
        }) {
            access.value = access.value.add(F::ONE);
        }
        assert_eq!(
            changed.validate(challenges()),
            Err(ZkX509IoAirErrorV1::Permutation)
        );
        let mut changed = trace.clone();
        changed.sorted[1].is_write = F::ONE;
        assert_eq!(
            changed.validate(challenges()),
            Err(ZkX509IoAirErrorV1::SortedMemory)
        );
        let mut changed = trace.clone();
        let public = changed
            .execution
            .iter_mut()
            .find(|access| access.endpoint.role == ZkX509IoSegmentRoleV1::PublicInput)
            .expect("public read");
        public.value = public.value.add(F::ONE);
        assert_eq!(
            changed.validate(challenges()),
            Err(ZkX509IoAirErrorV1::PublicInput)
        );
        let mut changed = trace;
        changed.permutation_rows[7].sorted_product_after[2] =
            changed.permutation_rows[7].sorted_product_after[2].add(F::ONE);
        assert_eq!(
            changed.validate(challenges()),
            Err(ZkX509IoAirErrorV1::Permutation)
        );
    }
    #[test]
    fn channel_declarations_and_resource_bound_are_strict() {
        let mut changed = valid_witnesses();
        changed[1].declaration.channel = 9;
        assert_eq!(
            build_zk_x509_io_trace_v1(&changed, challenges()),
            Err(ZkX509IoAirErrorV1::Topology)
        );
        let mut changed = valid_witnesses();
        changed[0].declaration.consumers[0] = changed[0].declaration.producer;
        assert_eq!(
            build_zk_x509_io_trace_v1(&changed, challenges()),
            Err(ZkX509IoAirErrorV1::Topology)
        );
        let mut changed = valid_witnesses();
        changed[2].declaration.public_value = None;
        assert_eq!(
            build_zk_x509_io_trace_v1(&changed, challenges()),
            Err(ZkX509IoAirErrorV1::Topology)
        );
        // The closed X5S1 profile admits four top-level DER documents of at
        // most 4 KiB each. Keep that census distinct from this generic
        // byte-memory adapter's larger standalone capacity.
        let document_bytes = 4 * 4_096;
        let witnesses = vec![witness(
            0,
            endpoint(ZkX509IoSegmentRoleV1::StrictDer, 0),
            vec![endpoint(ZkX509IoSegmentRoleV1::Sha256, 0)],
            &vec![0x55; document_bytes],
            false,
        )];
        let trace =
            build_zk_x509_io_trace_v1(&witnesses, challenges()).expect("bounded document I/O");
        assert_eq!(trace.rows(), 32_768);
        assert!(trace.rows() <= byte_memory_capacity_v1().expect("byte-memory capacity"));
        let capacity_bytes = 64 * 1_024;
        let witnesses = vec![witness(
            0,
            endpoint(ZkX509IoSegmentRoleV1::StrictDer, 0),
            vec![endpoint(ZkX509IoSegmentRoleV1::Sha256, 0)],
            &vec![0x5a; capacity_bytes],
            false,
        )];
        let trace = build_zk_x509_io_trace_v1(&witnesses, challenges()).expect("adapter capacity");
        assert_eq!(trace.rows(), 131_072);
        let oversized = vec![witness(
            0,
            endpoint(ZkX509IoSegmentRoleV1::StrictDer, 0),
            vec![endpoint(ZkX509IoSegmentRoleV1::Sha256, 0)],
            &vec![0x66; 131_073],
            false,
        )];
        assert_eq!(
            build_zk_x509_io_trace_v1(&oversized, challenges()),
            Err(ZkX509IoAirErrorV1::Resource)
        );
    }
    #[test]
    fn transcript_challenges_bind_both_trace_commitments() {
        let labels: Vec<_> = IO_PERMUTATION_CHALLENGE_LABELS_V1
            .iter()
            .flatten()
            .copied()
            .collect();
        assert_eq!(labels.len(), IO_PERMUTATION_LANES_V1 * 5);
        for (index, label) in labels.iter().enumerate() {
            assert!(!labels[..index].contains(label));
        }
        let profile = PrivacyOuterDigestV1::from_bytes([0x10; 48]);
        let public = PrivacyOuterDigestV1::from_bytes([0x20; 48]);
        let execution_root = PrivacyOuterDigestV1::from_bytes([0x30; 48]).to_bytes();
        let sorted_root = PrivacyOuterDigestV1::from_bytes([0x40; 48]).to_bytes();
        let mut transcript = TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"zk-x509-io-test",
            &profile,
            &public,
        )
        .expect("transcript");
        transcript
            .absorb(
                b"zk-x509-io-trace-commitments-v1",
                &[&execution_root, &sorted_root],
            )
            .expect("commit roots");
        let sampled = derive_zk_x509_io_challenges_v1(&mut transcript).expect("I/O challenges");
        sampled.validate().expect("valid challenges");
        let mut changed_root = sorted_root;
        changed_root[5] ^= 1;
        let mut changed = TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"zk-x509-io-test",
            &profile,
            &public,
        )
        .expect("transcript");
        changed
            .absorb(
                b"zk-x509-io-trace-commitments-v1",
                &[&execution_root, &changed_root],
            )
            .expect("changed roots");
        assert_ne!(
            sampled,
            derive_zk_x509_io_challenges_v1(&mut changed).expect("changed challenges")
        );
    }
}

#[cfg(test)]
#[path = "io_air_cleanup_tests.rs"]
mod cleanup_tests;

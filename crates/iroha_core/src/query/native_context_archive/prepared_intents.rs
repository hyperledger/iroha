//! Local, unresolved outbound Prepared intent from the original executed witness.
//!
//! One canonical frame borrows exact coordinates and a checked scalar row sequence. These are source coordinates, never finality or signing authority. No
//! AMX record graph is decoded. The unchanged `.nrt` is the complete original record
//! source, which an eventual consumer must authenticate with the native carrier.
//! The borrowed native consumer joins these bytes to the original proof/instruction owner.
//! TODO(S6): connect that instruction to an explicitly authorized, funded parent transaction
//! journal. No signed submission, restart scheduling or successful relay is represented here.

use super::*;
use crate::state::CapturedExecWitness;
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    execution_witness::ExecutionWitnessKeyTagV1,
    sumeragi_amx::{AMX_RECORD_WITNESS_KEY_BYTES, AmxRecordKind},
};
use iroha_model_base::topology::DataSpaceId;

#[derive(norito::Encode, norito::NoritoSchema)]
// The borrowed root explicitly projects to the sole owned frame identity; its nominal
// erased lifetime stays distinct, as required by Norito's schema contract.
#[norito_schema(
    name = "iroha_core::amx::PreparedIntentCoordinatesV1",
    frame = "iroha_core::amx::PreparedIntentCoordinatesV1"
)]
struct Coordinates<'a> {
    local_network: NetworkId,
    local_chain: &'a [u8],
    parent_network: NetworkId,
    parent_chain: &'a [u8],
    parent_instance: [u8; 32],
    parent_genesis: Hash,
    parent_successor: Hash,
    participant: DataSpaceId,
    height: u64,
    carrier: HashOf<BlockHeader>,
    ordinary_writes_root: Hash,
    records: u64,
    // Zero always means outbound signing/fee authority is unresolved.
    authority: u8,
    rows: RowsRef<'a>,
}
#[derive(Clone, Copy, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::amx::PreparedIntentRowV1")]
/// Fixed canonical intent observation; only native proof verification authenticates its claims.
pub(crate) struct Row {
    pub(crate) key: [u8; AMX_RECORD_WITNESS_KEY_BYTES],
    pub(crate) tx: [u8; 32],
    pub(crate) participant: DataSpaceId,
    pub(crate) value: Hash,
}

pub(super) fn is_prepared_key_prefix(key: &[u8]) -> bool {
    key.first() == Some(&(ExecutionWitnessKeyTagV1::AmxRecord as u8))
        && key.get(1) == Some(&(AmxRecordKind::Prepared as u8))
}
fn prepared_key(
    key: &[u8],
) -> Result<Option<[u8; AMX_RECORD_WITNESS_KEY_BYTES]>, NativeContextArchiveError> {
    if !is_prepared_key_prefix(key) {
        return Ok(None);
    }
    Ok(Some(key.try_into().map_err(|_| {
        NativeContextArchiveError::Source("original Prepared key length differs")
    })?))
}
fn row(write: &ExecKv, participant: DataSpaceId) -> Result<Option<Row>, NativeContextArchiveError> {
    let Some(key) = prepared_key(&write.key)? else {
        return Ok(None);
    };
    let mut tx = [0; 32];
    tx.copy_from_slice(&key[2..]);
    Ok(Some(Row {
        key,
        tx,
        participant,
        value: Hash::new(&write.value),
    }))
}
pub(crate) fn count(writes: &[ExecKv]) -> Result<usize, NativeContextArchiveError> {
    let mut count = 0usize;
    for write in writes {
        if prepared_key(&write.key)?.is_some() {
            count = count
                .checked_add(1)
                .ok_or(iroha_allocation::AllocationRefusal::DemandOverflow)
                .map_err(ChargedBufferError::Admission)?;
        }
    }
    Ok(count)
}

// Reuse Norito's actual canonical element-sequence writer, never a copied codec or Vec.
#[derive(Clone, Copy)]
enum RowsSource<'a> {
    Writes(&'a [ExecKv]),
    Encoded(&'a [u8]),
}
struct RowsRef<'a> {
    source: RowsSource<'a>,
    participant: DataSpaceId,
    count: usize,
}
impl norito::NoritoSchema for RowsRef<'_> {
    fn nominal_name() -> String {
        Self::static_nominal_name()
            .expect("declared borrowed rows identity")
            .into()
    }
    fn static_nominal_name() -> Option<&'static str> {
        Some("iroha_core::amx::PreparedIntentRowsRef<'_>")
    }
    fn frame_name() -> String {
        <Vec<Row> as norito::NoritoSchema>::frame_name()
    }
}
impl norito::core::SerializePayload for RowsRef<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        let RowsSource::Writes(writes) = &self.source else {
            let RowsSource::Encoded(bytes) = &self.source else {
                unreachable!()
            };
            // The sole reader validated this complete canonical sequence with the shared
            // span walker and each original Row leaf. Retain its exact borrowed bytes.
            norito::core::note_compact_len_emitted();
            std::io::Write::write_all(writer, bytes)?;
            return Ok(());
        };
        norito::core::write_element_sequence::<Row, _>(
            writer,
            Rows {
                writes: writes.iter(),
                participant: self.participant,
                remaining: self.count,
            },
        )
    }
}
struct Rows<'a> {
    writes: std::slice::Iter<'a, ExecKv>,
    participant: DataSpaceId,
    remaining: usize,
}
impl Iterator for Rows<'_> {
    type Item = Row;
    fn next(&mut self) -> Option<Row> {
        for write in self.writes.by_ref() {
            if is_prepared_key_prefix(&write.key) {
                // count() checked every exact key before constructing this immutable view.
                // A cardinality/length fault is refused by the shared sequence writer.
                let item = row(write, self.participant).ok().flatten()?;
                self.remaining = self.remaining.checked_sub(1)?;
                return Some(item);
            }
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Rows<'_> {}

impl NativeContextArchive {
    /// Complete the same context's local Prepared intent before State publication.
    /// Refusal leaves the completed canonical context and original execution live.
    pub(crate) fn prepare_amx_intents(
        &self,
        original: &mut PreparedNativeContext,
        overlay: &StateBlock<'_>,
        executed: &SignedBlock,
        result: &RetainedPayload<ExecutionResultCommitment>,
        witness: &CapturedExecWitness,
    ) -> Result<(), NativeContextArchiveError> {
        // Ordinary no-AMX blocks retain their original capture path unchanged.
        if original.intents_complete && original.prepared_intents.is_none() {
            return Ok(());
        }
        self.recheck_namespace()?;
        if !self.writable
            || !original.bytes.belongs_to(&self.budget)
            || !result.belongs_to(&self.budget)
            || !witness.pool().same_pool(&self.budget)
            || !witness.matches_original_native_execution(executed, result.get().execution)
            || original.height != executed.header().height().get()
            || original.carrier_hash != executed.hash()
            || executed.header() != overlay._curr_block
            || result.get().schedule.current.network_id != *overlay.network_id()
        {
            return Err(NativeContextArchiveError::Source(
                "intent lost its original execution or pool",
            ));
        }
        if original.intents_complete {
            return Ok(());
        }
        let records = count(&witness.writes)?;
        if records == 0 {
            original.intents_complete = true;
            return Ok(());
        }
        let parent = overlay
            .world()
            .sumeragi_amx_participant()
            .authenticated_parent_source(&self.budget)
            .ok_or(NativeContextArchiveError::Source(
                "Prepared intent lacks its original authenticated participant",
            ))?;
        let global = &parent.participant.global;
        // Never consult participant.prepared: same-block settle/prune may remove an
        // entry while the original transactionally committed witness retains it.
        let coordinates = Coordinates {
            local_network: *overlay.network_id(),
            local_chain: overlay.chain_id().as_str().as_bytes(),
            parent_network: global.current.network_id,
            parent_chain: &parent.global_chain_label,
            parent_instance: global.instance,
            parent_genesis: Hash::new(&parent.global_genesis),
            parent_successor: Hash::new(&parent.global_successor),
            participant: parent.participant.dataspace,
            height: original.height,
            carrier: original.carrier_hash,
            ordinary_writes_root: result.get().execution.ordinary_writes_root,
            records: u64::try_from(records).map_err(|_| norito::Error::LengthMismatch)?,
            authority: 0,
            rows: RowsRef {
                source: RowsSource::Writes(&witness.writes),
                participant: parent.participant.dataspace,
                count: records,
            },
        };
        let length = norito::canonical_frame_len(&coordinates)?;
        if length > self.maximum.get() {
            return Err(NativeContextArchiveError::Limit {
                maximum: self.maximum.get(),
                actual: length,
            });
        }
        // Admit every destination byte before encoding, from the original finite pool.
        let mut bytes = ChargedBuffer::new(length, &self.budget)?;
        norito::core::write_canonical_to_writer(&coordinates, &mut BufferWriter(&mut bytes))?;
        if bytes.as_slice().len() != length {
            return Err(norito::Error::LengthMismatch.into());
        }
        original.prepared_intents = Some(bytes);
        original.intents_complete = true;
        Ok(())
    }
}

// The sole borrowed intent decoder. All field and row framing belongs to Norito.
use norito::core::{self as ncore, DecodeIntoError};
use std::{convert::Infallible, ops::Range};

fn codec(error: DecodeIntoError<Infallible>) -> norito::Error {
    error.into_codec()
}
fn scalar<T>(payload: &[u8], offset: &mut usize) -> Result<T, norito::Error>
where
    T: for<'de> norito::DeserializePayload<'de> + norito::SerializePayload,
{
    ncore::framed_field::<T>(payload, offset)?.decode_owned()
}
fn range(source: &[u8], borrowed: &[u8]) -> Result<Range<usize>, norito::Error> {
    let start = (borrowed.as_ptr() as usize)
        .checked_sub(source.as_ptr() as usize)
        .ok_or(norito::Error::LengthMismatch)?;
    let end = start
        .checked_add(borrowed.len())
        .ok_or(norito::Error::LengthMismatch)?;
    if source.get(start..end) != Some(borrowed) {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(start..end)
}
fn chain_bytes<'a>(payload: &'a [u8], offset: &mut usize) -> Result<&'a [u8], norito::Error> {
    let field = ncore::framed_field::<Vec<u8>>(payload, offset)?;
    let original = range(payload, field.bytes())?;
    let (length, prefix) = field
        .with_payload(|bytes| {
            let (length, prefix) = ncore::read_seq_len_slice(bytes)?;
            if prefix.checked_add(length) != Some(bytes.len()) {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok::<_, DecodeIntoError<Infallible>>((length, prefix))
        })
        .map_err(codec)?;
    let start = original
        .start
        .checked_add(prefix)
        .ok_or(norito::Error::LengthMismatch)?;
    payload
        .get(start..start + length)
        .ok_or(norito::Error::LengthMismatch)
}
fn rows<'a>(payload: &'a [u8], offset: &mut usize) -> Result<RowsRef<'a>, norito::Error> {
    let field = ncore::framed_field::<Vec<Row>>(payload, offset)?;
    let original = range(payload, field.bytes())?;
    let count = field
        .with_payload(|bytes| {
            let (count, _) = ncore::read_seq_len_slice(bytes)?;
            let flags = ncore::effective_decode_flags().unwrap_or_else(ncore::default_encode_flags);
            let used = ncore::visit_binary_sequence_with_count(bytes, flags, count, |span| {
                let element = span.get(bytes)?;
                let (_, used) = ncore::decode_field_canonical::<Row>(element)?;
                if used != element.len() {
                    return Err(norito::Error::LengthMismatch);
                }
                Ok(())
            })?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok::<_, DecodeIntoError<Infallible>>(count)
        })
        .map_err(codec)?;
    Ok(RowsRef {
        source: RowsSource::Encoded(&payload[original]),
        participant: DataSpaceId::UNIVERSAL,
        count,
    })
}
fn decode_coordinates(payload: &[u8]) -> Result<Coordinates<'_>, norito::Error> {
    let mut offset = 0;
    let local_network = scalar(payload, &mut offset)?;
    let local_chain = chain_bytes(payload, &mut offset)?;
    let parent_network = scalar(payload, &mut offset)?;
    let parent_chain = chain_bytes(payload, &mut offset)?;
    let parent_instance =
        ncore::framed_byte_array_field::<32>(payload, &mut offset)?.decode_owned()?;
    let parent_genesis = scalar(payload, &mut offset)?;
    let parent_successor = scalar(payload, &mut offset)?;
    let participant = scalar(payload, &mut offset)?;
    let height = scalar(payload, &mut offset)?;
    let carrier = scalar(payload, &mut offset)?;
    let ordinary_writes_root = scalar(payload, &mut offset)?;
    let records = scalar(payload, &mut offset)?;
    let authority = scalar(payload, &mut offset)?;
    let mut rows = rows(payload, &mut offset)?;
    rows.participant = participant;
    if offset != payload.len() {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(Coordinates {
        local_network,
        local_chain,
        parent_network,
        parent_chain,
        parent_instance,
        parent_genesis,
        parent_successor,
        participant,
        height,
        carrier,
        ordinary_writes_root,
        records,
        authority,
        rows,
    })
}
impl<'a> norito::DeserializePayload<'a> for Coordinates<'a> {
    fn deserialize(archived: &'a norito::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("validated canonical intent payload")
    }
    fn try_deserialize(archived: &'a norito::Archived<Self>) -> Result<Self, norito::Error> {
        let ptr = std::ptr::from_ref(archived).cast::<u8>();
        let payload = ncore::payload_slice_from_ptr(ptr)?;
        let value = decode_coordinates(payload)?;
        ncore::finish_context_fields(ptr, payload.len())?;
        Ok(value)
    }
}
struct ExactWriter<'a> {
    original: &'a [u8],
    used: usize,
    mismatch: bool,
}
impl std::io::Write for ExactWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .used
            .checked_add(bytes.len())
            .ok_or(std::io::ErrorKind::InvalidData)?;
        if self.original.get(self.used..end) != Some(bytes) {
            self.mismatch = true;
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        self.used = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn read_coordinates(bytes: &[u8]) -> Result<Coordinates<'_>, norito::Error> {
    let view = ncore::from_bytes_view(bytes)?;
    if view.flags() != ncore::default_encode_flags() {
        return Err(norito::Error::NonCanonicalEncoding);
    }
    let value = view.decode_exact_with::<Coordinates<'_>, _, _>(|payload| {
        Ok((decode_coordinates(payload)?, payload.len()))
    })?;
    let mut exact = ExactWriter {
        original: bytes,
        used: 0,
        mismatch: false,
    };
    let encoded = ncore::write_canonical_to_writer(&value, &mut exact);
    if exact.mismatch || exact.used != bytes.len() {
        return Err(norito::Error::NonCanonicalEncoding);
    }
    encoded?;
    Ok(value)
}
fn decode_row(bytes: &[u8]) -> Result<(Row, usize), norito::Error> {
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let (len, prefix) =
        ncore::read_len_from_slice_with_flags(bytes, ncore::default_encode_flags())?;
    let end = prefix
        .checked_add(len)
        .ok_or(norito::Error::LengthMismatch)?;
    let element = bytes
        .get(prefix..end)
        .ok_or(norito::Error::LengthMismatch)?;
    let (row, used) = ncore::decode_field_canonical::<Row>(element)?;
    if used != element.len() {
        return Err(norito::Error::LengthMismatch);
    }
    Ok((row, end))
}
#[cfg(test)]
struct DecodedRows<'a> {
    bytes: &'a [u8],
    remaining: usize,
}
#[cfg(test)]
impl Iterator for DecodedRows<'_> {
    type Item = Result<Row, norito::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        match decode_row(self.bytes) {
            Ok((row, used)) => {
                self.remaining -= 1;
                self.bytes = &self.bytes[used..];
                Some(Ok(row))
            }
            Err(error) => {
                self.remaining = 0;
                Some(Err(error))
            }
        }
    }
}
#[cfg(test)]
impl<'a> RowsRef<'a> {
    fn iter(&self) -> Result<DecodedRows<'a>, norito::Error> {
        let RowsSource::Encoded(bytes) = self.source else {
            return Err(norito::Error::NonCanonicalEncoding);
        };
        let (count, prefix) = ncore::inspect_seq_len_slice(bytes)?;
        if count != self.count {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(DecodedRows {
            bytes: &bytes[prefix..],
            remaining: count,
        })
    }
}

/// Scalar observations retain no authority or allocation outside the original charged frame.
#[derive(Debug)]
pub(crate) struct IntentProjection {
    local_network: NetworkId,
    local_chain: Range<usize>,
    parent_network: NetworkId,
    parent_chain: Range<usize>,
    parent_instance: [u8; 32],
    parent_genesis: Hash,
    parent_successor: Hash,
    participant: DataSpaceId,
    height: u64,
    carrier: HashOf<BlockHeader>,
    pub(crate) ordinary_writes_root: Hash,
    rows: Range<usize>,
    count: usize,
}
impl IntentProjection {
    #[cfg(not(all(test, sumeragi_core_mutation = "HC218")))]
    pub(crate) fn record_count(&self) -> usize {
        self.count
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, norito::Error> {
        let value = read_coordinates(bytes)?;
        if value.authority != 0 {
            return Err(norito::Error::NonCanonicalEncoding);
        }
        let RowsSource::Encoded(rows) = value.rows.source else {
            unreachable!()
        };
        if value.records
            != u64::try_from(value.rows.count).map_err(|_| norito::Error::LengthMismatch)?
            || value.rows.count == 0
        {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(Self {
            local_network: value.local_network,
            local_chain: range(bytes, value.local_chain)?,
            parent_network: value.parent_network,
            parent_chain: range(bytes, value.parent_chain)?,
            parent_instance: value.parent_instance,
            parent_genesis: value.parent_genesis,
            parent_successor: value.parent_successor,
            participant: value.participant,
            height: value.height,
            carrier: value.carrier,
            ordinary_writes_root: value.ordinary_writes_root,
            rows: range(bytes, rows)?,
            count: value.rows.count,
        })
    }
    pub(crate) fn matches<V: StateReadOnly>(
        &self,
        bytes: &[u8],
        view: &V,
        budget: &AllocationBudget,
        height: u64,
        carrier: HashOf<BlockHeader>,
    ) -> bool {
        let Some(parent) = view
            .world()
            .sumeragi_amx_participant()
            .authenticated_parent_source(budget)
        else {
            return false;
        };
        let global = &parent.participant.global;
        self.local_network == *view.network_id()
            && self.height == height
            && self.carrier == carrier
            && bytes.get(self.local_chain.clone()) == Some(view.chain_id().as_str().as_bytes())
            && self.parent_network == global.current.network_id
            && bytes.get(self.parent_chain.clone()) == Some(parent.global_chain_label.as_slice())
            && self.parent_instance == global.instance
            && self.parent_genesis == Hash::new(&parent.global_genesis)
            && self.parent_successor == Hash::new(&parent.global_successor)
            && self.participant == parent.participant.dataspace
    }
    pub(crate) fn first_offset(&self, bytes: &[u8]) -> Result<usize, norito::Error> {
        let rows = bytes
            .get(self.rows.clone())
            .ok_or(norito::Error::LengthMismatch)?;
        let (count, prefix) = ncore::inspect_seq_len_slice(rows)?;
        if count != self.count {
            return Err(norito::Error::LengthMismatch);
        }
        self.rows
            .start
            .checked_add(prefix)
            .ok_or(norito::Error::LengthMismatch)
    }
    pub(crate) fn row(
        &self,
        bytes: &[u8],
        index: usize,
        offset: usize,
    ) -> Result<Option<(Row, usize)>, norito::Error> {
        if index == self.count {
            return if offset == self.rows.end {
                Ok(None)
            } else {
                Err(norito::Error::LengthMismatch)
            };
        }
        if index > self.count || offset < self.rows.start || offset >= self.rows.end {
            return Err(norito::Error::LengthMismatch);
        }
        let (row, used) = decode_row(&bytes[offset..self.rows.end])?;
        if row.participant != self.participant
            || prepared_key(&row.key).ok().flatten() != Some(row.key)
            || row.key.get(2..) != Some(row.tx.as_slice())
        {
            return Err(norito::Error::NonCanonicalEncoding);
        }
        Ok(Some((
            row,
            offset
                .checked_add(used)
                .ok_or(norito::Error::LengthMismatch)?,
        )))
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    // Rewrite only untrusted scalar claims through the sole canonical codec for adversarial
    // controls. No proof, signature, source selection or production authority is manufactured.
    pub(crate) fn one_row_subset(bytes: &[u8]) -> Vec<u8> {
        let mut value = read_coordinates(bytes).unwrap();
        assert_eq!(value.rows.count, 2, "genuine same-carrier two-row source");
        let row = value.rows.iter().unwrap().next().unwrap().unwrap();
        let mut encoded = Vec::new();
        let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        ncore::write_element_sequence::<Row, _>(
            &mut ncore::Encoder::for_buffer(&mut encoded),
            std::iter::once(row),
        )
        .unwrap();
        value.records = 1;
        value.rows = RowsRef {
            source: RowsSource::Encoded(&encoded),
            participant: value.participant,
            count: 1,
        };
        norito::encode_canonical(&value).unwrap()
    }
    pub(crate) fn rewrite_claims(bytes: &[u8], variant: u8) -> Vec<u8> {
        let mut value = read_coordinates(bytes).unwrap();
        match variant {
            0 => value.authority = 1,
            1 => {
                value.carrier =
                    HashOf::from_untyped_unchecked(Hash::new(b"foreign original carrier"))
            }
            2 => value.ordinary_writes_root = Hash::new(b"foreign original ordinary writes"),
            _ => panic!("exact adversarial claim variant"),
        }
        norito::encode_canonical(&value).unwrap()
    }
    pub(crate) fn verify_original(
        bytes: &[u8],
        overlay: &StateBlock<'_>,
        executed: &SignedBlock,
        result: &ExecutionResultCommitment,
        witness: &CapturedExecWitness,
    ) -> [u8; 32] {
        let value = read_coordinates(bytes).unwrap();
        assert_eq!(norito::encode_canonical(&value).unwrap(), bytes);
        let parent = overlay
            .world()
            .sumeragi_amx_participant()
            .canonical()
            .unwrap();
        assert_eq!(value.local_network, *overlay.network_id());
        assert_eq!(value.local_chain, overlay.chain_id().as_str().as_bytes());
        assert_eq!(
            value.parent_network,
            parent.participant.global.current.network_id
        );
        assert_eq!(value.parent_chain, parent.global_chain_label);
        assert_eq!(value.parent_instance, parent.participant.global.instance);
        assert_eq!(value.parent_genesis, Hash::new(&parent.global_genesis));
        assert_eq!(value.parent_successor, Hash::new(&parent.global_successor));
        assert_eq!(value.participant, parent.participant.dataspace);
        assert_eq!(value.height, executed.header().height().get());
        assert_eq!(value.carrier, executed.hash());
        assert_eq!(
            value.ordinary_writes_root,
            result.execution.ordinary_writes_root
        );
        assert_eq!(
            value.authority, 0,
            "captured intent never resolves missing outbound authority"
        );
        assert_eq!(value.records, u64::try_from(value.rows.count).unwrap());
        let expected: Vec<_> = witness
            .writes
            .iter()
            .filter_map(|write| row(write, value.participant).unwrap())
            .collect();
        assert_eq!(value.rows.count, expected.len());
        for (actual, expected) in value.rows.iter().unwrap().zip(&expected) {
            let actual = actual.unwrap();
            assert_eq!(actual.key, expected.key);
            assert_eq!(actual.tx, expected.tx);
            assert_eq!(actual.participant, expected.participant);
            assert_eq!(actual.value, expected.value);
        }
        assert!(
            value.rows.count != 0,
            "actual Prepared witness must capture an intent"
        );
        value.rows.iter().unwrap().next().unwrap().unwrap().tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sumeragi_amx::amx_record_witness_key;
    #[test]
    fn borrowed_intent_coordinates_declare_exact_owned_frame_without_erasing_nominal_lifetime() {
        use norito::NoritoSchema as _;
        assert_eq!(
            Coordinates::static_frame_name(),
            Some("iroha_core::amx::PreparedIntentCoordinatesV1")
        );
        assert_eq!(
            Coordinates::frame_name(),
            "iroha_core::amx::PreparedIntentCoordinatesV1"
        );
        assert_ne!(Coordinates::nominal_name(), Coordinates::frame_name());
        assert_eq!(
            norito::schema::identity::frame_hash::<Coordinates>(),
            norito::core::schema_hash_for_name("iroha_core::amx::PreparedIntentCoordinatesV1")
        );
    }
    #[test]
    fn original_prepared_key_selection_refuses_malformed_and_preserves_transaction() {
        let key = amx_record_witness_key(AmxRecordKind::Prepared, [0x41; 32]);
        assert!(is_prepared_key_prefix(&key));
        assert_eq!(prepared_key(&key).unwrap(), Some(key));
        assert!(matches!(
            prepared_key(&key[..33]),
            Err(NativeContextArchiveError::Source(_))
        ));
        assert!(
            prepared_key(&amx_record_witness_key(AmxRecordKind::Begin, [0x41; 32]))
                .unwrap()
                .is_none()
        );
        assert!(prepared_key(&[]).unwrap().is_none());
        let write = ExecKv {
            key: key.to_vec(),
            value: vec![1, 2, 3],
        };
        let selected = row(&write, DataSpaceId::new(5)).unwrap().unwrap();
        assert_eq!(selected.tx, [0x41; 32]);
        assert_eq!(selected.key, key);
        assert_eq!(selected.participant, DataSpaceId::new(5));
        assert_eq!(selected.value, Hash::new(&write.value));
    }
    #[test]
    fn borrowed_prepared_rows_use_canonical_sequence_and_refuse_changed_cardinality() {
        let writes = [
            ExecKv {
                key: amx_record_witness_key(AmxRecordKind::Prepared, [0x61; 32]).to_vec(),
                value: vec![3],
            },
            ExecKv {
                key: b"ordinary".to_vec(),
                value: vec![2],
            },
        ];
        let rows = RowsRef {
            source: RowsSource::Writes(&writes),
            participant: DataSpaceId::new(5),
            count: count(&writes).unwrap(),
        };
        let owned = vec![row(&writes[0], DataSpaceId::new(5)).unwrap().unwrap()];
        use norito::NoritoSchema as _;
        assert_ne!(RowsRef::nominal_name(), <Vec<Row>>::nominal_name());
        assert_eq!(RowsRef::frame_name(), <Vec<Row>>::frame_name());
        assert_eq!(
            norito::schema::identity::frame_hash::<RowsRef<'_>>(),
            norito::schema::identity::frame_hash::<Vec<Row>>()
        );
        assert_ne!(
            norito::schema::identity::frame_hash::<Vec<RowsRef<'_>>>(),
            norito::schema::identity::frame_hash::<Vec<Vec<Row>>>()
        );
        let actual = norito::core::to_bytes(&rows).unwrap();
        let expected = norito::core::to_bytes(&owned).unwrap();
        assert_eq!(actual, expected, "one shared canonical sequence kernel");
        let changed = RowsRef { count: 2, ..rows };
        assert!(matches!(
            norito::core::to_bytes(&changed),
            Err(norito::Error::LengthMismatch)
        ));
        let malformed = [ExecKv {
            key: writes[0].key[..33].to_vec(),
            value: vec![3],
        }];
        assert!(count(&malformed).is_err());
    }

    #[test]
    fn sole_intent_decoder_borrows_original_charged_ranges_and_refuses_framing_or_cumulative_limits()
     {
        let writes = [ExecKv {
            key: amx_record_witness_key(AmxRecordKind::Prepared, [0x71; 32]).to_vec(),
            value: vec![3, 7],
        }];
        let carrier = HashOf::from_untyped_unchecked(Hash::new(b"original codec fixture carrier"));
        let coordinates = Coordinates {
            local_network: NetworkId::from_genesis_hash(carrier),
            local_chain: b"local-original",
            parent_network: NetworkId::from_genesis_hash(carrier),
            parent_chain: b"parent-original",
            parent_instance: [0x55; 32],
            parent_genesis: Hash::new(b"G1"),
            parent_successor: Hash::new(b"H2"),
            participant: DataSpaceId::new(5),
            height: 2,
            carrier,
            ordinary_writes_root: Hash::new(b"writes"),
            records: 1,
            authority: 0,
            rows: RowsRef {
                source: RowsSource::Writes(&writes),
                participant: DataSpaceId::new(5),
                count: 1,
            },
        };
        let original = norito::encode_canonical(&coordinates).unwrap();
        // Both counterexamples are genuine codec-owned frames, not manually edited headers.
        let foreign =
            norito::encode_canonical(&row(&writes[0], DataSpaceId::new(5)).unwrap().unwrap())
                .unwrap();
        assert!(ncore::from_bytes_view(&foreign).is_ok());
        assert!(matches!(
            read_coordinates(&foreign),
            Err(norito::Error::SchemaMismatch)
        ));
        let other_layout = {
            let _flags = ncore::DecodeFlagsGuard::enter(0);
            ncore::to_bytes(&coordinates).unwrap()
        };
        let layout_view = ncore::from_bytes_view(&other_layout).unwrap();
        assert_eq!(layout_view.flags(), 0);
        layout_view
            .decode_exact_with::<Coordinates<'_>, _, _>(|payload| {
                Ok((decode_coordinates(payload)?, payload.len()))
            })
            .unwrap();
        assert!(
            matches!(
                read_coordinates(&other_layout),
                Err(norito::Error::NonCanonicalEncoding)
            ),
            "a valid other advertised layout cannot replace the original intent's canonical layout"
        );
        let budget = AllocationBudget::new(original.len());
        let mut bytes = ChargedBuffer::new(original.len(), &budget).unwrap();
        bytes.append(&original).unwrap();
        let decoded = read_coordinates(bytes.as_slice()).unwrap();
        for borrowed in [decoded.local_chain, decoded.parent_chain] {
            let selected = range(bytes.as_slice(), borrowed).unwrap();
            assert!(std::ptr::eq(
                borrowed.as_ptr(),
                bytes.as_slice()[selected].as_ptr()
            ));
        }
        let RowsSource::Encoded(rows) = decoded.rows.source else {
            panic!("original encoded row view");
        };
        let selected = range(bytes.as_slice(), rows).unwrap();
        assert!(std::ptr::eq(
            rows.as_ptr(),
            bytes.as_slice()[selected].as_ptr()
        ));
        assert_eq!(norito::encode_canonical(&decoded).unwrap(), original);
        let projection = IntentProjection::decode(bytes.as_slice()).unwrap();
        let first = projection.first_offset(bytes.as_slice()).unwrap();
        let (selected, next) = projection.row(bytes.as_slice(), 0, first).unwrap().unwrap();
        assert_eq!(selected.tx, [0x71; 32]);
        assert_eq!(selected.value, Hash::new(&writes[0].value));
        assert!(projection.row(bytes.as_slice(), 1, next).unwrap().is_none());
        assert!(range(bytes.as_slice(), b"unrelated bytes").is_err());
        assert!(read_coordinates(&original[..original.len() - 1]).is_err());
        let mut trailing = original.clone();
        trailing.push(1);
        assert!(read_coordinates(&trailing).is_err());
        let mut corrupt = original.clone();
        corrupt[0] ^= 0x80;
        assert!(read_coordinates(&corrupt).is_err());
        let limit =
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0);
        let cause = norito::core::with_decode_limits_scope(limit, || {
            norito::core::classify_decode_attempt(|| IntentProjection::decode(bytes.as_slice()))
        })
        .unwrap_err();
        assert_eq!(
            cause.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(bytes.as_slice(), original);
        assert!(bytes.belongs_to(&budget));
        assert_eq!(budget.reserved_bytes(), original.len());
        assert!(
            IntentProjection::decode(bytes.as_slice()).is_ok(),
            "same original source retry after caller scope retires"
        );
        drop(decoded);
        drop(bytes);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

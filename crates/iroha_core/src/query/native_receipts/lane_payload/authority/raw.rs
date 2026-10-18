//! Borrowed canonical creation fields and exact selected-config allocation planning.

use iroha_crypto::{Algorithm, Hash};
use iroha_data_model::sumeragi_finality::ChainParamsRecord;
use iroha_sumeragi::availability::{DataAvailabilityLayout, PayloadEncoding};
use norito::core::{self as ncore, SerializePayload};

use super::*;
use crate::query::native_receipts::lane_payload::select::{field, fields, identity};

fn number<const N: usize>(bytes: &[u8]) -> Result<[u8; N], LanePayloadError> {
    bytes
        .try_into()
        .map_err(|_| norito::Error::LengthMismatch.into())
}
fn uint(bytes: &[u8]) -> Result<u64, LanePayloadError> {
    Ok(u64::from_le_bytes(number(bytes)?))
}
fn sequence(bytes: &[u8]) -> Result<(usize, &[u8]), LanePayloadError> {
    let prefix = bytes.get(..8).ok_or(norito::Error::LengthMismatch)?;
    let count = usize::try_from(uint(prefix)?).map_err(|_| norito::Error::LengthMismatch)?;
    Ok((count, &bytes[8..]))
}
fn raw_bytes(bytes: &[u8]) -> Result<&[u8], LanePayloadError> {
    let (count, bytes) = sequence(bytes)?;
    if count != bytes.len() {
        return Err(norito::Error::LengthMismatch.into());
    }
    Ok(bytes)
}

pub(super) struct RawAuthority<'a> {
    values: [&'a [u8]; 13],
    members: &'a [u8],
    pub(super) count: usize,
    pub(super) lane: LaneId,
    pub(super) created: u64,
    pub(super) layout: DataAvailabilityLayout,
    pub(super) params: ChainParamsRecord,
    pub(super) demotion_window: u64,
}
impl<'a> RawAuthority<'a> {
    pub(super) fn parse(bytes: &'a [u8]) -> Result<Self, LanePayloadError> {
        let values = fields::<13>(bytes)?;
        let [lane] = fields::<1>(values[1])?;
        let lane = LaneId::new(u32::from_le_bytes(number(lane)?));
        let [dataspace] = fields::<1>(values[2])?;
        uint(dataspace)?;
        let incarnation = identity(values[3])?;
        let created = uint(values[6])?;
        let active = uint(values[7])?;
        if lane == LaneId::SINGLE
            || incarnation == [0; 32]
            || created == 0
            || created.checked_add(2) != Some(active)
            || values[8] != [0]
            || uint(values[11])? != active
            || uint(values[12])? != 0
        {
            return Err(LanePayloadError::Source);
        }
        uint(values[9])?;
        let [encoding, chunk, data, parity, maximum, chunks] = fields::<6>(values[0])?;
        if encoding != 0_u32.to_le_bytes() {
            return Err(norito::Error::NonCanonicalEncoding.into());
        }
        let layout = DataAvailabilityLayout {
            encoding: PayloadEncoding::ReedSolomon16,
            chunk_size_bytes: u32::from_le_bytes(number(chunk)?),
            data_shards: u16::from_le_bytes(number(data)?),
            parity_shards: u16::from_le_bytes(number(parity)?),
            max_payload_size_bytes: uint(maximum)?,
            max_chunk_count: u32::from_le_bytes(number(chunks)?),
        };
        layout.validate().map_err(|_| LanePayloadError::Source)?;
        // Match the complete current SumeragiParameters layout, including the
        // committed due-work clock policy before the key and chain parameters.
        let [
            block_cadence,
            _max_clock_drift,
            _due_work_max_lag,
            _key_activation_lead,
            _key_overlap_grace,
            _key_expiry_grace,
            _key_allowed_algorithms,
            payload_retry_interval,
            exec_budget,
            apply_budget,
            max_block_bytes,
            epoch_length,
            demotion_window,
        ] = fields::<13>(values[4])?;
        let params = ChainParamsRecord {
            block_time_ms: uint(block_cadence)?,
            payload_retry_interval_ms: uint(payload_retry_interval)?,
            exec_budget_ms: uint(exec_budget)?,
            apply_budget_ms: uint(apply_budget)?,
            max_block_bytes: u32::from_le_bytes(number(max_block_bytes)?),
            epoch_length_blocks: uint(epoch_length)?,
        };
        params.validate().map_err(|_| LanePayloadError::Source)?;
        let window = uint(demotion_window)?;
        if window == 0 || u64::from(params.max_block_bytes) > layout.max_payload_size_bytes {
            return Err(LanePayloadError::Source);
        }
        // Clock- and key-policy fields remain authenticated original bytes; no allocation is
        // necessary to hash their exact canonical representation into the pinned context.
        let (count, members) = sequence(values[5])?;
        if !iroha_data_model::block::consensus::is_valid_committee_size(count)
            || count > members.len()
        {
            return Err(LanePayloadError::Source);
        }
        let result = Self {
            values,
            members,
            count,
            lane,
            created,
            layout,
            params,
            demotion_window: window,
        };
        let mut previous = [0; iroha_sumeragi::types::MAX_PUBLIC_KEY_LEN];
        let mut length: Option<usize> = None;
        result.visit(|key, _| {
            if length.is_some_and(|length| {
                length
                    .cmp(&key.len())
                    .then_with(|| previous[..length].cmp(key))
                    .is_ge()
            }) {
                return Err(LanePayloadError::Source);
            }
            previous[..key.len()].copy_from_slice(key);
            length = Some(key.len());
            Ok(())
        })?;
        Ok(result)
    }

    pub(super) fn visit(
        &self,
        mut visit: impl FnMut(&[u8], &'a [u8]) -> Result<(), LanePayloadError>,
    ) -> Result<(), LanePayloadError> {
        let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        let mut bytes = self.members;
        for _ in 0..self.count {
            let [peer, proof] = fields::<2>(field(&mut bytes)?)?;
            let [encoded] = fields::<1>(peer)?;
            let mut scratch = [0; iroha_sumeragi::types::MAX_PUBLIC_KEY_LEN + 1];
            let (length, used) = ncore::decode_byte_element_sequence_into(encoded, &mut scratch)?;
            let (&algorithm, key) = scratch[..length]
                .split_first()
                .ok_or(norito::Error::LengthMismatch)?;
            if used != encoded.len() || algorithm != Algorithm::BlsNormal as u8 || key.is_empty() {
                return Err(LanePayloadError::Source);
            }
            visit(key, raw_bytes(proof)?)?;
        }
        if !bytes.is_empty() {
            return Err(norito::Error::LengthMismatch.into());
        }
        Ok(())
    }

    pub(super) fn frontier(&self) -> Result<SumeragiLaneFrontier, LanePayloadError> {
        let [height, hash, result] = fields::<3>(self.values[10])?;
        Ok(SumeragiLaneFrontier {
            height: uint(height)?,
            block_hash: identity(hash)?,
            result: identity(result)?,
        })
    }

    pub(super) fn demand(&self) -> Result<Demand, LanePayloadError> {
        let charges = self
            .count
            .checked_add(2)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut bytes = array::<AllocationCharge>(charges)?
            .size()
            .checked_add(array::<PublicKey>(self.count)?.size())
            .and_then(|n| n.checked_add(Layout::new::<EpochConfig>().size()))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        self.visit(|key, _| {
            bytes = bytes
                .checked_add(array::<u8>(key.len())?.size())
                .ok_or(AllocationRefusal::DemandOverflow)?;
            Ok(())
        })?;
        Ok(Demand { bytes, charges })
    }

    /// Stream the exact existing creation tuple. The named record's incarnation is raw32;
    /// the generic tuple's array uses its normal array codec, so it is supplied as that type.
    pub(super) fn context(&self) -> Result<Hash32, LanePayloadError> {
        let value = (
            RawField(self.values[1]),
            RawField(self.values[2]),
            identity(self.values[3])?,
            RawField(self.values[4]),
            RawField(self.values[0]),
            RawField(self.values[5]),
            RawField(self.values[6]),
            RawField(self.values[7]),
        );
        let hash = Hash::new_from_writer(|mut writer| {
            writer.write_all(crate::sumeragi::lanes::LANE_GENESIS_RESULT_TAG)?;
            norito::codec::encode_adaptive_into(&value, &mut writer)
                .map_err(std::io::Error::other)?;
            Ok(())
        })
        .map_err(|_| LanePayloadError::Source)?;
        Ok(Hash32(hash.into()))
    }
}

struct RawField<'a>(&'a [u8]);
impl SerializePayload for RawField<'_> {
    fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        writer.write_all(self.0)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

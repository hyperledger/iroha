//! Borrowed consensus-set encoders over already admitted input and output owners.
//!
//! These projections reproduce the sole public set frame byte for byte. They do not clone
//! rosters or change the schema identity when the backing owner is a charged buffer.

use norito::{
    NoritoSchema,
    core::{Encoder, SerializePayload, write_len_prefixed},
};

use super::proof::SccpLcSetDataV1;
use crate::{
    ethereum_source::EthereumNativeSyncCommitteeV1,
    ton_native::{TonValidatorConfigRef, TonValidatorV1},
};

/// Canonical top-level set frame borrowing its chain-specific payload.
pub(super) struct SetFrameRef<'a, T> {
    tag: u32,
    value: &'a T,
}

impl<'a, T> SetFrameRef<'a, T> {
    pub(super) const fn ethereum(value: &'a T) -> Self {
        Self { tag: 0, value }
    }
    pub(super) const fn bsc(value: &'a T) -> Self {
        Self { tag: 1, value }
    }
    pub(super) const fn ton(value: &'a T) -> Self {
        Self { tag: 2, value }
    }
}

impl<T: SerializePayload> SerializePayload for SetFrameRef<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.tag.serialize(writer)?;
        write_len_prefixed(writer, self.value)
    }
}

impl<T> NoritoSchema for SetFrameRef<'_, T> {
    fn nominal_name() -> String {
        SccpLcSetDataV1::nominal_name()
    }
    fn static_nominal_name() -> Option<&'static str> {
        SccpLcSetDataV1::static_nominal_name()
    }
    fn frame_name() -> String {
        SccpLcSetDataV1::frame_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        SccpLcSetDataV1::static_frame_name()
    }
}

/// Ethereum set borrowing the proof owner's authenticated committee.
pub(super) struct EthereumSetRef<'a> {
    pub(super) period: u64,
    pub(super) committee: &'a EthereumNativeSyncCommitteeV1,
}

impl SerializePayload for EthereumSetRef<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        write_len_prefixed(writer, &self.period)?;
        write_len_prefixed(writer, self.committee)
    }
}

/// BSC set borrowing the authenticated, admitted announcement roster.
pub(super) struct BscSetRef<'a> {
    pub(super) checkpoint_height: u64,
    pub(super) checkpoint_hash: [u8; 32],
    pub(super) previous_set_id: Option<u64>,
    pub(super) turn_length: u8,
    pub(super) validators: &'a [BscValidatorRef<'a>],
}

/// Native roster member borrowing its exact authenticated key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BscValidatorRef<'a> {
    pub(super) consensus_address: &'a [u8],
    pub(super) vote_public_key: &'a [u8],
}
impl SerializePayload for BscValidatorRef<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        write_len_prefixed(writer, &self.consensus_address)?;
        write_len_prefixed(writer, &self.vote_public_key)
    }
}
struct BscValidatorsRef<'a>(&'a [BscValidatorRef<'a>]);
impl SerializePayload for BscValidatorsRef<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<BscValidatorRef<'_>, _>(writer, self.0.iter())
    }
}
impl SerializePayload for BscSetRef<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        write_len_prefixed(writer, &self.checkpoint_height)?;
        norito::core::write_len(writer, 32)?;
        writer.write_all(&self.checkpoint_hash)?;
        write_len_prefixed(writer, &self.previous_set_id)?;
        write_len_prefixed(writer, &self.turn_length)?;
        write_len_prefixed(writer, &BscValidatorsRef(self.validators))
    }
}

struct ValidatorsRef<'a>(&'a [TonValidatorV1]);

impl SerializePayload for ValidatorsRef<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<TonValidatorV1, _>(writer, self.0.iter())
    }
}

impl SerializePayload for TonValidatorConfigRef<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        write_len_prefixed(writer, &self.valid_since)?;
        write_len_prefixed(writer, &self.valid_until)?;
        write_len_prefixed(writer, &self.main_validator_count)?;
        write_len_prefixed(writer, &self.shuffle_masterchain_validators)?;
        write_len_prefixed(writer, &ValidatorsRef(self.validators))
    }
}

/// TON epoch borrowing the native verifier's admitted validator roster.
pub(super) struct TonEpochRef<'a> {
    pub(super) key_block_seqno: u32,
    pub(super) key_block_root_hash: [u8; 32],
    pub(super) validators: TonValidatorConfigRef<'a>,
    pub(super) stake_held_for: u32,
}

impl SerializePayload for TonEpochRef<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        write_len_prefixed(writer, &self.key_block_seqno)?;
        // Derived fixed byte-array fields carry their raw bytes, not an array sequence.
        norito::core::write_len(writer, 32)?;
        writer.write_all(&self.key_block_root_hash)?;
        write_len_prefixed(writer, &self.validators)?;
        write_len_prefixed(writer, &self.stake_held_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        light_client::{ethereum::EthereumSyncCommitteeSetV1, ton::TonEpochV1},
        ton_native::TonValidatorConfigV1,
    };

    #[test]
    fn borrowed_bsc_rosters_reproduce_the_single_canonical_frame() {
        use crate::light_client::bsc::{BscValidatorSetV1, BscValidatorV1};
        for count in [0, 1, 64] {
            let set = BscValidatorSetV1 {
                checkpoint_height: 9_000,
                checkpoint_hash: [3; 32],
                previous_set_id: Some(8_800),
                turn_length: 16,
                validators: (0..count)
                    .map(|index| BscValidatorV1 {
                        consensus_address: vec![index; 20],
                        vote_public_key: vec![index + 1; 48],
                    })
                    .collect(),
            };
            let members: Vec<_> = set
                .validators
                .iter()
                .map(|member| BscValidatorRef {
                    consensus_address: &member.consensus_address,
                    vote_public_key: &member.vote_public_key,
                })
                .collect();
            let borrowed = BscSetRef {
                checkpoint_height: set.checkpoint_height,
                checkpoint_hash: set.checkpoint_hash,
                previous_set_id: set.previous_set_id,
                turn_length: set.turn_length,
                validators: &members,
            };
            assert_eq!(
                norito::encode_canonical(&SetFrameRef::bsc(&borrowed)).unwrap(),
                SccpLcSetDataV1::Bsc(set.clone()).to_frame().unwrap()
            );
        }
    }

    #[test]
    fn borrowed_ethereum_and_ton_sets_reproduce_the_single_canonical_frame() {
        let committee = EthereumNativeSyncCommitteeV1 {
            public_keys: vec![vec![7; 48]; 512],
            aggregate_public_key: vec![9; 48],
        };
        let ethereum = SccpLcSetDataV1::Ethereum(EthereumSyncCommitteeSetV1 {
            period: 17,
            committee: committee.clone(),
        });
        let borrowed = EthereumSetRef {
            period: 17,
            committee: &committee,
        };
        assert_eq!(
            norito::encode_canonical(&SetFrameRef::ethereum(&borrowed)).unwrap(),
            ethereum.to_frame().unwrap()
        );

        for count in [0, 1, 17] {
            let validators = TonValidatorConfigV1 {
                valid_since: 1,
                valid_until: 90,
                main_validator_count: 3,
                shuffle_masterchain_validators: true,
                validators: (0..count)
                    .map(|i| TonValidatorV1 {
                        public_key: [i; 32],
                        weight: u64::from(i) + 1,
                        adnl_address: [i + 1; 32],
                    })
                    .collect(),
            };
            let ton = SccpLcSetDataV1::Ton(TonEpochV1 {
                key_block_seqno: 43,
                key_block_root_hash: [3; 32],
                validators: validators.clone(),
                stake_held_for: 120,
            });
            let borrowed = TonEpochRef {
                key_block_seqno: 43,
                key_block_root_hash: [3; 32],
                validators: (&validators).into(),
                stake_held_for: 120,
            };
            assert_eq!(
                norito::encode_canonical(&SetFrameRef::ton(&borrowed)).unwrap(),
                ton.to_frame().unwrap()
            );
        }
    }
}

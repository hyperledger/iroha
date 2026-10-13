//! Light-client frames and normalized source events (`specs/sccp.md` §4.12, §4.13, §4.16).
//!
//! Proofs, advances, evidence, bootstraps and stored consensus sets are typed per-chain enums
//! encoded as headered canonical Norito frames (`norito::encode_canonical`), carried by the
//! data-model byte wrappers (`SccpSourceProofBytesV1`, `SccpLcAdvanceBytesV1`,
//! `SccpLcEvidenceBytesV1`, `SccpLcBootstrapV1.bytes`, `SccpLcConsensusSetV1.set_bytes`). A frame
//! decodes only if it is byte-for-byte canonical, so every frame has exactly one encoding and
//! evidence hashes are well defined. The variant names the source chain and must match the
//! instruction's network.
//!
//! A verified proof yields one [`SccpNormalizedEventV1`]: a `TransferToTaira` burn, a
//! `Finalized` outbound mint or a `Void` of outbound nonces, with the emitter the caller
//! compares to the revision's deployment.

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        deployment::SccpDeploymentV1,
        inbound::{SccpSourceLocatorV1, SccpSourceProofBytesV1},
        light_client::{
            SccpLcAdvanceBytesV1, SccpLcBootstrapV1, SccpLcCheckpointV1, SccpLcEvidenceBytesV1,
        },
        outbound::SccpVoidKindV1,
    },
};

use super::{
    SccpLcError,
    bsc::{
        BscHeaderSegmentV1, BscLcAdvanceV1, BscLcBootstrapV1, BscLcEvidenceV1, BscSourceProofV1,
        BscValidatorSetV1,
    },
    ethereum::{
        EthereumHeaderSegmentV1, EthereumLcAdvanceV1, EthereumLcEvidenceV1, EthereumSourceProofV1,
        EthereumSyncCommitteeSetV1,
    },
    ton::{TonEpochV1, TonLcAdvanceV1, TonLcBootstrapV1, TonLcEvidenceV1, TonSourceProofV1},
};
use crate::{ethereum_source::EthereumNativeLightClientBootstrapV1, v1::payload::PayloadAccountV1};

/// Return the chain of a canonically shaped, non-Backfill keeper advance without allocating
/// a decoded verifier graph. This confers no source validity or advancement authority.
#[must_use]
pub fn keeper_advance_network(bytes: &[u8]) -> Option<SccpNetworkV1> {
    super::shape::keeper_network(bytes)
}

fn encode_frame<T: norito::NoritoSerialize>(
    value: &T,
    kind: &'static str,
) -> Result<Vec<u8>, SccpLcError> {
    norito::encode_canonical(value).map_err(|_| SccpLcError::MalformedFrame(kind))
}

fn decode_frame<T>(bytes: &[u8], kind: &'static str) -> Result<T, SccpLcError>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical(bytes).map_err(|_| SccpLcError::MalformedFrame(kind))
}

fn mismatch(expected: SccpNetworkV1, found: SccpNetworkV1) -> Result<(), SccpLcError> {
    if expected == found {
        Ok(())
    } else {
        Err(SccpLcError::NetworkMismatch { expected, found })
    }
}

/// Inbound or void proof (`SubmitSccpInboundMessageV1.proof`, `SubmitSccpOutboundVoidV1.proof`).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "chain", content = "proof", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::proof::SccpSourceProofV1")]
#[allow(
    clippy::large_enum_variant,
    reason = "consensus wire type: Norito encodes `Box<T>` as a length-prefixed owned payload, so boxing a variant would change the canonical frame"
)]
pub enum SccpSourceProofV1 {
    /// Ethereum finality or checkpoint anchor, ancestry, receipt and log selector.
    Ethereum(EthereumSourceProofV1),
    /// BSC vote-attested (or checkpoint-anchored) header chain, receipt and log selector.
    Bsc(BscSourceProofV1),
    /// TON masterchain anchor, shard walk, transaction and external-out message.
    Ton(TonSourceProofV1),
}

/// Light-client advance (`AdvanceSccpLightClientV1.advance`).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "advance", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::proof::SccpLcAdvanceV1")]
pub enum SccpLcAdvanceV1 {
    /// Ethereum finalized `LightClientUpdate`s.
    Ethereum(EthereumLcAdvanceV1),
    /// BSC skipping steps: set-transition checkpoints and finalized blocks with vote
    /// attestations.
    Bsc(BscLcAdvanceV1),
    /// TON key-block hops.
    Ton(TonLcAdvanceV1),
    /// Proof-carrying backwards ancestry ending at a stored checkpoint; records the segment's
    /// first header as a checkpoint (`origin: Backfill`).
    Backfill {
        /// Parent-linked header segment.
        segment: SccpLcSegmentV1,
    },
}

/// Parent-linked header segment of a `Backfill` advance.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "chain", content = "segment", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::proof::SccpLcSegmentV1")]
pub enum SccpLcSegmentV1 {
    /// Ethereum execution header RLPs, ascending, the last one a stored checkpoint.
    Ethereum(EthereumHeaderSegmentV1),
    /// BSC header RLPs, ascending, the last one a stored checkpoint.
    Bsc(BscHeaderSegmentV1),
}

/// One quorum-valid record of equivocation evidence
/// (`ReportSccpLightClientEquivocationV1.{a, b}`).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "chain", content = "record", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::proof::SccpLcEvidenceV1")]
pub enum SccpLcEvidenceV1 {
    /// A signed Ethereum `LightClientUpdate`, optionally with a proven finalized execution
    /// ancestor.
    Ethereum(EthereumLcEvidenceV1),
    /// A BSC vote attestation, optionally with headers ending at its finalized block.
    Bsc(BscLcEvidenceV1),
    /// A TON signed masterchain block.
    Ton(TonLcEvidenceV1),
}

/// Weak-subjectivity bootstrap (`SccpLcBootstrapV1.bytes`).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "chain", content = "bootstrap", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::proof::SccpLcBootstrapDataV1")]
#[allow(
    clippy::large_enum_variant,
    reason = "consensus wire type: Norito encodes `Box<T>` as a length-prefixed owned payload, so boxing a variant would change the canonical frame"
)]
pub enum SccpLcBootstrapDataV1 {
    /// Ethereum `LightClientBootstrap` of a finalized block.
    Ethereum(EthereumNativeLightClientBootstrapV1),
    /// BSC epoch checkpoint with its announced validator set, and the previous checkpoint.
    Bsc(BscLcBootstrapV1),
    /// A TON key block with its config proof.
    Ton(TonLcBootstrapV1),
}

/// Stored consensus set (`SccpLcConsensusSetV1.set_bytes`).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "chain", content = "set", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::proof::SccpLcSetDataV1")]
pub enum SccpLcSetDataV1 {
    /// Ethereum sync committee of one period.
    Ethereum(EthereumSyncCommitteeSetV1),
    /// BSC Parlia validator set with BLS keys and turn length.
    Bsc(BscValidatorSetV1),
    /// TON validator epoch of one key block.
    Ton(TonEpochV1),
}

macro_rules! impl_frame {
    ($ty:ident, $kind:literal, { $($variant:ident => $network:ident),+ $(,)? }) => {
        impl $ty {
            /// Encode the canonical headered Norito frame.
            ///
            /// # Errors
            ///
            /// Returns [`SccpLcError::MalformedFrame`] when encoding fails.
            pub fn to_frame(&self) -> Result<Vec<u8>, SccpLcError> {
                encode_frame(self, $kind)
            }

            /// Decode a canonical headered Norito frame (non-canonical bytes are rejected).
            ///
            /// # Errors
            ///
            /// Returns [`SccpLcError::MalformedFrame`].
            pub fn from_frame(bytes: &[u8]) -> Result<Self, SccpLcError> {
                decode_frame(bytes, $kind)
            }

            /// Fail with [`SccpLcError::NetworkMismatch`] unless the frame is for `network`.
            ///
            /// # Errors
            ///
            /// Returns [`SccpLcError::NetworkMismatch`].
            pub fn expect_network(&self, network: SccpNetworkV1) -> Result<(), SccpLcError> {
                mismatch(network, self.network())
            }

            /// Source chain of the frame.
            pub const fn network(&self) -> SccpNetworkV1 {
                match self {
                    $(Self::$variant { .. } => SccpNetworkV1::$network,)+
                }
            }
        }
    };
}

impl_frame!(SccpSourceProofV1, "source proof", {
    Ethereum => EthereumMainnet,
    Bsc => BscMainnet,
    Ton => TonMainnet,
});
impl_frame!(SccpLcEvidenceV1, "evidence", {
    Ethereum => EthereumMainnet,
    Bsc => BscMainnet,
    Ton => TonMainnet,
});
impl_frame!(SccpLcBootstrapDataV1, "bootstrap", {
    Ethereum => EthereumMainnet,
    Bsc => BscMainnet,
    Ton => TonMainnet,
});
impl_frame!(SccpLcSetDataV1, "consensus set", {
    Ethereum => EthereumMainnet,
    Bsc => BscMainnet,
    Ton => TonMainnet,
});
impl_frame!(SccpLcSegmentV1, "segment", {
    Ethereum => EthereumMainnet,
    Bsc => BscMainnet,
});

impl SccpLcAdvanceV1 {
    /// Encode the canonical headered Norito frame.
    ///
    /// # Errors
    ///
    /// Returns [`SccpLcError::MalformedFrame`] when encoding fails.
    pub fn to_frame(&self) -> Result<Vec<u8>, SccpLcError> {
        encode_frame(self, "advance")
    }

    /// Decode a canonical headered Norito frame (non-canonical bytes are rejected).
    ///
    /// # Errors
    ///
    /// Returns [`SccpLcError::MalformedFrame`].
    pub fn from_frame(bytes: &[u8]) -> Result<Self, SccpLcError> {
        decode_frame(bytes, "advance")
    }

    /// Source chain of the frame.
    pub const fn network(&self) -> SccpNetworkV1 {
        match self {
            Self::Ethereum(_) => SccpNetworkV1::EthereumMainnet,
            Self::Bsc(_) => SccpNetworkV1::BscMainnet,
            Self::Ton(_) => SccpNetworkV1::TonMainnet,
            Self::Backfill { segment } => segment.network(),
        }
    }

    /// Fail with [`SccpLcError::NetworkMismatch`] unless the frame is for `network`.
    ///
    /// # Errors
    ///
    /// Returns [`SccpLcError::NetworkMismatch`].
    pub fn expect_network(&self, network: SccpNetworkV1) -> Result<(), SccpLcError> {
        mismatch(network, self.network())
    }

    /// Wrap the frame for `AdvanceSccpLightClientV1`.
    ///
    /// # Errors
    ///
    /// Returns [`SccpLcError::MalformedFrame`] or [`SccpLcError::FrameTooLarge`].
    pub fn to_bytes(&self) -> Result<SccpLcAdvanceBytesV1, SccpLcError> {
        let frame = self.to_frame()?;
        let len = frame.len();
        SccpLcAdvanceBytesV1::new(frame).map_err(|_| SccpLcError::FrameTooLarge {
            kind: "advance",
            len,
            max: SccpLcAdvanceBytesV1::MAX_BYTES,
        })
    }
}

impl SccpSourceProofV1 {
    /// Wrap the frame for `SubmitSccpInboundMessageV1` or `SubmitSccpOutboundVoidV1`.
    ///
    /// # Errors
    ///
    /// Returns [`SccpLcError::MalformedFrame`] or [`SccpLcError::FrameTooLarge`].
    pub fn to_bytes(&self) -> Result<SccpSourceProofBytesV1, SccpLcError> {
        let frame = self.to_frame()?;
        let len = frame.len();
        SccpSourceProofBytesV1::new(frame).map_err(|_| SccpLcError::FrameTooLarge {
            kind: "source proof",
            len,
            max: SccpSourceProofBytesV1::MAX_BYTES,
        })
    }
}

impl SccpLcEvidenceV1 {
    /// Wrap the frame for `ReportSccpLightClientEquivocationV1`.
    ///
    /// # Errors
    ///
    /// Returns [`SccpLcError::MalformedFrame`] or [`SccpLcError::FrameTooLarge`].
    pub fn to_bytes(&self) -> Result<SccpLcEvidenceBytesV1, SccpLcError> {
        let frame = self.to_frame()?;
        let len = frame.len();
        SccpLcEvidenceBytesV1::new(frame).map_err(|_| SccpLcError::FrameTooLarge {
            kind: "evidence",
            len,
            max: SccpLcEvidenceBytesV1::MAX_BYTES,
        })
    }
}

impl SccpLcBootstrapDataV1 {
    /// Wrap the frame for `InitializeLightClient`.
    ///
    /// # Errors
    ///
    /// Returns [`SccpLcError::MalformedFrame`] when encoding fails.
    pub fn to_bootstrap(&self) -> Result<SccpLcBootstrapV1, SccpLcError> {
        Ok(SccpLcBootstrapV1 {
            network: self.network(),
            bytes: self.to_frame()?,
        })
    }
}

/// Contract that emitted a source event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SccpSourceEmitterV1 {
    /// Ethereum or BSC contract address.
    Evm([u8; 20]),
    /// TON basechain account id.
    Ton([u8; 32]),
}

impl SccpSourceEmitterV1 {
    /// Whether the emitter is the contract of `deployment`.
    #[must_use]
    pub fn matches(&self, deployment: &SccpDeploymentV1) -> bool {
        match (self, deployment) {
            (Self::Evm(address), SccpDeploymentV1::Evm(deployment)) => {
                *address == deployment.address
            }
            (Self::Ton(account), SccpDeploymentV1::Ton(deployment)) => {
                *account == deployment.master_account
            }
            _ => false,
        }
    }
}

/// Source event yielded by a verified proof (§4.12.1 step 4, §4.16).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SccpNormalizedEventV1<Sender = PayloadAccountV1> {
    /// An outbound mint finalized on the destination, authenticated by its source proof.
    Finalized {
        /// Emitting destination contract.
        emitter: SccpSourceEmitterV1,
        /// Canonical outbound message identity.
        message_id: [u8; 32],
        /// Route outbound nonce.
        nonce: u64,
        /// EVM logs carry exact Taira units; TON requires the bound payload preimage.
        amount: Option<u128>,
        /// Original event position.
        locator: SccpSourceLocatorV1,
    },
    /// A burn on the source chain (`SccpTransferToTaira` and equivalents).
    TransferToTaira {
        /// Emitting contract.
        emitter: SccpSourceEmitterV1,
        /// Message id the source contract computed.
        message_id: [u8; 32],
        /// Burning account in the payload's sender codec.
        sender: Sender,
        /// Source per-sender nonce.
        nonce: u64,
        /// `payload_hash` of the payload the event carries.
        payload_hash: [u8; 32],
        /// Position of the event.
        locator: SccpSourceLocatorV1,
    },
    /// Outbound nonces voided on the destination (`SccpVoided` and equivalents).
    Void {
        /// Emitting contract.
        emitter: SccpSourceEmitterV1,
        /// `voidExpired` or `voidFrozen`.
        kind: SccpVoidKindV1,
        /// First voided nonce.
        first_nonce: u64,
        /// Number of consecutive voided nonces.
        count: u64,
        /// Voided message id (`voidExpired`), or zero (`voidFrozen`).
        message_id_or_zero: [u8; 32],
        /// Position of the event.
        locator: SccpSourceLocatorV1,
    },
}

impl<Sender> SccpNormalizedEventV1<Sender> {
    /// Emitting contract.
    #[must_use]
    pub const fn emitter(&self) -> &SccpSourceEmitterV1 {
        match self {
            Self::Finalized { emitter, .. }
            | Self::TransferToTaira { emitter, .. }
            | Self::Void { emitter, .. } => emitter,
        }
    }

    /// Position of the event.
    #[must_use]
    pub const fn locator(&self) -> &SccpSourceLocatorV1 {
        match self {
            Self::Finalized { locator, .. }
            | Self::TransferToTaira { locator, .. }
            | Self::Void { locator, .. } => locator,
        }
    }
}

/// Result of an accepted inbound, finalized-mint or void proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SccpVerifiedProofV1 {
    /// Normalized source event.
    pub event: SccpNormalizedEventV1,
    /// Checkpoints to record idempotently (origin `Proof`).
    pub checkpoints: Vec<SccpLcCheckpointV1>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ethereum_source::EthereumNativeMptProofV1,
        light_client::ethereum::{
            EthereumAncestryV1, EthereumEventSelectorV1, EthereumLogRefV1, EthereumProofAnchorV1,
            EthereumStoredCheckpointRefV1,
        },
        v1::constants::CODEC_EVM_ADDRESS20,
    };
    use iroha_data_model::sccp::deployment::{
        SccpEvmDeploymentV1, SccpTonCodeRefV1, SccpTonDeploymentV1,
    };

    fn proof() -> SccpSourceProofV1 {
        SccpSourceProofV1::Ethereum(EthereumSourceProofV1 {
            anchor: EthereumProofAnchorV1::StoredCheckpoint(EthereumStoredCheckpointRefV1 {
                source_height: 42,
            }),
            ancestry: EthereumAncestryV1::SameBlock,
            event_header: vec![0xc0],
            transaction_index: 3,
            receipt_proof: EthereumNativeMptProofV1 {
                nodes: vec![vec![1, 2, 3]],
            },
            event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 1 }),
        })
    }

    #[test]
    fn frames_roundtrip_canonically_and_name_their_network() {
        let proof = proof();
        let frame = proof.to_frame().expect("encode");
        assert_eq!(SccpSourceProofV1::from_frame(&frame), Ok(proof.clone()));
        assert_eq!(proof.network(), SccpNetworkV1::EthereumMainnet);
        assert_eq!(proof.expect_network(SccpNetworkV1::EthereumMainnet), Ok(()));
        assert_eq!(
            proof.expect_network(SccpNetworkV1::BscMainnet),
            Err(SccpLcError::NetworkMismatch {
                expected: SccpNetworkV1::BscMainnet,
                found: SccpNetworkV1::EthereumMainnet,
            })
        );
        let wrapped = proof.to_bytes().expect("bounded");
        assert_eq!(wrapped.as_bytes(), frame.as_slice());
        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(
            SccpSourceProofV1::from_frame(&trailing),
            Err(SccpLcError::MalformedFrame("source proof"))
        );
        assert_eq!(
            SccpLcAdvanceV1::from_frame(&frame),
            Err(SccpLcError::MalformedFrame("advance"))
        );
        let backfill = SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
                headers: vec![vec![0xc0], vec![0xc1, 0x80]],
            }),
        };
        let bytes = backfill.to_bytes().expect("bounded");
        assert_eq!(
            SccpLcAdvanceV1::from_frame(bytes.as_bytes()),
            Ok(backfill.clone())
        );
        assert_eq!(backfill.network(), SccpNetworkV1::EthereumMainnet);
    }

    #[test]
    fn emitters_match_only_their_deployment_family() {
        let evm = SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [7; 20],
            runtime_code_hash: [1; 32],
        });
        assert!(SccpSourceEmitterV1::Evm([7; 20]).matches(&evm));
        assert!(!SccpSourceEmitterV1::Evm([8; 20]).matches(&evm));
        let code = SccpTonCodeRefV1 {
            hash: [0; 32],
            depth: 1,
        };
        let ton = SccpDeploymentV1::Ton(SccpTonDeploymentV1 {
            master_account: [9; 32],
            minter_code: code,
            wallet_code: code,
            bucket_code: code,
        });
        assert!(SccpSourceEmitterV1::Ton([9; 32]).matches(&ton));
        assert!(!SccpSourceEmitterV1::Evm([9; 20]).matches(&ton));
        assert!(!SccpSourceEmitterV1::Ton([7; 32]).matches(&evm));
    }

    #[test]
    fn normalized_event_accessors_expose_emitter_and_locator() {
        let locator = SccpSourceLocatorV1 {
            source_height: 5,
            block_hash: [6; 32],
            index_in_block: 7,
        };
        let transfer = SccpNormalizedEventV1::TransferToTaira {
            emitter: SccpSourceEmitterV1::Evm([1; 20]),
            message_id: [2; 32],
            sender: PayloadAccountV1::new(CODEC_EVM_ADDRESS20, vec![3; 20]),
            nonce: 4,
            payload_hash: [5; 32],
            locator,
        };
        assert_eq!(transfer.emitter(), &SccpSourceEmitterV1::Evm([1; 20]));
        assert_eq!(transfer.locator(), &locator);
        let void: SccpNormalizedEventV1 = SccpNormalizedEventV1::Void {
            emitter: SccpSourceEmitterV1::Evm([1; 20]),
            kind: SccpVoidKindV1::Frozen,
            first_nonce: 1,
            count: 2,
            message_id_or_zero: [0; 32],
            locator,
        };
        assert_eq!(void.locator().index_in_block, 7);
    }
}

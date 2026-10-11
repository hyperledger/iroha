//! Publicly prepared, source-bound secret frame with no post-extraction allocation.

use super::*;
use crate::beacon::GlobalThresholdBeaconError;
use iroha_allocation::{AllocationRefusal, ChargedBuffer, PrepaidBufferError};
use iroha_crypto::threshold_bls::AdaptiveThresholdBlsSecretShare;

/// Original producer failure, without exposing secret bytes in its display.
#[derive(Debug, Error)]
pub enum GlobalBeaconCredentialEncodeErrorV1 {
    /// A public binding or canonical inventory was rejected before extraction.
    #[error(transparent)]
    Credential(#[from] ConsensusThresholdCredentialErrorV1),
    /// The exact operation pool refused its complete output reservation.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// An admitted physical backing allocation could not be constructed.
    #[error(transparent)]
    Buffer(#[from] PrepaidBufferError),
    /// The existing deterministic secret-component/public-commitment relation failed.
    #[error(transparent)]
    Share(#[from] GlobalThresholdBeaconError),
    /// The canonical serializer or original fixed destination failed.
    #[error(transparent)]
    Encoding(#[from] norito::Error),
    /// A public graph came from a different operation pool.
    #[error("credential public session belongs to another original pool")]
    ForeignOwner,
    /// The shares no longer match the exact prepared public owner or output state.
    #[error("credential prepared source or output state changed")]
    PlanChanged,
}

/// Immutable canonical secret bytes retaining their exact backing and original charge.
///
/// This owner cannot clone, grow or release its backing independently. Only initialized
/// bytes are scrubbed, before the charged buffer deallocates and refunds its pool.
pub struct SecretConsensusThresholdCredentialV1 {
    bytes: ChargedBuffer<u8>,
}
impl SecretConsensusThresholdCredentialV1 {
    /// Borrow the completed canonical frame without transferring secret custody.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Whether this output retains the caller's original operation pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.bytes.belongs_to(budget)
    }
    fn clear(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        self.bytes.truncate(0);
    }
}
impl Drop for SecretConsensusThresholdCredentialV1 {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        tests::observe_scrubbed(self.bytes.as_slice());
    }
}
impl AsRef<[u8]> for SecretConsensusThresholdCredentialV1 {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl std::ops::Deref for SecretConsensusThresholdCredentialV1 {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(NoritoSerialize)]
struct HeaderRef<'a> {
    magic: [u8; 8],
    version: u16,
    slot: u16,
    network_id: NetworkId,
    handle: &'a str,
    revision: u64,
    policy_digest: [u8; 32],
}
#[derive(NoritoSerialize)]
struct ComponentsRef<'a> {
    components: PayloadRef<'a, [[u8; 32]; 3]>,
}
#[derive(NoritoSerialize)]
struct ShareRef<'a> {
    public_session: PayloadRef<'a, GlobalThresholdBeaconKeySessionV1>,
    signer_index: u16,
    components: ComponentsRef<'a>,
}
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::beacon::credential::RuntimeGlobalBeaconSignerCredentialWireV1",
    frame = "iroha.runtime_provider_broker.v1.consensus_threshold.global_beacon_signer_credential"
)]
struct CredentialRef<'a> {
    header: HeaderRef<'a>,
    sessions: CredentialSequence<ShareRef<'a>>,
}

struct Binding {
    session: ValidatedGlobalThresholdBeaconSessionV1,
    seat: u16,
}

/// Complete public output plan, admitted before the caller extracts any private share.
///
/// The bounded inline inventory shares the original authenticated session graph. The
/// provider handle and full canonical output each own actual fixed backing, prepaid
/// in one reservation from that same operation pool. There is no new pool or late growth.
pub struct PreparedGlobalBeaconCredentialV1 {
    network: NetworkId,
    handle: ChargedBuffer<u8>,
    revision: u64,
    digest: [u8; 32],
    bindings: arrayvec::ArrayVec<Binding, MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1>,
    output: SecretConsensusThresholdCredentialV1,
    complete: bool,
}

impl PreparedGlobalBeaconCredentialV1 {
    /// Prepare exact output using only authenticated public information.
    ///
    /// # Errors
    /// Rejects changed inventory/qualification, duplicate sessions, foreign public
    /// owners, invalid seats, excessive frames, or the original admission/allocator cause.
    #[expect(
        single_use_lifetimes,
        reason = "anonymous lifetimes in impl Trait are unstable on the pinned Rust compiler"
    )]
    pub fn new<'a>(
        network: NetworkId,
        handle: &str,
        revision: u64,
        digest: [u8; 32],
        sessions: impl IntoIterator<Item = (&'a ValidatedGlobalThresholdBeaconSessionV1, u16)>,
        budget: &AllocationBudget,
    ) -> Result<Self, GlobalBeaconCredentialEncodeErrorV1> {
        validate_consensus_threshold_provisioning_v1(&network, handle, revision, digest)?;
        let mut bindings =
            arrayvec::ArrayVec::<Binding, MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1>::new();
        for (session, seat) in sessions {
            if !session.belongs_to(budget) {
                return Err(GlobalBeaconCredentialEncodeErrorV1::ForeignOwner);
            }
            if session.record().network_id != network
                || seat == 0
                || seat > session.record().committee_size
            {
                return Err(ConsensusThresholdCredentialErrorV1::Rejected.into());
            }
            bindings
                .try_push(Binding {
                    session: session.clone(),
                    seat,
                })
                .map_err(|_| ConsensusThresholdCredentialErrorV1::Rejected)?;
        }
        validate_consensus_threshold_session_count_v1(bindings.len())?;
        bindings.sort_unstable_by_key(|binding| binding.session.record().session_id);
        if bindings
            .windows(2)
            .any(|pair| pair[0].session.record().session_id == pair[1].session.record().session_id)
        {
            return Err(ConsensusThresholdCredentialErrorV1::Rejected.into());
        }
        let inventory = global_beacon_public_inventory_wire_v1(
            network,
            bindings
                .iter()
                .map(|binding| (binding.session.record(), binding.seat)),
        )?;
        if consensus_threshold_public_inventory_digest_v1(&inventory)? != digest {
            return Err(ConsensusThresholdCredentialErrorV1::Rejected.into());
        }
        let zero = [[0; 32]; 3];
        let shares = bindings
            .iter()
            .map(|binding| ShareRef {
                public_session: PayloadRef(binding.session.record()),
                signer_index: binding.seat,
                components: ComponentsRef {
                    components: PayloadRef(&zero),
                },
            })
            .collect::<arrayvec::ArrayVec<_, MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1>>();
        let shape = CredentialRef {
            header: HeaderRef {
                magic: CONSENSUS_THRESHOLD_CREDENTIAL_MAGIC_V1,
                version: CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1,
                slot: GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1,
                network_id: network,
                handle,
                revision,
                policy_digest: digest,
            },
            sessions: CredentialSequence(shares),
        };
        let size = norito::canonical_frame_len(&shape)?;
        if size == 0 || size > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1 {
            return Err(ConsensusThresholdCredentialErrorV1::Encoding.into());
        }
        drop(shape);
        drop(inventory);
        let bytes = size
            .checked_add(handle.len())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut reservation = budget.try_reserve_bytes(bytes)?;
        let mut handle_buffer = ChargedBuffer::from_reservation(handle.len(), &mut reservation)?;
        handle_buffer
            .append(handle.as_bytes())
            .expect("exact prepared handle capacity");
        let output = SecretConsensusThresholdCredentialV1 {
            bytes: ChargedBuffer::from_reservation(size, &mut reservation)?,
        };
        Ok(Self {
            network,
            handle: handle_buffer,
            revision,
            digest,
            bindings,
            output,
            complete: false,
        })
    }

    /// Return the exact authenticated public policy binding.
    #[must_use]
    pub fn policy_digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Whether both physical output owners retain this original operation pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.handle.belongs_to(budget) && self.output.belongs_to(budget)
    }
    /// Borrow completed bytes for a retained resumable export, never a partial frame.
    #[must_use]
    pub fn encoded(&self) -> Option<&[u8]> {
        self.complete.then(|| self.output.as_slice())
    }

    /// Move a successfully completed secret frame without copying, growing or refunding it.
    ///
    /// # Errors
    /// Returns this unchanged original preparation when no complete frame has been written.
    pub fn into_credential(
        self,
    ) -> Result<SecretConsensusThresholdCredentialV1, (Self, GlobalBeaconCredentialEncodeErrorV1)>
    {
        if !self.complete {
            return Err((self, GlobalBeaconCredentialEncodeErrorV1::PlanChanged));
        }
        Ok(self.output)
    }
}

struct ClearPartial<'a> {
    output: &'a mut SecretConsensusThresholdCredentialV1,
    committed: bool,
}
impl Drop for ClearPartial<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.output.clear();
        }
    }
}

/// Validate the borrowed original shares and fill the already prepared canonical frame.
///
/// No input share is consumed. A failure leaves the same public plan and empty zeroized
/// output for retry. A successful plan is single-use; the frame moves with `into_credential`.
///
/// # Errors
/// Returns exact original share-equation/encoding failures or changed prepared bindings.
pub fn encode_global_beacon_partial_signer_credential_v1<'a, 's>(
    prepared: &'a mut PreparedGlobalBeaconCredentialV1,
    sessions: impl IntoIterator<Item = GlobalBeaconCredentialSourceV1<'s>>,
) -> Result<&'a [u8], GlobalBeaconCredentialEncodeErrorV1> {
    let mut source = arrayvec::ArrayVec::<
        GlobalBeaconCredentialSourceV1<'s>,
        MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1,
    >::new();
    for share in sessions {
        source
            .try_push(share)
            .map_err(|_| GlobalBeaconCredentialEncodeErrorV1::PlanChanged)?;
    }
    if prepared.complete || source.len() != prepared.bindings.len() {
        return Err(GlobalBeaconCredentialEncodeErrorV1::PlanChanged);
    }
    let mut ordered = arrayvec::ArrayVec::<
        GlobalBeaconCredentialSourceV1<'s>,
        MAX_CONSENSUS_THRESHOLD_CREDENTIAL_SESSIONS_V1,
    >::new();
    for binding in &prepared.bindings {
        let mut found = source.iter().copied().filter(|share| {
            share.session.record().session_id == binding.session.record().session_id
        });
        let share = found
            .next()
            .ok_or(GlobalBeaconCredentialEncodeErrorV1::PlanChanged)?;
        if found.next().is_some()
            || share.seat != binding.seat
            || !share.session.ptr_eq(&binding.session)
        {
            return Err(GlobalBeaconCredentialEncodeErrorV1::PlanChanged);
        }
        // Verify the exact canonical components against the existing validated
        // transcript equation. Credential production is not runtime capability
        // import: no newly randomized partial proof is serialized into this wire.
        // The runtime importer separately retains its genuine signing self-test.
        AdaptiveThresholdBlsSecretShare::from_components(
            binding.session.transcript(),
            binding.seat,
            share.components[0],
            share.components[1],
            share.components[2],
        )
        .map_err(GlobalThresholdBeaconError::from)?;
        ordered.push(share);
    }
    let handle =
        std::str::from_utf8(prepared.handle.as_slice()).expect("prepared original UTF-8 handle");
    let wire = CredentialRef {
        header: HeaderRef {
            magic: CONSENSUS_THRESHOLD_CREDENTIAL_MAGIC_V1,
            version: CONSENSUS_THRESHOLD_CREDENTIAL_VERSION_V1,
            slot: GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1,
            network_id: prepared.network,
            handle,
            revision: prepared.revision,
            policy_digest: prepared.digest,
        },
        sessions: CredentialSequence(
            ordered
                .iter()
                .map(|share| ShareRef {
                    public_session: PayloadRef(share.session.record()),
                    signer_index: share.seat,
                    components: ComponentsRef {
                        components: PayloadRef(share.components),
                    },
                })
                .collect(),
        ),
    };
    let mut guard = ClearPartial {
        output: &mut prepared.output,
        committed: false,
    };
    #[cfg(all(test, sumeragi_core_mutation = "HC92"))]
    {
        // Deliberate mutant: allocate another whole secret frame after extraction
        // instead of emitting into the original pre-extraction backing.
        let late_output = Zeroizing::new(norito::encode_canonical(&wire)?);
        guard
            .output
            .bytes
            .append(&late_output)
            .map_err(norito::Error::from)?;
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC92")))]
    norito::core::write_canonical_to_writer(
        &wire,
        &mut crate::beacon::session_owner::ChargedBytesWriter(&mut guard.output.bytes),
    )?;
    if guard.output.bytes.as_slice().len() != guard.output.bytes.capacity() {
        return Err(GlobalBeaconCredentialEncodeErrorV1::PlanChanged);
    }
    guard.committed = true;
    drop(guard);
    prepared.complete = true;
    Ok(prepared.output.as_slice())
}

#[cfg(test)]
mod tests;

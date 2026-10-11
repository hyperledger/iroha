//! Source-owned immutable display and released peer originals. No transition or signing.
use super::*;

/// Original admission DATA. Copying this projection grants no custody or operation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWalletMetadataV1 {
    /// Authenticated installed scheme.
    pub scheme_id: [u8; 32],
    /// Authenticated enrolled incarnation.
    pub wallet_id: [u8; 32],
    /// Exact authenticated asset scope digest.
    pub asset_digest: [u8; 32],
    /// Existing account digest authenticated during original admission.
    pub account_digest: [u8; 32],
    /// Authoritative registered atomic scale.
    pub asset_scale: u32,
    /// Exact admitted canonical AccountId original, never a caller-selected replacement.
    pub account_original: Vec<u8>,
    /// Exact admitted canonical asset scope original.
    pub asset_original: Vec<u8>,
}

/// A copy of one actually released operation's authenticated source-bound output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeReleasedOutputV1 {
    /// Native statement-derived operation identity, not the local request identity.
    pub operation_id: [u8; 32],
    /// Actual released protocol family.
    pub kind: KagemushaWalletOperationKindV1,
    /// Actual released state sequence.
    pub sequence: u128,
    /// Exact original durable output: Payment for Send; Package for other operations.
    pub original: Vec<u8>,
    /// Exact deterministic peer original: Payment3 or Credited4; absent for other families.
    pub peer: Option<(u8, Vec<u8>)>,
}

fn released_output(step: &ReleasedStep) -> Result<NativeReleasedOutputV1, Error> {
    let capsule = &step.frozen.capsule;
    valid(
        step.retained
            .record
            .verify(&step.frozen.credential, capsule),
    )?;
    if step.retained.operation_id != capsule.operation_id
        || step.retained.capsule_digest != valid(capsule.capsule_digest())?
        || step.retained.frame != valid(step.retained.record.to_canonical_bytes())?
        || step.retained.completion_digest != valid(step.retained.record.completion_digest())?
    {
        return Err(Error::WitnessLost("output retained binding"));
    }
    let original = step.retained.record.output.clone();
    let peer = match capsule.kind {
        KagemushaWalletOperationKindV1::Send => Some((3, original.clone())),
        KagemushaWalletOperationKindV1::Receive => {
            let package: KagemushaWalletPackageV1 = archive::decode(&original)?;
            valid(package.verify(&step.frozen.credential))?;
            // Pure wrapping of the verified immutable Receive; no new receipt or signature.
            let credited = valid(KagemushaWalletCreditedV1::from_receive(package))?;
            let bytes = archive::encode(&credited)?;
            if bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
                return Err(Error::Invalid("Credited transport bound"));
            }
            Some((4, bytes))
        }
        _ => None,
    };
    Ok(NativeReleasedOutputV1 {
        operation_id: capsule.operation_id,
        kind: capsule.kind,
        sequence: capsule.statement.sequence,
        original,
        peer,
    })
}

// A selected, unfinished transition still owns the exact admitted account and asset.
// Reading this immutable DATA neither releases its output nor permits a new operation.
fn metadata_custody(
    status: &SlotStatus,
    credential: &KagemushaWalletCredentialV1,
) -> Result<(), Error> {
    let record = match status {
        SlotStatus::Enrollment(record)
        | SlotStatus::Pending(record)
        | SlotStatus::Released(record) => record,
        _ => return Err(Error::Pending),
    };
    let marker = record.marker();
    let body = &credential.body;
    if marker.scheme_id != body.scheme_id
        || marker.wallet_id != body.wallet_id
        || marker.asset_digest != body.asset_digest
        || marker.payment_key != body.payment_key
    {
        return Err(Error::WitnessLost("metadata admitted custody binding"));
    }
    Ok(())
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Copy exact authenticated admission originals under the current live custody bracket.
    /// Pending output does not hide immutable admission DATA needed to resume that request.
    /// # Errors
    /// Unavailable, lost or changed custody, or inconsistent admitted original bindings.
    pub fn metadata(&mut self) -> Result<NativeWalletMetadataV1, Error> {
        let selected = self.status()?;
        let credential = &self.proofs.enrollment;
        metadata_custody(&selected, credential)?;
        let account = crate::kagemusha_wallet_intake_v1::account(
            &self.proofs.account_original,
            &credential.body.account_digest,
        )
        .map_err(|_| Error::Proof("admitted account original"))?;
        let asset: KagemushaWalletAssetScopeV1 = archive::decode(&self.proofs.asset_original)?;
        valid(asset.validate())?;
        if account != self.proofs.account
            || asset != self.proofs.asset
            || asset.asset_digest() != credential.body.asset_digest
            || credential.body.scheme_id != self.scheme_id
            || credential.body.wallet_id != self.wallet_id
        {
            return Err(Error::Proof("admitted metadata binding"));
        }
        let value = NativeWalletMetadataV1 {
            scheme_id: self.scheme_id,
            wallet_id: self.wallet_id,
            asset_digest: asset.asset_digest(),
            account_digest: credential.body.account_digest,
            asset_scale: asset.scale,
            account_original: self.proofs.account_original.clone(),
            asset_original: self.proofs.asset_original.clone(),
        };
        if self.status()? != selected {
            return Err(Error::WitnessLost("metadata custody changed"));
        }
        Ok(value)
    }

    /// Read an actual Native operation without preparing, proving, debiting or signing again.
    /// # Errors
    /// Unknown, pending, archived/lost output, unavailable custody or altered retained binding.
    pub fn released_output(
        &mut self,
        operation: &[u8; 32],
    ) -> Result<NativeReleasedOutputV1, Error> {
        if *operation == [0; 32] {
            return Err(Error::Invalid("output operation identity"));
        }
        let selected = self.status()?;
        let retained = match self.custody.lookup(operation)? {
            Lookup::Retained(value) => value,
            Lookup::SelectedUnsigned { .. } => return Err(Error::Pending),
            Lookup::Archived(_) => return Err(Error::Collected),
            Lookup::DeliveryDataLoss => return Err(Error::WitnessLost("released output lost")),
            Lookup::Unknown => return Err(Error::Invalid("unknown output operation")),
        };
        let step = self.checked_step(retained.capsule_digest)?;
        if step.retained != *retained || step.retained.operation_id != *operation {
            return Err(Error::WitnessLost("released output changed"));
        }
        let value = released_output(&step)?;
        if self.status()? != selected {
            return Err(Error::WitnessLost("output custody changed"));
        }
        Ok(value)
    }

    /// Resolve the durable local retry mapping, then read its actual retained Native operation.
    /// # Errors
    /// No mapping, unfinished preparation, or any failure of `released_output`.
    pub fn released_request(
        &mut self,
        request: &[u8; 32],
    ) -> Result<NativeReleasedOutputV1, Error> {
        let selected = self.status()?;
        let (operation, capsule, kind) = self.prepared_output_mapping(request)?;
        let value = self.released_output(&operation)?;
        let Lookup::Retained(retained) = self.custody.lookup(&operation)? else {
            return Err(Error::WitnessLost("request output disappeared"));
        };
        if retained.capsule_digest != capsule || value.kind != kind || self.status()? != selected {
            return Err(Error::WitnessLost("request output binding"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_state_v1::tests::fixture;

    // Existing canonical DATA fixtures carry stand-in sigma/Omega. This checks immutable
    // completion/receipt binding and projection only, never installed proof qualification.
    fn received() -> ReleasedStep {
        let capsule: KagemushaWalletRecoveryCapsuleV1 = fixture("KagemushaWalletRecoveryCapsuleV1");
        let record: KagemushaWalletCompletionRecordV1 =
            fixture("KagemushaWalletCompletionRecordV1");
        // The standalone credential golden is the Android payer. This Receive capsule
        // and its P-256 receipt belong to the actual receiver carried by Request.
        let vectors: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .expect("vectors");
        let row = vectors["envelopes"]
            .as_array()
            .expect("envelopes")
            .iter()
            .find(|row| row["variant"].as_str() == Some("Request"))
            .expect("Request Envelope");
        let envelope: KagemushaWalletEnvelopeV1 = archive::decode(
            &hex::decode(row["canonical_hex"].as_str().expect("hex")).expect("hex"),
        )
        .expect("canonical Request Envelope");
        let KagemushaWalletMessageV1::Request { request } = envelope.message else {
            panic!("Request fixture family");
        };
        let credential = request.receiver_credential;
        assert_eq!(credential.body.wallet_id, capsule.wallet_id);
        assert_eq!(
            credential.credential_digest(),
            capsule.statement.credential_digest
        );
        record
            .verify(&credential, &capsule)
            .expect("fixture receipt binding");
        ReleasedStep {
            frozen: FrozenTransition {
                credential,
                capsule,
            },
            retained: Retained {
                operation_id: record.operation_id,
                capsule_digest: record.capsule_digest,
                selected_generation: 1,
                completion_digest: record.completion_digest().unwrap(),
                frame: record.to_canonical_bytes().unwrap(),
                record,
            },
        }
    }
    #[test]
    fn receive_peer_projection_uses_exact_verified_retained_package() {
        let step = received();
        let value = released_output(&step).unwrap();
        assert_eq!(value.kind, KagemushaWalletOperationKindV1::Receive);
        assert_eq!(value.operation_id, step.frozen.capsule.operation_id);
        assert_eq!(value.original, step.retained.record.output);
        let (kind, bytes) = value.peer.unwrap();
        assert_eq!(kind, 4);
        let credited: KagemushaWalletCreditedV1 = archive::decode(&bytes).unwrap();
        let KagemushaWalletCreditedEvidenceV1::Receive { package } = credited.evidence else {
            panic!("Receive evidence");
        };
        assert_eq!(
            archive::encode(&package).unwrap(),
            step.retained.record.output
        );
        assert_eq!(
            released_output(&step).unwrap(),
            released_output(&step).unwrap()
        );
    }
    #[test]
    fn no_output_projection_from_replaced_receipt_capsule_or_retained_identity() {
        for mutation in 0..6 {
            let mut step = received();
            match mutation {
                0 => step.retained.operation_id[0] ^= 1,
                1 => step.retained.capsule_digest[0] ^= 1,
                2 => step.retained.frame[0] ^= 1,
                3 => step.retained.completion_digest[0] ^= 1,
                4 => step.retained.record.output[0] ^= 1,
                _ => step.frozen.capsule.operation_id[0] ^= 1,
            }
            assert!(released_output(&step).is_err(), "mutation {mutation}");
        }
    }
    // Marker codec tests only: these do not establish Native startup, proving or phone qualification.
    #[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_core::zk::kagemusha_wallet_advance_v1::MarkerFileV1")]
    struct MetadataMarkerFile {
        version: u16,
        slot: [u8; 32],
        anchor_kind: u8,
        written_boot_id: [u8; 32],
        completion_digest: [u8; 32],
        selected_generation: u128,
        archive_checkpoint: [u8; 32],
        marker: Vec<u8>,
    }

    fn metadata_marker(
        marker: KagemushaWalletMarkerV1,
        completion_digest: [u8; 32],
    ) -> crate::kagemusha_wallet_advance_v1::KagemushaWalletMarkerRecordV1 {
        use crate::kagemusha_wallet_advance_v1::{
            KagemushaWalletMarkerRecordV1, KagemushaWalletSlotIdV1,
        };
        let slot = KagemushaWalletSlotIdV1([0x55; 32]);
        let selected_generation = match marker.state {
            KagemushaWalletMarkerStateV1::Head { .. } if completion_digest == [0; 32] => {
                marker.generation
            }
            KagemushaWalletMarkerStateV1::Head { .. } => marker.generation - 1,
            _ => 0,
        };
        let frame = archive::encode(&MetadataMarkerFile {
            version: 1,
            slot: slot.0,
            anchor_kind: 0,
            written_boot_id: [0x44; 32],
            completion_digest,
            selected_generation,
            archive_checkpoint: [0; 32],
            marker: marker.to_canonical_bytes().expect("canonical marker"),
        })
        .unwrap();
        KagemushaWalletMarkerRecordV1::decode(&frame, &slot, &marker.scheme_id).unwrap()
    }

    fn pending_metadata_marker() -> (SlotStatus, KagemushaWalletCredentialV1) {
        let step = received();
        let body = &step.frozen.credential.body;
        let marker = KagemushaWalletMarkerV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: body.scheme_id,
            asset_digest: body.asset_digest,
            wallet_id: body.wallet_id,
            payment_key: body.payment_key,
            generation: 1,
            state: step.frozen.capsule.head_marker_state().unwrap(),
        };
        (
            SlotStatus::Pending(metadata_marker(marker, [0; 32])),
            step.frozen.credential,
        )
    }

    #[test]
    fn immutable_metadata_is_available_while_exact_admitted_output_is_pending() {
        let (pending, credential) = pending_metadata_marker();
        assert!(metadata_custody(&pending, &credential).is_ok());
        let mut marker = *pending.marker().unwrap().marker();
        marker.generation += 1;
        let released = SlotStatus::Released(metadata_marker(
            marker,
            received().retained.completion_digest,
        ));
        assert!(metadata_custody(&released, &credential).is_ok());
        let enrollment =
            SlotStatus::Enrollment(metadata_marker(fixture("KagemushaWalletMarkerV1"), [0; 32]));
        assert!(metadata_custody(&enrollment, &fixture("KagemushaWalletCredentialV1")).is_ok());
        // The custody bracket still distinguishes Pending from Released and generation changes.
        assert_ne!(pending, released);
    }

    #[test]
    fn pending_metadata_rejects_changed_admitted_scheme_wallet_asset_or_payment_key() {
        let (pending, credential) = pending_metadata_marker();
        for changed in 0..4 {
            let mut other = credential;
            match changed {
                0 => other.body.scheme_id[0] ^= 1,
                1 => other.body.wallet_id[0] ^= 1,
                2 => other.body.asset_digest[0] ^= 1,
                _ => {
                    other.body.payment_key =
                        fixture::<KagemushaWalletCredentialV1>("KagemushaWalletCredentialV1")
                            .body
                            .payment_key
                }
            }
            assert!(
                metadata_custody(&pending, &other).is_err(),
                "binding {changed}"
            );
        }
    }

    #[test]
    fn metadata_remains_unavailable_for_unadmitted_or_terminal_custody() {
        let (pending, credential) = pending_metadata_marker();
        let marker = pending
            .marker()
            .unwrap()
            .marker()
            .successor(KagemushaWalletMarkerStateV1::Terminal {
                reason: KagemushaWalletTerminalReasonV1::CustodyDeleted,
                last_capsule_digest: received().retained.capsule_digest,
            })
            .unwrap();
        for status in [
            SlotStatus::Empty,
            SlotStatus::IntentOnly,
            SlotStatus::SlotAbandoned,
            SlotStatus::Terminal(metadata_marker(marker, [0; 32])),
        ] {
            assert!(metadata_custody(&status, &credential).is_err());
        }
    }
}

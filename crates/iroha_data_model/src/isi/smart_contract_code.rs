//! Dataspace-scoped immutable contract artifacts and address-scoped deployment lifecycle.
use super::*;
use crate::smart_contract::{ContractArtifactId, manifest::ContractManifest};
/// Maximum number of contract artifact bytes carried by one native upload chunk.
pub const SMART_CONTRACT_CODE_CHUNK_BYTES: usize = 65_536;
isi! {
    /// Register a smart contract manifest under its exact dataspace artifact identity.
    ///
    /// The authority must be registered and sign the manifest with its own authorized key. The corresponding
    /// verified bytecode must already be present under the manifest's `code_hash`.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::RegisterSmartContractCode")]
    pub struct RegisterSmartContractCode {
        /// Exact artifact dataspace and hash; the manifest must carry the same hash.
        pub artifact_id: ContractArtifactId,
        /// Manifest containing `code_hash` (required) and `abi_hash`.
        pub manifest: ContractManifest,
    }
}
impl crate::seal::Instruction for RegisterSmartContractCode {}
isi! {
    /// Deactivate a contract instance by removing the `contract_address` binding.
    ///
    /// The authority must be the address's current account lifecycle owner. Parliament-owned or
    /// delegated changes use the certified governance corridor. The address becomes unavailable
    /// immediately, while provenance information is emitted via the data event stream.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::DeactivateContractInstance")]
    pub struct DeactivateContractInstance {
        /// Canonical contract address.
        pub contract_address: crate::smart_contract::ContractAddress,
        /// Exact lifecycle revision required before deactivation.
        pub expected_revision: u64,
        /// Optional audit reason describing why the instance was deactivated.
        #[norito(default)]
        pub reason: Option<String>,
    }
}
impl crate::seal::Instruction for DeactivateContractInstance {}
isi! {
    /// Activate or perform `kaizen`/`改善` on a contract instance by binding
    /// `contract_address` to a `code_hash`.
    ///
    /// The authority must be the address's current account lifecycle owner. A first address binding
    /// is created only by atomic direct deployment or Parliament deployment. Rebinding an active
    /// address is an in-place `kaizen`/`改善` and stages the new artifact's declared hook. Until that
    /// exact hook succeeds, ordinary calls are rejected.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::ActivateContractInstance")]
    pub struct ActivateContractInstance {
        /// Canonical contract address.
        pub contract_address: crate::smart_contract::ContractAddress,
        /// Exact lifecycle revision required before activation or replacement.
        pub expected_revision: u64,
        /// Domain-separated canonical hash of the complete `.to` artifact to bind.
        pub code_hash: iroha_crypto::Hash,
    }
}
impl crate::seal::Instruction for ActivateContractInstance {}
isi! {
    #[norito(decode_from_slice)]
    /// Set or revoke the account owner's consensual Parliament lifecycle delegation.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::SetContractParliamentDelegation")]
    pub struct SetContractParliamentDelegation {
        /// Contract whose delegation changes.
        pub contract_address: crate::smart_contract::ContractAddress,
        /// Exact lifecycle revision required before applying the change.
        pub expected_revision: u64,
        /// Whether Parliament may activate and deactivate this contract.
        pub delegated: bool,
    }
}
impl crate::seal::Instruction for SetContractParliamentDelegation {}
isi! {
    #[norito(decode_from_slice)]
    /// Offer contract lifecycle ownership to an account or Parliament.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::OfferContractOwnership")]
    pub struct OfferContractOwnership {
        /// Contract whose ownership is offered.
        pub contract_address: crate::smart_contract::ContractAddress,
        /// Exact lifecycle revision required before recording the offer.
        pub expected_revision: u64,
        /// Proposed next owner; acceptance is always a separate transition.
        pub new_owner: crate::smart_contract::ContractLifecycleOwnerV1,
    }
}
impl crate::seal::Instruction for OfferContractOwnership {}
isi! {
    #[norito(decode_from_slice)]
    /// Accept an account-targeted contract ownership offer.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::AcceptContractOwnership")]
    pub struct AcceptContractOwnership {
        /// Contract whose ownership is accepted.
        pub contract_address: crate::smart_contract::ContractAddress,
        /// Exact lifecycle revision required before acceptance.
        pub expected_revision: u64,
    }
}
impl crate::seal::Instruction for AcceptContractOwnership {}
isi! {
    #[norito(decode_from_slice)]
    /// Cancel an outstanding contract ownership offer.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::CancelContractOwnershipOffer")]
    pub struct CancelContractOwnershipOffer {
        /// Contract whose outstanding offer is cancelled.
        pub contract_address: crate::smart_contract::ContractAddress,
        /// Exact lifecycle revision required before cancellation.
        pub expected_revision: u64,
    }
}
impl crate::seal::Instruction for CancelContractOwnershipOffer {}
isi! {
    /// Atomically deploy a new contract address and move its stable alias.
    ///
    /// `expected_deploy_nonce` and `expected_previous_contract_address` are compare-and-swap
    /// guards. The executor derives `contract_address` from the authority, nonce, exact
    /// genesis-derived `NetworkId`, and alias dataspace, then either creates the first binding or
    /// replaces the exact active alias target. The authority must already exist, the referenced
    /// verified artifact and manifest must already exist, and the authority must be allowed to
    /// manage the alias. Registered accounts create immutable artifacts with normal fees;
    /// `CanManageSmartContractCode` is reserved for privileged administration. Raw deployment into a
    /// protected namespace is rejected; those addresses can be created only by the certified
    /// Parliament deployment corridor.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::CommitContractDeployment")]
    pub struct CommitContractDeployment {
        /// Exact next deployment nonce expected in the authority's reserved metadata.
        pub expected_deploy_nonce: u64,
        /// Newly derived canonical contract address.
        pub contract_address: crate::smart_contract::ContractAddress,
        /// Domain-separated canonical hash of the complete `.to` artifact to activate.
        pub code_hash: iroha_crypto::Hash,
        /// Stable alias to bind to the new address.
        pub contract_alias: crate::smart_contract::ContractAlias,
        /// Optional alias lease expiry in Unix milliseconds.
        pub lease_expiry_ms: Option<u64>,
        /// Exact previous live alias target expected by the submitter, or `None` for first deploy.
        pub expected_previous_contract_address: Option<crate::smart_contract::ContractAddress>,
    }
}
impl crate::seal::Instruction for CommitContractDeployment {}
isi! {
    /// Register compiled contract bytecode under its exact dataspace artifact identity.
    ///
    /// The bytecode is the full compiled `.to` image including the IVM header. Nodes verify that
    /// `code_hash` equals the domain-separated canonical hash of the complete deployable `.to`
    /// artifact, including the execution header, `CNTR`, literals, and code, before storing. The
    /// authority must be registered; normal transaction fee admission applies.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::RegisterSmartContractBytes")]
    pub struct RegisterSmartContractBytes {
        /// Exact dataspace and domain-separated hash of the complete artifact.
        pub artifact_id: ContractArtifactId,
        /// Full compiled `.to` image (including IVM header).
        pub code: Vec<u8>,
    }
}
impl crate::seal::Instruction for RegisterSmartContractBytes {}
isi! {
    /// Upload one bounded chunk of a compiled smart-contract artifact.
    ///
    /// Chunks are staged under `(authority, artifact_id)` until an explicit
    /// [`FinalizeSmartContractCodeUpload`] verifies and atomically registers the
    /// complete artifact. Chunks may arrive out of order.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::UploadSmartContractCodeChunk")]
    pub struct UploadSmartContractCodeChunk {
        /// Exact dataspace and domain-separated hash of the complete artifact.
        pub artifact_id: ContractArtifactId,
        /// Declared byte length of the complete artifact.
        pub total_size: u64,
        /// Zero-based position of this chunk in the complete artifact.
        pub chunk_index: u32,
        /// Declared total number of chunks in the complete artifact.
        pub chunk_count: u32,
        /// Artifact bytes for `chunk_index`.
        pub chunk: Vec<u8>,
    }
}
impl crate::seal::Instruction for UploadSmartContractCodeChunk {}
isi! {
    /// Verify and atomically register a completely staged smart-contract artifact.
    ///
    /// Failed finalization leaves the pending upload intact so the owner can
    /// retry it or cancel it explicitly.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::FinalizeSmartContractCodeUpload")]
    pub struct FinalizeSmartContractCodeUpload {
        /// Exact dataspace and domain-separated hash of the complete artifact.
        pub artifact_id: ContractArtifactId,
        /// Declared byte length of the complete artifact.
        pub total_size: u64,
        /// Declared total number of chunks in the complete artifact.
        pub chunk_count: u32,
    }
}
impl crate::seal::Instruction for FinalizeSmartContractCodeUpload {}
isi! {
    /// Cancel the authority's pending upload for the exact `artifact_id`.
    ///
    /// Cancellation is owner-scoped and idempotent.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::CancelSmartContractCodeUpload")]
    pub struct CancelSmartContractCodeUpload {
        /// Exact dataspace and domain-separated hash of the complete artifact.
        pub artifact_id: ContractArtifactId,
    }
}
impl crate::seal::Instruction for CancelSmartContractCodeUpload {}
isi! {
    /// Remove compiled contract bytecode from on-chain storage.
    ///
    /// The authority must hold `CanManageSmartContractCode`. Removal succeeds only when no
    /// manifests or active instances reference the supplied `code_hash`. An optional audit reason
    /// surfaces alongside the emitted removal event.
    #[norito_schema(name = "iroha_data_model::isi::smart_contract_code::RemoveSmartContractBytes")]
    pub struct RemoveSmartContractBytes {
        /// Exact dataspace and domain-separated hash of the complete artifact.
        pub artifact_id: ContractArtifactId,
        /// Optional audit reason explaining why the bytecode was removed.
        #[norito(default)]
        pub reason: Option<String>,
    }
}
impl crate::seal::Instruction for RemoveSmartContractBytes {}
fn smart_contract_code_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
impl<'a> norito::core::DecodeFromSlice<'a> for RegisterSmartContractCode {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = smart_contract_code_decode_flags();
        let mut offset = 0usize;
        let artifact_id = super::decode_aos_canonical_field::<ContractArtifactId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let manifest = super::decode_aos_canonical_field::<ContractManifest>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                artifact_id,
                manifest,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for DeactivateContractInstance {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = smart_contract_code_decode_flags();
        let mut offset = 0usize;
        let contract_address = super::decode_aos_canonical_field::<
            crate::smart_contract::ContractAddress,
        >(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let expected_revision = super::decode_aos_canonical_field::<u64>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let reason = if offset < bytes.len() {
            super::decode_aos_canonical_field::<Option<String>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?
        } else {
            None
        };
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                contract_address,
                expected_revision,
                reason,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for ActivateContractInstance {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = smart_contract_code_decode_flags();
        let mut offset = 0usize;
        let contract_address = super::decode_aos_canonical_field::<
            crate::smart_contract::ContractAddress,
        >(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let expected_revision = super::decode_aos_canonical_field::<u64>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let code_hash = super::decode_aos_canonical_field::<iroha_crypto::Hash>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                contract_address,
                expected_revision,
                code_hash,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for CommitContractDeployment {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = smart_contract_code_decode_flags();
        let mut offset = 0usize;
        let expected_deploy_nonce = super::decode_aos_canonical_field::<u64>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let contract_address = super::decode_aos_canonical_field::<
            crate::smart_contract::ContractAddress,
        >(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let code_hash = super::decode_aos_canonical_field::<iroha_crypto::Hash>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let contract_alias = super::decode_aos_canonical_field::<
            crate::smart_contract::ContractAlias,
        >(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let lease_expiry_ms = super::decode_aos_canonical_field::<Option<u64>>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let expected_previous_contract_address =
            super::decode_aos_canonical_field::<Option<crate::smart_contract::ContractAddress>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                expected_deploy_nonce,
                contract_address,
                code_hash,
                contract_alias,
                lease_expiry_ms,
                expected_previous_contract_address,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for RegisterSmartContractBytes {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = smart_contract_code_decode_flags();
        let mut offset = 0usize;
        let artifact_id = super::decode_aos_canonical_field::<ContractArtifactId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let code = super::decode_aos_slice_field::<Vec<u8>>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { artifact_id, code }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for UploadSmartContractCodeChunk {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = smart_contract_code_decode_flags();
        let mut offset = 0usize;
        let artifact_id = super::decode_aos_canonical_field::<ContractArtifactId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let total_size = super::decode_aos_canonical_field::<u64>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let chunk_index = super::decode_aos_canonical_field::<u32>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let chunk_count = super::decode_aos_canonical_field::<u32>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let chunk = super::decode_aos_slice_field::<Vec<u8>>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                artifact_id,
                total_size,
                chunk_index,
                chunk_count,
                chunk,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for FinalizeSmartContractCodeUpload {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = smart_contract_code_decode_flags();
        let mut offset = 0usize;
        let artifact_id = super::decode_aos_canonical_field::<ContractArtifactId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let total_size = super::decode_aos_canonical_field::<u64>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let chunk_count = super::decode_aos_canonical_field::<u32>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                artifact_id,
                total_size,
                chunk_count,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for CancelSmartContractCodeUpload {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = smart_contract_code_decode_flags();
        let mut offset = 0usize;
        let artifact_id = super::decode_aos_canonical_field::<ContractArtifactId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { artifact_id }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for RemoveSmartContractBytes {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = smart_contract_code_decode_flags();
        let mut offset = 0usize;
        let artifact_id = super::decode_aos_canonical_field::<ContractArtifactId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let reason = if offset < bytes.len() {
            super::decode_aos_canonical_field::<Option<String>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?
        } else {
            None
        };
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                artifact_id,
                reason,
            },
            offset,
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{
        assert_registry_decodes_registered_type as assert_registry_decodes, assert_slice_roundtrip,
    };
    use crate::{
        account::AccountId,
        smart_contract::{ContractAddress, ContractAlias},
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_model_base::topology::DataSpaceId;
    use norito::core::DecodeFromSlice;
    fn account() -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![0xD1; 32], Algorithm::Ed25519)
            .expect("derive checked smart-contract-code fixture account keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn contract_address() -> ContractAddress {
        ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &account(),
            7,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address")
    }
    fn code_hash() -> Hash {
        Hash::new(b"contract-code")
    }
    fn contract_alias() -> ContractAlias {
        "payments::universal".parse().expect("contract alias")
    }
    fn manifest() -> ContractManifest {
        ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash()),
            abi_hash: Some(Hash::new(b"abi-policy")),
            compiler_fingerprint: Some("kotodama-1.2.3".to_owned()),
            features_bitmap: Some(0),
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        }
    }
    #[test]
    #[ignore = "explicit maintenance command captures scoped artifact and private-root ISI frames"]
    fn print_scoped_artifact_instruction_identity_frames() {
        use super::super::generated_record_identity_tests::capture;
        let artifact_id = ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash());
        let rows = [
            capture(crate::isi::private_dataspace::RegisterPrivateDataspace {
                alias: "acme".into(),
                expected_ownership_generation: u64::MAX,
                registration: vec![1, 2],
            }),
            capture(crate::isi::private_dataspace::AnchorPrivateDataspace {
                dataspace_id: DataSpaceId::new(u64::MAX),
                anchor: vec![3, 4],
            }),
            capture(RegisterSmartContractCode {
                artifact_id,
                manifest: manifest(),
            }),
            capture(RegisterSmartContractBytes {
                artifact_id,
                code: vec![1, 2, 3],
            }),
            capture(UploadSmartContractCodeChunk {
                artifact_id,
                total_size: 3,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![1, 2, 3],
            }),
            capture(FinalizeSmartContractCodeUpload {
                artifact_id,
                total_size: 3,
                chunk_count: 1,
            }),
            capture(CancelSmartContractCodeUpload { artifact_id }),
            capture(RemoveSmartContractBytes {
                artifact_id,
                reason: Some("superseded".to_owned()),
            }),
        ];
        for row in rows {
            println!(
                "SCOPED_ARTIFACT_ISI_FRAME={}",
                norito::json::to_json(&row).expect("typed artifact capture")
            );
        }
    }
    #[test]
    fn smart_contract_code_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(RegisterSmartContractCode {
            artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
            manifest: manifest(),
        });
        assert_slice_roundtrip(DeactivateContractInstance {
            contract_address: contract_address(),
            expected_revision: 7,
            reason: Some("governance pause".to_owned()),
        });
        assert_slice_roundtrip(ActivateContractInstance {
            contract_address: contract_address(),
            expected_revision: 8,
            code_hash: code_hash(),
        });
        assert_slice_roundtrip(CommitContractDeployment {
            expected_deploy_nonce: 7,
            contract_address: contract_address(),
            code_hash: code_hash(),
            contract_alias: contract_alias(),
            lease_expiry_ms: Some(42_000),
            expected_previous_contract_address: Some(contract_address()),
        });
        assert_slice_roundtrip(RegisterSmartContractBytes {
            artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
            code: vec![0x01, 0x02, 0x03],
        });
        assert_slice_roundtrip(UploadSmartContractCodeChunk {
            artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
            total_size: 3,
            chunk_index: 0,
            chunk_count: 1,
            chunk: vec![0x01, 0x02, 0x03],
        });
        assert_slice_roundtrip(FinalizeSmartContractCodeUpload {
            artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
            total_size: 3,
            chunk_count: 1,
        });
        assert_slice_roundtrip(CancelSmartContractCodeUpload {
            artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
        });
        assert_slice_roundtrip(RemoveSmartContractBytes {
            artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
            reason: Some("superseded".to_owned()),
        });
    }
    #[test]
    fn commit_contract_deployment_rejects_missing_trailing_fields() {
        let encoded = CommitContractDeployment {
            expected_deploy_nonce: 7,
            contract_address: contract_address(),
            code_hash: code_hash(),
            contract_alias: contract_alias(),
            lease_expiry_ms: None,
            expected_previous_contract_address: None,
        }
        .encode();
        let flags = norito::core::default_encode_flags();
        let mut offset = 0usize;
        for _ in 0..4 {
            crate::isi::read_aos_field(&encoded, &mut offset, flags).expect("required field");
        }
        assert!(
            CommitContractDeployment::decode_from_slice(&encoded[..offset]).is_err(),
            "wire payload missing both optional-valued fields must be rejected"
        );
        crate::isi::read_aos_field(&encoded, &mut offset, flags).expect("lease field");
        assert!(
            CommitContractDeployment::decode_from_slice(&encoded[..offset]).is_err(),
            "wire payload missing expected_previous_contract_address must be rejected"
        );
    }
    #[test]
    fn lifecycle_activation_payloads_reject_missing_cas_revision() {
        let flags = norito::core::default_encode_flags();
        let activation = ActivateContractInstance {
            contract_address: contract_address(),
            expected_revision: 8,
            code_hash: code_hash(),
        }
        .encode();
        let mut activation_offset = 0usize;
        crate::isi::read_aos_field(&activation, &mut activation_offset, flags)
            .expect("contract address field");
        assert!(
            ActivateContractInstance::decode_from_slice(&activation[..activation_offset]).is_err(),
            "activation payloads must never infer a missing lifecycle revision"
        );

        let deactivation = DeactivateContractInstance {
            contract_address: contract_address(),
            expected_revision: 9,
            reason: None,
        }
        .encode();
        let mut deactivation_offset = 0usize;
        crate::isi::read_aos_field(&deactivation, &mut deactivation_offset, flags)
            .expect("contract address field");
        assert!(
            DeactivateContractInstance::decode_from_slice(&deactivation[..deactivation_offset])
                .is_err(),
            "deactivation payloads must never infer a missing lifecycle revision"
        );
    }
    #[test]
    fn smart_contract_code_registry_decodes_canonical_wire_ids() {
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<RegisterSmartContractCode>(
                "iroha.instruction.v1::smart_contract_code::RegisterSmartContractCode",
            )
            .register_with_id_slice::<DeactivateContractInstance>(
                "iroha.instruction.v1::smart_contract_code::DeactivateContractInstance",
            )
            .register_with_id_slice::<ActivateContractInstance>(
                "iroha.instruction.v1::smart_contract_code::ActivateContractInstance",
            )
            .register_with_id_slice::<CommitContractDeployment>(
                "iroha.instruction.v1::smart_contract_code::CommitContractDeployment",
            )
            .register_with_id_slice::<RegisterSmartContractBytes>(
                "iroha.instruction.v1::smart_contract_code::RegisterSmartContractBytes",
            )
            .register_with_id_slice::<UploadSmartContractCodeChunk>(
                "iroha.instruction.v1::smart_contract_code::UploadSmartContractCodeChunk",
            )
            .register_with_id_slice::<FinalizeSmartContractCodeUpload>(
                "iroha.instruction.v1::smart_contract_code::FinalizeSmartContractCodeUpload",
            )
            .register_with_id_slice::<CancelSmartContractCodeUpload>(
                "iroha.instruction.v1::smart_contract_code::CancelSmartContractCodeUpload",
            )
            .register_with_id_slice::<RemoveSmartContractBytes>(
                "iroha.instruction.v1::smart_contract_code::RemoveSmartContractBytes",
            );
        assert_registry_decodes(
            &registry,
            RegisterSmartContractCode {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
                manifest: manifest(),
            },
        );
        assert_registry_decodes(
            &registry,
            DeactivateContractInstance {
                contract_address: contract_address(),
                expected_revision: 7,
                reason: Some("governance pause".to_owned()),
            },
        );
        assert_registry_decodes(
            &registry,
            ActivateContractInstance {
                contract_address: contract_address(),
                expected_revision: 8,
                code_hash: code_hash(),
            },
        );
        assert_registry_decodes(
            &registry,
            CommitContractDeployment {
                expected_deploy_nonce: 7,
                contract_address: contract_address(),
                code_hash: code_hash(),
                contract_alias: contract_alias(),
                lease_expiry_ms: Some(42_000),
                expected_previous_contract_address: Some(contract_address()),
            },
        );
        assert_registry_decodes(
            &registry,
            RegisterSmartContractBytes {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
                code: vec![0x01, 0x02, 0x03],
            },
        );
        assert_registry_decodes(
            &registry,
            UploadSmartContractCodeChunk {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
                total_size: 3,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![0x01, 0x02, 0x03],
            },
        );
        assert_registry_decodes(
            &registry,
            FinalizeSmartContractCodeUpload {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
                total_size: 3,
                chunk_count: 1,
            },
        );
        assert_registry_decodes(
            &registry,
            CancelSmartContractCodeUpload {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
            },
        );
        assert_registry_decodes(
            &registry,
            RemoveSmartContractBytes {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
                reason: Some("superseded".to_owned()),
            },
        );
    }
    #[test]
    fn default_instruction_registry_decodes_native_upload_instructions() {
        let registry = crate::instruction_registry::default();
        assert_registry_decodes(
            &registry,
            UploadSmartContractCodeChunk {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
                total_size: 3,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![0x01, 0x02, 0x03],
            },
        );
        assert_registry_decodes(
            &registry,
            FinalizeSmartContractCodeUpload {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
                total_size: 3,
                chunk_count: 1,
            },
        );
        assert_registry_decodes(
            &registry,
            CancelSmartContractCodeUpload {
                artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash()),
            },
        );
        assert_registry_decodes(
            &registry,
            CommitContractDeployment {
                expected_deploy_nonce: 7,
                contract_address: contract_address(),
                code_hash: code_hash(),
                contract_alias: contract_alias(),
                lease_expiry_ms: None,
                expected_previous_contract_address: None,
            },
        );
    }
}

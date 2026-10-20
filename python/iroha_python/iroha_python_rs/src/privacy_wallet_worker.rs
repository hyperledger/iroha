//! Wallet-local privacy witness custody.
//!
//! This module deliberately exposes no operation that returns witness bytes.
//! A caller may import a credential file, inspect or cancel its opaque handle,
//! consume a generic privacy credential exactly once through opcode 5, or use
//! the purpose-separated settlement opcodes 6--9. Generic execution validates
//! canonical public intent and a witness-free transaction plan before entering
//! a native Rust closure. Settlement proving accepts only canonical public
//! Norito objects. Both paths decode owner material only inside Rust, wipe it
//! after terminal use, and return public artifacts only.
use crate::{
    privacy_native_actions::{
        OrchardOrderedContractCallsV1, PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1,
        PrivacyActionTransactionContextV1, PrivacyNativeActionRequestV1, SignedPrivacyActionV1,
        build_signed_orchard_note_action_with_contract_calls_v1,
        build_signed_privacy_native_action_v1, inspect_signed_privacy_native_action_v1,
        inspect_signed_privacy_orchard_note_action_with_contract_calls_v1,
        network_id_from_genesis_hash_bytes, privacy_native_action_capability_for_protocol_v1,
        validate_orchard_ordered_context,
    },
    privacy_wallet_bundle::{
        InspectedPrivacyWalletExecutionBundleV1, PrivacyWalletExecutionBundleManifestV1,
        decode_privacy_wallet_execution_bundle_v1, inspect_privacy_wallet_execution_bundle_v1,
    },
};
use iroha_core_privacy::privacy_engines::atomic_private_settlement::{
    AtomicPrivateSettlementPreparedLegV1, AtomicPrivateSettlementWalletErrorV1,
    AtomicPrivateSettlementWalletInspectionV1, complete_atomic_private_settlement_prepared_leg_v1,
    consume_atomic_private_settlement_wallet_bundle_v1,
    inspect_atomic_private_settlement_wallet_bundle_v1,
};
use iroha_crypto::Algorithm;
use iroha_data_model::{
    nexus::{
        AtomicPrivateSettlementV1, PrivateSettlementAuditCapsuleV1, PrivateSettlementAuditPolicyV1,
        PrivateSettlementProofProfileV1, PrivateSettlementProofStatementV1,
    },
    prelude::AccountId,
    privacy::PrivacyProtocolIdV1,
    transaction::FeePaymentIntent,
};
use iroha_model_base::metadata::Metadata;
use rand_core_06::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    num::NonZeroU32,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_FRAME_BYTES: usize = 34 * 1_024 * 1_024;
pub const MAX_CREDENTIAL_BYTES: u64 = 8_388_608;
pub const MAX_CANONICAL_PUBLIC_INTENT_BYTES: usize = 524_288;
pub const MAX_CANONICAL_EXECUTION_PLAN_BYTES: usize = 2 * 1_024 * 1_024;
pub const MAX_HANDLES: usize = 1_024;
pub const MIN_TTL_MILLIS: u64 = 1_000;
pub const MAX_TTL_MILLIS: u64 = 15 * 60 * 1_000;
const MAGIC: &[u8; 4] = b"IPWW";
const AUTH_TAG_BYTES: usize = 32;
const HANDLE_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const NONCE_BYTES: usize = 32;
const MAX_SIGNER_BYTES: usize = 512;
const MAX_PROTOCOL_BYTES: usize = 96;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_SETTLEMENT_PUBLIC_OBJECT_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_SETTLEMENT_PROOF_BYTES: usize = 8 * 1_024 * 1_024;
const ATOMIC_PRIVATE_SETTLEMENT_PROTOCOL_LABEL_V1: &str = "atomic-private-settlement-v1";
const PUBLIC_INTENT_DIGEST_DOMAIN: &[u8] = b"iroha-privacy-wallet-binding-v1\0";
const COMPILED_PROFILE_DIGEST_DOMAIN: &[u8] = b"iroha-privacy-compiled-profile-binding-v1\0";
const PUBLIC_INTENT_BASE_FIELDS: &[&str] = &[
    "algorithm_id",
    "operation_schema",
    "protocol_id",
    "public_action",
    "selected_features",
    "selected_criteria",
    "signer_wallet_id",
];
const PRIVACY_FEATURE_FIELDS: &[&str] = &[
    "hide_amount",
    "hide_sender",
    "hide_receiver",
    "hide_asset_type",
    "post_quantum",
];
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct WitnessHandle([u8; HANDLE_BYTES]);
impl WitnessHandle {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HANDLE_BYTES]) -> Self {
        Self(bytes)
    }
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HANDLE_BYTES] {
        &self.0
    }
    #[must_use]
    pub fn encode_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn decode_hex(value: &str) -> Result<Self, WorkerError> {
        if value.len() != HANDLE_BYTES * 2
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(WorkerError::InvalidHandle);
        }
        let decoded = hex::decode(value).map_err(|_| WorkerError::InvalidHandle)?;
        let bytes = decoded.try_into().map_err(|_| WorkerError::InvalidHandle)?;
        Ok(Self(bytes))
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct WitnessBinding {
    pub network_id: [u8; DIGEST_BYTES],
    pub signer: String,
    pub protocol: String,
    pub profile_digest: [u8; DIGEST_BYTES],
    pub public_intent_digest: [u8; DIGEST_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    /// Digest of a separately verified signed authority, never the IPC key.
    pub signed_release_authority_digest: [u8; DIGEST_BYTES],
}
impl WitnessBinding {
    pub fn validate(&self) -> Result<(), WorkerError> {
        validate_text("signer", &self.signer, MAX_SIGNER_BYTES)?;
        validate_text("protocol", &self.protocol, MAX_PROTOCOL_BYTES)?;
        validate_worker_protocol(&self.protocol)?;
        if self.network_id == [0; DIGEST_BYTES]
            || (self.protocol != ATOMIC_PRIVATE_SETTLEMENT_PROTOCOL_LABEL_V1
                && self.network_id[DIGEST_BYTES - 1] & 1 != 1)
            || self.profile_digest == [0; DIGEST_BYTES]
            || self.public_intent_digest == [0; DIGEST_BYTES]
            || self.nonce == [0; NONCE_BYTES]
            || self.signed_release_authority_digest == [0; DIGEST_BYTES]
        {
            return Err(WorkerError::InvalidBinding(
                "binding digests and nonce must be non-zero",
            ));
        }
        Ok(())
    }
    #[must_use]
    fn digest(&self) -> [u8; DIGEST_BYTES] {
        let mut encoded = Vec::with_capacity(512);
        encoded.extend_from_slice(&self.network_id);
        put_text(&mut encoded, &self.signer);
        put_text(&mut encoded, &self.protocol);
        encoded.extend_from_slice(&self.profile_digest);
        encoded.extend_from_slice(&self.public_intent_digest);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.signed_release_authority_digest);
        sha256(&encoded)
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct CompiledProfileBinding {
    pub parameter_id: [u8; DIGEST_BYTES],
    pub parameter_digest: [u8; DIGEST_BYTES],
    pub verifier_digest: [u8; DIGEST_BYTES],
    pub statement_schema_digest: [u8; DIGEST_BYTES],
    pub engine_manifest_digest: [u8; DIGEST_BYTES],
}
impl CompiledProfileBinding {
    fn validate(&self) -> Result<(), WorkerError> {
        if [
            self.parameter_id,
            self.parameter_digest,
            self.verifier_digest,
            self.statement_schema_digest,
            self.engine_manifest_digest,
        ]
        .contains(&[0; DIGEST_BYTES])
        {
            return Err(WorkerError::InvalidBinding(
                "compiled profile digests must be non-zero",
            ));
        }
        Ok(())
    }
}
pub fn compiled_profile_digest(
    protocol: &str,
    binding: &CompiledProfileBinding,
) -> Result<[u8; DIGEST_BYTES], WorkerError> {
    validate_text("compiled profile protocol", protocol, MAX_PROTOCOL_BYTES)?;
    validate_worker_protocol(protocol)?;
    binding.validate()?;
    let mut digest = Sha256::new();
    digest.update(COMPILED_PROFILE_DIGEST_DOMAIN);
    let protocol_length = u16::try_from(protocol.len())
        .map_err(|_| WorkerError::InvalidBinding("compiled profile protocol is too long"))?;
    digest.update(protocol_length.to_be_bytes());
    digest.update(protocol.as_bytes());
    digest.update(binding.parameter_id);
    digest.update(binding.parameter_digest);
    digest.update(binding.verifier_digest);
    digest.update(binding.statement_schema_digest);
    digest.update(binding.engine_manifest_digest);
    Ok(digest.finalize().into())
}
#[must_use]
pub fn canonical_public_intent_digest(canonical_public_intent: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(PUBLIC_INTENT_DIGEST_DOMAIN);
    digest.update(canonical_public_intent);
    digest.finalize().into()
}
pub struct ImportRequest {
    pub credential_path: PathBuf,
    pub binding: WitnessBinding,
    pub ttl_millis: u64,
}
#[derive(Clone, Eq, PartialEq)]
pub struct WitnessLease {
    pub handle: WitnessHandle,
    pub expires_at_millis: u64,
    pub manifest: PrivacyWalletExecutionBundleManifestV1,
    pub public_action_digest: [u8; DIGEST_BYTES],
}
struct StoredWitness {
    binding: WitnessBinding,
    binding_digest: [u8; DIGEST_BYTES],
    expires_at_millis: u64,
    inspection: InspectedPrivacyWalletExecutionBundleV1,
    material: Zeroizing<Vec<u8>>,
}
pub struct WitnessVault {
    entries: HashMap<WitnessHandle, StoredWitness>,
    maximum_handles: usize,
}
impl Default for WitnessVault {
    fn default() -> Self {
        Self::new(MAX_HANDLES)
    }
}
impl Drop for WitnessVault {
    fn drop(&mut self) {
        for witness in self.entries.values_mut() {
            witness.material.zeroize();
        }
        self.entries.clear();
    }
}
impl WitnessVault {
    #[must_use]
    pub fn new(maximum_handles: usize) -> Self {
        Self {
            entries: HashMap::new(),
            maximum_handles: maximum_handles.clamp(1, MAX_HANDLES),
        }
    }
    pub fn import_credential(
        &mut self,
        request: ImportRequest,
    ) -> Result<WitnessLease, WorkerError> {
        let now_millis = unix_time_millis()?;
        self.import_credential_at(request, now_millis)
    }
    fn import_credential_at(
        &mut self,
        request: ImportRequest,
        now_millis: u64,
    ) -> Result<WitnessLease, WorkerError> {
        request.binding.validate()?;
        validate_clock_and_ttl(now_millis, request.ttl_millis)?;
        self.purge_expired_at(now_millis);
        if self.entries.len() >= self.maximum_handles {
            return Err(WorkerError::CapacityExceeded);
        }
        let material = read_credential_file(&request.credential_path)?;
        let inspection = inspect_privacy_wallet_execution_bundle_v1(&material)
            .map_err(|_| WorkerError::InvalidExecutionBundle)?;
        if request.binding.signer != inspection.manifest.wallet_id
            || request.binding.protocol != inspection.manifest.protocol_id.canonical_label()
        {
            return Err(WorkerError::WrongBinding);
        }
        let expires_at_millis = now_millis
            .checked_add(request.ttl_millis)
            .ok_or(WorkerError::InvalidTtl)?;
        let handle = self.unique_handle()?;
        let binding_digest = request.binding.digest();
        self.entries.insert(
            handle,
            StoredWitness {
                binding: request.binding,
                binding_digest,
                expires_at_millis,
                inspection: inspection.clone(),
                material,
            },
        );
        Ok(WitnessLease {
            handle,
            expires_at_millis,
            manifest: inspection.manifest,
            public_action_digest: inspection.public_action_digest,
        })
    }
    pub fn inspect(
        &mut self,
        handle: WitnessHandle,
        expected_binding: &WitnessBinding,
    ) -> Result<WitnessLease, WorkerError> {
        let now_millis = unix_time_millis()?;
        self.inspect_at(handle, expected_binding, now_millis)
    }
    fn inspect_at(
        &mut self,
        handle: WitnessHandle,
        expected_binding: &WitnessBinding,
        now_millis: u64,
    ) -> Result<WitnessLease, WorkerError> {
        self.purge_expired_at(now_millis);
        let stored = self
            .entries
            .get(&handle)
            .ok_or(WorkerError::UnknownHandle)?;
        validate_expected_binding(stored, expected_binding)?;
        Ok(WitnessLease {
            handle,
            expires_at_millis: stored.expires_at_millis,
            manifest: stored.inspection.manifest.clone(),
            public_action_digest: stored.inspection.public_action_digest,
        })
    }
    pub fn cancel(
        &mut self,
        handle: WitnessHandle,
        expected_binding: &WitnessBinding,
    ) -> Result<(), WorkerError> {
        let now_millis = unix_time_millis()?;
        self.cancel_at(handle, expected_binding, now_millis)
    }
    fn cancel_at(
        &mut self,
        handle: WitnessHandle,
        expected_binding: &WitnessBinding,
        now_millis: u64,
    ) -> Result<(), WorkerError> {
        self.purge_expired_at(now_millis);
        {
            let stored = self
                .entries
                .get(&handle)
                .ok_or(WorkerError::UnknownHandle)?;
            validate_expected_binding(stored, expected_binding)?;
        }
        let mut removed = self
            .entries
            .remove(&handle)
            .ok_or(WorkerError::UnknownHandle)?;
        removed.material.zeroize();
        Ok(())
    }
    /// Atomically removes a witness and lends it to one native operation.
    ///
    /// Removal happens before `operation` runs. Success, failure, and panic
    /// unwinding all drop a zeroizing buffer, so retrying a handle is
    /// impossible and callback errors never reinsert secret material.
    fn consume_with<T, E>(
        &mut self,
        handle: WitnessHandle,
        expected_binding: &WitnessBinding,
        operation: impl FnOnce(&mut [u8]) -> Result<T, E>,
    ) -> Result<T, ConsumeError<E>> {
        let now_millis = unix_time_millis().map_err(ConsumeError::Custody)?;
        self.consume_with_at(handle, expected_binding, now_millis, operation)
    }
    fn consume_with_at<T, E>(
        &mut self,
        handle: WitnessHandle,
        expected_binding: &WitnessBinding,
        now_millis: u64,
        operation: impl FnOnce(&mut [u8]) -> Result<T, E>,
    ) -> Result<T, ConsumeError<E>> {
        self.purge_expired_at(now_millis);
        {
            let stored = self
                .entries
                .get(&handle)
                .ok_or(ConsumeError::Custody(WorkerError::UnknownHandle))?;
            validate_expected_binding(stored, expected_binding).map_err(ConsumeError::Custody)?;
        }
        let mut stored = self
            .entries
            .remove(&handle)
            .ok_or(ConsumeError::Custody(WorkerError::UnknownHandle))?;
        let result = operation(stored.material.as_mut_slice()).map_err(ConsumeError::Operation);
        stored.material.zeroize();
        result
    }
    pub fn purge_expired(&mut self) -> Result<usize, WorkerError> {
        Ok(self.purge_expired_at(unix_time_millis()?))
    }
    fn purge_expired_at(&mut self, now_millis: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, witness| witness.expires_at_millis > now_millis);
        before - self.entries.len()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    fn unique_handle(&self) -> Result<WitnessHandle, WorkerError> {
        for _ in 0..32 {
            let mut bytes = [0_u8; HANDLE_BYTES];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|_| WorkerError::EntropyUnavailable)?;
            bytes[0] &= 0x7f;
            if bytes != [0; HANDLE_BYTES] {
                let candidate = WitnessHandle(bytes);
                if !self.entries.contains_key(&candidate) {
                    return Ok(candidate);
                }
            }
        }
        Err(WorkerError::EntropyUnavailable)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PrivateSettlementWitnessLeaseV1 {
    handle: WitnessHandle,
    expires_at_millis: u64,
    inspection: AtomicPrivateSettlementWalletInspectionV1,
}

struct StoredPrivateSettlementWitnessV1 {
    binding: WitnessBinding,
    binding_digest: [u8; DIGEST_BYTES],
    expires_at_millis: u64,
    inspection: AtomicPrivateSettlementWalletInspectionV1,
    material: Zeroizing<Vec<u8>>,
}

struct PrivateSettlementWitnessVaultV1 {
    entries: HashMap<WitnessHandle, StoredPrivateSettlementWitnessV1>,
    maximum_handles: usize,
}

impl Default for PrivateSettlementWitnessVaultV1 {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            maximum_handles: MAX_HANDLES,
        }
    }
}

impl Drop for PrivateSettlementWitnessVaultV1 {
    fn drop(&mut self) {
        for witness in self.entries.values_mut() {
            witness.material.zeroize();
        }
        self.entries.clear();
    }
}

impl PrivateSettlementWitnessVaultV1 {
    fn import_credential(
        &mut self,
        request: ImportRequest,
    ) -> Result<PrivateSettlementWitnessLeaseV1, WorkerError> {
        let now_millis = unix_time_millis()?;
        request.binding.validate()?;
        if request.binding.protocol != ATOMIC_PRIVATE_SETTLEMENT_PROTOCOL_LABEL_V1 {
            return Err(WorkerError::UnsupportedProtocol);
        }
        validate_clock_and_ttl(now_millis, request.ttl_millis)?;
        self.purge_expired_at(now_millis);
        if self.entries.len() >= self.maximum_handles {
            return Err(WorkerError::CapacityExceeded);
        }
        let material = read_credential_file(&request.credential_path)?;
        let inspection = inspect_atomic_private_settlement_wallet_bundle_v1(&material)
            .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
        let expected_profile = PrivateSettlementProofProfileV1::IvmPrivateNoteFixed2In3Out.digest();
        if request.binding.signer != inspection.wallet_id
            || !constant_time_eq(
                &request.binding.public_intent_digest,
                inspection.proof_binding_digest.as_ref(),
            )
            || !constant_time_eq(&request.binding.profile_digest, expected_profile.as_ref())
        {
            return Err(WorkerError::WrongBinding);
        }
        let expires_at_millis = now_millis
            .checked_add(request.ttl_millis)
            .ok_or(WorkerError::InvalidTtl)?;
        let handle = self.unique_handle()?;
        let binding_digest = request.binding.digest();
        self.entries.insert(
            handle,
            StoredPrivateSettlementWitnessV1 {
                binding: request.binding,
                binding_digest,
                expires_at_millis,
                inspection: inspection.clone(),
                material,
            },
        );
        Ok(PrivateSettlementWitnessLeaseV1 {
            handle,
            expires_at_millis,
            inspection,
        })
    }

    fn inspect(
        &mut self,
        handle: WitnessHandle,
        expected_binding: &WitnessBinding,
    ) -> Result<PrivateSettlementWitnessLeaseV1, WorkerError> {
        let now_millis = unix_time_millis()?;
        self.purge_expired_at(now_millis);
        let stored = self
            .entries
            .get(&handle)
            .ok_or(WorkerError::UnknownHandle)?;
        validate_private_settlement_expected_binding(stored, expected_binding)?;
        Ok(PrivateSettlementWitnessLeaseV1 {
            handle,
            expires_at_millis: stored.expires_at_millis,
            inspection: stored.inspection.clone(),
        })
    }

    fn cancel(
        &mut self,
        handle: WitnessHandle,
        expected_binding: &WitnessBinding,
    ) -> Result<(), WorkerError> {
        let now_millis = unix_time_millis()?;
        self.purge_expired_at(now_millis);
        {
            let stored = self
                .entries
                .get(&handle)
                .ok_or(WorkerError::UnknownHandle)?;
            validate_private_settlement_expected_binding(stored, expected_binding)?;
        }
        let mut removed = self
            .entries
            .remove(&handle)
            .ok_or(WorkerError::UnknownHandle)?;
        removed.material.zeroize();
        Ok(())
    }

    fn consume_with<T, E>(
        &mut self,
        handle: WitnessHandle,
        expected_binding: &WitnessBinding,
        operation: impl FnOnce(&mut [u8]) -> Result<T, E>,
    ) -> Result<T, ConsumeError<E>> {
        let now_millis = unix_time_millis().map_err(ConsumeError::Custody)?;
        self.purge_expired_at(now_millis);
        {
            let stored = self
                .entries
                .get(&handle)
                .ok_or(ConsumeError::Custody(WorkerError::UnknownHandle))?;
            validate_private_settlement_expected_binding(stored, expected_binding)
                .map_err(ConsumeError::Custody)?;
        }
        let mut stored = self
            .entries
            .remove(&handle)
            .ok_or(ConsumeError::Custody(WorkerError::UnknownHandle))?;
        let result = operation(stored.material.as_mut_slice()).map_err(ConsumeError::Operation);
        stored.material.zeroize();
        result
    }

    fn purge_expired_at(&mut self, now_millis: u64) {
        self.entries
            .retain(|_, witness| witness.expires_at_millis > now_millis);
    }

    fn unique_handle(&self) -> Result<WitnessHandle, WorkerError> {
        for _ in 0..32 {
            let mut bytes = [0_u8; HANDLE_BYTES];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|_| WorkerError::EntropyUnavailable)?;
            bytes[0] |= 0x80;
            let candidate = WitnessHandle(bytes);
            if !self.entries.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(WorkerError::EntropyUnavailable)
    }
}

#[derive(Debug)]
pub enum ConsumeError<E> {
    Custody(WorkerError),
    Operation(E),
}
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum CommandKind {
    Ping = 1,
    Import = 2,
    Inspect = 3,
    Cancel = 4,
    Execute = 5,
    ImportPrivateSettlement = 6,
    InspectPrivateSettlement = 7,
    CancelPrivateSettlement = 8,
    ProvePrivateSettlement = 9,
}
impl TryFrom<u8> for CommandKind {
    type Error = WorkerError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ping),
            2 => Ok(Self::Import),
            3 => Ok(Self::Inspect),
            4 => Ok(Self::Cancel),
            5 => Ok(Self::Execute),
            6 => Ok(Self::ImportPrivateSettlement),
            7 => Ok(Self::InspectPrivateSettlement),
            8 => Ok(Self::CancelPrivateSettlement),
            9 => Ok(Self::ProvePrivateSettlement),
            _ => Err(WorkerError::UnknownCommand),
        }
    }
}
pub struct AuthenticatedFrame {
    pub kind: CommandKind,
    pub sequence: u64,
    pub payload: Vec<u8>,
}
pub fn encode_frame(
    frame: &AuthenticatedFrame,
    auth_key: &[u8; DIGEST_BYTES],
) -> Result<Vec<u8>, WorkerError> {
    if frame.sequence == 0 || frame.payload.len() > MAX_FRAME_BYTES {
        return Err(WorkerError::InvalidFrame);
    }
    let payload_len = u32::try_from(frame.payload.len()).map_err(|_| WorkerError::FrameTooLarge)?;
    let mut authenticated = Vec::with_capacity(18 + frame.payload.len());
    authenticated.extend_from_slice(MAGIC);
    authenticated.push(PROTOCOL_VERSION);
    authenticated.push(frame.kind as u8);
    authenticated.extend_from_slice(&frame.sequence.to_be_bytes());
    authenticated.extend_from_slice(&payload_len.to_be_bytes());
    authenticated.extend_from_slice(&frame.payload);
    let tag = hmac_sha256(auth_key, &authenticated);
    authenticated.extend_from_slice(&tag);
    if authenticated.len() > MAX_FRAME_BYTES {
        return Err(WorkerError::FrameTooLarge);
    }
    let frame_len = u32::try_from(authenticated.len()).map_err(|_| WorkerError::FrameTooLarge)?;
    let mut encoded = Vec::with_capacity(4 + authenticated.len());
    encoded.extend_from_slice(&frame_len.to_be_bytes());
    encoded.extend_from_slice(&authenticated);
    Ok(encoded)
}
pub fn decode_frame(
    encoded: &[u8],
    auth_key: &[u8; DIGEST_BYTES],
) -> Result<AuthenticatedFrame, WorkerError> {
    if encoded.len() < 4 {
        return Err(WorkerError::InvalidFrame);
    }
    let declared = u32::from_be_bytes(
        encoded[0..4]
            .try_into()
            .map_err(|_| WorkerError::InvalidFrame)?,
    ) as usize;
    if declared > MAX_FRAME_BYTES {
        return Err(WorkerError::FrameTooLarge);
    }
    if declared != encoded.len() - 4 || declared < 18 + AUTH_TAG_BYTES {
        return Err(WorkerError::InvalidFrame);
    }
    let authenticated_end = encoded.len() - AUTH_TAG_BYTES;
    let authenticated = &encoded[4..authenticated_end];
    let actual_tag = &encoded[authenticated_end..];
    let expected_tag = hmac_sha256(auth_key, authenticated);
    if !constant_time_eq(actual_tag, &expected_tag) {
        return Err(WorkerError::AuthenticationFailed);
    }
    if &authenticated[0..4] != MAGIC || authenticated[4] != PROTOCOL_VERSION {
        return Err(WorkerError::InvalidFrame);
    }
    let kind = CommandKind::try_from(authenticated[5])?;
    let sequence = u64::from_be_bytes(
        authenticated[6..14]
            .try_into()
            .map_err(|_| WorkerError::InvalidFrame)?,
    );
    if sequence == 0 {
        return Err(WorkerError::InvalidFrame);
    }
    let payload_len = u32::from_be_bytes(
        authenticated[14..18]
            .try_into()
            .map_err(|_| WorkerError::InvalidFrame)?,
    ) as usize;
    if payload_len != authenticated.len() - 18 {
        return Err(WorkerError::InvalidFrame);
    }
    Ok(AuthenticatedFrame {
        kind,
        sequence,
        payload: authenticated[18..].to_vec(),
    })
}
pub fn read_frame(
    reader: &mut impl Read,
    auth_key: &[u8; DIGEST_BYTES],
) -> Result<Option<AuthenticatedFrame>, WorkerError> {
    let mut length = [0_u8; 4];
    match reader.read(&mut length[0..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("one-byte read returned more than one byte"),
        Err(error) => return Err(WorkerError::Io(error.kind())),
    }
    reader
        .read_exact(&mut length[1..])
        .map_err(|error| WorkerError::Io(error.kind()))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(WorkerError::FrameTooLarge);
    }
    if length < 18 + AUTH_TAG_BYTES {
        return Err(WorkerError::InvalidFrame);
    }
    let mut encoded = vec![0_u8; length + 4];
    encoded[0..4].copy_from_slice(&(length as u32).to_be_bytes());
    reader
        .read_exact(&mut encoded[4..])
        .map_err(|error| WorkerError::Io(error.kind()))?;
    decode_frame(&encoded, auth_key).map(Some)
}
pub fn write_frame(
    writer: &mut impl Write,
    frame: &AuthenticatedFrame,
    auth_key: &[u8; DIGEST_BYTES],
) -> Result<(), WorkerError> {
    let encoded = encode_frame(frame, auth_key)?;
    writer
        .write_all(&encoded)
        .map_err(|error| WorkerError::Io(error.kind()))?;
    writer
        .flush()
        .map_err(|error| WorkerError::Io(error.kind()))
}
pub fn run_pipe_session(
    reader: &mut impl Read,
    writer: &mut impl Write,
    auth_key: Zeroizing<[u8; DIGEST_BYTES]>,
) -> Result<(), WorkerError> {
    if auth_key.iter().all(|byte| *byte == 0) {
        return Err(WorkerError::AuthenticationFailed);
    }
    let mut vault = WitnessVault::default();
    let mut private_settlement_vault = PrivateSettlementWitnessVaultV1::default();
    let mut expected_sequence = 1_u64;
    while let Some(frame) = read_frame(reader, &auth_key)? {
        if frame.sequence != expected_sequence {
            return Err(WorkerError::ReplayOrOutOfOrder);
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(WorkerError::ReplayOrOutOfOrder)?;
        let response = match frame.kind {
            CommandKind::ImportPrivateSettlement
            | CommandKind::InspectPrivateSettlement
            | CommandKind::CancelPrivateSettlement
            | CommandKind::ProvePrivateSettlement => dispatch_private_settlement(
                &mut private_settlement_vault,
                frame.kind,
                &frame.payload,
            ),
            _ => dispatch(&mut vault, frame.kind, &frame.payload),
        };
        write_frame(
            writer,
            &AuthenticatedFrame {
                kind: frame.kind,
                sequence: frame.sequence,
                payload: encode_response(response),
            },
            &auth_key,
        )?;
    }
    Ok(())
}
enum CommandResponse {
    Pong,
    Lease(WitnessLease),
    Cancelled,
    SignedAction(Box<SignedActionResponseV1>),
    PrivateSettlementLease(PrivateSettlementWitnessLeaseV1),
    PrivateSettlementProof(Box<PrivateSettlementProofResponseV1>),
    Error(WorkerError),
}
struct SignedActionResponseV1 {
    protocol_id: String,
    operation_schema: String,
    network_id: [u8; DIGEST_BYTES],
    authority: String,
    authority_public_key: String,
    adaptive_signed_transaction: Vec<u8>,
    versioned_signed_transaction: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    transaction_hash: [u8; DIGEST_BYTES],
    transaction_intent_digest: [u8; DIGEST_BYTES],
    statement_digest: [u8; DIGEST_BYTES],
    proof_envelope_hash: [u8; DIGEST_BYTES],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
    adaptive_signed_transaction_bytes: u32,
    submitted_versioned_transaction_bytes: u32,
}
struct ExecuteRequestV1 {
    handle: WitnessHandle,
    binding: WitnessBinding,
    canonical_public_intent: Vec<u8>,
    canonical_execution_plan: Vec<u8>,
}

struct PrivateSettlementProveRequestV1 {
    handle: WitnessHandle,
    binding: WitnessBinding,
    manifest: AtomicPrivateSettlementV1,
    statement: PrivateSettlementProofStatementV1,
    capsule: PrivateSettlementAuditCapsuleV1,
    policy: PrivateSettlementAuditPolicyV1,
    canonical_genesis_hash: [u8; DIGEST_BYTES],
    current_height: u64,
}

struct PrivateSettlementProofResponseV1 {
    wallet_id: String,
    canonical_genesis_hash: [u8; DIGEST_BYTES],
    proof_binding_digest: [u8; DIGEST_BYTES],
    statement_digest: [u8; DIGEST_BYTES],
    capsule_digest: [u8; DIGEST_BYTES],
    audit_plaintext_commitment: [u8; DIGEST_BYTES],
    prepared: AtomicPrivateSettlementPreparedLegV1,
}
struct ValidatedPublicIntentV1 {
    operation_schema: String,
    public_action: Vec<u8>,
    orchard_contract_calls: Option<OrchardOrderedContractCallsV1>,
}
struct ValidatedExecutionPlanV1 {
    context: PrivacyActionTransactionContextV1,
    public_action: Vec<u8>,
    operation_schema: String,
    orchard_contract_calls: Option<OrchardOrderedContractCallsV1>,
}
// Public plan decoding and exact response checks share no witness-bearing values.
include!("privacy_wallet_worker_orchard_ordered.rs");
fn dispatch(vault: &mut WitnessVault, kind: CommandKind, payload: &[u8]) -> CommandResponse {
    let result = match kind {
        CommandKind::Ping => {
            if payload.is_empty() {
                return CommandResponse::Pong;
            }
            Err(WorkerError::InvalidPayload)
        }
        CommandKind::Import => decode_import(payload)
            .and_then(|request| vault.import_credential(request))
            .map(CommandResponse::Lease),
        CommandKind::Inspect => decode_handle_request(payload).and_then(|(handle, binding)| {
            vault.inspect(handle, &binding).map(CommandResponse::Lease)
        }),
        CommandKind::Cancel => decode_handle_request(payload).and_then(|(handle, binding)| {
            vault
                .cancel(handle, &binding)
                .map(|()| CommandResponse::Cancelled)
        }),
        CommandKind::Execute => decode_execute_payload(payload).and_then(|request| {
            execute_native_action_v1(vault, request)
                .map(Box::new)
                .map(CommandResponse::SignedAction)
        }),
        CommandKind::ImportPrivateSettlement
        | CommandKind::InspectPrivateSettlement
        | CommandKind::CancelPrivateSettlement
        | CommandKind::ProvePrivateSettlement => Err(WorkerError::UnknownCommand),
    };
    result.unwrap_or_else(CommandResponse::Error)
}

fn dispatch_private_settlement(
    vault: &mut PrivateSettlementWitnessVaultV1,
    kind: CommandKind,
    payload: &[u8],
) -> CommandResponse {
    let result = match kind {
        CommandKind::ImportPrivateSettlement => decode_import(payload)
            .and_then(|request| vault.import_credential(request))
            .map(CommandResponse::PrivateSettlementLease),
        CommandKind::InspectPrivateSettlement => {
            decode_handle_request(payload).and_then(|(handle, binding)| {
                vault
                    .inspect(handle, &binding)
                    .map(CommandResponse::PrivateSettlementLease)
            })
        }
        CommandKind::CancelPrivateSettlement => {
            decode_handle_request(payload).and_then(|(handle, binding)| {
                vault
                    .cancel(handle, &binding)
                    .map(|()| CommandResponse::Cancelled)
            })
        }
        CommandKind::ProvePrivateSettlement => decode_private_settlement_prove_payload(payload)
            .and_then(|request| {
                prove_private_settlement_v1(vault, request)
                    .map(Box::new)
                    .map(CommandResponse::PrivateSettlementProof)
            }),
        CommandKind::Ping
        | CommandKind::Import
        | CommandKind::Inspect
        | CommandKind::Cancel
        | CommandKind::Execute => Err(WorkerError::UnknownCommand),
    };
    result.unwrap_or_else(CommandResponse::Error)
}
pub fn encode_import_payload(request: &ImportRequest) -> Result<Vec<u8>, WorkerError> {
    request.binding.validate()?;
    let path = request
        .credential_path
        .to_str()
        .ok_or(WorkerError::InvalidCredentialPath)?;
    validate_text("credential path", path, MAX_PATH_BYTES)?;
    let mut payload = Vec::with_capacity(768);
    put_text(&mut payload, path);
    encode_binding(&mut payload, &request.binding);
    payload.extend_from_slice(&request.ttl_millis.to_be_bytes());
    Ok(payload)
}
pub fn encode_handle_payload(
    handle: WitnessHandle,
    binding: &WitnessBinding,
) -> Result<Vec<u8>, WorkerError> {
    binding.validate()?;
    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(handle.as_bytes());
    encode_binding(&mut payload, binding);
    Ok(payload)
}
pub fn encode_execute_payload(
    handle: WitnessHandle,
    binding: &WitnessBinding,
    canonical_public_intent: &[u8],
    canonical_execution_plan: &[u8],
) -> Result<Vec<u8>, WorkerError> {
    binding.validate()?;
    validate_canonical_json_bytes(
        canonical_public_intent,
        MAX_CANONICAL_PUBLIC_INTENT_BYTES,
        WorkerError::InvalidPublicIntent,
    )?;
    validate_canonical_json_bytes(
        canonical_execution_plan,
        MAX_CANONICAL_EXECUTION_PLAN_BYTES,
        WorkerError::InvalidExecutionPlan,
    )?;
    let mut payload =
        Vec::with_capacity(1_024 + canonical_public_intent.len() + canonical_execution_plan.len());
    payload.extend_from_slice(handle.as_bytes());
    encode_binding(&mut payload, binding);
    put_bytes_u32(&mut payload, canonical_public_intent)?;
    put_bytes_u32(&mut payload, canonical_execution_plan)?;
    Ok(payload)
}

/// Encode one witness-free atomic private-settlement proving request.
///
/// Only canonical public objects and an opaque handle cross this IPC boundary;
/// spending secrets and membership paths remain in the owner-only credential.
#[expect(
    clippy::too_many_arguments,
    reason = "the encoder preserves every independent public binding of the fixed proving request"
)]
pub fn encode_private_settlement_prove_payload(
    handle: WitnessHandle,
    binding: &WitnessBinding,
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    capsule: &PrivateSettlementAuditCapsuleV1,
    policy: &PrivateSettlementAuditPolicyV1,
    canonical_genesis_hash: [u8; DIGEST_BYTES],
    current_height: u64,
) -> Result<Vec<u8>, WorkerError> {
    binding.validate()?;
    if binding.protocol != ATOMIC_PRIVATE_SETTLEMENT_PROTOCOL_LABEL_V1 {
        return Err(WorkerError::UnsupportedProtocol);
    }
    let manifest_bytes = norito::encode_canonical(manifest)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let statement_bytes = norito::encode_canonical(statement)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let capsule_bytes = norito::encode_canonical(capsule)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let policy_bytes = norito::encode_canonical(policy)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    for bytes in [
        manifest_bytes.as_slice(),
        statement_bytes.as_slice(),
        capsule_bytes.as_slice(),
        policy_bytes.as_slice(),
    ] {
        if bytes.is_empty() || bytes.len() > MAX_SETTLEMENT_PUBLIC_OBJECT_BYTES {
            return Err(WorkerError::InvalidPayload);
        }
    }
    let mut payload = Vec::with_capacity(
        768 + manifest_bytes.len()
            + statement_bytes.len()
            + capsule_bytes.len()
            + policy_bytes.len(),
    );
    payload.extend_from_slice(handle.as_bytes());
    encode_binding(&mut payload, binding);
    put_bytes_u32(&mut payload, &manifest_bytes)?;
    put_bytes_u32(&mut payload, &statement_bytes)?;
    put_bytes_u32(&mut payload, &capsule_bytes)?;
    put_bytes_u32(&mut payload, &policy_bytes)?;
    payload.extend_from_slice(&canonical_genesis_hash);
    payload.extend_from_slice(&current_height.to_be_bytes());
    if payload.len() > MAX_FRAME_BYTES {
        return Err(WorkerError::FrameTooLarge);
    }
    Ok(payload)
}
fn decode_import(payload: &[u8]) -> Result<ImportRequest, WorkerError> {
    let mut cursor = Cursor::new(payload);
    let path = cursor.text(MAX_PATH_BYTES)?;
    let binding = decode_binding(&mut cursor)?;
    let ttl_millis = cursor.u64()?;
    cursor.finish()?;
    let credential_path = PathBuf::from(path);
    Ok(ImportRequest {
        credential_path,
        binding,
        ttl_millis,
    })
}
fn decode_handle_request(payload: &[u8]) -> Result<(WitnessHandle, WitnessBinding), WorkerError> {
    let mut cursor = Cursor::new(payload);
    let handle = WitnessHandle(cursor.array()?);
    let binding = decode_binding(&mut cursor)?;
    cursor.finish()?;
    Ok((handle, binding))
}
fn decode_execute_payload(payload: &[u8]) -> Result<ExecuteRequestV1, WorkerError> {
    let mut cursor = Cursor::new(payload);
    let handle = WitnessHandle(cursor.array()?);
    let binding = decode_binding(&mut cursor)?;
    let canonical_public_intent = cursor
        .bytes_u32(MAX_CANONICAL_PUBLIC_INTENT_BYTES)?
        .to_vec();
    let canonical_execution_plan = cursor
        .bytes_u32(MAX_CANONICAL_EXECUTION_PLAN_BYTES)?
        .to_vec();
    cursor.finish()?;
    Ok(ExecuteRequestV1 {
        handle,
        binding,
        canonical_public_intent,
        canonical_execution_plan,
    })
}

fn decode_private_settlement_prove_payload(
    payload: &[u8],
) -> Result<PrivateSettlementProveRequestV1, WorkerError> {
    let mut cursor = Cursor::new(payload);
    let handle = WitnessHandle(cursor.array()?);
    let binding = decode_binding(&mut cursor)?;
    if binding.protocol != ATOMIC_PRIVATE_SETTLEMENT_PROTOCOL_LABEL_V1 {
        return Err(WorkerError::UnsupportedProtocol);
    }
    let manifest_bytes = cursor.bytes_u32(MAX_SETTLEMENT_PUBLIC_OBJECT_BYTES)?;
    let statement_bytes = cursor.bytes_u32(MAX_SETTLEMENT_PUBLIC_OBJECT_BYTES)?;
    let capsule_bytes = cursor.bytes_u32(MAX_SETTLEMENT_PUBLIC_OBJECT_BYTES)?;
    let policy_bytes = cursor.bytes_u32(MAX_SETTLEMENT_PUBLIC_OBJECT_BYTES)?;
    let canonical_genesis_hash = cursor.array()?;
    let current_height = cursor.u64()?;
    cursor.finish()?;
    let manifest = norito::decode_canonical::<AtomicPrivateSettlementV1>(manifest_bytes)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let statement = norito::decode_canonical::<PrivateSettlementProofStatementV1>(statement_bytes)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let capsule = norito::decode_canonical::<PrivateSettlementAuditCapsuleV1>(capsule_bytes)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let policy = norito::decode_canonical::<PrivateSettlementAuditPolicyV1>(policy_bytes)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    if norito::encode_canonical(&manifest)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?
        != manifest_bytes
        || norito::encode_canonical(&statement)
            .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?
            != statement_bytes
        || norito::encode_canonical(&capsule)
            .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?
            != capsule_bytes
        || norito::encode_canonical(&policy)
            .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?
            != policy_bytes
    {
        return Err(WorkerError::InvalidPrivateSettlementBundle);
    }
    Ok(PrivateSettlementProveRequestV1 {
        handle,
        binding,
        manifest,
        statement,
        capsule,
        policy,
        canonical_genesis_hash,
        current_height,
    })
}

fn prove_private_settlement_v1(
    vault: &mut PrivateSettlementWitnessVaultV1,
    request: PrivateSettlementProveRequestV1,
) -> Result<PrivateSettlementProofResponseV1, WorkerError> {
    let lease = vault.inspect(request.handle, &request.binding)?;
    validate_private_settlement_public_request(&lease, &request)?;
    let inspection = lease.inspection;
    let wallet_id = inspection.wallet_id.clone();
    let prepared = vault
        .consume_with(request.handle, &request.binding, |material| {
            consume_atomic_private_settlement_wallet_bundle_v1(
                material,
                &wallet_id,
                &request.manifest,
                &request.statement,
                &request.capsule,
                &request.policy,
                request.canonical_genesis_hash,
                request.current_height,
            )
            .map_err(|error| match error {
                AtomicPrivateSettlementWalletErrorV1::Proof(_) => {
                    WorkerError::NativePrivateSettlementProofFailed
                }
                _ => WorkerError::InvalidPrivateSettlementBundle,
            })
        })
        .map_err(|error| match error {
            ConsumeError::Custody(error) | ConsumeError::Operation(error) => error,
        })?;
    let prepared = complete_atomic_private_settlement_prepared_leg_v1(prepared)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    if prepared.statement != request.statement || prepared.audit_capsule != request.capsule {
        return Err(WorkerError::NativePrivateSettlementProofFailed);
    }
    if prepared.proof.is_empty() || prepared.proof.len() > MAX_SETTLEMENT_PROOF_BYTES {
        return Err(WorkerError::NativePrivateSettlementProofFailed);
    }
    Ok(PrivateSettlementProofResponseV1 {
        wallet_id: inspection.wallet_id,
        canonical_genesis_hash: request.canonical_genesis_hash,
        proof_binding_digest: *inspection.proof_binding_digest.as_ref(),
        statement_digest: *inspection.statement_digest.as_ref(),
        capsule_digest: *inspection.capsule_digest.as_ref(),
        audit_plaintext_commitment: *inspection.audit_plaintext_commitment.as_ref(),
        prepared,
    })
}

fn validate_private_settlement_public_request(
    lease: &PrivateSettlementWitnessLeaseV1,
    request: &PrivateSettlementProveRequestV1,
) -> Result<(), WorkerError> {
    request
        .manifest
        .validate()
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    request
        .statement
        .validate()
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    request
        .policy
        .validate()
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    request
        .capsule
        .validate_against(&request.policy)
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let proof_binding_digest = request
        .manifest
        .proof_binding_digest()
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let statement_digest = request
        .statement
        .digest()
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let capsule_digest = request
        .capsule
        .digest()
        .map_err(|_| WorkerError::InvalidPrivateSettlementBundle)?;
    let manifest_genesis_hash = *request.manifest.network_id.as_genesis_hash().as_ref();
    let leg = request
        .manifest
        .legs
        .get(usize::from(request.statement.leg_ordinal))
        .ok_or(WorkerError::InvalidPrivateSettlementBundle)?;
    if request.binding.protocol != ATOMIC_PRIVATE_SETTLEMENT_PROTOCOL_LABEL_V1
        || request.binding.signer != lease.inspection.wallet_id
        || request.binding.network_id != request.canonical_genesis_hash
        || manifest_genesis_hash != request.canonical_genesis_hash
        || !constant_time_eq(
            &request.binding.public_intent_digest,
            proof_binding_digest.as_ref(),
        )
        || !constant_time_eq(
            &request.binding.profile_digest,
            request.statement.profile.digest().as_ref(),
        )
        || lease.inspection.proof_binding_digest != proof_binding_digest
        || lease.inspection.statement_digest != statement_digest
        || lease.inspection.capsule_digest != capsule_digest
        || lease.inspection.audit_plaintext_commitment
            != request.statement.audit_plaintext_commitment
        || request.statement.network_id != request.manifest.network_id
        || request.statement.bundle_id != request.manifest.bundle_id
        || request.statement.authority_context_height != request.manifest.authority_context_height
        || request.statement.expiry_height != request.manifest.expiry_height
        || request.statement.reimbursement_leg_ordinal != request.manifest.reimbursement_leg_ordinal
        || request.statement.fee_intent_digest != request.manifest.fee_intent_digest
        || request.statement.reimbursement_terms_commitment
            != request.manifest.reimbursement_terms_commitment
        || request.statement.route != leg.route
        || request.statement.pool_id != leg.pool_id
        || request.statement.asset_binding_commitment != leg.asset_binding_commitment
        || request.statement.audit_policy_digest != leg.audit_policy_digest
        || request.statement.audit_policy_digest != request.policy.policy_digest
        || request.statement.audit_key_epoch != request.policy.body.key_epoch
        || request.statement.audit_capsule_digest != capsule_digest
        || request.capsule.aad.network_id != request.statement.network_id
        || request.capsule.aad.bundle_id != request.statement.bundle_id
        || request.capsule.aad.leg_ordinal != request.statement.leg_ordinal
        || request.capsule.aad.route != request.statement.route
        || request.capsule.aad.plaintext_commitment != request.statement.audit_plaintext_commitment
        || request.current_height < request.manifest.authority_context_height
        || request.current_height > request.manifest.expiry_height
    {
        return Err(WorkerError::WrongBinding);
    }
    Ok(())
}
fn execute_native_action_v1(
    vault: &mut WitnessVault,
    request: ExecuteRequestV1,
) -> Result<SignedActionResponseV1, WorkerError> {
    let public_intent =
        validate_canonical_public_intent(&request.canonical_public_intent, &request.binding)?;
    let lease = vault.inspect(request.handle, &request.binding)?;
    if lease.manifest.wallet_id != request.binding.signer
        || lease.manifest.protocol_id.canonical_label() != request.binding.protocol
        || lease.manifest.operation_schema != public_intent.operation_schema
    {
        return Err(WorkerError::WrongBinding);
    }
    let public_action_digest =
        crate::privacy_wallet_bundle::privacy_wallet_bundle_public_action_digest_v1(
            &public_intent.public_action,
        );
    if !constant_time_eq(&public_action_digest, &lease.public_action_digest) {
        return Err(WorkerError::PublicActionMismatch);
    }
    let plan = validate_execution_plan_v1(
        &request.canonical_execution_plan,
        &request.binding,
        &lease.manifest,
        &public_intent,
    )?;
    let manifest = lease.manifest;
    let expected_public_action = plan.public_action;
    let network_id = request.binding.network_id;
    let expected_context = plan.context;
    let expected_calls = plan.orchard_contract_calls;
    let signed = vault
        .consume_with(request.handle, &request.binding, |material| {
            let decoded =
                decode_privacy_wallet_execution_bundle_v1(material, &expected_public_action)
                    .map_err(|_| WorkerError::InvalidExecutionBundle)?;
            if decoded.manifest != manifest
                || decoded.request.protocol_id() != manifest.protocol_id
                || decoded.manifest.operation_schema != plan.operation_schema
            {
                return Err(WorkerError::WrongBinding);
            }
            match (decoded.request, expected_calls.as_ref()) {
                (PrivacyNativeActionRequestV1::Orchard(orchard), Some(calls)) => {
                    build_signed_orchard_note_action_with_contract_calls_v1(
                        expected_context.clone(),
                        orchard,
                        calls.clone(),
                        network_id,
                        &decoded.signer_private_key,
                    )
                }
                (_, Some(_)) => return Err(WorkerError::WrongBinding),
                (request, None) => build_signed_privacy_native_action_v1(
                    expected_context.clone(),
                    request,
                    network_id,
                    &decoded.signer_private_key,
                ),
            }
            .map_err(|_| WorkerError::NativeActionFailed)
        })
        .map_err(|error| match error {
            ConsumeError::Custody(error) | ConsumeError::Operation(error) => error,
        })?;
    let response = signed_action_response_v1(signed, &manifest, network_id)?;
    if let Some(calls) = &expected_calls {
        inspect_ordered_response_v1(&response, &expected_context, calls)?;
    }
    Ok(response)
}
fn signed_action_response_v1(
    signed: SignedPrivacyActionV1,
    manifest: &PrivacyWalletExecutionBundleManifestV1,
    network_id: [u8; DIGEST_BYTES],
) -> Result<SignedActionResponseV1, WorkerError> {
    let inspected = inspect_signed_privacy_native_action_v1(signed.signed_transaction())
        .map_err(|_| WorkerError::NativeSelfInspectionFailed)?;
    if inspected.protocol_id() != manifest.protocol_id
        || signed
            .signed_transaction()
            .network_id()
            .map(|id| id.as_bytes())
            != Some(&network_id)
        || inspected.transaction_hash() != signed.transaction_hash()
        || inspected.transaction_intent_digest() != signed.transaction_intent_digest()
        || inspected.statement_digest() != signed.statement_digest()
        || inspected.proof_envelope_hash() != signed.proof_envelope_hash()
        || inspected.statement_bytes() != signed.statement_bytes()
        || inspected.proof_bytes() != signed.proof_bytes()
        || inspected.encoded_proof_envelope_bytes() != signed.encoded_proof_envelope_bytes()
        || inspected.adaptive_signed_transaction_bytes()
            != signed.adaptive_signed_transaction_bytes()
    {
        return Err(WorkerError::NativeSelfInspectionFailed);
    }
    let adaptive_signed_transaction = norito::codec::encode_adaptive(signed.signed_transaction());
    let versioned_signed_transaction = signed
        .encode_versioned()
        .map_err(|_| WorkerError::NativeSelfInspectionFailed)?;
    if adaptive_signed_transaction.len()
        != usize::try_from(signed.adaptive_signed_transaction_bytes())
            .map_err(|_| WorkerError::NativeSelfInspectionFailed)?
        || versioned_signed_transaction.len()
            != usize::try_from(signed.versioned_signed_transaction_bytes())
                .map_err(|_| WorkerError::NativeSelfInspectionFailed)?
        || adaptive_signed_transaction.len() > PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1
        || versioned_signed_transaction.len()
            > PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1
    {
        return Err(WorkerError::NativeSelfInspectionFailed);
    }
    let signature = signed.signed_transaction().signature().0.payload().to_vec();
    let (algorithm, public_key) = manifest
        .public_key
        .try_to_bytes()
        .map_err(|_| WorkerError::NativeSelfInspectionFailed)?;
    if algorithm != Algorithm::Ed25519 || signature.len() != 64 || public_key.len() != 32 {
        return Err(WorkerError::NativeSelfInspectionFailed);
    }
    Ok(SignedActionResponseV1 {
        protocol_id: manifest.protocol_id.canonical_label().to_owned(),
        operation_schema: manifest.operation_schema.to_owned(),
        network_id,
        authority: manifest.authority.to_string(),
        authority_public_key: manifest.public_key.to_string(),
        adaptive_signed_transaction,
        versioned_signed_transaction,
        signature,
        public_key: public_key.to_vec(),
        transaction_hash: signed.transaction_hash(),
        transaction_intent_digest: signed.transaction_intent_digest(),
        statement_digest: signed.statement_digest(),
        proof_envelope_hash: signed.proof_envelope_hash(),
        statement_bytes: signed.statement_bytes(),
        proof_bytes: signed.proof_bytes(),
        encoded_proof_envelope_bytes: signed.encoded_proof_envelope_bytes(),
        adaptive_signed_transaction_bytes: signed.adaptive_signed_transaction_bytes(),
        submitted_versioned_transaction_bytes: signed.versioned_signed_transaction_bytes(),
    })
}
fn encode_binding(output: &mut Vec<u8>, binding: &WitnessBinding) {
    output.extend_from_slice(&binding.network_id);
    put_text(output, &binding.signer);
    put_text(output, &binding.protocol);
    output.extend_from_slice(&binding.profile_digest);
    output.extend_from_slice(&binding.public_intent_digest);
    output.extend_from_slice(&binding.nonce);
    output.extend_from_slice(&binding.signed_release_authority_digest);
}
fn decode_binding(cursor: &mut Cursor<'_>) -> Result<WitnessBinding, WorkerError> {
    let binding = WitnessBinding {
        network_id: cursor.array()?,
        signer: cursor.text(MAX_SIGNER_BYTES)?,
        protocol: cursor.text(MAX_PROTOCOL_BYTES)?,
        profile_digest: cursor.array()?,
        public_intent_digest: cursor.array()?,
        nonce: cursor.array()?,
        signed_release_authority_digest: cursor.array()?,
    };
    binding.validate()?;
    Ok(binding)
}
fn encode_response(response: CommandResponse) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    match response {
        CommandResponse::Pong => output.push(0),
        CommandResponse::Lease(lease) => {
            output.push(1);
            output.extend_from_slice(lease.handle.as_bytes());
            output.extend_from_slice(&lease.expires_at_millis.to_be_bytes());
            output.push(lease.manifest.schema_version);
            put_text(&mut output, &lease.manifest.wallet_id);
            put_text(&mut output, &lease.manifest.authority.to_string());
            put_text(&mut output, &lease.manifest.public_key.to_string());
            put_text(&mut output, lease.manifest.protocol_id.canonical_label());
            put_text(&mut output, lease.manifest.operation_schema);
        }
        CommandResponse::Cancelled => output.push(2),
        CommandResponse::SignedAction(signed) => {
            output.push(3);
            put_text(&mut output, &signed.protocol_id);
            put_text(&mut output, &signed.operation_schema);
            output.extend_from_slice(&signed.network_id);
            put_text(&mut output, &signed.authority);
            put_text(&mut output, &signed.authority_public_key);
            put_bytes_u32(&mut output, &signed.adaptive_signed_transaction)
                .expect("bounded native signed action");
            put_bytes_u32(&mut output, &signed.versioned_signed_transaction)
                .expect("bounded native signed action");
            put_bytes_u16(&mut output, &signed.signature).expect("bounded native signature");
            put_bytes_u16(&mut output, &signed.public_key).expect("bounded native public key");
            output.extend_from_slice(&signed.transaction_hash);
            output.extend_from_slice(&signed.transaction_intent_digest);
            output.extend_from_slice(&signed.statement_digest);
            output.extend_from_slice(&signed.proof_envelope_hash);
            output.extend_from_slice(&signed.statement_bytes.to_be_bytes());
            output.extend_from_slice(&signed.proof_bytes.to_be_bytes());
            output.extend_from_slice(&signed.encoded_proof_envelope_bytes.to_be_bytes());
            output.extend_from_slice(&signed.adaptive_signed_transaction_bytes.to_be_bytes());
            output.extend_from_slice(&signed.submitted_versioned_transaction_bytes.to_be_bytes());
        }
        CommandResponse::PrivateSettlementLease(lease) => {
            output.push(4);
            output.extend_from_slice(lease.handle.as_bytes());
            output.extend_from_slice(&lease.expires_at_millis.to_be_bytes());
            put_text(&mut output, &lease.inspection.wallet_id);
            output.extend_from_slice(lease.inspection.proof_binding_digest.as_ref());
            output.extend_from_slice(lease.inspection.statement_digest.as_ref());
            output.extend_from_slice(lease.inspection.capsule_digest.as_ref());
            output.extend_from_slice(lease.inspection.audit_plaintext_commitment.as_ref());
        }
        CommandResponse::PrivateSettlementProof(response) => {
            output.push(5);
            put_text(&mut output, &response.wallet_id);
            output.extend_from_slice(&response.canonical_genesis_hash);
            output.extend_from_slice(&response.proof_binding_digest);
            output.extend_from_slice(&response.statement_digest);
            output.extend_from_slice(&response.capsule_digest);
            output.extend_from_slice(&response.audit_plaintext_commitment);
            let statement = norito::encode_canonical(&response.prepared.statement)
                .expect("validated private-settlement statement");
            let capsule = norito::encode_canonical(&response.prepared.audit_capsule)
                .expect("validated private-settlement audit capsule");
            let delta = norito::encode_canonical(&response.prepared.delta)
                .expect("validated private-settlement delta");
            put_bytes_u32(&mut output, &statement).expect("bounded private-settlement statement");
            put_bytes_u32(&mut output, &response.prepared.proof)
                .expect("bounded private-settlement proof");
            put_bytes_u32(&mut output, &delta).expect("bounded private-settlement delta");
            put_bytes_u32(&mut output, &capsule).expect("bounded private-settlement audit capsule");
        }
        CommandResponse::Error(error) => {
            output.push(255);
            output.extend_from_slice(&error.code().to_be_bytes());
            let message = error.message();
            put_text(&mut output, message);
        }
    }
    output
}
struct Cursor<'a> {
    source: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    const fn new(source: &'a [u8]) -> Self {
        Self { source, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], WorkerError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(WorkerError::InvalidPayload)?;
        let value = self
            .source
            .get(self.offset..end)
            .ok_or(WorkerError::InvalidPayload)?;
        self.offset = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], WorkerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WorkerError::InvalidPayload)
    }
    fn u16(&mut self) -> Result<u16, WorkerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, WorkerError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, WorkerError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn text(&mut self, maximum_bytes: usize) -> Result<String, WorkerError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum_bytes {
            return Err(WorkerError::InvalidPayload);
        }
        let value =
            std::str::from_utf8(self.take(length)?).map_err(|_| WorkerError::InvalidPayload)?;
        validate_text("payload text", value, maximum_bytes)?;
        Ok(value.to_owned())
    }
    fn bytes_u32(&mut self, maximum_bytes: usize) -> Result<&'a [u8], WorkerError> {
        let length = usize::try_from(self.u32()?).map_err(|_| WorkerError::InvalidPayload)?;
        if length == 0 || length > maximum_bytes {
            return Err(WorkerError::InvalidPayload);
        }
        self.take(length)
    }
    fn finish(self) -> Result<(), WorkerError> {
        if self.offset == self.source.len() {
            Ok(())
        } else {
            Err(WorkerError::InvalidPayload)
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerError {
    AuthenticationFailed,
    CapacityExceeded,
    ClockUnavailable,
    CredentialChangedDuringImport,
    CredentialFileEmpty,
    CredentialFileInsecure,
    CredentialFileTooLarge,
    EntropyUnavailable,
    Expired,
    FrameTooLarge,
    InvalidBinding(&'static str),
    InvalidCredentialPath,
    InvalidExecutionBundle,
    InvalidExecutionPlan,
    InvalidPrivateSettlementBundle,
    InvalidFrame,
    InvalidHandle,
    InvalidPayload,
    InvalidPublicIntent,
    InvalidTtl,
    Io(io::ErrorKind),
    NativeActionFailed,
    NativePrivateSettlementProofFailed,
    NativeSelfInspectionFailed,
    PublicActionMismatch,
    PublicIntentDigestMismatch,
    ReplayOrOutOfOrder,
    UnknownCommand,
    UnknownHandle,
    UnsupportedProtocol,
    WrongBinding,
}
impl WorkerError {
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::AuthenticationFailed => 1,
            Self::CapacityExceeded => 2,
            Self::ClockUnavailable => 24,
            Self::CredentialChangedDuringImport => 3,
            Self::CredentialFileEmpty => 4,
            Self::CredentialFileInsecure => 5,
            Self::CredentialFileTooLarge => 6,
            Self::EntropyUnavailable => 7,
            Self::Expired => 8,
            Self::FrameTooLarge => 9,
            Self::InvalidBinding(_) => 10,
            Self::InvalidCredentialPath => 11,
            Self::InvalidExecutionBundle => 25,
            Self::InvalidExecutionPlan => 26,
            Self::InvalidPrivateSettlementBundle => 30,
            Self::InvalidFrame => 12,
            Self::InvalidHandle => 13,
            Self::InvalidPayload => 14,
            Self::InvalidPublicIntent => 23,
            Self::NativeActionFailed => 27,
            Self::NativePrivateSettlementProofFailed => 31,
            Self::NativeSelfInspectionFailed => 28,
            Self::PublicActionMismatch => 29,
            Self::InvalidTtl => 15,
            Self::Io(_) => 16,
            Self::PublicIntentDigestMismatch => 17,
            Self::ReplayOrOutOfOrder => 18,
            Self::UnknownCommand => 19,
            Self::UnknownHandle => 20,
            Self::UnsupportedProtocol => 21,
            Self::WrongBinding => 22,
        }
    }
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "IPC authentication failed",
            Self::CapacityExceeded => "witness handle capacity exceeded",
            Self::ClockUnavailable => "native system clock is unavailable",
            Self::CredentialChangedDuringImport => "credential file changed during import",
            Self::CredentialFileEmpty => "credential file is empty",
            Self::CredentialFileInsecure => "credential file permissions are not owner-only",
            Self::CredentialFileTooLarge => "credential file exceeds the bounded size",
            Self::EntropyUnavailable => "secure operating-system entropy is unavailable",
            Self::Expired => "witness handle expired",
            Self::FrameTooLarge => "IPC frame exceeds the bounded size",
            Self::InvalidBinding(message) => message,
            Self::InvalidCredentialPath => "credential path is invalid",
            Self::InvalidExecutionBundle => "owner-only privacy execution bundle is invalid",
            Self::InvalidExecutionPlan => "witness-free privacy execution plan is invalid",
            Self::InvalidPrivateSettlementBundle => {
                "owner-only atomic private-settlement bundle is invalid"
            }
            Self::InvalidFrame => "IPC frame is non-canonical",
            Self::InvalidHandle => "witness handle is invalid",
            Self::InvalidPayload => "IPC payload is non-canonical",
            Self::InvalidPublicIntent => "public intent bytes are not canonical typed JSON",
            Self::NativeActionFailed => "native privacy action construction failed",
            Self::NativePrivateSettlementProofFailed => {
                "native atomic private-settlement proof failed"
            }
            Self::NativeSelfInspectionFailed => {
                "native signed privacy action self-inspection failed"
            }
            Self::PublicActionMismatch => {
                "public action does not match the owner-only execution bundle"
            }
            Self::InvalidTtl => "witness handle TTL is invalid",
            Self::Io(_) => "local IPC or credential file I/O failed",
            Self::PublicIntentDigestMismatch => {
                "public intent bytes do not match the witness binding digest"
            }
            Self::ReplayOrOutOfOrder => "IPC sequence replay or reordering detected",
            Self::UnknownCommand => "IPC command is unknown",
            Self::UnknownHandle => "witness handle is unknown",
            Self::UnsupportedProtocol => "privacy protocol is unsupported",
            Self::WrongBinding => "witness handle binding does not match the public intent",
        }
    }
}
fn unix_time_millis() -> Result<u64, WorkerError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WorkerError::ClockUnavailable)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| WorkerError::ClockUnavailable)
}
fn validate_clock_and_ttl(now_millis: u64, ttl_millis: u64) -> Result<(), WorkerError> {
    if now_millis == 0
        || !(MIN_TTL_MILLIS..=MAX_TTL_MILLIS).contains(&ttl_millis)
        || now_millis.checked_add(ttl_millis).is_none()
    {
        return Err(WorkerError::InvalidTtl);
    }
    Ok(())
}
fn validate_expected_binding(
    stored: &StoredWitness,
    expected: &WitnessBinding,
) -> Result<(), WorkerError> {
    expected.validate()?;
    let expected_digest = expected.digest();
    if !constant_time_eq(&stored.binding_digest, &expected_digest) || stored.binding != *expected {
        return Err(WorkerError::WrongBinding);
    }
    Ok(())
}

fn validate_private_settlement_expected_binding(
    stored: &StoredPrivateSettlementWitnessV1,
    expected: &WitnessBinding,
) -> Result<(), WorkerError> {
    expected.validate()?;
    if expected.protocol != ATOMIC_PRIVATE_SETTLEMENT_PROTOCOL_LABEL_V1 {
        return Err(WorkerError::UnsupportedProtocol);
    }
    let expected_digest = expected.digest();
    if !constant_time_eq(&stored.binding_digest, &expected_digest) || stored.binding != *expected {
        return Err(WorkerError::WrongBinding);
    }
    Ok(())
}

fn validate_worker_protocol(protocol: &str) -> Result<(), WorkerError> {
    if protocol == ATOMIC_PRIVATE_SETTLEMENT_PROTOCOL_LABEL_V1 {
        return Ok(());
    }
    retained_protocol(protocol).map(|_| ())
}
fn retained_protocol(protocol: &str) -> Result<PrivacyProtocolIdV1, WorkerError> {
    let protocol_id = PrivacyProtocolIdV1::from_canonical_label(protocol)
        .ok_or(WorkerError::UnsupportedProtocol)?;
    match protocol_id {
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1
        | PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1
        | PrivacyProtocolIdV1::VeRangeTransparentRangeV1
        | PrivacyProtocolIdV1::IrohaZkAmsV1
        | PrivacyProtocolIdV1::VegaExistingCredentialZkV1
        | PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1
        | PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1
        | PrivacyProtocolIdV1::OrchardHalo2ActionsV1
        | PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1
        | PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1
        | PrivacyProtocolIdV1::PqMaspStarkV1 => {}
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1 => {
            return Err(WorkerError::UnsupportedProtocol);
        }
    }
    privacy_native_action_capability_for_protocol_v1(protocol_id)
        .ok_or(WorkerError::UnsupportedProtocol)?;
    Ok(protocol_id)
}
fn feature_bit(field: &str) -> Option<u8> {
    Some(match field {
        "hide_amount" => 1,
        "hide_sender" => 1 << 1,
        "hide_receiver" => 1 << 2,
        "hide_asset_type" => 1 << 3,
        "post_quantum" => 1 << 4,
        _ => return None,
    })
}
fn validate_feature_contract(
    value: Option<&norito::json::Value>,
    feature_mask: u8,
) -> Result<(), WorkerError> {
    let Some(norito::json::Value::Object(flags)) = value else {
        return Err(WorkerError::InvalidPublicIntent);
    };
    if flags.len() != PRIVACY_FEATURE_FIELDS.len() {
        return Err(WorkerError::InvalidPublicIntent);
    }
    for field in PRIVACY_FEATURE_FIELDS {
        let expected =
            feature_mask & feature_bit(field).ok_or(WorkerError::InvalidPublicIntent)? != 0;
        if flags.get(*field).and_then(norito::json::Value::as_bool) != Some(expected) {
            return Err(WorkerError::InvalidPublicIntent);
        }
    }
    Ok(())
}
/// Validate the public transport representation before the single-use native
/// bundle decoder and action dispatcher enter `WitnessVault::consume_with`.
fn validate_canonical_public_intent(
    canonical_public_intent: &[u8],
    binding: &WitnessBinding,
) -> Result<ValidatedPublicIntentV1, WorkerError> {
    let value = validate_canonical_json_bytes(
        canonical_public_intent,
        MAX_CANONICAL_PUBLIC_INTENT_BYTES,
        WorkerError::InvalidPublicIntent,
    )?;
    let Some(object) = value.as_object() else {
        return Err(WorkerError::InvalidPublicIntent);
    };
    let protocol_id = retained_protocol(&binding.protocol)?;
    let capability = privacy_native_action_capability_for_protocol_v1(protocol_id)
        .ok_or(WorkerError::UnsupportedProtocol)?;
    if object.len()
        != PUBLIC_INTENT_BASE_FIELDS.len()
            + usize::from(object.contains_key("orchard_contract_calls"))
        || !PUBLIC_INTENT_BASE_FIELDS
            .iter()
            .all(|field| object.contains_key(*field))
        || object
            .get("algorithm_id")
            .and_then(norito::json::Value::as_str)
            != Some(binding.protocol.as_str())
        || object
            .get("protocol_id")
            .and_then(norito::json::Value::as_str)
            != Some(binding.protocol.as_str())
        || object
            .get("signer_wallet_id")
            .and_then(norito::json::Value::as_str)
            != Some(binding.signer.as_str())
        || object
            .get("operation_schema")
            .and_then(norito::json::Value::as_str)
            != Some(capability.operation_schema)
    {
        return Err(WorkerError::InvalidPublicIntent);
    }
    validate_feature_contract(
        object.get("selected_features"),
        capability.privacy_feature_mask,
    )?;
    validate_feature_contract(
        object.get("selected_criteria"),
        capability.privacy_feature_mask,
    )?;
    let public_action = object
        .get("public_action")
        .ok_or(WorkerError::InvalidPublicIntent)?;
    if public_action
        .as_object()
        .is_none_or(norito::json::Map::is_empty)
    {
        return Err(WorkerError::InvalidPublicIntent);
    }
    let public_action = norito::json::to_json(public_action)
        .map_err(|_| WorkerError::InvalidPublicIntent)?
        .into_bytes();
    let actual_digest = canonical_public_intent_digest(canonical_public_intent);
    if !constant_time_eq(&actual_digest, &binding.public_intent_digest) {
        return Err(WorkerError::PublicIntentDigestMismatch);
    }
    // This object is part of the canonical public-intent digest already pinned to the handle.
    let orchard_contract_calls = validate_orchard_contract_calls_v1(
        object.get("orchard_contract_calls"),
        &binding.protocol,
        WorkerError::InvalidPublicIntent,
    )?;
    Ok(ValidatedPublicIntentV1 {
        operation_schema: capability.operation_schema.to_owned(),
        public_action,
        orchard_contract_calls,
    })
}
fn validate_canonical_json_bytes(
    bytes: &[u8],
    maximum: usize,
    error: WorkerError,
) -> Result<norito::json::Value, WorkerError> {
    if bytes.is_empty() || bytes.len() > maximum || bytes.contains(&0) {
        return Err(error);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| error)?;
    let value = norito::json::parse_value(text).map_err(|_| error)?;
    let canonical = norito::json::to_json(&value).map_err(|_| error)?;
    if canonical.as_bytes() != bytes {
        return Err(error);
    }
    Ok(value)
}
fn validate_execution_plan_v1(
    canonical_execution_plan: &[u8],
    binding: &WitnessBinding,
    manifest: &PrivacyWalletExecutionBundleManifestV1,
    public_intent: &ValidatedPublicIntentV1,
) -> Result<ValidatedExecutionPlanV1, WorkerError> {
    const FIELDS: &[&str] = &[
        "authority",
        "authority_public_key",
        "creation_time_ms",
        "fee_payment",
        "network_id_hex",
        "nonce",
        "operation_schema",
        "protocol_id",
        "public_action",
        "schema_version",
        "transaction_metadata",
        "ttl_ms",
    ];
    let value = validate_canonical_json_bytes(
        canonical_execution_plan,
        MAX_CANONICAL_EXECUTION_PLAN_BYTES,
        WorkerError::InvalidExecutionPlan,
    )?;
    let object = value.as_object().ok_or(WorkerError::InvalidExecutionPlan)?;
    if object.len() != FIELDS.len() + usize::from(object.contains_key("orchard_contract_calls"))
        || FIELDS.iter().any(|field| !object.contains_key(*field))
        || object
            .get("schema_version")
            .and_then(norito::json::Value::as_u64)
            != Some(1)
    {
        return Err(WorkerError::InvalidExecutionPlan);
    }
    let text = |field: &str| {
        object
            .get(field)
            .and_then(norito::json::Value::as_str)
            .ok_or(WorkerError::InvalidExecutionPlan)
    };
    let protocol_label = text("protocol_id")?;
    let operation_schema = text("operation_schema")?;
    let authority_label = text("authority")?;
    let authority_public_key = text("authority_public_key")?;
    if protocol_label != binding.protocol
        || protocol_label != manifest.protocol_id.canonical_label()
        || operation_schema != public_intent.operation_schema
        || operation_schema != manifest.operation_schema
        || authority_label != manifest.authority.to_string()
        || authority_public_key != manifest.public_key.to_string()
    {
        return Err(WorkerError::WrongBinding);
    }
    let network_id_hex = text("network_id_hex")?;
    if network_id_hex.len() != DIGEST_BYTES * 2
        || !network_id_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WorkerError::InvalidExecutionPlan);
    }
    let mut network_id = [0_u8; DIGEST_BYTES];
    hex::decode_to_slice(network_id_hex, &mut network_id)
        .map_err(|_| WorkerError::InvalidExecutionPlan)?;
    if !constant_time_eq(&network_id, &binding.network_id) {
        return Err(WorkerError::WrongBinding);
    }
    let authority =
        AccountId::parse_encoded(authority_label).map_err(|_| WorkerError::InvalidExecutionPlan)?;
    if authority != manifest.authority {
        return Err(WorkerError::WrongBinding);
    }
    let creation_time_ms = object
        .get("creation_time_ms")
        .and_then(norito::json::Value::as_u64)
        .ok_or(WorkerError::InvalidExecutionPlan)?;
    let ttl_ms = object
        .get("ttl_ms")
        .and_then(norito::json::Value::as_u64)
        .ok_or(WorkerError::InvalidExecutionPlan)?;
    let nonce_u64 = object
        .get("nonce")
        .and_then(norito::json::Value::as_u64)
        .ok_or(WorkerError::InvalidExecutionPlan)?;
    let nonce =
        NonZeroU32::new(u32::try_from(nonce_u64).map_err(|_| WorkerError::InvalidExecutionPlan)?)
            .ok_or(WorkerError::InvalidExecutionPlan)?;
    let now = unix_time_millis()?;
    let expires_at = creation_time_ms
        .checked_add(ttl_ms)
        .ok_or(WorkerError::InvalidExecutionPlan)?;
    if creation_time_ms == 0
        || creation_time_ms < now.saturating_sub(30_000)
        || creation_time_ms > now.saturating_add(5_000)
        || !(1..=120_000).contains(&ttl_ms)
        || expires_at <= now
    {
        return Err(WorkerError::InvalidExecutionPlan);
    }
    let fee_payment = norito::json::from_value::<FeePaymentIntent>(
        object
            .get("fee_payment")
            .cloned()
            .ok_or(WorkerError::InvalidExecutionPlan)?,
    )
    .map_err(|_| WorkerError::InvalidExecutionPlan)?;
    let metadata = norito::json::from_value::<Metadata>(
        object
            .get("transaction_metadata")
            .cloned()
            .ok_or(WorkerError::InvalidExecutionPlan)?,
    )
    .map_err(|_| WorkerError::InvalidExecutionPlan)?;
    let public_action = norito::json::to_json(
        object
            .get("public_action")
            .ok_or(WorkerError::InvalidExecutionPlan)?,
    )
    .map_err(|_| WorkerError::InvalidExecutionPlan)?
    .into_bytes();
    if !constant_time_eq(&public_action, &public_intent.public_action) {
        return Err(WorkerError::PublicActionMismatch);
    }
    let orchard_contract_calls = validate_orchard_contract_calls_v1(
        object.get("orchard_contract_calls"),
        &binding.protocol,
        WorkerError::InvalidExecutionPlan,
    )?;
    // Both absent is the explicit standalone case. Stripping or adding calls cannot switch it.
    if orchard_contract_calls != public_intent.orchard_contract_calls {
        return Err(WorkerError::WrongBinding);
    }
    let context = PrivacyActionTransactionContextV1 {
        network_id: network_id_from_genesis_hash_bytes(network_id),
        authority,
        creation_time: Duration::from_millis(creation_time_ms),
        time_to_live: Some(Duration::from_millis(ttl_ms)),
        nonce: Some(nonce),
        fee_payment,
        metadata,
    };
    if let Some(calls) = &orchard_contract_calls {
        validate_orchard_ordered_context(&context, calls)
            .map_err(|_| WorkerError::InvalidExecutionPlan)?;
    }
    Ok(ValidatedExecutionPlanV1 {
        context,
        public_action,
        operation_schema: operation_schema.to_owned(),
        orchard_contract_calls,
    })
}
fn validate_text(
    _label: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), WorkerError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(WorkerError::InvalidBinding("binding text is invalid"));
    }
    Ok(())
}
fn put_text(output: &mut Vec<u8>, value: &str) {
    let length = u16::try_from(value.len()).expect("validated text length fits u16");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}
fn put_bytes_u16(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WorkerError> {
    let length = u16::try_from(value.len()).map_err(|_| WorkerError::InvalidPayload)?;
    if length == 0 {
        return Err(WorkerError::InvalidPayload);
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
fn put_bytes_u32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WorkerError> {
    let length = u32::try_from(value.len()).map_err(|_| WorkerError::InvalidPayload)?;
    if length == 0 {
        return Err(WorkerError::InvalidPayload);
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
fn read_credential_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, WorkerError> {
    if !path.is_absolute() {
        return Err(WorkerError::InvalidCredentialPath);
    }
    let before = fs::symlink_metadata(path).map_err(|error| WorkerError::Io(error.kind()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(WorkerError::InvalidCredentialPath);
    }
    validate_file_security(&before)?;
    if before.len() == 0 {
        return Err(WorkerError::CredentialFileEmpty);
    }
    if before.len() > MAX_CREDENTIAL_BYTES {
        return Err(WorkerError::CredentialFileTooLarge);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(path)
        .map_err(|error| WorkerError::Io(error.kind()))?;
    let opened = file
        .metadata()
        .map_err(|error| WorkerError::Io(error.kind()))?;
    if !same_file_snapshot(&before, &opened) {
        return Err(WorkerError::CredentialChangedDuringImport);
    }
    let mut material = Zeroizing::new(Vec::with_capacity(
        usize::try_from(before.len()).map_err(|_| WorkerError::CredentialFileTooLarge)?,
    ));
    Read::by_ref(&mut file)
        .take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut material)
        .map_err(|error| WorkerError::Io(error.kind()))?;
    if material.is_empty() {
        return Err(WorkerError::CredentialFileEmpty);
    }
    if material.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(WorkerError::CredentialFileTooLarge);
    }
    let after = file
        .metadata()
        .map_err(|error| WorkerError::Io(error.kind()))?;
    if !same_file_snapshot(&opened, &after) || material.len() as u64 != after.len() {
        material.zeroize();
        return Err(WorkerError::CredentialChangedDuringImport);
    }
    let material_digest = Zeroizing::new(sha256(&material));
    file.seek(SeekFrom::Start(0))
        .map_err(|error| WorkerError::Io(error.kind()))?;
    let mut verification_digest = Sha256::new();
    let mut verification_buffer = Zeroizing::new([0_u8; 8_192]);
    let mut verified_bytes = 0_u64;
    loop {
        let read = file
            .read(&mut verification_buffer[..])
            .map_err(|error| WorkerError::Io(error.kind()))?;
        if read == 0 {
            break;
        }
        verified_bytes = verified_bytes
            .checked_add(read as u64)
            .ok_or(WorkerError::CredentialFileTooLarge)?;
        if verified_bytes > MAX_CREDENTIAL_BYTES {
            material.zeroize();
            return Err(WorkerError::CredentialFileTooLarge);
        }
        verification_digest.update(&verification_buffer[..read]);
        verification_buffer[..read].zeroize();
    }
    let verified_digest_array: [u8; DIGEST_BYTES] = verification_digest.finalize().into();
    let verified_digest = Zeroizing::new(verified_digest_array);
    let verified = file
        .metadata()
        .map_err(|error| WorkerError::Io(error.kind()))?;
    if !same_file_snapshot(&after, &verified)
        || verified_bytes != material.len() as u64
        || !constant_time_eq(&material_digest[..], &verified_digest[..])
    {
        material.zeroize();
        return Err(WorkerError::CredentialChangedDuringImport);
    }
    Ok(material)
}
#[cfg(unix)]
fn validate_file_security(metadata: &fs::Metadata) -> Result<(), WorkerError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(WorkerError::CredentialFileInsecure);
    }
    Ok(())
}
#[cfg(not(unix))]
fn validate_file_security(_metadata: &fs::Metadata) -> Result<(), WorkerError> {
    Err(WorkerError::CredentialFileInsecure)
}
#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
}
#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.created().ok() == right.created().ok()
        && left.modified().ok() == right.modified().ok()
}
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_file_identity(left, right)
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}
fn sha256(input: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(input).into()
}
fn hmac_sha256(key: &[u8; DIGEST_BYTES], message: &[u8]) -> [u8; AUTH_TAG_BYTES] {
    const BLOCK_BYTES: usize = 64;
    let mut inner_key = Zeroizing::new([0x36_u8; BLOCK_BYTES]);
    let mut outer_key = Zeroizing::new([0x5c_u8; BLOCK_BYTES]);
    for (index, byte) in key.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(&inner_key[..]);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&outer_key[..]);
    outer.update(inner_digest);
    outer.finalize().into()
}
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}
#[cfg(test)]
mod tests {
    include!("privacy_wallet_worker_orchard_ordered_tests.rs");
    use super::*;
    use iroha_crypto::{Hash, PrivateKey, PublicKey};
    use iroha_data_model::transaction::SignedTransaction;
    use iroha_version::codec::DecodeVersioned;
    use std::{
        io::Cursor as IoCursor,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tempfile::TempDir;
    const NOW: u64 = 1_800_000_000_000;
    const KEY: [u8; 32] = [0x51; 32];
    const TEST_SIGNER_SEED: [u8; 32] = [7; 32];
    const JINDO_PUBLIC_ACTION: &[u8] = br#"{"evaluation_point_hex":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
    const JINDO_WITNESS: &[u8] = concat!(
        "{\"polynomials_hex\":[[\"",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "\"],[\"",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "\"],[\"",
        "0200000000000000000000000000000000000000000000000000000000000000",
        "\"],[\"",
        "0300000000000000000000000000000000000000000000000000000000000000",
        "\"]]}"
    )
    .as_bytes();
    const CANONICAL_JINDO_PUBLIC_INTENT: &[u8] = br#"{"algorithm_id":"iroha-jindo-polynomial-commitment-v1","operation_schema":"jindo_polynomial_evaluation_v1","protocol_id":"iroha-jindo-polynomial-commitment-v1","public_action":{"evaluation_point_hex":"0000000000000000000000000000000000000000000000000000000000000000"},"selected_criteria":{"hide_amount":false,"hide_asset_type":false,"hide_receiver":false,"hide_sender":false,"post_quantum":false},"selected_features":{"hide_amount":false,"hide_asset_type":false,"hide_receiver":false,"hide_sender":false,"post_quantum":false},"signer_wallet_id":"alice@wonderland"}"#;
    fn binding() -> WitnessBinding {
        WitnessBinding {
            network_id: [1; 32],
            signer: "alice@wonderland".to_owned(),
            protocol: "iroha-jindo-polynomial-commitment-v1".to_owned(),
            profile_digest: [2; 32],
            public_intent_digest: canonical_public_intent_digest(CANONICAL_JINDO_PUBLIC_INTENT),
            nonce: [4; 32],
            signed_release_authority_digest: [5; 32],
        }
    }

    fn settlement_binding() -> WitnessBinding {
        WitnessBinding {
            network_id: [0x10; 32],
            signer: "settlement-wallet-1".to_owned(),
            protocol: ATOMIC_PRIVATE_SETTLEMENT_PROTOCOL_LABEL_V1.to_owned(),
            profile_digest: *PrivateSettlementProofProfileV1::IvmPrivateNoteFixed2In3Out
                .digest()
                .as_ref(),
            public_intent_digest: [0x25; 32],
            nonce: [0x33; 32],
            signed_release_authority_digest: [0x44; 32],
        }
    }

    fn settlement_inspection() -> AtomicPrivateSettlementWalletInspectionV1 {
        AtomicPrivateSettlementWalletInspectionV1 {
            wallet_id: "settlement-wallet-1".to_owned(),
            proof_binding_digest: Hash::prehashed([0x25; 32]),
            statement_digest: Hash::prehashed([0x62; 32]),
            capsule_digest: Hash::prehashed([0x63; 32]),
            audit_plaintext_commitment: Hash::prehashed([0x64; 32]),
        }
    }

    fn seeded_settlement_vault() -> (PrivateSettlementWitnessVaultV1, WitnessHandle) {
        let binding = settlement_binding();
        let handle = WitnessHandle::from_bytes([0xD1; 32]);
        let mut vault = PrivateSettlementWitnessVaultV1::default();
        vault.entries.insert(
            handle,
            StoredPrivateSettlementWitnessV1 {
                binding: binding.clone(),
                binding_digest: binding.digest(),
                expires_at_millis: u64::MAX,
                inspection: settlement_inspection(),
                material: Zeroizing::new(b"owner-only-settlement-secret".to_vec()),
            },
        );
        (vault, handle)
    }
    fn credential_file(directory: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = directory.path().join(name);
        fs::write(&path, bytes).expect("write credential");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("secure permissions");
        }
        path
    }
    fn test_signer() -> (PrivateKey, PublicKey, AccountId) {
        let private_key =
            PrivateKey::from_bytes(Algorithm::Ed25519, &TEST_SIGNER_SEED).expect("private key");
        let public_key = PublicKey::from(private_key.clone());
        let authority = AccountId::new(public_key.clone());
        (private_key, public_key, authority)
    }
    fn execution_bundle(protocol_witness: &[u8]) -> Vec<u8> {
        let (_, _, authority) = test_signer();
        let mut output = Vec::new();
        output.extend_from_slice(b"IPWB");
        output.push(1);
        put_text(&mut output, "alice@wonderland");
        put_text(&mut output, &authority.to_string());
        put_text(&mut output, "iroha-jindo-polynomial-commitment-v1");
        put_text(&mut output, "jindo_polynomial_evaluation_v1");
        put_bytes_u32(&mut output, JINDO_PUBLIC_ACTION).expect("public action");
        output.extend_from_slice(&TEST_SIGNER_SEED);
        put_bytes_u32(&mut output, protocol_witness).expect("protocol witness");
        output
    }
    fn execution_bundle_file(directory: &TempDir, name: &str, protocol_witness: &[u8]) -> PathBuf {
        credential_file(directory, name, &execution_bundle(protocol_witness))
    }
    #[test]
    fn generic_worker_registry_rejects_the_separate_zk_x509_path() {
        assert!(matches!(
            retained_protocol("iroha-zk-x509-stark-p256-v1"),
            Err(WorkerError::UnsupportedProtocol)
        ));
        for protocol in [
            "zk-ace-pq-authorization-v1",
            "anonymous-pgc-k-out-of-n-v1",
            "verange-transparent-range-v1",
            "iroha-zk-ams-v1",
            "vega-existing-credential-zk-v1",
            "iroha-jindo-polynomial-commitment-v1",
            "iroha-bootle-lantern-anoncred-v1",
            "orchard-halo2-actions-v1",
            "monero-fcmp-plus-plus-v1",
            "iroha-ivm-private-note-stark-v1",
            "pq-masp-stark-v1",
        ] {
            assert!(retained_protocol(protocol).is_ok(), "{protocol}");
        }
    }

    #[test]
    fn private_settlement_commands_and_handle_namespace_are_closed() {
        for (wire, expected) in [
            (6, CommandKind::ImportPrivateSettlement),
            (7, CommandKind::InspectPrivateSettlement),
            (8, CommandKind::CancelPrivateSettlement),
            (9, CommandKind::ProvePrivateSettlement),
        ] {
            assert!(CommandKind::try_from(wire).expect("assigned command") == expected);
        }
        assert!(settlement_binding().validate().is_ok());
        let mut even_generic = binding();
        even_generic.network_id = [0x10; 32];
        assert!(matches!(
            even_generic.validate(),
            Err(WorkerError::InvalidBinding(_))
        ));
        let (settlement_vault, _) = seeded_settlement_vault();
        let settlement_handle = settlement_vault.unique_handle().expect("settlement handle");
        let generic_handle = WitnessVault::default()
            .unique_handle()
            .expect("generic handle");
        assert_ne!(settlement_handle.as_bytes()[0] & 0x80, 0);
        assert_eq!(generic_handle.as_bytes()[0] & 0x80, 0);
    }

    #[test]
    fn private_settlement_inspect_cancel_and_failed_consume_are_single_use() {
        let (mut vault, handle) = seeded_settlement_vault();
        let lease = vault
            .inspect(handle, &settlement_binding())
            .expect("inspect public lease");
        assert_eq!(lease.inspection, settlement_inspection());
        let outcome = vault.consume_with(handle, &settlement_binding(), |material| {
            assert!(
                material
                    .windows(b"settlement-secret".len())
                    .any(|window| window == b"settlement-secret")
            );
            Err::<(), _>(WorkerError::NativePrivateSettlementProofFailed)
        });
        assert!(matches!(
            outcome,
            Err(ConsumeError::Operation(
                WorkerError::NativePrivateSettlementProofFailed
            ))
        ));
        assert!(matches!(
            vault.inspect(handle, &settlement_binding()),
            Err(WorkerError::UnknownHandle)
        ));

        let (mut vault, handle) = seeded_settlement_vault();
        vault
            .cancel(handle, &settlement_binding())
            .expect("cancel settlement handle");
        assert!(matches!(
            vault.inspect(handle, &settlement_binding()),
            Err(WorkerError::UnknownHandle)
        ));
    }

    #[test]
    fn private_settlement_lease_response_contains_only_public_commitments() {
        let (vault, handle) = seeded_settlement_vault();
        let stored = vault.entries.get(&handle).expect("stored settlement");
        let response = encode_response(CommandResponse::PrivateSettlementLease(
            PrivateSettlementWitnessLeaseV1 {
                handle,
                expires_at_millis: stored.expires_at_millis,
                inspection: stored.inspection.clone(),
            },
        ));
        assert_eq!(response.first(), Some(&4));
        assert!(
            response
                .windows(stored.inspection.wallet_id.len())
                .any(|window| window == stored.inspection.wallet_id.as_bytes())
        );
        assert!(
            !response
                .windows(stored.material.len())
                .any(|window| window == stored.material.as_slice())
        );
    }
    fn canonical_execution_plan() -> Vec<u8> {
        let (_, public_key, authority) = test_signer();
        let now = unix_time_millis().expect("native clock");
        let raw = format!(
            concat!(
                "{{\"authority\":\"{}\",",
                "\"authority_public_key\":\"{}\",",
                "\"creation_time_ms\":{},",
                "\"fee_payment\":{{\"payer\":\"authority\",\"value\":{{\"charge_limits\":[],\"gas_limit\":10000000}}}},",
                "\"network_id_hex\":\"{}\",",
                "\"nonce\":7,",
                "\"operation_schema\":\"jindo_polynomial_evaluation_v1\",",
                "\"protocol_id\":\"iroha-jindo-polynomial-commitment-v1\",",
                "\"public_action\":{{\"evaluation_point_hex\":\"0000000000000000000000000000000000000000000000000000000000000000\"}},",
                "\"schema_version\":1,",
                "\"transaction_metadata\":{{}},",
                "\"ttl_ms\":120000}}"
            ),
            authority,
            public_key,
            now,
            "01".repeat(32),
        );
        let value = norito::json::parse_value(&raw).expect("execution plan JSON");
        norito::json::to_json(&value)
            .expect("canonical execution plan")
            .into_bytes()
    }
    fn import(vault: &mut WitnessVault, path: &Path) -> WitnessLease {
        vault
            .import_credential_at(
                ImportRequest {
                    credential_path: path.to_owned(),
                    binding: binding(),
                    ttl_millis: 30_000,
                },
                NOW,
            )
            .expect("import")
    }
    fn import_now(vault: &mut WitnessVault, path: &Path) -> WitnessLease {
        vault
            .import_credential(ImportRequest {
                credential_path: path.to_owned(),
                binding: binding(),
                ttl_millis: 30_000,
            })
            .expect("import")
    }
    #[test]
    fn handles_are_random_opaque_and_single_use() {
        let directory = TempDir::new().expect("temp dir");
        let first_bundle = execution_bundle(JINDO_WITNESS);
        let first = credential_file(&directory, "first", &first_bundle);
        let second = execution_bundle_file(&directory, "second", JINDO_WITNESS);
        let mut vault = WitnessVault::default();
        let first_lease = import(&mut vault, &first);
        let second_lease = import(&mut vault, &second);
        assert!(first_lease.handle != second_lease.handle);
        assert_ne!(first_lease.handle.as_bytes(), &[0; 32]);
        let observed = vault
            .consume_with_at(first_lease.handle, &binding(), NOW + 1, |secret| {
                Ok::<_, ()>(secret.to_vec())
            })
            .expect("consume");
        assert_eq!(observed, first_bundle);
        assert!(matches!(
            vault.consume_with_at(first_lease.handle, &binding(), NOW + 2, |_| Ok::<_, ()>(())),
            Err(ConsumeError::Custody(WorkerError::UnknownHandle))
        ));
    }
    #[test]
    fn callback_failure_still_consumes_the_handle() {
        let directory = TempDir::new().expect("temp dir");
        let path = execution_bundle_file(&directory, "credential", JINDO_WITNESS);
        let mut vault = WitnessVault::default();
        let lease = import(&mut vault, &path);
        let result = vault.consume_with_at(lease.handle, &binding(), NOW + 1, |_| {
            Err::<(), _>("prover failure")
        });
        assert!(matches!(
            result,
            Err(ConsumeError::Operation("prover failure"))
        ));
        assert!(matches!(
            vault.inspect_at(lease.handle, &binding(), NOW + 2),
            Err(WorkerError::UnknownHandle)
        ));
    }
    #[test]
    fn panic_unwind_removes_handle_without_reinsertion() {
        let directory = TempDir::new().expect("temp dir");
        let path = execution_bundle_file(&directory, "credential", JINDO_WITNESS);
        let mut vault = WitnessVault::default();
        let lease = import(&mut vault, &path);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), ConsumeError<()>> =
                vault.consume_with_at(lease.handle, &binding(), NOW + 1, |_| panic!("stop"));
        }));
        assert!(panicked.is_err());
        assert!(matches!(
            vault.inspect_at(lease.handle, &binding(), NOW + 2),
            Err(WorkerError::UnknownHandle)
        ));
    }
    #[test]
    fn all_binding_dimensions_are_enforced() {
        let directory = TempDir::new().expect("temp dir");
        let path = execution_bundle_file(&directory, "credential", JINDO_WITNESS);
        let mutations: [fn(&mut WitnessBinding); 7] = [
            |value| value.network_id[0] ^= 1,
            |value| value.signer.push_str("-other"),
            |value| value.protocol = "verange-transparent-range-v1".to_owned(),
            |value| value.profile_digest[0] ^= 1,
            |value| value.public_intent_digest[0] ^= 1,
            |value| value.nonce[0] ^= 1,
            |value| value.signed_release_authority_digest[0] ^= 1,
        ];
        for mutate in mutations {
            let mut vault = WitnessVault::default();
            let lease = import(&mut vault, &path);
            let mut wrong = binding();
            mutate(&mut wrong);
            assert!(matches!(
                vault.inspect_at(lease.handle, &wrong, NOW + 1),
                Err(WorkerError::WrongBinding)
            ));
            assert_eq!(vault.len(), 1, "mismatch must not consume the handle");
        }
    }
    #[test]
    fn expiry_and_cancel_are_atomic_terminal_states() {
        let directory = TempDir::new().expect("temp dir");
        let first = execution_bundle_file(&directory, "first", JINDO_WITNESS);
        let second = execution_bundle_file(&directory, "second", JINDO_WITNESS);
        let mut vault = WitnessVault::default();
        let expired = import(&mut vault, &first);
        assert!(matches!(
            vault.inspect_at(expired.handle, &binding(), expired.expires_at_millis),
            Err(WorkerError::UnknownHandle)
        ));
        let cancelled = import(&mut vault, &second);
        vault
            .cancel_at(cancelled.handle, &binding(), NOW + 1)
            .expect("cancel");
        assert!(matches!(
            vault.inspect_at(cancelled.handle, &binding(), NOW + 2),
            Err(WorkerError::UnknownHandle)
        ));
    }
    #[test]
    fn capacity_is_bounded_and_expiry_releases_capacity() {
        let directory = TempDir::new().expect("temp dir");
        let first = execution_bundle_file(&directory, "first", JINDO_WITNESS);
        let second = execution_bundle_file(&directory, "second", JINDO_WITNESS);
        let mut vault = WitnessVault::new(1);
        let lease = import(&mut vault, &first);
        assert!(matches!(
            vault.import_credential_at(
                ImportRequest {
                    credential_path: second.clone(),
                    binding: binding(),
                    ttl_millis: 30_000,
                },
                NOW + 1,
            ),
            Err(WorkerError::CapacityExceeded)
        ));
        assert_eq!(vault.purge_expired_at(lease.expires_at_millis), 1);
        assert!(
            vault
                .import_credential_at(
                    ImportRequest {
                        credential_path: second,
                        binding: binding(),
                        ttl_millis: 30_000,
                    },
                    lease.expires_at_millis,
                )
                .is_ok()
        );
    }
    #[test]
    fn ttl_and_binding_validation_fail_closed() {
        let directory = TempDir::new().expect("temp dir");
        let path = credential_file(&directory, "credential", b"secret");
        for ttl in [0, MIN_TTL_MILLIS - 1, MAX_TTL_MILLIS + 1] {
            assert!(matches!(
                WitnessVault::default().import_credential_at(
                    ImportRequest {
                        credential_path: path.clone(),
                        binding: binding(),
                        ttl_millis: ttl,
                    },
                    NOW,
                ),
                Err(WorkerError::InvalidTtl)
            ));
        }
        let mut invalid = binding();
        invalid.network_id[DIGEST_BYTES - 1] &= !1;
        assert!(matches!(
            invalid.validate(),
            Err(WorkerError::InvalidBinding(_))
        ));
        let mut invalid = binding();
        invalid.nonce = [0; 32];
        assert!(matches!(
            WitnessVault::default().import_credential_at(
                ImportRequest {
                    credential_path: path,
                    binding: invalid,
                    ttl_millis: MIN_TTL_MILLIS,
                },
                NOW,
            ),
            Err(WorkerError::InvalidBinding(_))
        ));
    }
    #[test]
    fn relative_symlink_empty_and_oversized_files_are_rejected() {
        let directory = TempDir::new().expect("temp dir");
        let empty = credential_file(&directory, "empty", b"");
        assert!(matches!(
            read_credential_file(Path::new("relative")),
            Err(WorkerError::InvalidCredentialPath)
        ));
        assert!(matches!(
            read_credential_file(&empty),
            Err(WorkerError::CredentialFileEmpty)
        ));
        let oversized = credential_file(&directory, "oversized", b"x");
        fs::File::options()
            .write(true)
            .open(&oversized)
            .expect("open oversized")
            .set_len(MAX_CREDENTIAL_BYTES + 1)
            .expect("extend");
        assert!(matches!(
            read_credential_file(&oversized),
            Err(WorkerError::CredentialFileTooLarge)
        ));
        #[cfg(unix)]
        {
            let target = credential_file(&directory, "target", b"secret");
            let link = directory.path().join("link");
            std::os::unix::fs::symlink(target, &link).expect("symlink");
            assert!(matches!(
                read_credential_file(&link),
                Err(WorkerError::InvalidCredentialPath)
            ));
        }
    }
    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_files_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TempDir::new().expect("temp dir");
        let path = credential_file(&directory, "credential", b"secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("change permissions");
        assert!(matches!(
            read_credential_file(&path),
            Err(WorkerError::CredentialFileInsecure)
        ));
    }
    #[test]
    fn authenticated_frame_round_trip_is_canonical() {
        let frame = AuthenticatedFrame {
            kind: CommandKind::Ping,
            sequence: 1,
            payload: vec![],
        };
        let encoded = encode_frame(&frame, &KEY).expect("encode");
        let decoded = decode_frame(&encoded, &KEY).expect("decode");
        assert_eq!(decoded.kind as u8, CommandKind::Ping as u8);
        assert_eq!(decoded.sequence, 1);
        assert!(decoded.payload.is_empty());
        assert_eq!(encode_frame(&decoded, &KEY).expect("re-encode"), encoded);
    }
    #[test]
    fn tampering_wrong_key_trailing_bytes_and_bad_lengths_are_rejected() {
        let frame = AuthenticatedFrame {
            kind: CommandKind::Ping,
            sequence: 1,
            payload: vec![],
        };
        let encoded = encode_frame(&frame, &KEY).expect("encode");
        let mut tampered = encoded.clone();
        tampered[10] ^= 1;
        assert!(matches!(
            decode_frame(&tampered, &KEY),
            Err(WorkerError::AuthenticationFailed)
        ));
        assert!(matches!(
            decode_frame(&encoded, &[0x52; 32]),
            Err(WorkerError::AuthenticationFailed)
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_frame(&trailing, &KEY),
            Err(WorkerError::InvalidFrame)
        ));
        let mut short = encoded.clone();
        short[0..4].copy_from_slice(&1_u32.to_be_bytes());
        assert!(matches!(
            decode_frame(&short, &KEY),
            Err(WorkerError::InvalidFrame)
        ));
        let mut unknown = encoded;
        unknown[9] = 99;
        let tag_offset = unknown.len() - AUTH_TAG_BYTES;
        let tag = hmac_sha256(&KEY, &unknown[4..tag_offset]);
        unknown[tag_offset..].copy_from_slice(&tag);
        assert!(matches!(
            decode_frame(&unknown, &KEY),
            Err(WorkerError::UnknownCommand)
        ));
    }
    #[test]
    fn oversized_frames_are_rejected_before_allocation() {
        let mut input = IoCursor::new(((MAX_FRAME_BYTES as u32) + 1).to_be_bytes());
        assert!(matches!(
            read_frame(&mut input, &KEY),
            Err(WorkerError::FrameTooLarge)
        ));
        let frame = AuthenticatedFrame {
            kind: CommandKind::Ping,
            sequence: 1,
            payload: vec![0; MAX_FRAME_BYTES],
        };
        assert!(matches!(
            encode_frame(&frame, &KEY),
            Err(WorkerError::FrameTooLarge)
        ));
    }
    #[test]
    fn truncated_prefix_and_zero_session_key_fail_closed() {
        let mut truncated = IoCursor::new(vec![0_u8, 0]);
        assert!(matches!(
            read_frame(&mut truncated, &KEY),
            Err(WorkerError::Io(io::ErrorKind::UnexpectedEof))
        ));
        let mut empty = IoCursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        assert!(matches!(
            run_pipe_session(&mut empty, &mut output, Zeroizing::new([0; DIGEST_BYTES]),),
            Err(WorkerError::AuthenticationFailed)
        ));
    }
    #[test]
    fn duplicate_and_out_of_order_sequences_terminate_the_session() {
        let ping = |sequence| {
            encode_frame(
                &AuthenticatedFrame {
                    kind: CommandKind::Ping,
                    sequence,
                    payload: vec![],
                },
                &KEY,
            )
            .expect("encode")
        };
        for input in [[ping(1), ping(1)].concat(), ping(2)] {
            let mut reader = IoCursor::new(input);
            let mut writer = Vec::new();
            assert!(matches!(
                run_pipe_session(&mut reader, &mut writer, Zeroizing::new(KEY)),
                Err(WorkerError::ReplayOrOutOfOrder)
            ));
        }
    }
    #[test]
    fn opcode_five_executes_one_exact_self_inspected_signed_wire_and_consumes_once() {
        let directory = TempDir::new().expect("temp dir");
        let path = execution_bundle_file(&directory, "credential", JINDO_WITNESS);
        let mut vault = WitnessVault::default();
        let lease = import_now(&mut vault, &path);
        assert!(
            CommandKind::try_from(5).expect("assigned execute command") == CommandKind::Execute
        );
        let payload = encode_execute_payload(
            lease.handle,
            &binding(),
            CANONICAL_JINDO_PUBLIC_INTENT,
            &canonical_execution_plan(),
        )
        .expect("execute payload");
        let authenticated_execute = encode_frame(
            &AuthenticatedFrame {
                kind: CommandKind::Execute,
                sequence: 1,
                payload,
            },
            &KEY,
        )
        .expect("authenticated execute frame");
        let decoded_frame =
            decode_frame(&authenticated_execute, &KEY).expect("decode authenticated execute");
        assert!(decoded_frame.kind == CommandKind::Execute);
        assert_eq!(
            encode_frame(&decoded_frame, &KEY).expect("re-encode execute"),
            authenticated_execute
        );
        let response = dispatch(
            &mut vault,
            decoded_frame.kind,
            decoded_frame.payload.as_slice(),
        );
        let signed = match response {
            CommandResponse::SignedAction(signed) => signed,
            CommandResponse::Error(error) => {
                panic!("valid Jindo execute returned worker error: {error:?}")
            }
            _ => panic!("valid Jindo execute returned the wrong response kind"),
        };
        let (_, expected_public_key, expected_authority) = test_signer();
        assert_eq!(signed.protocol_id, "iroha-jindo-polynomial-commitment-v1");
        assert_eq!(signed.operation_schema, "jindo_polynomial_evaluation_v1");
        assert_eq!(signed.network_id, [1; 32]);
        assert_eq!(signed.authority, expected_authority.to_string());
        assert_eq!(signed.authority_public_key, expected_public_key.to_string());
        assert_eq!(signed.signature.len(), 64);
        assert_eq!(signed.public_key.len(), 32);
        assert!(signed.statement_bytes > 0);
        assert!(signed.proof_bytes > 0);
        assert!(signed.encoded_proof_envelope_bytes >= signed.proof_bytes);
        assert_eq!(
            signed.adaptive_signed_transaction.len(),
            signed.adaptive_signed_transaction_bytes as usize
        );
        assert_eq!(
            signed.versioned_signed_transaction.len(),
            signed.submitted_versioned_transaction_bytes as usize
        );
        let adaptive: SignedTransaction =
            norito::codec::decode_adaptive(&signed.adaptive_signed_transaction)
                .expect("decode adaptive signed transaction");
        let versioned =
            SignedTransaction::decode_all_versioned(&signed.versioned_signed_transaction)
                .expect("decode versioned signed transaction");
        for decoded in [&adaptive, &versioned] {
            let inspected = inspect_signed_privacy_native_action_v1(decoded)
                .expect("independently inspect signed transaction");
            assert_eq!(
                inspected.protocol_id(),
                PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1
            );
            assert_eq!(inspected.transaction_hash(), signed.transaction_hash);
            assert_eq!(
                inspected.transaction_intent_digest(),
                signed.transaction_intent_digest
            );
            assert_eq!(inspected.statement_digest(), signed.statement_digest);
            assert_eq!(inspected.proof_envelope_hash(), signed.proof_envelope_hash);
            assert_eq!(inspected.statement_bytes(), signed.statement_bytes);
            assert_eq!(inspected.proof_bytes(), signed.proof_bytes);
        }
        assert_eq!(
            norito::codec::encode_adaptive(&versioned),
            signed.adaptive_signed_transaction
        );
        let response_wire = encode_response(CommandResponse::SignedAction(signed));
        assert_eq!(response_wire.first(), Some(&3));
        assert!(
            !response_wire
                .windows(TEST_SIGNER_SEED.len())
                .any(|window| window == TEST_SIGNER_SEED.as_slice()),
            "signed-action response must not export the signer seed"
        );
        assert!(
            !response_wire
                .windows(JINDO_WITNESS.len())
                .any(|window| window == JINDO_WITNESS),
            "signed-action response must not export canonical witness bytes"
        );
        assert!(
            matches!(
                vault.inspect(lease.handle, &binding()),
                Err(WorkerError::UnknownHandle)
            ),
            "successful native execution must consume the handle exactly once"
        );
    }
    #[test]
    fn public_validation_failures_do_not_consume_but_native_bundle_failure_is_terminal() {
        let directory = TempDir::new().expect("temp dir");
        let valid_path = execution_bundle_file(&directory, "valid", JINDO_WITNESS);
        let mut vault = WitnessVault::default();
        let valid_lease = import_now(&mut vault, &valid_path);
        let first_display_label = "same-privacy-network-label";
        let second_display_label = "same-privacy-network-label";
        assert_eq!(first_display_label, second_display_label);
        let wrong_plan = std::str::from_utf8(&canonical_execution_plan())
            .expect("plan utf8")
            .replace(&"01".repeat(32), &"02".repeat(32))
            .into_bytes();
        let wrong_plan_payload = encode_execute_payload(
            valid_lease.handle,
            &binding(),
            CANONICAL_JINDO_PUBLIC_INTENT,
            &wrong_plan,
        )
        .expect("canonical wrong plan payload");
        assert!(matches!(
            dispatch(
                &mut vault,
                CommandKind::Execute,
                wrong_plan_payload.as_slice()
            ),
            CommandResponse::Error(WorkerError::WrongBinding)
        ));
        assert!(
            vault.inspect(valid_lease.handle, &binding()).is_ok(),
            "public validation must precede single-use consumption"
        );
        vault
            .cancel(valid_lease.handle, &binding())
            .expect("cancel preserved handle");
        let malformed_bundle =
            execution_bundle_file(&directory, "malformed-witness", br#"{"unexpected":true}"#);
        let malformed_lease = import_now(&mut vault, &malformed_bundle);
        let execute_payload = encode_execute_payload(
            malformed_lease.handle,
            &binding(),
            CANONICAL_JINDO_PUBLIC_INTENT,
            &canonical_execution_plan(),
        )
        .expect("execute payload");
        assert!(matches!(
            dispatch(&mut vault, CommandKind::Execute, &execute_payload),
            CommandResponse::Error(WorkerError::InvalidExecutionBundle)
        ));
        assert!(
            matches!(
                vault.inspect(malformed_lease.handle, &binding()),
                Err(WorkerError::UnknownHandle)
            ),
            "a native callback failure must remain terminal and non-retryable"
        );
    }
    #[test]
    fn forged_ipc_time_never_releases_or_consumes() {
        let directory = TempDir::new().expect("temp dir");
        let path = execution_bundle_file(&directory, "credential", JINDO_WITNESS);
        let mut vault = WitnessVault::default();
        let now = unix_time_millis().expect("native clock");
        let lease = vault
            .import_credential_at(
                ImportRequest {
                    credential_path: path,
                    binding: binding(),
                    ttl_millis: 30_000,
                },
                now,
            )
            .expect("import");
        let mut forged_time =
            encode_handle_payload(lease.handle, &binding()).expect("handle payload");
        forged_time.extend_from_slice(&1_u64.to_be_bytes());
        let response = encode_response(dispatch(&mut vault, CommandKind::Inspect, &forged_time));
        assert_eq!(response[0], 255);
        assert!(vault.inspect_at(lease.handle, &binding(), now + 1).is_ok());
    }
    #[test]
    fn canonical_public_intent_is_exact_and_bound_to_wire_execution() {
        assert_eq!(
            hex::encode(canonical_public_intent_digest(
                CANONICAL_JINDO_PUBLIC_INTENT,
            )),
            "94b48efc270f5fe4b8c54a194df47771d4af52492fcb2488609bd22ef20bcc31"
        );
        validate_canonical_public_intent(CANONICAL_JINDO_PUBLIC_INTENT, &binding())
            .expect("canonical typed transport intent");
        let noncanonical = [b" ".as_slice(), CANONICAL_JINDO_PUBLIC_INTENT].concat();
        assert!(matches!(
            validate_canonical_public_intent(&noncanonical, &binding()),
            Err(WorkerError::InvalidPublicIntent)
        ));
        let altered = std::str::from_utf8(CANONICAL_JINDO_PUBLIC_INTENT)
            .expect("utf8")
            .replace(
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0100000000000000000000000000000000000000000000000000000000000000",
            );
        assert!(matches!(
            validate_canonical_public_intent(altered.as_bytes(), &binding()),
            Err(WorkerError::PublicIntentDigestMismatch)
        ));
        let wrong_signer = std::str::from_utf8(CANONICAL_JINDO_PUBLIC_INTENT)
            .expect("utf8")
            .replace("alice@wonderland", "mallory@wonderland");
        assert!(matches!(
            validate_canonical_public_intent(wrong_signer.as_bytes(), &binding()),
            Err(WorkerError::InvalidPublicIntent)
        ));
    }
    #[test]
    fn compiled_profile_digest_binds_protocol_and_all_five_digests() {
        let profile = CompiledProfileBinding {
            parameter_id: [0x11; 32],
            parameter_digest: [0x22; 32],
            verifier_digest: [0x33; 32],
            statement_schema_digest: [0x44; 32],
            engine_manifest_digest: [0x55; 32],
        };
        let baseline = compiled_profile_digest("iroha-jindo-polynomial-commitment-v1", &profile)
            .expect("profile digest");
        assert_eq!(
            hex::encode(baseline),
            "ae65a35ac3420351ec4c7da140ba820d80756446a09c18e0a8e6ea4a19c80a89"
        );
        let mut mutations = [
            profile.parameter_id,
            profile.parameter_digest,
            profile.verifier_digest,
            profile.statement_schema_digest,
            profile.engine_manifest_digest,
        ];
        for index in 0..mutations.len() {
            mutations[index][0] ^= 1;
            let changed = CompiledProfileBinding {
                parameter_id: mutations[0],
                parameter_digest: mutations[1],
                verifier_digest: mutations[2],
                statement_schema_digest: mutations[3],
                engine_manifest_digest: mutations[4],
            };
            assert_ne!(
                baseline,
                compiled_profile_digest("iroha-jindo-polynomial-commitment-v1", &changed,)
                    .expect("changed profile digest")
            );
            mutations[index][0] ^= 1;
        }
        assert_ne!(
            baseline,
            compiled_profile_digest("verange-transparent-range-v1", &profile)
                .expect("changed protocol digest")
        );
    }
    #[test]
    fn drop_path_is_exercised_without_cloning_or_debugging_secret_storage() {
        let directory = TempDir::new().expect("temp dir");
        let path = execution_bundle_file(&directory, "credential", JINDO_WITNESS);
        let dropped = Arc::new(AtomicBool::new(false));
        struct DropMarker(Arc<AtomicBool>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let marker = DropMarker(Arc::clone(&dropped));
        let mut vault = WitnessVault::default();
        let lease = import(&mut vault, &path);
        let _: Result<(), ConsumeError<()>> =
            vault.consume_with_at(lease.handle, &binding(), NOW + 1, |_| {
                drop(marker);
                Ok(())
            });
        assert!(dropped.load(Ordering::SeqCst));
        assert!(vault.is_empty());
    }
}

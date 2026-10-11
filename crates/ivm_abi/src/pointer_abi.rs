//! Pointer-ABI TLV helpers and type table.
//!
//! Envelope layout (in validated INPUT, allocated HEAP, or a loader-validated `LTLB` code literal):
//! - type_id: u16 (BE)
//! - version: u8
//! - len: u32 (BE)
//! - payload: [u8; len]
//! - hash: [u8; 32] (Iroha Hash of payload)
//!
//! Validation rules:
//! - VM-level pointer validation accepts an envelope wholly within INPUT, the
//!   allocated portion of owned HEAP, or an exact loader-validated literal
//!   start in read-only code. Stack, OUTPUT, and unallocated heap capacity are
//!   rejected even when their bytes resemble a valid envelope. The lower-level
//!   `Memory::validate_tlv` helper remains INPUT-only; syscall paths use the
//!   provenance-aware `IVM::validate_tlv` validator.
//! - `LDLIT` code pointers are validated once at program load and must name an
//!   exact envelope in the read-only literal data.
//! - `version` currently must be 1.
//! - `type_id` must be known in the table below.
//! - Hash must match `iroha_crypto::Hash::new(payload)`.
use crate::{SyscallPolicy, error::VMError};
use std::{cell::Cell, collections::HashSet, marker::PhantomData, rc::Rc, sync::OnceLock};
/// Known pointer-ABI types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PointerType {
    AccountId = 0x0001,
    AssetDefinitionId = 0x0002,
    Name = 0x0003,
    Json = 0x0004,
    NftId = 0x0005,
    /// Raw bytes payload
    Blob = 0x0006,
    /// Full AssetId (definition + account)
    AssetId = 0x0007,
    /// Domain identifier
    DomainId = 0x0008,
    /// Norito-encoded bytes payload (distinguishes structured Norito from raw blobs)
    NoritoBytes = 0x0009,
    /// Identifier of a data space / lane group used for cross-DS routing.
    DataSpaceId = 0x000A,
    /// Descriptor of an atomic cross-transaction (AXT) envelope.
    AxtDescriptor = 0x000B,
    /// Proof blob (deterministic Norito or compressed proof bytes).
    ProofBlob = 0x000D,
    /// Soracloud host request envelope.
    SoracloudRequest = 0x000E,
    /// Soracloud host response envelope.
    SoracloudResponse = 0x000F,
    /// Canonical non-negative nominal Kotodama `quantity` value.
    Quantity = 0x0010,
    /// Canonical Kotodama `int` value.
    Int = 0x0011,
    /// Canonical exact Kotodama `decimal` value.
    Decimal = 0x0012,
    /// Canonical issuer-signed AXT anchored spend, including its claimed source receipt.
    AxtAnchoredSpendV1 = 0x0013,
    /// Test-only pointer type used to exercise policy failures.
    #[cfg(test)]
    TestOnly = 0x0FFE,
}
impl PointerType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::AccountId),
            0x0002 => Some(Self::AssetDefinitionId),
            0x0003 => Some(Self::Name),
            0x0004 => Some(Self::Json),
            0x0005 => Some(Self::NftId),
            0x0006 => Some(Self::Blob),
            0x0007 => Some(Self::AssetId),
            0x0008 => Some(Self::DomainId),
            0x0009 => Some(Self::NoritoBytes),
            0x000A => Some(Self::DataSpaceId),
            0x000B => Some(Self::AxtDescriptor),
            0x000D => Some(Self::ProofBlob),
            0x000E => Some(Self::SoracloudRequest),
            0x000F => Some(Self::SoracloudResponse),
            0x0010 => Some(Self::Quantity),
            0x0011 => Some(Self::Int),
            0x0012 => Some(Self::Decimal),
            0x0013 => Some(Self::AxtAnchoredSpendV1),
            #[cfg(test)]
            0x0FFE => Some(Self::TestOnly),
            _ => None,
        }
    }
    /// Return all known pointer types in numeric ID order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::AccountId,
            Self::AssetDefinitionId,
            Self::Name,
            Self::Json,
            Self::NftId,
            Self::Blob,
            Self::AssetId,
            Self::DomainId,
            Self::NoritoBytes,
            Self::DataSpaceId,
            Self::AxtDescriptor,
            Self::ProofBlob,
            Self::SoracloudRequest,
            Self::SoracloudResponse,
            Self::Quantity,
            Self::Int,
            Self::Decimal,
            Self::AxtAnchoredSpendV1,
            #[cfg(test)]
            Self::TestOnly,
        ]
    }
}
/// Validated view of a TLV envelope.
pub struct Tlv<'a> {
    pub type_id: PointerType,
    pub version: u8,
    pub payload: &'a [u8],
}
impl<'a> Tlv<'a> {
    pub fn type_id_raw(&self) -> u16 {
        self.type_id as u16
    }
}
impl<'a> core::fmt::Debug for Tlv<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tlv")
            .field("type_id", &self.type_id)
            .field("version", &self.version)
            .field("len", &self.payload.len())
            .finish()
    }
}
/// Encode the sole canonical V1 pointer envelope over the exact payload bytes.
///
/// # Errors
/// Rejects an unrepresentable payload or total length with [`VMError::NoritoInvalid`].
/// Native reservation failure retains the local
/// `ExecutionDeferred::AllocationUnavailable` result.
pub fn encode_tlv(pointer_type: PointerType, payload: &[u8]) -> Result<Vec<u8>, VMError> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| VMError::NoritoInvalid)?;
    let total = 7usize
        .checked_add(payload.len())
        .and_then(|len| len.checked_add(iroha_crypto::Hash::LENGTH))
        .ok_or(VMError::NoritoInvalid)?;
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| {
        VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
    })?;
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(iroha_crypto::Hash::new(payload).as_ref());
    Ok(out)
}
/// Validate a TLV envelope provided as a raw byte slice and return a view over
/// its payload. The slice must contain the full header, payload, and hash.
pub fn validate_tlv_bytes(bytes: &[u8]) -> Result<Tlv<'_>, VMError> {
    if bytes.len() < 7 + iroha_crypto::Hash::LENGTH {
        return Err(VMError::NoritoInvalid);
    }
    let type_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let version = bytes[2];
    if version != 1 {
        return Err(VMError::NoritoInvalid);
    }
    let len = u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as usize;
    let total = 7usize
        .checked_add(len)
        .and_then(|x| x.checked_add(iroha_crypto::Hash::LENGTH))
        .ok_or(VMError::NoritoInvalid)?;
    if bytes.len() != total {
        return Err(VMError::NoritoInvalid);
    }
    let payload = &bytes[7..7 + len];
    let hash_bytes = &bytes[7 + len..total];
    let mut expected_hash = [0u8; iroha_crypto::Hash::LENGTH];
    expected_hash.copy_from_slice(hash_bytes);
    let computed: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new(payload).into();
    if expected_hash != computed {
        return Err(VMError::NoritoInvalid);
    }
    let tlv_type = PointerType::from_u16(type_id).ok_or(VMError::NoritoInvalid)?;
    Ok(Tlv {
        type_id: tlv_type,
        version,
        payload,
    })
}
// Memory-region validation lives in the VM crate, which owns the `Memory` type.
const ABI_V1_POINTER_TYPES: &[PointerType] = &[
    PointerType::AccountId,
    PointerType::AssetDefinitionId,
    PointerType::Name,
    PointerType::Json,
    PointerType::NftId,
    PointerType::Blob,
    PointerType::AssetId,
    PointerType::DomainId,
    PointerType::NoritoBytes,
    PointerType::DataSpaceId,
    PointerType::AxtDescriptor,
    PointerType::ProofBlob,
    PointerType::SoracloudRequest,
    PointerType::SoracloudResponse,
    PointerType::Quantity,
    PointerType::Int,
    PointerType::Decimal,
    PointerType::AxtAnchoredSpendV1,
];
/// Expose the policy allowlist for callers that need to diff surfaces.
pub fn policy_pointer_types(policy: SyscallPolicy) -> &'static HashSet<PointerType> {
    static ABI_V1: OnceLock<HashSet<PointerType>> = OnceLock::new();
    let SyscallPolicy::AbiV1 = policy;
    ABI_V1.get_or_init(|| ABI_V1_POINTER_TYPES.iter().copied().collect())
}
/// Check the static pointer-ABI allowlist without allocating on first use.
pub fn is_type_allowed_for_policy(policy: SyscallPolicy, ty: PointerType) -> bool {
    let SyscallPolicy::AbiV1 = policy;
    ABI_V1_POINTER_TYPES.contains(&ty)
}
thread_local! {
    static ENFORCED_POLICY: Cell<Option<(SyscallPolicy, u8)>> = const { Cell::new(None) };
}
/// Guard that enforces a pointer-ABI policy for the current thread during its lifetime.
pub struct PointerPolicyGuard {
    previous: Option<(SyscallPolicy, u8)>,
    // A thread-local policy must be restored on the thread that installed it.
    _not_send_or_sync: PhantomData<Rc<()>>,
}
impl PointerPolicyGuard {
    /// Install a guard that enforces `policy` and annotates violations with `abi_version`.
    pub fn install(policy: SyscallPolicy, abi_version: u8) -> Self {
        let previous = ENFORCED_POLICY.with(|cell| cell.get());
        ENFORCED_POLICY.with(|cell| cell.set(Some((policy, abi_version))));
        Self {
            previous,
            _not_send_or_sync: PhantomData,
        }
    }
}
impl Drop for PointerPolicyGuard {
    fn drop(&mut self) {
        ENFORCED_POLICY.with(|cell| cell.set(self.previous));
    }
}
/// Return the currently enforced pointer-ABI policy for this thread.
pub fn current_policy() -> Option<(SyscallPolicy, u8)> {
    ENFORCED_POLICY.with(|cell| cell.get())
}
/// Render a markdown table of pointer types and their policy allowlists.
///
/// The format is suitable to be embedded between doc markers in
/// `crates/ivm/docs/pointer_abi.md` and validated by a doc-sync test.
pub fn render_pointer_types_markdown_table() -> String {
    // Keep the list in numeric ID order for stable diffs/readability
    let mut all: Vec<(u16, PointerType)> = vec![
        (PointerType::AccountId as u16, PointerType::AccountId),
        (
            PointerType::AssetDefinitionId as u16,
            PointerType::AssetDefinitionId,
        ),
        (PointerType::Name as u16, PointerType::Name),
        (PointerType::Json as u16, PointerType::Json),
        (PointerType::NftId as u16, PointerType::NftId),
        (PointerType::Blob as u16, PointerType::Blob),
        (PointerType::AssetId as u16, PointerType::AssetId),
        (PointerType::DomainId as u16, PointerType::DomainId),
        (PointerType::NoritoBytes as u16, PointerType::NoritoBytes),
        (PointerType::DataSpaceId as u16, PointerType::DataSpaceId),
        (
            PointerType::AxtDescriptor as u16,
            PointerType::AxtDescriptor,
        ),
        (PointerType::ProofBlob as u16, PointerType::ProofBlob),
        (
            PointerType::SoracloudRequest as u16,
            PointerType::SoracloudRequest,
        ),
        (
            PointerType::SoracloudResponse as u16,
            PointerType::SoracloudResponse,
        ),
        (PointerType::Quantity as u16, PointerType::Quantity),
        (PointerType::Int as u16, PointerType::Int),
        (PointerType::Decimal as u16, PointerType::Decimal),
        (
            PointerType::AxtAnchoredSpendV1 as u16,
            PointerType::AxtAnchoredSpendV1,
        ),
    ];
    all.sort_by_key(|(id, _)| *id);
    let mut out = String::new();
    out.push_str("| ID | Name | ABI v1 |\n");
    out.push_str("|---|---|---|\n");
    for (id, ty) in all {
        let v1 = if is_type_allowed_for_policy(SyscallPolicy::AbiV1, ty) {
            "OK"
        } else {
            "-"
        };
        // name via Debug fmt
        let name = format!("{ty:?}");
        let _ =
            core::fmt::Write::write_fmt(&mut out, format_args!("| 0x{id:04X} | {name} | {v1} |\n"));
    }
    out
}
#[cfg(test)]
mod tests {

    #[test]
    fn canonical_tlv_producer_preserves_exact_v1_bytes_for_all_payload_boundaries() {
        for len in [0usize, 1, 31, 32, 33, 255, 256, 4096] {
            let payload = vec![0xa5; len];
            let encoded = super::encode_tlv(PointerType::Blob, &payload).expect("canonical TLV");
            let mut expected = Vec::new();
            expected.extend_from_slice(&(PointerType::Blob as u16).to_be_bytes());
            expected.push(1);
            expected.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes());
            expected.extend_from_slice(&payload);
            expected.extend_from_slice(iroha_crypto::Hash::new(&payload).as_ref());
            assert_eq!(encoded, expected, "V1 bytes at payload length {len}");
            assert_eq!(validate_tlv_bytes(&encoded).unwrap().payload, payload);
        }
    }

    #[test]
    fn encoded_tlv_authenticates_exact_payload_and_rejects_trailing_bytes() {
        let payload = b"canonical shared pointer payload";
        let mut envelope =
            super::encode_tlv(PointerType::Blob, payload).expect("encode V1 pointer");
        let tlv = validate_tlv_bytes(&envelope).expect("validate V1 pointer");
        assert_eq!(tlv.type_id, PointerType::Blob);
        assert_eq!(tlv.version, 1);
        assert_eq!(tlv.payload, payload);
        envelope.push(0);
        assert!(validate_tlv_bytes(&envelope).is_err());
    }

    use super::{
        PointerPolicyGuard, PointerType, SyscallPolicy, VMError, current_policy,
        is_type_allowed_for_policy, validate_tlv_bytes,
    };
    #[test]
    fn static_policy_membership_matches_the_diagnostic_allowlist() {
        let diagnostic = super::policy_pointer_types(SyscallPolicy::AbiV1);
        assert_eq!(diagnostic.len(), super::ABI_V1_POINTER_TYPES.len());
        for ty in PointerType::all() {
            assert_eq!(
                is_type_allowed_for_policy(SyscallPolicy::AbiV1, *ty),
                diagnostic.contains(ty)
            );
        }
    }
    #[test]
    fn pointer_policy_guard_sets_and_restores() {
        assert!(current_policy().is_none());
        {
            let _guard = PointerPolicyGuard::install(SyscallPolicy::AbiV1, 1);
            assert_eq!(current_policy(), Some((SyscallPolicy::AbiV1, 1)));
        }
        assert!(current_policy().is_none());
    }
    #[test]
    fn pointer_policy_guard_restores_previous() {
        let _first = PointerPolicyGuard::install(SyscallPolicy::AbiV1, 1);
        assert_eq!(current_policy(), Some((SyscallPolicy::AbiV1, 1)));
        {
            let _second = PointerPolicyGuard::install(SyscallPolicy::AbiV1, 7);
            assert_eq!(current_policy(), Some((SyscallPolicy::AbiV1, 7)));
        }
        assert_eq!(current_policy(), Some((SyscallPolicy::AbiV1, 1)));
    }
    #[test]
    fn exact_numeric_pointer_ids_match_the_v1_contract() {
        assert_eq!(PointerType::from_u16(0x0010), Some(PointerType::Quantity));
        assert_eq!(PointerType::from_u16(0x0011), Some(PointerType::Int));
        assert_eq!(PointerType::from_u16(0x0012), Some(PointerType::Decimal));
        assert_eq!(
            PointerType::from_u16(0x0013),
            Some(PointerType::AxtAnchoredSpendV1)
        );
        for ty in [
            PointerType::Quantity,
            PointerType::Int,
            PointerType::Decimal,
            PointerType::AxtAnchoredSpendV1,
        ] {
            assert!(is_type_allowed_for_policy(SyscallPolicy::AbiV1, ty));
        }
    }
    #[test]
    fn envelope_rejects_truncation_and_trailing_bytes() {
        let payload = b"canonical";
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&(PointerType::Int as u16).to_be_bytes());
        envelope.push(1);
        envelope.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        envelope.extend_from_slice(payload);
        envelope.extend_from_slice(iroha_crypto::Hash::new(payload).as_ref());
        assert!(validate_tlv_bytes(&envelope).is_ok());
        let mut truncated = envelope.clone();
        truncated.pop();
        assert!(matches!(
            validate_tlv_bytes(&truncated),
            Err(VMError::NoritoInvalid)
        ));
        let mut trailing = envelope;
        trailing.push(0);
        assert!(matches!(
            validate_tlv_bytes(&trailing),
            Err(VMError::NoritoInvalid)
        ));
    }
    #[test]
    fn envelope_rejects_unassigned_numeric_pointer_id() {
        let payload = b"canonical";
        for type_id in [0x000C_u16, 0x0014_u16] {
            let mut envelope = Vec::new();
            envelope.extend_from_slice(&type_id.to_be_bytes());
            envelope.push(1);
            envelope.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            envelope.extend_from_slice(payload);
            envelope.extend_from_slice(iroha_crypto::Hash::new(payload).as_ref());
            assert!(matches!(
                validate_tlv_bytes(&envelope),
                Err(VMError::NoritoInvalid)
            ));
        }
    }
}

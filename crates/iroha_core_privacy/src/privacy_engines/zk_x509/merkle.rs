//! Canonical SHA-256 commitments used by the first zk-X509 release.
//!
//! The governed trust-anchor set is a compact, fixed-capacity Merkle tree.
//! Publishers sort exact root-SPKI DER byte strings, reject duplicates, hash
//! each occupied leaf, and pad the remaining 4,096 leaves with one
//! domain-separated empty leaf.  Membership therefore needs a private
//! 12-bit index and exactly twelve siblings; the index directly selects the
//! sorted leaf position.
//!
//! Revocation has no second tree.  The complete signed CRL is parsed in the
//! RFC adapter, its `TBSCertList` digest is bound to P-256, and its exact signed
//! DER bytes are domain-framed and hashed to the governed CRL-record digest.
//! Keeping these commitments here gives the native reference code and the SHA
//! adapter one canonical preimage encoder.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::profile::ZK_X509_CA_EMPTY_LEAF_DOMAIN_V1;
use super::profile::{
    ZK_X509_CA_LEAF_DOMAIN_V1, ZK_X509_CA_NODE_DOMAIN_V1, ZK_X509_CRL_DER_DIGEST_DOMAIN_V1,
    ZK_X509_CRL_ISSUER_SPKI_DIGEST_DOMAIN_V1, ZK_X509_HASH_FRAME_DOMAIN_V1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use iroha_data_model::privacy::{
    PrivacyX509ExtendedKeyUsageV1, PrivacyX509KeyUsageV1, PrivacyZkX509CertificatePolicyRecordV1,
    PrivacyZkX509CrlRecordV1, PrivacyZkX509RecordLifecycleV1, PrivacyZkX509TrustAnchorRecordV1,
    ZK_X509_CERTIFICATE_POLICY_RECORD_DIGEST_DOMAIN_V1, ZK_X509_CRL_RECORD_DIGEST_DOMAIN_V1,
    ZK_X509_GOVERNANCE_RECORD_VERSION_V1, ZK_X509_TRUST_ANCHOR_RECORD_DIGEST_DOMAIN_V1,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
/// Number of leaves in the governed compact trust-anchor tree.
pub const ZK_X509_CA_COMPACT_TREE_CAPACITY_V1: usize = 4_096;
/// Depth of the governed compact trust-anchor tree.
pub const ZK_X509_CA_COMPACT_TREE_DEPTH_V1: usize = 12;
/// Exact DER width of the sole admitted uncompressed P-256 SPKI.
pub const ZK_X509_CA_SPKI_DER_BYTES_V1: usize = 91;
/// Maximum exact signed CRL DER bytes admitted by the closed relation.
pub const ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1: usize = 4_096;
/// Exact framed width of every trust-anchor governance record.
pub const ZK_X509_TRUST_ANCHOR_RECORD_PREIMAGE_BYTES_V1: usize = 289;
/// Maximum framed width of a certificate-policy governance record.
pub const ZK_X509_CERTIFICATE_POLICY_RECORD_MAX_PREIMAGE_BYTES_V1: usize = 313;
/// Exact framed width of every signed-CRL governance record.
pub const ZK_X509_CRL_RECORD_PREIMAGE_BYTES_V1: usize = 352;
const _: () = assert!(ZK_X509_CA_COMPACT_TREE_CAPACITY_V1 == 1 << ZK_X509_CA_COMPACT_TREE_DEPTH_V1);
/// One SHA-256 commitment digest.
pub type ZkX509MerkleDigestV1 = [u8; 32];
/// Fixed-shape compact-tree membership witness.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, norito::SerializePayload)]
pub struct ZkX509CaMembershipPathV1 {
    /// Canonical sorted-leaf index.  Only the low twelve bits are legal.
    pub(crate) index: u16,
    /// Siblings ordered from the occupied leaf to the root.
    pub(crate) siblings: [ZkX509MerkleDigestV1; ZK_X509_CA_COMPACT_TREE_DEPTH_V1],
}
/// Commitment construction or membership failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509MerkleErrorV1 {
    /// A mandatory byte string was empty.
    #[error("zk-X509 commitment field {field} must not be empty")]
    EmptyField {
        /// Stable field name.
        field: &'static str,
    },
    /// A P-256 SPKI does not have the one admitted canonical DER width.
    #[error("zk-X509 root SPKI DER has length {actual}; expected {expected}")]
    InvalidSpkiLength {
        /// Supplied length.
        actual: usize,
        /// Canonical length.
        expected: usize,
    },
    /// A publisher supplied no trust anchors.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 trust-anchor set must not be empty")]
    EmptyTrustAnchorSet,
    /// A publisher exceeded the fixed compact-tree capacity.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 trust-anchor set has {actual} entries; maximum is {maximum}")]
    TrustAnchorCapacity {
        /// Supplied entries.
        actual: usize,
        /// Fixed capacity.
        maximum: usize,
    },
    /// A complete publisher input contains the same exact SPKI more than once.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 trust-anchor set contains duplicate exact SPKI DER")]
    DuplicateTrustAnchor,
    /// A requested trust anchor is absent from the complete publisher input.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 requested trust anchor is absent")]
    MissingMember,
    /// A private compact-tree index is outside the fixed capacity.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 compact trust-anchor index {index} is outside the tree")]
    InvalidPathIndex {
        /// Supplied index.
        index: u16,
    },
    /// A derived root does not equal the governed root.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 compact trust-anchor path does not match the governed root")]
    RootMismatch,
    /// Exact signed CRL DER exceeds the closed first-release admission bound.
    #[error("zk-X509 exact signed CRL DER has length {actual}; maximum is {maximum}")]
    CrlTooLarge {
        /// Supplied length.
        actual: usize,
        /// Closed-profile maximum.
        maximum: usize,
    },
    /// A frame label, field count, or field length cannot be represented.
    #[error("zk-X509 SHA-256 frame length overflow")]
    FrameLengthOverflow,
    /// A checked allocation failed.
    #[error("zk-X509 commitment allocation failed")]
    AllocationFailure,
    /// An authoritative governance record is not canonical and self-consistent.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 governance record is invalid")]
    InvalidGovernanceRecord,
}
/// Hash one canonical length-delimited frame.
///
/// The frame is:
/// `frame-domain || u16(domain-len) || domain || u16(field-count) ||
/// repeated(u64(field-len) || field)`.
pub fn hash_frame_v1(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<ZkX509MerkleDigestV1, ZkX509MerkleErrorV1> {
    Ok(Sha256::digest(encode_hash_frame_v1(domain, fields)?).into())
}
/// Encode the sole canonical SHA-256 field frame.
pub fn encode_hash_frame_v1(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<Vec<u8>, ZkX509MerkleErrorV1> {
    if domain.is_empty() {
        return Err(ZkX509MerkleErrorV1::EmptyField { field: "domain" });
    }
    let domain_len =
        u16::try_from(domain.len()).map_err(|_| ZkX509MerkleErrorV1::FrameLengthOverflow)?;
    let field_count =
        u16::try_from(fields.len()).map_err(|_| ZkX509MerkleErrorV1::FrameLengthOverflow)?;
    let encoded_len = fields.iter().try_fold(
        ZK_X509_HASH_FRAME_DOMAIN_V1
            .len()
            .checked_add(2)
            .and_then(|length| length.checked_add(domain.len()))
            .and_then(|length| length.checked_add(2))
            .ok_or(ZkX509MerkleErrorV1::FrameLengthOverflow)?,
        |length, field| {
            u64::try_from(field.len()).map_err(|_| ZkX509MerkleErrorV1::FrameLengthOverflow)?;
            length
                .checked_add(8)
                .and_then(|length| length.checked_add(field.len()))
                .ok_or(ZkX509MerkleErrorV1::FrameLengthOverflow)
        },
    )?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(encoded_len)
        .map_err(|_| ZkX509MerkleErrorV1::AllocationFailure)?;
    frame.extend_from_slice(ZK_X509_HASH_FRAME_DOMAIN_V1);
    frame.extend_from_slice(&domain_len.to_be_bytes());
    frame.extend_from_slice(domain);
    frame.extend_from_slice(&field_count.to_be_bytes());
    for field in fields {
        let field_len =
            u64::try_from(field.len()).map_err(|_| ZkX509MerkleErrorV1::FrameLengthOverflow)?;
        frame.extend_from_slice(&field_len.to_be_bytes());
        frame.extend_from_slice(field);
    }
    if frame.len() != encoded_len {
        return Err(ZkX509MerkleErrorV1::FrameLengthOverflow);
    }
    Ok(frame)
}
fn validate_spki_v1(root_spki_der: &[u8]) -> Result<(), ZkX509MerkleErrorV1> {
    if root_spki_der.is_empty() {
        return Err(ZkX509MerkleErrorV1::EmptyField {
            field: "root_spki_der",
        });
    }
    if root_spki_der.len() != ZK_X509_CA_SPKI_DER_BYTES_V1 {
        return Err(ZkX509MerkleErrorV1::InvalidSpkiLength {
            actual: root_spki_der.len(),
            expected: ZK_X509_CA_SPKI_DER_BYTES_V1,
        });
    }
    Ok(())
}
/// Hash one occupied compact-tree leaf from exact root-SPKI DER.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn ca_leaf_v1(root_spki_der: &[u8]) -> Result<ZkX509MerkleDigestV1, ZkX509MerkleErrorV1> {
    validate_spki_v1(root_spki_der)?;
    hash_frame_v1(ZK_X509_CA_LEAF_DOMAIN_V1, &[root_spki_der])
}
/// Encode one occupied compact-tree leaf preimage for the SHA call manifest.
pub fn ca_leaf_preimage_v1(root_spki_der: &[u8]) -> Result<Vec<u8>, ZkX509MerkleErrorV1> {
    validate_spki_v1(root_spki_der)?;
    encode_hash_frame_v1(ZK_X509_CA_LEAF_DOMAIN_V1, &[root_spki_der])
}
/// Derive the unique padded compact-tree leaf.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn ca_empty_leaf_v1() -> ZkX509MerkleDigestV1 {
    hash_frame_v1(ZK_X509_CA_EMPTY_LEAF_DOMAIN_V1, &[])
        .expect("fixed empty trust-anchor leaf frame is representable")
}
/// Encode one height-bound compact-tree node preimage.
pub fn ca_node_preimage_v1(
    level: usize,
    left: &ZkX509MerkleDigestV1,
    right: &ZkX509MerkleDigestV1,
) -> Result<Vec<u8>, ZkX509MerkleErrorV1> {
    if level >= ZK_X509_CA_COMPACT_TREE_DEPTH_V1 {
        return Err(ZkX509MerkleErrorV1::FrameLengthOverflow);
    }
    let height = u16::try_from(level + 1)
        .map_err(|_| ZkX509MerkleErrorV1::FrameLengthOverflow)?
        .to_be_bytes();
    encode_hash_frame_v1(ZK_X509_CA_NODE_DOMAIN_V1, &[&height, left, right])
}
/// Hash one height-bound compact-tree node.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn ca_node_v1(
    level: usize,
    left: &ZkX509MerkleDigestV1,
    right: &ZkX509MerkleDigestV1,
) -> Result<ZkX509MerkleDigestV1, ZkX509MerkleErrorV1> {
    Ok(Sha256::digest(ca_node_preimage_v1(level, left, right)?).into())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn canonical_spkis_v1<'a>(
    root_spkis_der: &'a [&'a [u8]],
) -> Result<Vec<&'a [u8]>, ZkX509MerkleErrorV1> {
    if root_spkis_der.is_empty() {
        return Err(ZkX509MerkleErrorV1::EmptyTrustAnchorSet);
    }
    if root_spkis_der.len() > ZK_X509_CA_COMPACT_TREE_CAPACITY_V1 {
        return Err(ZkX509MerkleErrorV1::TrustAnchorCapacity {
            actual: root_spkis_der.len(),
            maximum: ZK_X509_CA_COMPACT_TREE_CAPACITY_V1,
        });
    }
    for spki in root_spkis_der {
        validate_spki_v1(spki)?;
    }
    let mut canonical = Vec::new();
    canonical
        .try_reserve_exact(root_spkis_der.len())
        .map_err(|_| ZkX509MerkleErrorV1::AllocationFailure)?;
    canonical.extend_from_slice(root_spkis_der);
    canonical.sort_unstable();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ZkX509MerkleErrorV1::DuplicateTrustAnchor);
    }
    Ok(canonical)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compact_leaf_level_v1(
    canonical_spkis: &[&[u8]],
) -> Result<Vec<ZkX509MerkleDigestV1>, ZkX509MerkleErrorV1> {
    let mut leaves = Vec::new();
    leaves
        .try_reserve_exact(ZK_X509_CA_COMPACT_TREE_CAPACITY_V1)
        .map_err(|_| ZkX509MerkleErrorV1::AllocationFailure)?;
    for spki in canonical_spkis {
        leaves.push(ca_leaf_v1(spki)?);
    }
    leaves.resize(ZK_X509_CA_COMPACT_TREE_CAPACITY_V1, ca_empty_leaf_v1());
    Ok(leaves)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn reduce_compact_level_v1(
    level: usize,
    current: &[ZkX509MerkleDigestV1],
) -> Result<Vec<ZkX509MerkleDigestV1>, ZkX509MerkleErrorV1> {
    if current.len() < 2 || current.len() & 1 != 0 {
        return Err(ZkX509MerkleErrorV1::FrameLengthOverflow);
    }
    let mut parents = Vec::new();
    parents
        .try_reserve_exact(current.len() / 2)
        .map_err(|_| ZkX509MerkleErrorV1::AllocationFailure)?;
    for children in current.chunks_exact(2) {
        parents.push(ca_node_v1(level, &children[0], &children[1])?);
    }
    Ok(parents)
}
/// Construct the canonical fixed-capacity governed trust-anchor root.
///
/// Caller order is ignored.  Exact SPKI DER byte strings are sorted, duplicate
/// strings are rejected, and all unused leaves receive the unique empty-leaf
/// digest.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn ca_root_from_complete_spkis_v1(
    root_spkis_der: &[&[u8]],
) -> Result<ZkX509MerkleDigestV1, ZkX509MerkleErrorV1> {
    let canonical = canonical_spkis_v1(root_spkis_der)?;
    let mut level_nodes = compact_leaf_level_v1(&canonical)?;
    for level in 0..ZK_X509_CA_COMPACT_TREE_DEPTH_V1 {
        level_nodes = reduce_compact_level_v1(level, &level_nodes)?;
    }
    level_nodes
        .first()
        .copied()
        .filter(|_| level_nodes.len() == 1)
        .ok_or(ZkX509MerkleErrorV1::FrameLengthOverflow)
}
/// Construct the unique compact-tree membership witness for one governed SPKI.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn ca_membership_path_from_complete_spkis_v1(
    root_spkis_der: &[&[u8]],
    member_spki_der: &[u8],
) -> Result<ZkX509CaMembershipPathV1, ZkX509MerkleErrorV1> {
    validate_spki_v1(member_spki_der)?;
    let canonical = canonical_spkis_v1(root_spkis_der)?;
    let mut index = canonical
        .binary_search(&member_spki_der)
        .map_err(|_| ZkX509MerkleErrorV1::MissingMember)?;
    let original_index =
        u16::try_from(index).map_err(|_| ZkX509MerkleErrorV1::FrameLengthOverflow)?;
    let mut level_nodes = compact_leaf_level_v1(&canonical)?;
    let mut siblings = [[0_u8; 32]; ZK_X509_CA_COMPACT_TREE_DEPTH_V1];
    for (level, sibling) in siblings.iter_mut().enumerate() {
        *sibling = *level_nodes
            .get(index ^ 1)
            .ok_or(ZkX509MerkleErrorV1::FrameLengthOverflow)?;
        level_nodes = reduce_compact_level_v1(level, &level_nodes)?;
        index >>= 1;
    }
    Ok(ZkX509CaMembershipPathV1 {
        index: original_index,
        siblings,
    })
}
/// Reconstruct the compact governed root selected by one private path.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn ca_root_from_path_v1(
    root_spki_der: &[u8],
    path: &ZkX509CaMembershipPathV1,
) -> Result<ZkX509MerkleDigestV1, ZkX509MerkleErrorV1> {
    if usize::from(path.index) >= ZK_X509_CA_COMPACT_TREE_CAPACITY_V1 {
        return Err(ZkX509MerkleErrorV1::InvalidPathIndex { index: path.index });
    }
    let mut current = ca_leaf_v1(root_spki_der)?;
    for (level, sibling) in path.siblings.iter().enumerate() {
        let (left, right) = if path.index & (1 << level) == 0 {
            (&current, sibling)
        } else {
            (sibling, &current)
        };
        current = ca_node_v1(level, left, right)?;
    }
    Ok(current)
}
/// Verify compact trust-anchor membership against the governed root.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn verify_ca_membership_v1(
    governed_root: ZkX509MerkleDigestV1,
    root_spki_der: &[u8],
    path: &ZkX509CaMembershipPathV1,
) -> Result<(), ZkX509MerkleErrorV1> {
    if ca_root_from_path_v1(root_spki_der, path)? != governed_root {
        return Err(ZkX509MerkleErrorV1::RootMismatch);
    }
    Ok(())
}
/// Encode the exact signed CRL commitment preimage.
pub fn crl_commitment_preimage_v1(
    exact_signed_crl_der: &[u8],
) -> Result<Vec<u8>, ZkX509MerkleErrorV1> {
    if exact_signed_crl_der.is_empty() {
        return Err(ZkX509MerkleErrorV1::EmptyField {
            field: "exact_signed_crl_der",
        });
    }
    if exact_signed_crl_der.len() > ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1 {
        return Err(ZkX509MerkleErrorV1::CrlTooLarge {
            actual: exact_signed_crl_der.len(),
            maximum: ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1,
        });
    }
    encode_hash_frame_v1(ZK_X509_CRL_DER_DIGEST_DOMAIN_V1, &[exact_signed_crl_der])
}
/// Hash the exact complete signed CRL to the governed record commitment.
#[cfg(test)]
pub fn crl_commitment_v1(
    exact_signed_crl_der: &[u8],
) -> Result<ZkX509MerkleDigestV1, ZkX509MerkleErrorV1> {
    Ok(Sha256::digest(crl_commitment_preimage_v1(exact_signed_crl_der)?).into())
}
/// Encode the exact issuer-SPKI digest preimage governed by the CRL record.
pub fn crl_issuer_spki_preimage_v1(issuer_spki_der: &[u8]) -> Result<Vec<u8>, ZkX509MerkleErrorV1> {
    validate_spki_v1(issuer_spki_der)?;
    encode_hash_frame_v1(ZK_X509_CRL_ISSUER_SPKI_DIGEST_DOMAIN_V1, &[issuer_spki_der])
}
/// Hash the exact CRL issuer SPKI to the governed record digest.
#[cfg(test)]
pub fn crl_issuer_spki_digest_v1(
    issuer_spki_der: &[u8],
) -> Result<ZkX509MerkleDigestV1, ZkX509MerkleErrorV1> {
    Ok(Sha256::digest(crl_issuer_spki_preimage_v1(issuer_spki_der)?).into())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn governance_predecessor_v1(previous: Option<&[u8; 32]>) -> [u8; 33] {
    let mut framed = [0_u8; 33];
    if let Some(previous) = previous {
        framed[0] = 1;
        framed[1..].copy_from_slice(previous);
    }
    framed
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
const fn governance_lifecycle_v1(lifecycle: PrivacyZkX509RecordLifecycleV1) -> [u8; 1] {
    [match lifecycle {
        PrivacyZkX509RecordLifecycleV1::Active => 0,
        PrivacyZkX509RecordLifecycleV1::Revoked => 1,
    }]
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn governance_key_usage_v1(key_usage: PrivacyX509KeyUsageV1) -> [u8; 1] {
    [u8::from(key_usage.digital_signature.is_required())
        | (u8::from(key_usage.content_commitment.is_required()) << 1)
        | (u8::from(key_usage.key_encipherment.is_required()) << 2)
        | (u8::from(key_usage.key_agreement.is_required()) << 3)]
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
const fn governance_eku_code_v1(usage: PrivacyX509ExtendedKeyUsageV1) -> u8 {
    match usage {
        PrivacyX509ExtendedKeyUsageV1::ClientAuthentication => 0,
        PrivacyX509ExtendedKeyUsageV1::DocumentSigning => 1,
        PrivacyX509ExtendedKeyUsageV1::WalletIdentity => 2,
    }
}
/// Encode the exact trust-anchor governance-record digest preimage.
///
/// This is an independent proof-side encoder for the data-model self-digest.
/// Keeping the explicit fields here prevents the prover from treating the
/// public record digest as an unconstrained host assertion.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn trust_anchor_record_preimage_v1(
    record: &PrivacyZkX509TrustAnchorRecordV1,
) -> Result<Vec<u8>, ZkX509MerkleErrorV1> {
    record
        .validate()
        .map_err(|_| ZkX509MerkleErrorV1::InvalidGovernanceRecord)?;
    let version = ZK_X509_GOVERNANCE_RECORD_VERSION_V1.to_be_bytes();
    let record_epoch = record.record_epoch.to_be_bytes();
    let root_epoch = record.ca_membership_root_epoch.to_be_bytes();
    let predecessor = governance_predecessor_v1(
        record
            .previous_record_digest
            .as_ref()
            .map(|value| value.as_bytes()),
    );
    let lifecycle = governance_lifecycle_v1(record.lifecycle);
    let preimage = encode_hash_frame_v1(
        ZK_X509_TRUST_ANCHOR_RECORD_DIGEST_DOMAIN_V1,
        &[
            &version,
            record.trust_anchor_id.as_bytes(),
            &record_epoch,
            record.trust_store_digest.as_bytes(),
            record.ca_membership_root.as_bytes(),
            &root_epoch,
            &predecessor,
            &lifecycle,
        ],
    )?;
    if preimage.len() != ZK_X509_TRUST_ANCHOR_RECORD_PREIMAGE_BYTES_V1 {
        return Err(ZkX509MerkleErrorV1::FrameLengthOverflow);
    }
    Ok(preimage)
}
/// Encode the exact certificate-policy governance-record digest preimage.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn certificate_policy_record_preimage_v1(
    record: &PrivacyZkX509CertificatePolicyRecordV1,
) -> Result<Vec<u8>, ZkX509MerkleErrorV1> {
    record
        .validate()
        .map_err(|_| ZkX509MerkleErrorV1::InvalidGovernanceRecord)?;
    let version = ZK_X509_GOVERNANCE_RECORD_VERSION_V1.to_be_bytes();
    let record_epoch = record.record_epoch.to_be_bytes();
    let key_usage = governance_key_usage_v1(record.required_key_usage);
    let mut extended_key_usages = Vec::new();
    extended_key_usages
        .try_reserve_exact(1 + record.required_extended_key_usages.len())
        .map_err(|_| ZkX509MerkleErrorV1::AllocationFailure)?;
    extended_key_usages.push(
        u8::try_from(record.required_extended_key_usages.len())
            .map_err(|_| ZkX509MerkleErrorV1::FrameLengthOverflow)?,
    );
    extended_key_usages.extend(
        record
            .required_extended_key_usages
            .iter()
            .copied()
            .map(governance_eku_code_v1),
    );
    let mut disclosures = Vec::new();
    disclosures
        .try_reserve_exact(1 + record.required_disclosed_attribute_indices.len())
        .map_err(|_| ZkX509MerkleErrorV1::AllocationFailure)?;
    disclosures.push(
        u8::try_from(record.required_disclosed_attribute_indices.len())
            .map_err(|_| ZkX509MerkleErrorV1::FrameLengthOverflow)?,
    );
    disclosures.extend_from_slice(&record.required_disclosed_attribute_indices);
    let predecessor = governance_predecessor_v1(
        record
            .previous_record_digest
            .as_ref()
            .map(|value| value.as_bytes()),
    );
    let lifecycle = governance_lifecycle_v1(record.lifecycle);
    let preimage = encode_hash_frame_v1(
        ZK_X509_CERTIFICATE_POLICY_RECORD_DIGEST_DOMAIN_V1,
        &[
            &version,
            record.trust_anchor_id.as_bytes(),
            record.policy_id.as_bytes(),
            &record_epoch,
            record.policy_digest.as_bytes(),
            &key_usage,
            &extended_key_usages,
            &disclosures,
            &predecessor,
            &lifecycle,
        ],
    )?;
    if preimage.len() > ZK_X509_CERTIFICATE_POLICY_RECORD_MAX_PREIMAGE_BYTES_V1 {
        return Err(ZkX509MerkleErrorV1::FrameLengthOverflow);
    }
    Ok(preimage)
}
/// Encode the exact signed-CRL governance-record digest preimage.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn crl_record_preimage_v1(
    record: &PrivacyZkX509CrlRecordV1,
) -> Result<Vec<u8>, ZkX509MerkleErrorV1> {
    record
        .validate()
        .map_err(|_| ZkX509MerkleErrorV1::InvalidGovernanceRecord)?;
    let version = ZK_X509_GOVERNANCE_RECORD_VERSION_V1.to_be_bytes();
    let record_epoch = record.record_epoch.to_be_bytes();
    let crl_number = record.crl_number.to_be_bytes();
    let this_update = record.this_update_unix_seconds.to_be_bytes();
    let next_update = record.next_update_unix_seconds.to_be_bytes();
    let predecessor = governance_predecessor_v1(
        record
            .previous_record_digest
            .as_ref()
            .map(|value| value.as_bytes()),
    );
    let lifecycle = governance_lifecycle_v1(record.lifecycle);
    let preimage = encode_hash_frame_v1(
        ZK_X509_CRL_RECORD_DIGEST_DOMAIN_V1,
        &[
            &version,
            record.trust_anchor_id.as_bytes(),
            record.certificate_policy_id.as_bytes(),
            &record_epoch,
            &crl_number,
            record.crl_der_digest.as_bytes(),
            record.issuer_spki_digest.as_bytes(),
            &this_update,
            &next_update,
            &predecessor,
            &lifecycle,
        ],
    )?;
    if preimage.len() != ZK_X509_CRL_RECORD_PREIMAGE_BYTES_V1 {
        return Err(ZkX509MerkleErrorV1::FrameLengthOverflow);
    }
    Ok(preimage)
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::privacy::{
        PrivacyIssuerIdV1, PrivacyPolicyDigestV1, PrivacyPolicyIdV1, PrivacyRootV1,
        PrivacyX509CrlDerDigestV1, PrivacyX509CrlIssuerSpkiDigestV1,
        PrivacyX509KeyUsageRequirementV1, PrivacyX509TrustStoreDigestV1,
    };
    fn spki(index: u16) -> [u8; ZK_X509_CA_SPKI_DER_BYTES_V1] {
        let mut value = [0x42_u8; ZK_X509_CA_SPKI_DER_BYTES_V1];
        value[..2].copy_from_slice(&index.to_be_bytes());
        value
    }
    fn complete_set(count: usize) -> Vec<[u8; ZK_X509_CA_SPKI_DER_BYTES_V1]> {
        (0..count)
            .map(|index| spki(u16::try_from(index).expect("test index")))
            .collect()
    }
    fn hex32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        core::array::from_fn(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("test hex byte")
        })
    }
    #[test]
    fn canonical_frame_is_unambiguous_and_domain_separated() {
        let encoded = encode_hash_frame_v1(b"d", &[b"ab", b"c"]).expect("frame");
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&encoded)), {
            hash_frame_v1(b"d", &[b"ab", b"c"]).expect("digest")
        });
        assert_ne!(
            hash_frame_v1(b"d", &[b"ab", b"c"]).expect("digest"),
            hash_frame_v1(b"d", &[b"a", b"bc"]).expect("digest")
        );
        assert_ne!(
            hash_frame_v1(b"d", &[b"ab", b"c"]).expect("digest"),
            hash_frame_v1(b"e", &[b"ab", b"c"]).expect("digest")
        );
        assert_eq!(
            encode_hash_frame_v1(&[], &[]),
            Err(ZkX509MerkleErrorV1::EmptyField { field: "domain" })
        );
    }
    #[test]
    fn governance_preimages_cross_check_the_data_model_known_answers() {
        let trust = PrivacyZkX509TrustAnchorRecordV1::new(
            PrivacyIssuerIdV1::new([0x11; 32]),
            1,
            PrivacyX509TrustStoreDigestV1::new([0x22; 32]),
            PrivacyRootV1::new([0x33; 32]),
            1,
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        )
        .expect("trust record");
        let trust_preimage = trust_anchor_record_preimage_v1(&trust).expect("trust preimage");
        assert_eq!(
            trust_preimage.len(),
            ZK_X509_TRUST_ANCHOR_RECORD_PREIMAGE_BYTES_V1
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(trust_preimage)),
            hex32("e4a0cf77fc1f0acefeeb98e62c74f718a2aa44e6471f7d1ee4d8b9022743e429")
        );
        assert_eq!(
            trust.record_digest.as_bytes(),
            &hex32("e4a0cf77fc1f0acefeeb98e62c74f718a2aa44e6471f7d1ee4d8b9022743e429")
        );
        let policy = PrivacyZkX509CertificatePolicyRecordV1::new(
            PrivacyIssuerIdV1::new([0x11; 32]),
            PrivacyPolicyIdV1::new([0x22; 32]),
            1,
            PrivacyPolicyDigestV1::new([0x33; 32]),
            PrivacyX509KeyUsageV1 {
                digital_signature: PrivacyX509KeyUsageRequirementV1::new(true),
                content_commitment: PrivacyX509KeyUsageRequirementV1::new(false),
                key_encipherment: PrivacyX509KeyUsageRequirementV1::new(false),
                key_agreement: PrivacyX509KeyUsageRequirementV1::new(false),
            },
            vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
            ],
            vec![0, 3],
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        )
        .expect("policy record");
        let policy_preimage =
            certificate_policy_record_preimage_v1(&policy).expect("policy preimage");
        assert!(policy_preimage.len() <= ZK_X509_CERTIFICATE_POLICY_RECORD_MAX_PREIMAGE_BYTES_V1);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(policy_preimage)),
            hex32("9a1b485c0566abe3130bf29cacb9e2108adb6372174f8578021019a2f58c8ab0")
        );
        let maximum_policy = PrivacyZkX509CertificatePolicyRecordV1::new(
            PrivacyIssuerIdV1::new([0x11; 32]),
            PrivacyPolicyIdV1::new([0x22; 32]),
            2,
            PrivacyPolicyDigestV1::new([0x33; 32]),
            PrivacyX509KeyUsageV1 {
                digital_signature: PrivacyX509KeyUsageRequirementV1::new(true),
                content_commitment: PrivacyX509KeyUsageRequirementV1::new(true),
                key_encipherment: PrivacyX509KeyUsageRequirementV1::new(true),
                key_agreement: PrivacyX509KeyUsageRequirementV1::new(true),
            },
            vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::DocumentSigning,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
            ],
            vec![0, 1, 2, 3],
            Some(policy.record_digest),
            PrivacyZkX509RecordLifecycleV1::Active,
        )
        .expect("maximum policy record");
        assert_eq!(
            certificate_policy_record_preimage_v1(&maximum_policy)
                .expect("maximum policy preimage")
                .len(),
            ZK_X509_CERTIFICATE_POLICY_RECORD_MAX_PREIMAGE_BYTES_V1
        );
        let crl = PrivacyZkX509CrlRecordV1::new(
            PrivacyIssuerIdV1::new([0x11; 32]),
            PrivacyPolicyIdV1::new([0x22; 32]),
            1,
            42,
            PrivacyX509CrlDerDigestV1::new(hex32(
                "bfa3e6225fbdc178b8595c06d8fb7ac8c48bcbf22370733501284b73fbba7e98",
            )),
            PrivacyX509CrlIssuerSpkiDigestV1::new(hex32(
                "f7e1ecd75dd0aee92a81c2e8cfbb22cdee73ba8700b64349f6331d989d2b4400",
            )),
            1_700_000_000,
            1_700_000_300,
            None,
            PrivacyZkX509RecordLifecycleV1::Active,
        )
        .expect("CRL record");
        let crl_preimage = crl_record_preimage_v1(&crl).expect("CRL preimage");
        assert_eq!(crl_preimage.len(), ZK_X509_CRL_RECORD_PREIMAGE_BYTES_V1);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(crl_preimage)),
            hex32("d9cc3938a2fb3b8407f17c9e71ce926c627c144c1bf6c6a89a5fa2b73176c64d")
        );
        let mut tampered = trust;
        tampered.record_digest =
            iroha_data_model::privacy::PrivacyZkX509TrustAnchorRecordDigestV1::new([0x99; 32]);
        assert_eq!(
            trust_anchor_record_preimage_v1(&tampered),
            Err(ZkX509MerkleErrorV1::InvalidGovernanceRecord)
        );
    }
    #[test]
    fn compact_root_is_order_independent_but_duplicate_intolerant() {
        let values = complete_set(4);
        let forward = values
            .iter()
            .map(|value: &[u8; ZK_X509_CA_SPKI_DER_BYTES_V1]| value.as_slice())
            .collect::<Vec<_>>();
        let reverse = values
            .iter()
            .rev()
            .map(|value: &[u8; ZK_X509_CA_SPKI_DER_BYTES_V1]| value.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(
            ca_root_from_complete_spkis_v1(&forward).expect("forward"),
            ca_root_from_complete_spkis_v1(&reverse).expect("reverse")
        );
        let duplicate = [
            values[0].as_slice(),
            values[1].as_slice(),
            values[0].as_slice(),
        ];
        assert_eq!(
            ca_root_from_complete_spkis_v1(&duplicate),
            Err(ZkX509MerkleErrorV1::DuplicateTrustAnchor)
        );
        assert_eq!(
            ca_root_from_complete_spkis_v1(&[]),
            Err(ZkX509MerkleErrorV1::EmptyTrustAnchorSet)
        );
    }
    #[test]
    fn membership_covers_first_last_and_capacity_boundary() {
        let values = complete_set(ZK_X509_CA_COMPACT_TREE_CAPACITY_V1);
        let refs = values
            .iter()
            .map(|value: &[u8; ZK_X509_CA_SPKI_DER_BYTES_V1]| value.as_slice())
            .collect::<Vec<_>>();
        let root = ca_root_from_complete_spkis_v1(&refs).expect("root");
        for index in [0, 1, 2_047, 4_095] {
            let path =
                ca_membership_path_from_complete_spkis_v1(&refs, &values[index]).expect("path");
            assert_eq!(usize::from(path.index), index);
            verify_ca_membership_v1(root, &values[index], &path).expect("membership");
        }
        let extra = spki(4_096);
        let mut over_capacity = refs;
        over_capacity.push(&extra);
        assert_eq!(
            ca_root_from_complete_spkis_v1(&over_capacity),
            Err(ZkX509MerkleErrorV1::TrustAnchorCapacity {
                actual: ZK_X509_CA_COMPACT_TREE_CAPACITY_V1 + 1,
                maximum: ZK_X509_CA_COMPACT_TREE_CAPACITY_V1,
            })
        );
    }
    #[test]
    fn membership_rejects_wrong_index_sibling_member_and_root() {
        let values = complete_set(5);
        let refs = values
            .iter()
            .map(|value: &[u8; ZK_X509_CA_SPKI_DER_BYTES_V1]| value.as_slice())
            .collect::<Vec<_>>();
        let root = ca_root_from_complete_spkis_v1(&refs).expect("root");
        let path =
            ca_membership_path_from_complete_spkis_v1(&refs, &values[3]).expect("membership");
        let mut wrong_index = path;
        wrong_index.index ^= 1;
        assert_eq!(
            verify_ca_membership_v1(root, &values[3], &wrong_index),
            Err(ZkX509MerkleErrorV1::RootMismatch)
        );
        let mut wrong_sibling = path;
        wrong_sibling.siblings[0][0] ^= 1;
        assert_eq!(
            verify_ca_membership_v1(root, &values[3], &wrong_sibling),
            Err(ZkX509MerkleErrorV1::RootMismatch)
        );
        let absent = spki(8_000);
        assert_eq!(
            ca_membership_path_from_complete_spkis_v1(&refs, &absent),
            Err(ZkX509MerkleErrorV1::MissingMember)
        );
        assert_eq!(
            verify_ca_membership_v1([0; 32], &values[3], &path),
            Err(ZkX509MerkleErrorV1::RootMismatch)
        );
    }
    #[test]
    fn invalid_spki_lengths_and_path_indices_fail_closed() {
        assert_eq!(
            ca_leaf_v1(&[]),
            Err(ZkX509MerkleErrorV1::EmptyField {
                field: "root_spki_der",
            })
        );
        assert_eq!(
            ca_leaf_v1(&[0; ZK_X509_CA_SPKI_DER_BYTES_V1 - 1]),
            Err(ZkX509MerkleErrorV1::InvalidSpkiLength {
                actual: ZK_X509_CA_SPKI_DER_BYTES_V1 - 1,
                expected: ZK_X509_CA_SPKI_DER_BYTES_V1,
            })
        );
        let path = ZkX509CaMembershipPathV1 {
            index: u16::try_from(ZK_X509_CA_COMPACT_TREE_CAPACITY_V1).expect("capacity fits u16"),
            siblings: [[0; 32]; ZK_X509_CA_COMPACT_TREE_DEPTH_V1],
        };
        assert_eq!(
            ca_root_from_path_v1(&spki(1), &path),
            Err(ZkX509MerkleErrorV1::InvalidPathIndex { index: 4_096 })
        );
    }
    #[test]
    fn crl_commitments_match_data_model_and_enforce_bounds() {
        let exact_crl = b"0\\x03\\x02\\x01\\x01";
        assert_eq!(
            crl_commitment_v1(exact_crl).expect("CRL commitment"),
            *PrivacyX509CrlDerDigestV1::digest_exact_der(exact_crl).as_bytes()
        );
        let issuer = spki(7);
        assert_eq!(
            crl_issuer_spki_digest_v1(&issuer).expect("issuer commitment"),
            *PrivacyX509CrlIssuerSpkiDigestV1::digest_exact_der(&issuer).as_bytes()
        );
        assert_eq!(
            crl_commitment_preimage_v1(&[]),
            Err(ZkX509MerkleErrorV1::EmptyField {
                field: "exact_signed_crl_der",
            })
        );
        assert_eq!(
            crl_commitment_preimage_v1(&[0; ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1 + 1]),
            Err(ZkX509MerkleErrorV1::CrlTooLarge {
                actual: ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1 + 1,
                maximum: ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1,
            })
        );
    }
    #[test]
    fn exact_frame_lengths_fix_the_sha_resource_schedule() {
        let issuer = spki(9);
        assert_eq!(ca_leaf_preimage_v1(&issuer).expect("leaf").len(), 156);
        assert_eq!(
            ca_node_preimage_v1(0, &[1; 32], &[2; 32])
                .expect("node")
                .len(),
            147
        );
        assert_eq!(
            crl_issuer_spki_preimage_v1(&issuer).expect("issuer").len(),
            164
        );
        assert_eq!(
            crl_commitment_preimage_v1(&[0; ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1])
                .expect("CRL")
                .len(),
            4_161
        );
    }
}

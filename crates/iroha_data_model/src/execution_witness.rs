//! Canonical key namespace for the ordinary execution-witness sparse tree.
//!
//! Tagged recorder and synthetic families reserve their first byte here. Distinct
//! enum discriminants make overlapping tagged families a compile error. Existing
//! text-domain-separated lane and private-dataspace keys keep their complete
//! namespaces. The enum is not a separately serialized Norito value.

/// Disjoint first-byte namespaces for execution-witness keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecutionWitnessKeyTagV1 {
    /// Account metadata: account identifier and metadata name.
    AccountMetadata = 0xA1,
    /// Domain metadata: domain identifier and metadata name.
    DomainMetadata = 0xA2,
    /// NFT metadata: NFT identifier and metadata name.
    NftMetadata = 0xA3,
    /// Asset-definition metadata: definition identifier and metadata name.
    AssetDefinitionMetadata = 0xA4,
    /// Asset balance by asset identifier.
    AssetBalance = 0xB1,
    /// Asset-definition total supply by definition identifier.
    AssetDefinitionTotalSupply = 0xB2,
    /// Account-to-role binding by account and role identifiers.
    AccountRoleBinding = 0xC1,
    /// Role presence by role identifier.
    Role = 0xC2,
    /// Account permission by account identifier and permission name.
    AccountPermission = 0xC3,
    /// Role permission by role identifier and permission name.
    RolePermission = 0xC4,
    /// Fixed validation-fee policy-registry snapshot.
    ValidationFeePolicy = 0xD4,
    /// Fixed Parliament timed-OVN casting-context snapshot.
    ParliamentTimedOvnCasting = 0xD5,
    /// Fixed ordinary FASTPQ source-statement manifest, derived by validator execution.
    FastpqOrdinarySourceStatements = 0xD7,
    /// Fixed SCCP state-delta witness; the exact SCCP key bytes remain unchanged.
    SccpStateDelta = 0xD8,
    /// AMX records bind begin/commit/abort, replay and terminal witnesses.
    /// `0xD8` remains owned by the SCCP state-delta witness family.
    AmxRecord = 0xD9,
    /// Certified post-block retail fee evidence snapshot.
    FeeSnapshot = 0xDA,
    /// A canonical retained retail receipt or validator allocation original.
    FeeRecord = 0xDB,
    /// Bounded historical staking exposure under original certified block custody.
    RewardExposureArchive = 0xDC,
}

const fn tagged_fixed_key<const N: usize>(
    tag: ExecutionWitnessKeyTagV1,
    mut key: [u8; N],
) -> [u8; N] {
    key[0] = tag as u8;
    key
}

/// Fixed validation-fee policy key committed by every executed block.
pub const VALIDATION_FEE_POLICY_WITNESS_KEY_V1: &[u8] = &tagged_fixed_key(
    ExecutionWitnessKeyTagV1::ValidationFeePolicy,
    *b"\0iroha:validation-fee:policy-registry:v1",
);

/// Fixed Parliament casting-context key committed by every executed block.
pub const PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1: &[u8] = &tagged_fixed_key(
    ExecutionWitnessKeyTagV1::ParliamentTimedOvnCasting,
    *b"\0iroha:parliament:timed-ovn:casting-contexts:v1",
);

/// Protected fixed key for the canonical ordinary FASTPQ source-statement manifest.
///
/// Reserving this namespace does not enable compact proof admission. Only the
/// validator-derived complete projection may be inserted under this key.
pub const FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1: &[u8] = &tagged_fixed_key(
    ExecutionWitnessKeyTagV1::FastpqOrdinarySourceStatements,
    *b"\0iroha:fastpq:ordinary-source-statements:v1",
);

/// Fixed per-block native fee accounting snapshot key.
pub const FEE_EVIDENCE_WITNESS_KEY_V1: &[u8] = &tagged_fixed_key(
    ExecutionWitnessKeyTagV1::FeeSnapshot,
    *b"\0iroha:fee-evidence:root:v1",
);
/// Reserved family for native fee record bytes in an execution witness.
pub const FEE_EVIDENCE_RECORD_TAG_V1: u8 = ExecutionWitnessKeyTagV1::FeeRecord as u8;
/// Reserved family for canonical historical staking exposure archive bytes.
pub const REWARD_EXPOSURE_ARCHIVE_TAG_V1: u8 =
    ExecutionWitnessKeyTagV1::RewardExposureArchive as u8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_and_synthetic_key_families_are_disjoint() {
        use ExecutionWitnessKeyTagV1::*;
        let tags = [
            AccountMetadata,
            DomainMetadata,
            NftMetadata,
            AssetDefinitionMetadata,
            AssetBalance,
            AssetDefinitionTotalSupply,
            AccountRoleBinding,
            Role,
            AccountPermission,
            RolePermission,
            ValidationFeePolicy,
            ParliamentTimedOvnCasting,
            FastpqOrdinarySourceStatements,
            SccpStateDelta,
            AmxRecord,
            FeeSnapshot,
            FeeRecord,
            RewardExposureArchive,
        ];
        let distinct = tags
            .into_iter()
            .map(|tag| tag as u8)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(distinct.len(), tags.len());
        assert_eq!(
            VALIDATION_FEE_POLICY_WITNESS_KEY_V1,
            b"\xd4iroha:validation-fee:policy-registry:v1"
        );
        assert_eq!(
            PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1,
            b"\xd5iroha:parliament:timed-ovn:casting-contexts:v1"
        );
        assert_eq!(
            FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
            b"\xd7iroha:fastpq:ordinary-source-statements:v1"
        );
        let fixed = [
            VALIDATION_FEE_POLICY_WITNESS_KEY_V1,
            PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1,
            FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
            FEE_EVIDENCE_WITNESS_KEY_V1,
        ]
        .map(|key| key[0])
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            fixed.len(),
            4,
            "fixed-key prefix selectors must be disjoint"
        );
        assert!(!fixed.contains(&FEE_EVIDENCE_RECORD_TAG_V1));
        assert!(!fixed.contains(&REWARD_EXPOSURE_ARCHIVE_TAG_V1));
        assert_eq!(REWARD_EXPOSURE_ARCHIVE_TAG_V1, 0xDC);
    }
}

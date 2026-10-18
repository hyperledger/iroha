//! Verifier-owned zk-X509 public-input and release-profile declarations.
//!
//! These declarations remain part of every node build. They depend only on the typed consensus
//! statement and authoritative finalized state; private witness parsing and proof construction live
//! behind the release-evidence boundary.
use super::der_air::{ZkX509DerEkuV1, ZkX509Rfc5280StatementV1};
use crate::privacy_state::PrivacyZkX509AuthoritativeStateV1;
use iroha_data_model::privacy::{IrohaZkX509StarkP256StatementV1, PrivacyX509ExtendedKeyUsageV1};
/// Manifest descriptor for the verifier-bound local SHA-256 circuit.
pub const ZK_X509_SHA256_LOCAL_AIR_DESCRIPTOR_V1: &[u8] = b"sha256-local-air-v1:canonical-padding:private-message-length:word-input-bits-le:sha256-bytes-be:boolean-and-xor-full-adder:gates-per-block=55552:fixed-canonical-topology:acyclic-single-assignment-wire-addresses:mod2^32-carry-discard:output-digest-reconstruction:global-wire-copy-and-cross-segment-binding=complete-via-sha256-word-air+sha-call-bus-stark";
/// Stable identity of the canonical production material assembler.
pub const ZK_X509_MAIN_ASSEMBLY_DESCRIPTOR_V1: &[u8] =
    b"zk-x509-main-assembly-v1-incompatible:strict-reference-prover-invariant:exact-der-rfc-projection-ca-sources:29-verifier-positioned-sha-witnesses:five-p256-equations:selected-input-byte-pairs40960to41119-bound-to-writers47-48-52-53-and-digest-word:small-multiplicity-polynomial012:optional-slot2-rfc-zero-source-and-public-valid-dummy-selector:statement-compiled-deduplicated-sequential-byte-io:exact-witness-declaration-replay:logical-active-row-census:exact49-registrations:no-host-verification-substitute:public-terminal-replay-and-private-committed-endpoint-air-links=complete:no-unmasked-der-rfc-source-or-p256-terminal-scalars:activation=governance-gated";
const KEY_USAGE_DIGITAL_SIGNATURE_V1: u16 = 1 << 0;
const KEY_USAGE_CONTENT_COMMITMENT_V1: u16 = 1 << 1;
const KEY_USAGE_KEY_ENCIPHERMENT_V1: u16 = 1 << 2;
const KEY_USAGE_KEY_AGREEMENT_V1: u16 = 1 << 4;
pub fn rfc_statement_with_crl_number_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    crl_number: u64,
) -> ZkX509Rfc5280StatementV1 {
    let key_usage = u16::from(statement.key_usage.digital_signature.is_required())
        * KEY_USAGE_DIGITAL_SIGNATURE_V1
        | u16::from(statement.key_usage.content_commitment.is_required())
            * KEY_USAGE_CONTENT_COMMITMENT_V1
        | u16::from(statement.key_usage.key_encipherment.is_required())
            * KEY_USAGE_KEY_ENCIPHERMENT_V1
        | u16::from(statement.key_usage.key_agreement.is_required()) * KEY_USAGE_KEY_AGREEMENT_V1;
    let leaf_extended_key_usages = statement
        .extended_key_usages
        .iter()
        .map(|usage| match usage {
            PrivacyX509ExtendedKeyUsageV1::ClientAuthentication => {
                ZkX509DerEkuV1::ClientAuthentication
            }
            PrivacyX509ExtendedKeyUsageV1::DocumentSigning => ZkX509DerEkuV1::DocumentSigning,
            PrivacyX509ExtendedKeyUsageV1::WalletIdentity => ZkX509DerEkuV1::WalletIdentity,
        })
        .collect();
    ZkX509Rfc5280StatementV1 {
        presentation_not_before_unix_seconds: statement.presentation_not_before_unix_seconds,
        presentation_not_after_unix_seconds: statement.presentation_not_after_unix_seconds,
        leaf_key_usage: key_usage,
        leaf_extended_key_usages,
        crl_number,
        disclosed_attribute_indices: statement
            .disclosed_attributes
            .iter()
            .map(|attribute| attribute.index)
            .collect(),
    }
}
/// Compile RFC public input from the typed statement and finalized state.
///
/// The CRL number is deliberately read from authoritative state; no proof
/// metadata or prover-supplied governance selector participates.
pub fn compile_zk_x509_rfc_statement_from_authoritative_state_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    authoritative_state: &PrivacyZkX509AuthoritativeStateV1,
) -> ZkX509Rfc5280StatementV1 {
    rfc_statement_with_crl_number_v1(statement, authoritative_state.crl_record().crl_number)
}

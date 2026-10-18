//! Verifier-owned byte-channel declarations for the zk-X509 MAIN aggregate.
//!
//! The channel graph is public preprocessing. It depends only on the typed public statement and the
//! closed first-release profile; no private witness, prover-selected channel metadata, or
//! trace-derived length can change it. The MAIN assembler compares its witness-bearing declarations
//! byte-for-byte with this plan before committing either I/O base table.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::io_air::ZkX509IoChannelWitnessV1;
use super::{
    der_air::ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
    io_air::{
        ZK_X509_IO_FIXED_CAPACITY_ROWS_V1, ZkX509IoAirErrorV1, ZkX509IoChannelDeclarationV1,
        ZkX509IoEndpointV1, ZkX509IoSegmentRoleV1, validate_declarations_v1,
    },
    profile::{
        ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1, ZK_X509_MAX_SERIAL_BYTES_V1,
        ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
    },
    projection_air::{
        ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1, ZK_X509_PROJECTION_SPKI_DER_BYTES_V1,
    },
};
use iroha_data_model::privacy::{
    IrohaZkX509StarkP256StatementV1, PrivacyConsensusLimitsV1, PrivacyStatementV1,
    ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1,
};
use thiserror::Error;
/// Stable identity of the verifier-owned MAIN I/O declaration compiler.
pub const ZK_X509_MAIN_IO_DECLARATIONS_DESCRIPTOR_V1: &[u8] = b"zk-x509-main-io-declarations-v1-incompatible:statement-only:three-spki-prefix:serial-length+padded:per-disclosure-attribute-length+padded:three-certificate-tbs-pairs:optional-certificate-selector:three-certificate-signature-triples:crl-tbs+complete-crl+signature:issuer+leaf-keys:issuer+root-spki:active-projection-sha-triples:public-digests-verifier-fixed:declarations=40+5d:logical-rows=55922+4736d:max74866:fixed-capacity262144:first-release";
/// Fixed declaration count with no selective disclosures.
pub const ZK_X509_MAIN_IO_BASE_DECLARATIONS_V1: usize = 40;
/// Additional declarations for each selectively disclosed attribute.
pub const ZK_X509_MAIN_IO_DECLARATIONS_PER_DISCLOSURE_V1: usize = 5;
/// Fixed logical byte-access rows with no selective disclosures.
pub const ZK_X509_MAIN_IO_BASE_LOGICAL_ROWS_V1: usize = 55_922;
/// Additional logical byte-access rows for each selective disclosure.
pub const ZK_X509_MAIN_IO_LOGICAL_ROWS_PER_DISCLOSURE_V1: usize = 4_736;
/// Maximum logical byte-access rows admitted by the closed statement shape.
pub const ZK_X509_MAIN_IO_MAX_LOGICAL_ROWS_V1: usize = ZK_X509_MAIN_IO_BASE_LOGICAL_ROWS_V1
    + ZK_X509_MAIN_IO_LOGICAL_ROWS_PER_DISCLOSURE_V1 * ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1;
const FIXED_CERTIFICATE_SLOTS_V1: usize = 3;
const LENGTH_BYTES_V1: usize = core::mem::size_of::<u64>();
const SIGNATURE_DER_BYTES_V1: usize = 72;
const SHA256_DIGEST_BYTES_V1: usize = 32;
const OPTIONAL_CERTIFICATE_SELECTOR_BYTES_V1: usize = 1;
/// Verifier-owned declarations and the exact non-padding row census.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509MainIoDeclarationsV1 {
    /// Sequential fixed channel declarations.
    pub(crate) declarations: Vec<ZkX509IoChannelDeclarationV1>,
    /// Exact producer-plus-consumer byte accesses before fixed-capacity padding.
    pub(crate) logical_active_rows: usize,
}
impl ZkX509MainIoDeclarationsV1 {
    /// Reject witness-selected channel metadata before either base table is built.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn validate_witness_declarations_v1(
        &self,
        witnesses: &[ZkX509IoChannelWitnessV1],
    ) -> Result<(), ZkX509MainIoPlanErrorV1> {
        if witnesses.len() != self.declarations.len()
            || witnesses
                .iter()
                .zip(&self.declarations)
                .any(|(witness, expected)| witness.declaration != *expected)
        {
            return Err(ZkX509MainIoPlanErrorV1::Topology);
        }
        Ok(())
    }
    /// Replay the statement-only compiler and reject any altered plan field.
    #[cfg(test)]
    pub(crate) fn validate_for_statement_v1(
        &self,
        statement: &IrohaZkX509StarkP256StatementV1,
    ) -> Result<(), ZkX509MainIoPlanErrorV1> {
        let expected = compile_zk_x509_main_io_declarations_v1(statement)?;
        if self != &expected {
            return Err(ZkX509MainIoPlanErrorV1::Topology);
        }
        Ok(())
    }
}
/// Statement validation, topology, or bounded-allocation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509MainIoPlanErrorV1 {
    /// The typed public statement is not valid under the first-release profile.
    #[error("zk-X509 MAIN I/O statement is invalid")]
    Statement,
    /// A fixed channel, endpoint, public value, or exact census is inconsistent.
    #[error("zk-X509 MAIN I/O declaration topology is invalid")]
    Topology,
    /// Checked arithmetic, allocation, or fixed-capacity accounting failed.
    #[error("zk-X509 MAIN I/O declaration resource bound is exceeded")]
    Resource,
}
impl From<ZkX509IoAirErrorV1> for ZkX509MainIoPlanErrorV1 {
    fn from(error: ZkX509IoAirErrorV1) -> Self {
        if error == ZkX509IoAirErrorV1::Resource {
            Self::Resource
        } else {
            Self::Topology
        }
    }
}
fn endpoint_v1(role: ZkX509IoSegmentRoleV1) -> ZkX509IoEndpointV1 {
    ZkX509IoEndpointV1 { role, instance: 0 }
}
fn copy_bytes_v1(bytes: &[u8]) -> Result<Vec<u8>, ZkX509MainIoPlanErrorV1> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| ZkX509MainIoPlanErrorV1::Resource)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}
fn copy_endpoints_v1(
    endpoints: &[ZkX509IoEndpointV1],
) -> Result<Vec<ZkX509IoEndpointV1>, ZkX509MainIoPlanErrorV1> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(endpoints.len())
        .map_err(|_| ZkX509MainIoPlanErrorV1::Resource)?;
    copy.extend_from_slice(endpoints);
    Ok(copy)
}
fn push_declaration_v1(
    declarations: &mut Vec<ZkX509IoChannelDeclarationV1>,
    producer: ZkX509IoEndpointV1,
    consumers: &[ZkX509IoEndpointV1],
    byte_len: usize,
    public_value: Option<&[u8]>,
) -> Result<(), ZkX509MainIoPlanErrorV1> {
    let channel =
        u32::try_from(declarations.len()).map_err(|_| ZkX509MainIoPlanErrorV1::Resource)?;
    let byte_len = u32::try_from(byte_len).map_err(|_| ZkX509MainIoPlanErrorV1::Resource)?;
    declarations.push(ZkX509IoChannelDeclarationV1 {
        channel,
        producer,
        consumers: copy_endpoints_v1(consumers)?,
        byte_len,
        public_value: public_value.map(copy_bytes_v1).transpose()?,
    });
    Ok(())
}
fn push_private_copy_v1(
    declarations: &mut Vec<ZkX509IoChannelDeclarationV1>,
    producer: ZkX509IoEndpointV1,
    consumer: ZkX509IoEndpointV1,
    byte_len: usize,
) -> Result<(), ZkX509MainIoPlanErrorV1> {
    push_declaration_v1(declarations, producer, &[consumer], byte_len, None)
}
fn push_projection_sha_invocation_v1(
    declarations: &mut Vec<ZkX509IoChannelDeclarationV1>,
    public_digest: Option<&[u8; SHA256_DIGEST_BYTES_V1]>,
) -> Result<(), ZkX509MainIoPlanErrorV1> {
    let projection = endpoint_v1(ZkX509IoSegmentRoleV1::Projection);
    let sha = endpoint_v1(ZkX509IoSegmentRoleV1::Sha256);
    let p256 = endpoint_v1(ZkX509IoSegmentRoleV1::P256);
    let public = endpoint_v1(ZkX509IoSegmentRoleV1::PublicInput);
    push_private_copy_v1(
        declarations,
        projection,
        sha,
        ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1,
    )?;
    push_private_copy_v1(declarations, projection, sha, LENGTH_BYTES_V1)?;
    if let Some(digest) = public_digest {
        push_declaration_v1(
            declarations,
            sha,
            &[projection, public],
            SHA256_DIGEST_BYTES_V1,
            Some(digest),
        )
    } else {
        push_declaration_v1(
            declarations,
            sha,
            &[p256, projection],
            SHA256_DIGEST_BYTES_V1,
            None,
        )
    }
}
fn append_shared_prefix_v1(
    declarations: &mut Vec<ZkX509IoChannelDeclarationV1>,
    disclosed_attributes: usize,
) -> Result<(), ZkX509MainIoPlanErrorV1> {
    let strict_der = endpoint_v1(ZkX509IoSegmentRoleV1::StrictDer);
    let projection = endpoint_v1(ZkX509IoSegmentRoleV1::Projection);
    for _ in 0..FIXED_CERTIFICATE_SLOTS_V1 {
        push_private_copy_v1(
            declarations,
            strict_der,
            projection,
            ZK_X509_PROJECTION_SPKI_DER_BYTES_V1,
        )?;
    }
    push_private_copy_v1(declarations, strict_der, projection, LENGTH_BYTES_V1)?;
    push_private_copy_v1(
        declarations,
        strict_der,
        projection,
        ZK_X509_MAX_SERIAL_BYTES_V1,
    )?;
    for _ in 0..disclosed_attributes {
        push_private_copy_v1(declarations, strict_der, projection, LENGTH_BYTES_V1)?;
        push_private_copy_v1(
            declarations,
            strict_der,
            projection,
            ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1,
        )?;
    }
    Ok(())
}
fn append_rfc5280_tail_v1(
    declarations: &mut Vec<ZkX509IoChannelDeclarationV1>,
) -> Result<(), ZkX509MainIoPlanErrorV1> {
    let strict_der = endpoint_v1(ZkX509IoSegmentRoleV1::StrictDer);
    let sha = endpoint_v1(ZkX509IoSegmentRoleV1::Sha256);
    let p256 = endpoint_v1(ZkX509IoSegmentRoleV1::P256);
    let ca_accumulator = endpoint_v1(ZkX509IoSegmentRoleV1::CaAccumulator);
    for _ in 0..FIXED_CERTIFICATE_SLOTS_V1 {
        push_private_copy_v1(
            declarations,
            strict_der,
            sha,
            ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
        )?;
        push_private_copy_v1(declarations, strict_der, sha, LENGTH_BYTES_V1)?;
    }
    push_private_copy_v1(
        declarations,
        strict_der,
        p256,
        OPTIONAL_CERTIFICATE_SELECTOR_BYTES_V1,
    )?;
    for _ in 0..FIXED_CERTIFICATE_SLOTS_V1 {
        push_private_copy_v1(declarations, strict_der, p256, SIGNATURE_DER_BYTES_V1)?;
        push_private_copy_v1(declarations, strict_der, p256, LENGTH_BYTES_V1)?;
        push_private_copy_v1(
            declarations,
            strict_der,
            p256,
            ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
        )?;
    }
    for _ in 0..2 {
        push_private_copy_v1(
            declarations,
            strict_der,
            sha,
            ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
        )?;
        push_private_copy_v1(declarations, strict_der, sha, LENGTH_BYTES_V1)?;
    }
    push_private_copy_v1(declarations, strict_der, p256, SIGNATURE_DER_BYTES_V1)?;
    push_private_copy_v1(declarations, strict_der, p256, LENGTH_BYTES_V1)?;
    push_private_copy_v1(
        declarations,
        strict_der,
        p256,
        ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
    )?;
    push_private_copy_v1(
        declarations,
        strict_der,
        p256,
        ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
    )?;
    push_private_copy_v1(
        declarations,
        strict_der,
        sha,
        ZK_X509_PROJECTION_SPKI_DER_BYTES_V1,
    )?;
    push_private_copy_v1(
        declarations,
        strict_der,
        ca_accumulator,
        ZK_X509_PROJECTION_SPKI_DER_BYTES_V1,
    )
}
fn logical_rows_v1(
    declarations: &[ZkX509IoChannelDeclarationV1],
) -> Result<usize, ZkX509MainIoPlanErrorV1> {
    declarations.iter().try_fold(0_usize, |rows, declaration| {
        let byte_len =
            usize::try_from(declaration.byte_len).map_err(|_| ZkX509MainIoPlanErrorV1::Resource)?;
        let endpoints = declaration
            .consumers
            .len()
            .checked_add(1)
            .ok_or(ZkX509MainIoPlanErrorV1::Resource)?;
        rows.checked_add(
            byte_len
                .checked_mul(endpoints)
                .ok_or(ZkX509MainIoPlanErrorV1::Resource)?,
        )
        .ok_or(ZkX509MainIoPlanErrorV1::Resource)
    })
}
/// Compile the exact verifier-owned MAIN byte-channel graph.
///
/// The full typed statement is first validated against the Taira hard-ceiling profile. The
/// resulting declarations depend only on its disclosure count and public projection digests. Every
/// remaining statement field is bound by the other verifier-owned MAIN fixed-column providers.
pub fn compile_zk_x509_main_io_declarations_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<ZkX509MainIoDeclarationsV1, ZkX509MainIoPlanErrorV1> {
    PrivacyStatementV1::IrohaZkX509StarkP256V1(statement.clone())
        .validate(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| ZkX509MainIoPlanErrorV1::Statement)?;
    let disclosed_attributes = statement.disclosed_attributes.len();
    if disclosed_attributes > ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 {
        return Err(ZkX509MainIoPlanErrorV1::Statement);
    }
    let expected_declarations = ZK_X509_MAIN_IO_BASE_DECLARATIONS_V1
        .checked_add(
            disclosed_attributes
                .checked_mul(ZK_X509_MAIN_IO_DECLARATIONS_PER_DISCLOSURE_V1)
                .ok_or(ZkX509MainIoPlanErrorV1::Resource)?,
        )
        .ok_or(ZkX509MainIoPlanErrorV1::Resource)?;
    let mut declarations = Vec::new();
    declarations
        .try_reserve_exact(expected_declarations)
        .map_err(|_| ZkX509MainIoPlanErrorV1::Resource)?;
    append_shared_prefix_v1(&mut declarations, disclosed_attributes)?;
    append_rfc5280_tail_v1(&mut declarations)?;
    push_projection_sha_invocation_v1(
        &mut declarations,
        Some(statement.subject_public_key_digest.as_bytes()),
    )?;
    push_projection_sha_invocation_v1(
        &mut declarations,
        Some(statement.certificate_nullifier.as_bytes()),
    )?;
    for disclosure in &statement.disclosed_attributes {
        push_projection_sha_invocation_v1(
            &mut declarations,
            Some(disclosure.attribute_digest.as_bytes()),
        )?;
    }
    push_projection_sha_invocation_v1(&mut declarations, None)?;
    validate_declarations_v1(&declarations)?;
    let logical_active_rows = logical_rows_v1(&declarations)?;
    let expected_logical_rows = ZK_X509_MAIN_IO_BASE_LOGICAL_ROWS_V1
        .checked_add(
            disclosed_attributes
                .checked_mul(ZK_X509_MAIN_IO_LOGICAL_ROWS_PER_DISCLOSURE_V1)
                .ok_or(ZkX509MainIoPlanErrorV1::Resource)?,
        )
        .ok_or(ZkX509MainIoPlanErrorV1::Resource)?;
    if declarations.len() != expected_declarations
        || logical_active_rows != expected_logical_rows
        || logical_active_rows > ZK_X509_MAIN_IO_MAX_LOGICAL_ROWS_V1
    {
        return Err(ZkX509MainIoPlanErrorV1::Topology);
    }
    if logical_active_rows > ZK_X509_IO_FIXED_CAPACITY_ROWS_V1 {
        return Err(ZkX509MainIoPlanErrorV1::Resource);
    }
    Ok(ZkX509MainIoDeclarationsV1 {
        declarations,
        logical_active_rows,
    })
}
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::projection_air::tests::fixture;
    use iroha_data_model::privacy::{
        PrivacyAttributeDigestV1, PrivacyCertificateKeyDigestV1, PrivacyNullifierV1,
        PrivacyZkX509DisclosedAttributeV1,
    };
    pub fn statement_with_disclosures_v1(disclosures: usize) -> IrohaZkX509StarkP256StatementV1 {
        let (mut statement, _) = fixture();
        // The projection AIR fixture intentionally exercises a non-consensus
        // action index. MAIN I/O compilation validates the complete Taira
        // statement, whose first-release transaction ceiling admits only
        // action index zero.
        statement.context.action_index = 0;
        statement.disclosed_attributes = (0..disclosures)
            .map(|index| PrivacyZkX509DisclosedAttributeV1 {
                index: u8::try_from(index).expect("test disclosure index fits u8"),
                attribute_digest: PrivacyAttributeDigestV1::new(
                    [0x40_u8
                        .wrapping_add(u8::try_from(index).expect("test disclosure index fits u8"));
                        SHA256_DIGEST_BYTES_V1],
                ),
            })
            .collect();
        statement
    }
    fn assert_private_copy_v1(
        declaration: &ZkX509IoChannelDeclarationV1,
        producer: ZkX509IoSegmentRoleV1,
        consumer: ZkX509IoSegmentRoleV1,
        byte_len: usize,
    ) {
        assert_eq!(declaration.producer, endpoint_v1(producer));
        assert_eq!(declaration.consumers, vec![endpoint_v1(consumer)]);
        assert_eq!(
            usize::try_from(declaration.byte_len).expect("test byte length fits usize"),
            byte_len
        );
        assert_eq!(declaration.public_value, None);
    }
    fn assert_rfc_tail_v1(
        declarations: &[ZkX509IoChannelDeclarationV1],
        mut cursor: usize,
    ) -> usize {
        for _ in 0..FIXED_CERTIFICATE_SLOTS_V1 {
            assert_private_copy_v1(
                &declarations[cursor],
                ZkX509IoSegmentRoleV1::StrictDer,
                ZkX509IoSegmentRoleV1::Sha256,
                ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
            );
            assert_private_copy_v1(
                &declarations[cursor + 1],
                ZkX509IoSegmentRoleV1::StrictDer,
                ZkX509IoSegmentRoleV1::Sha256,
                LENGTH_BYTES_V1,
            );
            cursor += 2;
        }
        assert_private_copy_v1(
            &declarations[cursor],
            ZkX509IoSegmentRoleV1::StrictDer,
            ZkX509IoSegmentRoleV1::P256,
            OPTIONAL_CERTIFICATE_SELECTOR_BYTES_V1,
        );
        cursor += 1;
        for _ in 0..FIXED_CERTIFICATE_SLOTS_V1 {
            for byte_len in [
                SIGNATURE_DER_BYTES_V1,
                LENGTH_BYTES_V1,
                ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
            ] {
                assert_private_copy_v1(
                    &declarations[cursor],
                    ZkX509IoSegmentRoleV1::StrictDer,
                    ZkX509IoSegmentRoleV1::P256,
                    byte_len,
                );
                cursor += 1;
            }
        }
        for _ in 0..2 {
            assert_private_copy_v1(
                &declarations[cursor],
                ZkX509IoSegmentRoleV1::StrictDer,
                ZkX509IoSegmentRoleV1::Sha256,
                ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
            );
            assert_private_copy_v1(
                &declarations[cursor + 1],
                ZkX509IoSegmentRoleV1::StrictDer,
                ZkX509IoSegmentRoleV1::Sha256,
                LENGTH_BYTES_V1,
            );
            cursor += 2;
        }
        for byte_len in [SIGNATURE_DER_BYTES_V1, LENGTH_BYTES_V1] {
            assert_private_copy_v1(
                &declarations[cursor],
                ZkX509IoSegmentRoleV1::StrictDer,
                ZkX509IoSegmentRoleV1::P256,
                byte_len,
            );
            cursor += 1;
        }
        for _ in 0..2 {
            assert_private_copy_v1(
                &declarations[cursor],
                ZkX509IoSegmentRoleV1::StrictDer,
                ZkX509IoSegmentRoleV1::P256,
                ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
            );
            cursor += 1;
        }
        assert_private_copy_v1(
            &declarations[cursor],
            ZkX509IoSegmentRoleV1::StrictDer,
            ZkX509IoSegmentRoleV1::Sha256,
            ZK_X509_PROJECTION_SPKI_DER_BYTES_V1,
        );
        assert_private_copy_v1(
            &declarations[cursor + 1],
            ZkX509IoSegmentRoleV1::StrictDer,
            ZkX509IoSegmentRoleV1::CaAccumulator,
            ZK_X509_PROJECTION_SPKI_DER_BYTES_V1,
        );
        cursor + 2
    }
    #[test]
    fn every_disclosure_count_has_exact_topology_counts_and_rows() {
        for disclosures in 0..=ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 {
            let statement = statement_with_disclosures_v1(disclosures);
            let plan = compile_zk_x509_main_io_declarations_v1(&statement)
                .expect("valid statement must compile");
            assert_eq!(
                plan.declarations.len(),
                ZK_X509_MAIN_IO_BASE_DECLARATIONS_V1
                    + ZK_X509_MAIN_IO_DECLARATIONS_PER_DISCLOSURE_V1 * disclosures
            );
            assert_eq!(
                plan.logical_active_rows,
                ZK_X509_MAIN_IO_BASE_LOGICAL_ROWS_V1
                    + ZK_X509_MAIN_IO_LOGICAL_ROWS_PER_DISCLOSURE_V1 * disclosures
            );
            assert_eq!(
                logical_rows_v1(&plan.declarations).expect("row census"),
                plan.logical_active_rows
            );
            assert!(plan.logical_active_rows <= ZK_X509_IO_FIXED_CAPACITY_ROWS_V1);
            assert_eq!(
                plan.declarations
                    .iter()
                    .enumerate()
                    .map(|(index, declaration)| {
                        declaration.channel == u32::try_from(index).expect("test channel fits u32")
                    })
                    .filter(|sequential| *sequential)
                    .count(),
                plan.declarations.len()
            );
            validate_declarations_v1(&plan.declarations).expect("canonical declarations");
            let mut cursor = 0;
            for _ in 0..FIXED_CERTIFICATE_SLOTS_V1 {
                assert_private_copy_v1(
                    &plan.declarations[cursor],
                    ZkX509IoSegmentRoleV1::StrictDer,
                    ZkX509IoSegmentRoleV1::Projection,
                    ZK_X509_PROJECTION_SPKI_DER_BYTES_V1,
                );
                cursor += 1;
            }
            for byte_len in [LENGTH_BYTES_V1, ZK_X509_MAX_SERIAL_BYTES_V1] {
                assert_private_copy_v1(
                    &plan.declarations[cursor],
                    ZkX509IoSegmentRoleV1::StrictDer,
                    ZkX509IoSegmentRoleV1::Projection,
                    byte_len,
                );
                cursor += 1;
            }
            for _ in 0..disclosures {
                for byte_len in [LENGTH_BYTES_V1, ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1] {
                    assert_private_copy_v1(
                        &plan.declarations[cursor],
                        ZkX509IoSegmentRoleV1::StrictDer,
                        ZkX509IoSegmentRoleV1::Projection,
                        byte_len,
                    );
                    cursor += 1;
                }
            }
            cursor = assert_rfc_tail_v1(&plan.declarations, cursor);
            assert_eq!(cursor, 31 + 2 * disclosures);
            let expected_public_digests =
                core::iter::once(statement.subject_public_key_digest.as_bytes().as_slice())
                    .chain(core::iter::once(
                        statement.certificate_nullifier.as_bytes().as_slice(),
                    ))
                    .chain(
                        statement
                            .disclosed_attributes
                            .iter()
                            .map(|disclosure| disclosure.attribute_digest.as_bytes().as_slice()),
                    )
                    .collect::<Vec<_>>();
            for expected_digest in expected_public_digests {
                assert_private_copy_v1(
                    &plan.declarations[cursor],
                    ZkX509IoSegmentRoleV1::Projection,
                    ZkX509IoSegmentRoleV1::Sha256,
                    ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1,
                );
                assert_private_copy_v1(
                    &plan.declarations[cursor + 1],
                    ZkX509IoSegmentRoleV1::Projection,
                    ZkX509IoSegmentRoleV1::Sha256,
                    LENGTH_BYTES_V1,
                );
                let digest = &plan.declarations[cursor + 2];
                assert_eq!(digest.producer, endpoint_v1(ZkX509IoSegmentRoleV1::Sha256));
                assert_eq!(
                    digest.consumers,
                    vec![
                        endpoint_v1(ZkX509IoSegmentRoleV1::Projection),
                        endpoint_v1(ZkX509IoSegmentRoleV1::PublicInput),
                    ]
                );
                assert_eq!(digest.byte_len, SHA256_DIGEST_BYTES_V1 as u32);
                assert_eq!(digest.public_value.as_deref(), Some(expected_digest));
                cursor += 3;
            }
            assert_private_copy_v1(
                &plan.declarations[cursor],
                ZkX509IoSegmentRoleV1::Projection,
                ZkX509IoSegmentRoleV1::Sha256,
                ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1,
            );
            assert_private_copy_v1(
                &plan.declarations[cursor + 1],
                ZkX509IoSegmentRoleV1::Projection,
                ZkX509IoSegmentRoleV1::Sha256,
                LENGTH_BYTES_V1,
            );
            let ownership_digest = &plan.declarations[cursor + 2];
            assert_eq!(
                ownership_digest.producer,
                endpoint_v1(ZkX509IoSegmentRoleV1::Sha256)
            );
            assert_eq!(
                ownership_digest.consumers,
                vec![
                    endpoint_v1(ZkX509IoSegmentRoleV1::P256),
                    endpoint_v1(ZkX509IoSegmentRoleV1::Projection),
                ]
            );
            assert_eq!(ownership_digest.byte_len, SHA256_DIGEST_BYTES_V1 as u32);
            assert_eq!(ownership_digest.public_value, None);
            cursor += 3;
            assert_eq!(cursor, plan.declarations.len());
            assert_eq!(
                plan.declarations
                    .iter()
                    .filter(|declaration| declaration.public_value.is_some())
                    .count(),
                2 + disclosures
            );
        }
    }
    #[test]
    fn maximum_disclosure_shape_hits_the_pinned_maximum_not_capacity_padding() {
        let statement = statement_with_disclosures_v1(ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1);
        let plan = compile_zk_x509_main_io_declarations_v1(&statement).expect("maximum valid plan");
        assert_eq!(
            plan.logical_active_rows,
            ZK_X509_MAIN_IO_MAX_LOGICAL_ROWS_V1
        );
        assert!(plan.logical_active_rows < ZK_X509_IO_FIXED_CAPACITY_ROWS_V1);
        assert_eq!(
            ZK_X509_IO_FIXED_CAPACITY_ROWS_V1 - plan.logical_active_rows,
            187_278
        );
    }
    #[test]
    fn each_public_digest_changes_exactly_its_own_channel() {
        let statement = statement_with_disclosures_v1(ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1);
        let baseline = compile_zk_x509_main_io_declarations_v1(&statement).expect("baseline plan");
        let projection_start = 31 + 2 * ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1;
        for public_digest in 0..2 + ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 {
            let mut changed = statement.clone();
            let replacement = [0xD0_u8.wrapping_add(public_digest as u8); SHA256_DIGEST_BYTES_V1];
            match public_digest {
                0 => {
                    changed.subject_public_key_digest =
                        PrivacyCertificateKeyDigestV1::new(replacement);
                }
                1 => changed.certificate_nullifier = PrivacyNullifierV1::new(replacement),
                index => {
                    changed.disclosed_attributes[index - 2].attribute_digest =
                        PrivacyAttributeDigestV1::new(replacement);
                }
            }
            let changed =
                compile_zk_x509_main_io_declarations_v1(&changed).expect("changed valid plan");
            let differences = baseline
                .declarations
                .iter()
                .zip(&changed.declarations)
                .enumerate()
                .filter_map(|(index, (left, right))| (left != right).then_some(index))
                .collect::<Vec<_>>();
            assert_eq!(differences, vec![projection_start + public_digest * 3 + 2]);
            assert_eq!(changed.logical_active_rows, baseline.logical_active_rows);
        }
    }
    #[test]
    fn malformed_statement_shapes_fail_before_emitting_a_plan() {
        let mut malformed = Vec::new();
        let mut too_many = statement_with_disclosures_v1(ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1);
        too_many
            .disclosed_attributes
            .push(PrivacyZkX509DisclosedAttributeV1 {
                index: 4,
                attribute_digest: PrivacyAttributeDigestV1::new([0x91; SHA256_DIGEST_BYTES_V1]),
            });
        malformed.push(too_many);
        let mut unsupported_index = statement_with_disclosures_v1(1);
        unsupported_index.disclosed_attributes[0].index = 4;
        malformed.push(unsupported_index);
        let mut duplicate = statement_with_disclosures_v1(2);
        duplicate.disclosed_attributes[1].index = duplicate.disclosed_attributes[0].index;
        malformed.push(duplicate);
        let mut descending = statement_with_disclosures_v1(2);
        descending.disclosed_attributes[0].index = 3;
        descending.disclosed_attributes[1].index = 1;
        malformed.push(descending);
        let mut zero_attribute = statement_with_disclosures_v1(1);
        zero_attribute.disclosed_attributes[0].attribute_digest =
            PrivacyAttributeDigestV1::new([0; SHA256_DIGEST_BYTES_V1]);
        malformed.push(zero_attribute);
        let mut zero_subject = statement_with_disclosures_v1(0);
        zero_subject.subject_public_key_digest =
            PrivacyCertificateKeyDigestV1::new([0; SHA256_DIGEST_BYTES_V1]);
        malformed.push(zero_subject);
        let mut zero_nullifier = statement_with_disclosures_v1(0);
        zero_nullifier.certificate_nullifier = PrivacyNullifierV1::new([0; SHA256_DIGEST_BYTES_V1]);
        malformed.push(zero_nullifier);
        let mut inverted_window = statement_with_disclosures_v1(0);
        inverted_window.presentation_not_after_unix_seconds =
            inverted_window.presentation_not_before_unix_seconds;
        malformed.push(inverted_window);
        for statement in malformed {
            assert_eq!(
                compile_zk_x509_main_io_declarations_v1(&statement),
                Err(ZkX509MainIoPlanErrorV1::Statement)
            );
        }
    }
    #[test]
    fn exact_replay_rejects_every_plan_metadata_class() {
        let statement = statement_with_disclosures_v1(2);
        let canonical =
            compile_zk_x509_main_io_declarations_v1(&statement).expect("canonical plan");
        canonical
            .validate_for_statement_v1(&statement)
            .expect("canonical replay");
        let mut mutations = Vec::new();
        let mut changed = canonical.clone();
        changed.declarations[0].channel = 1;
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed.declarations.swap(0, 1);
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed.declarations[0].byte_len += 1;
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed.declarations[0].producer = endpoint_v1(ZkX509IoSegmentRoleV1::Sha256);
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed.declarations[0].consumers[0] = endpoint_v1(ZkX509IoSegmentRoleV1::P256);
        mutations.push(changed);
        let mut changed = canonical.clone();
        let public = changed
            .declarations
            .iter_mut()
            .find(|declaration| declaration.public_value.is_some())
            .expect("public declaration");
        public.public_value.as_mut().expect("public value")[0] ^= 1;
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed.logical_active_rows += 1;
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed.declarations.pop();
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed.declarations.push(canonical.declarations[0].clone());
        mutations.push(changed);
        for mutation in mutations {
            assert_eq!(
                mutation.validate_for_statement_v1(&statement),
                Err(ZkX509MainIoPlanErrorV1::Topology)
            );
        }
    }
}

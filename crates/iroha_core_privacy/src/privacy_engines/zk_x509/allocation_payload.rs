//! Capacity-based payload accounting for retained private prover sources.
//!
//! Counts allocations reachable from the named owner, including unused vector
//! capacity. It excludes allocator metadata, thread stacks and transient replay
//! scratch, so callers must reserve those separately rather than call this RSS.

use super::{
    der_air::{ZkX509DerNameV1, ZkX509DerSignatureV1, ZkX509Rfc5280TraceV1},
    io_air::ZkX509IoChannelDeclarationV1,
    main_assembly::ZkX509MainTraceAssemblyV1,
    p256_trace::{P256EcdsaTopologyV1, P256EcdsaTraceMaterialV1},
};

/// Allocation allowance for native MAIN providers built from an admitted
/// assembly. Actual capacities are checked again at every phase transition.
pub const MAIN_NATIVE_SOURCE_ALLOWANCE_BYTES_V1: usize = 6 << 30;

/// Separate allowance for serial source construction and column replay;
/// native/coefficient/FFT columns are charged by the MAIN transform plan.
pub const MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1: usize = 1 << 30;

/// Sum payload sizes without allowing overflow to reduce a resource charge.
pub fn sum_v1(values: impl IntoIterator<Item = usize>) -> usize {
    values.into_iter().fold(0, usize::saturating_add)
}

/// Allocated vector storage, including unused capacity and inline element data.
pub fn vector_v1<T>(values: &Vec<T>) -> usize {
    values.capacity().saturating_mul(core::mem::size_of::<T>())
}

fn optional_vector_v1<T>(values: Option<&Vec<T>>) -> usize {
    values.map_or(0, vector_v1)
}

/// Allocation payload of the value-free P-256 verifier schedule.
pub fn p256_topology_v1(value: &P256EcdsaTopologyV1) -> usize {
    sum_v1([
        vector_v1(&value.initial_values),
        vector_v1(&value.linked_operations),
        vector_v1(&value.equalities),
        vector_v1(&value.boolean_bridges),
        vector_v1(&value.windows),
        vector_v1(&value.reductions),
        vector_v1(&value.low_s),
    ])
}

/// Allocation payload of native P-256 material borrowed by every proof phase.
pub fn p256_material_v1(value: &P256EcdsaTraceMaterialV1) -> usize {
    sum_v1([
        vector_v1(&value.initial_values),
        vector_v1(&value.linked_operations),
        vector_v1(&value.equalities),
        vector_v1(&value.boolean_bridges),
        vector_v1(&value.windows),
        vector_v1(&value.reductions),
        vector_v1(&value.low_s),
        sum_v1(value.windows.iter().map(|window| {
            sum_v1([
                vector_v1(&window.trace.fixed),
                vector_v1(&window.trace.base),
            ])
        })),
    ])
}

fn name_v1(value: &ZkX509DerNameV1) -> usize {
    sum_v1([
        vector_v1(&value.encoded),
        sum_v1(
            value
                .attributes
                .iter()
                .map(Option::as_ref)
                .map(optional_vector_v1),
        ),
    ])
}

fn signature_v1(value: &ZkX509DerSignatureV1) -> usize {
    sum_v1([
        vector_v1(&value.encoded),
        vector_v1(&value.r),
        vector_v1(&value.s),
    ])
}

fn rfc_trace_v1(value: &ZkX509Rfc5280TraceV1) -> usize {
    let documents = sum_v1(value.documents.iter().chain(&value.embedded_documents).map(
        |document| {
            sum_v1([
                vector_v1(&document.bytes),
                vector_v1(&document.nodes),
                vector_v1(&document.primitive_rows),
                vector_v1(&document.set_order_rows),
            ])
        },
    ));
    let certificates = sum_v1(value.certificates.iter().map(|certificate| {
        sum_v1([
            vector_v1(&certificate.tbs_der),
            vector_v1(&certificate.serial),
            name_v1(&certificate.issuer),
            name_v1(&certificate.subject),
            vector_v1(&certificate.spki_der),
            vector_v1(&certificate.public_key),
            signature_v1(&certificate.signature),
            vector_v1(&certificate.extensions.authority_key_identifier),
            vector_v1(&certificate.extensions.subject_key_identifier),
            optional_vector_v1(certificate.extensions.extended_key_usages.as_ref()),
        ])
    }));
    let crl = &value.crl;
    sum_v1([
        vector_v1(&value.documents),
        vector_v1(&value.embedded_documents),
        documents,
        vector_v1(&value.embedded_byte_rows),
        vector_v1(&value.certificates),
        certificates,
        vector_v1(&value.path_rows),
        vector_v1(&value.semantic_provenance),
        sum_v1(
            value
                .semantic_provenance
                .iter()
                .map(|document| vector_v1(&document.nodes)),
        ),
        vector_v1(&value.statement.leaf_extended_key_usages),
        vector_v1(&value.statement.disclosed_attribute_indices),
        vector_v1(&crl.tbs_der),
        name_v1(&crl.issuer),
        vector_v1(&crl.revoked_serials),
        sum_v1(crl.revoked_serials.iter().map(vector_v1)),
        vector_v1(&crl.authority_key_identifier),
        signature_v1(&crl.signature),
    ])
}

/// Nested allocations owned by one canonical byte-channel declaration.
pub fn declaration_v1(value: &ZkX509IoChannelDeclarationV1) -> usize {
    sum_v1([
        vector_v1(&value.consumers),
        optional_vector_v1(value.public_value.as_ref()),
    ])
}

impl ZkX509MainTraceAssemblyV1 {
    /// Exact reachable allocation payload plus this owner's inline storage.
    ///
    /// The assembly remains borrowed while the bound DER/P-256 sources exist;
    /// callers must therefore charge both owners. RFC column providers borrow
    /// `rfc_base`, so its storage is charged here exactly once.
    pub(crate) fn allocated_payload_bytes_v1(&self) -> usize {
        let projection = &self.projection_trace;
        let io = &self.io;
        sum_v1([
            core::mem::size_of_val(self),
            rfc_trace_v1(&self.rfc_trace),
            vector_v1(&self.der_base.private_shape.document_lengths),
            vector_v1(&self.der_base.rows),
            self.rfc_base.allocated_heap_bytes_v1(),
            vector_v1(&projection.fixed.rows),
            vector_v1(&projection.fixed.copy_identity),
            vector_v1(&projection.fixed.copy_sigma),
            vector_v1(&projection.base.rows),
            vector_v1(&projection.io_channels),
            sum_v1(projection.io_channels.iter().map(|channel| {
                sum_v1([
                    vector_v1(&channel.consumers),
                    vector_v1(&channel.value),
                    optional_vector_v1(channel.public_value.as_ref()),
                ])
            })),
            sum_v1(
                self.ca_accumulator_trace
                    .hash_witnesses
                    .iter()
                    .map(|call| vector_v1(&call.message)),
            ),
            sum_v1(
                self.sha_witnesses
                    .iter()
                    .map(|call| vector_v1(&call.message)),
            ),
            sum_v1(self.p256_materials.iter().map(p256_material_v1)),
            vector_v1(&io.witnesses),
            vector_v1(&io.declarations),
            vector_v1(&io.execution),
            vector_v1(&io.sorted),
            sum_v1(io.declarations.iter().map(declaration_v1)),
            sum_v1(io.witnesses.iter().map(|witness| {
                sum_v1([
                    declaration_v1(&witness.declaration),
                    vector_v1(&witness.producer_value),
                    vector_v1(&witness.consumer_values),
                    sum_v1(witness.consumer_values.iter().map(vector_v1)),
                ])
            })),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_payload_retains_original_vector_capacity() {
        assert_eq!(optional_vector_v1::<u64>(None), 0);
        let mut original = Vec::<u64>::with_capacity(37);
        original.push(9);
        let pointer = original.as_ptr();
        let capacity = original.capacity();
        assert_eq!(optional_vector_v1(Some(&original)), capacity * 8);
        assert_eq!(original.as_slice(), &[9]);
        original.clear();
        assert_eq!(optional_vector_v1(Some(&original)), capacity * 8);
        assert_eq!(original.as_ptr(), pointer);
        assert_eq!(original.capacity(), capacity);
        assert!(original.is_empty());
        assert_eq!(optional_vector_v1(Some(&Vec::<u64>::new())), 0);
        assert_eq!(optional_vector_v1(Some(&vec![(); 3])), 0);
    }

    #[test]
    fn capacity_payload_counts_unused_capacity_and_saturates_overflow() {
        let mut values = Vec::<u64>::with_capacity(37);
        values.push(9);
        let charged = vector_v1(&values);
        assert_eq!(charged, values.capacity() * 8);
        values.clear();
        assert_eq!(vector_v1(&values), charged);
        assert_eq!(sum_v1([usize::MAX, 1]), usize::MAX);
    }

    #[test]
    fn canonical_topology_payload_tracks_both_roles_and_retained_capacity() {
        use super::super::{
            p256_ecdsa_air::P256EcdsaRoleV1, p256_trace::compile_p256_ecdsa_topology_v1,
        };
        for role in [
            P256EcdsaRoleV1::CertificateOrCrl,
            P256EcdsaRoleV1::WalletOwnership,
        ] {
            let mut topology = compile_p256_ecdsa_topology_v1(role).unwrap();
            assert_eq!(topology.linked_operations.len(), 14_828);
            let before = p256_topology_v1(&topology);
            let old = vector_v1(&topology.linked_operations);
            topology.linked_operations.reserve_exact(17);
            assert_eq!(
                p256_topology_v1(&topology),
                before - old + vector_v1(&topology.linked_operations)
            );
            topology.linked_operations.clear();
            assert_eq!(
                p256_topology_v1(&topology),
                before - old + vector_v1(&topology.linked_operations)
            );
        }
    }
}

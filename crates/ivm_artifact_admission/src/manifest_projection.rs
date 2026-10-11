//! Borrowed canonical manifest fields from the verifier's one native CNTR interface.
//!
//! This source is intentionally not registered until native graph custody follows the original
//! read/write/VM owner through admission and consuming exports. A view grants no validation,
//! allocation credit or storage authority; it only preserves the existing native field codec.

use iroha_crypto::Hash;
use iroha_data_model::smart_contract::manifest::{
    BorrowedEntrypoints, BorrowedManifestValue, BorrowedStates, ContractManifest,
    ContractManifestSignaturePayloadView, EntrypointDescriptorView, ManifestEntrypointSequenceV1,
    ManifestStateSequenceV1, ManifestStateTypeNameV1, ManifestTypeNameView, StateDescriptorView,
};
use ivm_abi::metadata::EmbeddedContractInterfaceV1;
use norito::core::{BoundedEncodeError, DecodeBudgetContext, Error};

/// Immutable borrowed native interface and its fixed whole-artifact identities.
///
/// The native verifier/prepared program constructs this view only after its original policy
/// checks. Entrypoint PCs and callable records remain in that same executable interface; the
/// manifest projection intentionally exposes only canonical signed presentation fields.
pub struct ContractManifestProjection<'a> {
    interface: &'a EmbeddedContractInterfaceV1,
    code_hash: Hash,
    abi_hash: Hash,
}

impl<'a> ContractManifestProjection<'a> {
    pub(super) const fn new(
        interface: &'a EmbeddedContractInterfaceV1,
        code_hash: Hash,
        abi_hash: Hash,
    ) -> Self {
        Self {
            interface,
            code_hash,
            abi_hash,
        }
    }

    /// Borrow every canonical signing field without cloning a sequence, state type or string.
    pub fn signature_payload(&self) -> ContractManifestSignaturePayloadView<'_> {
        ContractManifestSignaturePayloadView {
            seiyaku_name: Some(&self.interface.seiyaku_name),
            code_hash: Some(self.code_hash),
            abi_hash: Some(self.abi_hash),
            compiler_fingerprint: Some(&self.interface.compiler_fingerprint),
            features_bitmap: Some(self.interface.features_bitmap),
            access_set_hints: self
                .interface
                .access_set_hints
                .as_ref()
                .map(BorrowedManifestValue),
            permissions: BorrowedManifestValue(&self.interface.permissions),
            events: BorrowedManifestValue(&self.interface.events),
            entrypoints: Some(BorrowedEntrypoints(self)),
            states: Some(BorrowedStates(self)),
            error_types: (!self.interface.error_types.is_empty())
                .then_some(BorrowedManifestValue(&self.interface.error_types)),
            enum_types: BorrowedManifestValue(&self.interface.enum_types),
            error_messages: (!self.interface.error_messages.is_empty())
                .then_some(BorrowedManifestValue(&self.interface.error_messages)),
            kotoba: (!self.interface.kotoba.is_empty())
                .then_some(BorrowedManifestValue(&self.interface.kotoba)),
        }
    }

    /// Encode the exact canonical signing frame under the caller's original cumulative context.
    /// The caller retains its real source/output owner; this view provides no physical permit.
    pub fn signature_payload_bytes(
        &self,
        context: &DecodeBudgetContext,
        max_frame_bytes: usize,
    ) -> Result<Vec<u8>, BoundedEncodeError> {
        self.signature_payload().to_bytes(context, max_frame_bytes)
    }

    /// Stream the exact canonical signing frame without constructing a second frame buffer.
    /// The original native source and the writer's physical backing remain caller-owned.
    pub fn write_signature_payload(
        &self,
        context: &DecodeBudgetContext,
        max_frame_bytes: usize,
        writer: &mut dyn std::io::Write,
    ) -> Result<(), BoundedEncodeError> {
        self.signature_payload()
            .write_canonical(context, max_frame_bytes, writer)
    }

    /// Compare all signed content, preserving absence and ordering, without materializing it.
    /// Stored provenance is checked separately by the caller's existing signature authority.
    ///
    /// # Errors
    /// Native state projection refusal remains typed rather than selecting another manifest.
    pub fn same_signed_content(&self, manifest: &ContractManifest) -> Result<bool, Error> {
        if manifest.seiyaku_name.as_deref() != Some(self.interface.seiyaku_name.as_str())
            || manifest.code_hash != Some(self.code_hash)
            || manifest.abi_hash != Some(self.abi_hash)
            || manifest.compiler_fingerprint.as_deref()
                != Some(self.interface.compiler_fingerprint.as_str())
            || manifest.features_bitmap != Some(self.interface.features_bitmap)
            || manifest.access_set_hints.as_ref() != self.interface.access_set_hints.as_ref()
            || manifest.permissions != self.interface.permissions
            || manifest.events != self.interface.events
            || manifest.error_types.as_ref()
                != (!self.interface.error_types.is_empty()).then_some(&self.interface.error_types)
            || manifest.enum_types != self.interface.enum_types
            || manifest.error_messages.as_ref()
                != (!self.interface.error_messages.is_empty())
                    .then_some(&self.interface.error_messages)
            || manifest.kotoba.as_ref()
                != (!self.interface.kotoba.is_empty()).then_some(&self.interface.kotoba)
        {
            return Ok(false);
        }
        let Some(entries) = manifest.entrypoints.as_ref() else {
            return Ok(false);
        };
        let Some(states) = manifest.states.as_ref() else {
            return Ok(false);
        };
        if entries.len() != self.interface.entrypoints.len()
            || states.len() != self.interface.states.len()
        {
            return Ok(false);
        }
        for (index, entry) in entries.iter().enumerate() {
            if !ManifestEntrypointSequenceV1::get(self, index)
                .ok_or(Error::LengthMismatch)?
                .same_content(entry)
            {
                return Ok(false);
            }
        }
        for (index, state) in states.iter().enumerate() {
            if !ManifestStateSequenceV1::get(self, index)
                .ok_or(Error::LengthMismatch)?
                .same_content(state)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl ManifestEntrypointSequenceV1 for ContractManifestProjection<'_> {
    fn len(&self) -> usize {
        self.interface.entrypoints.len()
    }

    fn get(&self, index: usize) -> Option<EntrypointDescriptorView<'_>> {
        let entry = self.interface.entrypoints.get(index)?;
        Some(EntrypointDescriptorView {
            name: &entry.name,
            kind: BorrowedManifestValue(&entry.kind),
            params: BorrowedManifestValue(&entry.params),
            argument_schema: BorrowedManifestValue(&entry.argument_schema),
            return_type: entry.return_type.as_deref(),
            return_schema: BorrowedManifestValue(&entry.return_schema),
            authorization: BorrowedManifestValue(&entry.authorization),
            read_keys: BorrowedManifestValue(&entry.read_keys),
            write_keys: BorrowedManifestValue(&entry.write_keys),
            access_hints_complete: entry.access_hints_complete,
            access_hints_skipped: BorrowedManifestValue(&entry.access_hints_skipped),
            triggers: BorrowedManifestValue(&entry.triggers),
        })
    }
}

impl ManifestStateSequenceV1 for ContractManifestProjection<'_> {
    fn len(&self) -> usize {
        self.interface.states.len()
    }

    fn get(&self, index: usize) -> Option<StateDescriptorView<'_>> {
        let state = self.interface.states.get(index)?;
        Some(StateDescriptorView {
            name: &state.name,
            type_name: ManifestTypeNameView::State(ManifestStateTypeNameV1::new(&state.ty)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::AllocationBudget;

    fn native() -> super::super::VerifiedContractArtifact {
        let source = r#"seiyaku Projection {
            state int count;
            hajimari() { count = 0; }
            view fn value() authorize(anyone) -> int { return count; }
        }"#;
        let artifact = kotodama_lang::compiler::Compiler::new()
            .compile_source(source)
            .expect("genuine initialized native contract");
        super::super::verify_contract_artifact(&artifact).expect("native artifact admission")
    }

    #[test]
    fn native_manifest_projection_preserves_wire_and_signed_field_substitution_checks() {
        let verified = native();
        let projection = ContractManifestProjection::new(
            &verified.contract_interface,
            verified.code_hash,
            verified.abi_hash,
        );
        assert!(projection.same_signed_content(&verified.manifest).unwrap());
        let limits = norito::core::DecodeLimits::new(
            1024 * 1024,
            1024 * 1024,
            4 * 1024 * 1024,
            4 * 1024 * 1024,
            256,
        );
        let pool = AllocationBudget::new(4 * 1024 * 1024);
        let context = DecodeBudgetContext::try_new_owned(limits, &pool).unwrap();
        assert_eq!(
            projection
                .signature_payload_bytes(&context, 1024 * 1024)
                .unwrap(),
            verified
                .manifest
                .signature_payload_bytes(&context, 1024 * 1024)
                .unwrap(),
        );
        let mut changed = verified.manifest.clone();
        changed.entrypoints.as_mut().unwrap()[0].authorization =
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "CanSubstitute".parse().unwrap(),
            );
        assert!(!projection.same_signed_content(&changed).unwrap());
        changed = verified.manifest.clone();
        changed.states.as_mut().unwrap()[0].type_name = "decimal".into();
        assert!(!projection.same_signed_content(&changed).unwrap());
        changed = verified.manifest.clone();
        changed.entrypoints = None;
        assert!(!projection.same_signed_content(&changed).unwrap());
    }

    #[test]
    fn native_manifest_projection_borrows_original_entry_and_state_fields() {
        let verified = native();
        let projection = ContractManifestProjection::new(
            &verified.contract_interface,
            verified.code_hash,
            verified.abi_hash,
        );
        let entry = ManifestEntrypointSequenceV1::get(&projection, 0).unwrap();
        assert!(std::ptr::eq(
            entry.params.0,
            &verified.contract_interface.entrypoints[0].params,
        ));
        assert!(std::ptr::eq(
            entry.triggers.0,
            &verified.contract_interface.entrypoints[0].triggers,
        ));
        let state = ManifestStateSequenceV1::get(&projection, 0).unwrap();
        assert_eq!(
            state.name.as_ptr(),
            verified.contract_interface.states[0].name.as_ptr()
        );
    }
}

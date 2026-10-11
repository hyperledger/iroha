//! Untrusted original lookup followed by the same mandatory complete source import.

use super::*;
use iroha_plonk::{cs::CurveV1, keys::SourceFingerprintV2};

impl OfflineCompilerV1<'_> {
    pub(super) fn remember_candidate(
        &mut self,
        fingerprint: [u8; 32],
        original: OriginalV1,
    ) -> Result<(), CompilationErrorV1> {
        if let Some(previous) = self.candidates.get(&fingerprint) {
            if *previous != original {
                return Err(CompilationErrorV1::Closure);
            }
        } else {
            if self.candidates.len() >= ARTIFACT_MAX_COUNT_V1 {
                return Err(Error::Inventory.into());
            }
            self.candidates.insert(fingerprint, original);
        }
        Ok(())
    }

    /// Index a bounded original already available through this compiler's store.
    /// This reads exact canonical DATA, not source or commitment authority. A
    /// later matching source must still pass complete native original import.
    /// No catalog, compiled key, or installation capability is returned here.
    ///
    /// # Errors
    /// Missing/changed/oversized originals, noncanonical descriptor/key/tables,
    /// an ambiguous index entry or the bounded maximum candidate count.
    pub fn index_original(&mut self, original: OriginalV1) -> Result<(), CompilationErrorV1> {
        original.validate()?;
        let descriptor = read(self.sink, original.descriptor, DESCRIPTOR_MAX_BYTES_V1)?;
        let binding = DescriptorBinding::decode_v2(&descriptor).map_err(|_| Error::Inventory)?;
        let vk = read(
            self.sink,
            original.verifying_key,
            VERIFYING_KEY_MAX_BYTES_V1,
        )?;
        let bytes = read(self.sink, original.proving_key, self.config.maximum_bytes)?;
        let fingerprint = match binding.descriptor().curve {
            CurveV1::Pallas => iroha_plonk::keys::pk::artifact::source_fingerprint_v2::<Ep>(
                &bytes,
                &binding,
                self.config,
                None,
            )?,
            CurveV1::Vesta => iroha_plonk::keys::pk::artifact::source_fingerprint_v2::<Eq>(
                &bytes,
                &binding,
                self.config,
                None,
            )?,
        };
        // The canonical original reader checked the complete fixed VK length.
        // Require the separate retained VK to be that very original as well.
        let vk_length = bytes
            .get(40..44)
            .and_then(|length| length.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(CompilationErrorV1::Closure)? as usize;
        if vk_length != vk.len() || bytes.get(44..44 + vk.len()) != Some(vk.as_slice()) {
            return Err(CompilationErrorV1::Closure);
        }
        self.remember_candidate(*fingerprint.digest(), original)
    }

    fn register_original(&mut self, original: OriginalV1) -> Result<(), CompilationErrorV1> {
        let mut additions = BTreeMap::new();
        for blob in [
            original.descriptor,
            original.verifying_key,
            original.proving_key,
        ] {
            if let Some(length) = self
                .blobs
                .get(&blob.sha256)
                .or_else(|| additions.get(&blob.sha256))
            {
                if *length != blob.bytes {
                    return Err(Error::Inventory.into());
                }
            } else {
                additions.insert(blob.sha256, blob.bytes);
            }
        }
        let total = additions.values().try_fold(self.bytes, |sum, bytes| {
            sum.checked_add(*bytes)
                .filter(|sum| *sum <= self.maximum_total_bytes)
                .ok_or(Error::Inventory)
        })?;
        self.blobs.extend(additions);
        self.bytes = total;
        Ok(())
    }

    pub(super) fn import_candidate<C: PastaCurve, S: Circuit<C::ScalarExt>>(
        &mut self,
        original: OriginalV1,
        fingerprint: &SourceFingerprintV2,
        circuit: &S,
        params: &PinnedParams<C>,
    ) -> Result<CompiledKeyV1<C>, CompilationErrorV1> {
        let descriptor = read(self.sink, original.descriptor, DESCRIPTOR_MAX_BYTES_V1)?;
        if descriptor != fingerprint.binding().encoded() {
            return Err(CompilationErrorV1::Closure);
        }
        let vk = read(
            self.sink,
            original.verifying_key,
            VERIFYING_KEY_MAX_BYTES_V1,
        )?;
        let expected =
            VerifyingKey::<C>::read(&vk, fingerprint.binding()).map_err(|_| Error::Inventory)?;
        let bytes = read(self.sink, original.proving_key, self.config.maximum_bytes)?;
        let imported = ProvingKey::from_artifact_v2(
            &bytes,
            fingerprint.binding(),
            params,
            circuit,
            self.config,
        )?;
        if imported.vk().to_bytes() != expected.to_bytes() {
            return Err(CompilationErrorV1::Closure);
        }
        let metadata = KeyArtifact::new(imported.binding().clone(), imported.vk().clone())
            .map_err(|_| CompilationErrorV1::Closure)?;
        self.register_original(original)?;
        Ok(CompiledKeyV1 { original, metadata })
    }
}

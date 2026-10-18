//! Exact compiled-profile selection and the independent strict generator boundary.
//!
//! The complete canonical inventory, source policy and network select a finite
//! native entry. They never supply expected identities or construct source seals.

use iroha_plonk::keys::{BuiltinSourceMemberV1, BuiltinSourceProfileV1};

use super::*;

/// The native owner contract, independent of signed certificate renewal.
const OWNER_CONTRACT: &[u8] = b"iroha.kagemusha.complete-builtin-source-profile.v1";

#[derive(NoritoSerialize, NoritoSchema)]
#[norito_schema(name = "iroha.core_zk.kagemusha.builtin_source_profile.v1")]
struct ProfileEnvelope {
    owner_contract: Vec<u8>,
    inventory: Vec<u8>,
    network: [u8; 32],
    provider: [u8; 32],
    root: Vec<u8>,
    parameters: Vec<[u8; 32]>,
}

pub(super) fn profile_bytes(
    inventory: &ProducerInventoryV1,
    scheme: &KagemushaWalletSchemeV1,
) -> Result<Vec<u8>, Error> {
    // This also validates the finite root and provider representation. The
    // network is independently authenticated by the caller's finality owner.
    SourceScopeV1::from_scheme(scheme)?;
    let parameters = [
        (CurveV1::Vesta, 12),
        (CurveV1::Vesta, 14),
        (CurveV1::Vesta, 16),
        (CurveV1::Pallas, 16),
    ]
    .into_iter()
    .map(|(curve, k)| pinned_params_digest(curve, k).ok_or(Error::Profile))
    .collect::<Result<Vec<_>, _>>()?;
    norito::encode_canonical(&ProfileEnvelope {
        owner_contract: OWNER_CONTRACT.to_vec(),
        inventory: inventory.to_canonical_bytes()?,
        network: scheme.network_id,
        provider: scheme.provider_contract,
        root: scheme.scheme_root_key.as_sec1_bytes().to_vec(),
        parameters,
    })
    .map_err(|_| Error::Inventory)
}

/// Only the complete-wallet entry point selects this mode. Existing public
/// per-source and complete strict importers always pass `Strict` explicitly.
#[derive(Clone, Copy)]
pub(super) enum Admission<'a> {
    Strict,
    Builtin(&'a BuiltinSourceProfileV1),
}

impl Admission<'_> {
    pub(super) fn member(self, path: &[u32]) -> Result<Option<BuiltinSourceMemberV1>, Error> {
        match self {
            Self::Strict => Ok(None),
            Self::Builtin(profile) => profile.member(path).map(Some).map_err(|_| Error::Inventory),
        }
    }
}

// A cache hit still admits the CURRENT compiled role against every freshly read
// original. Its existing typed metadata saves decoding only after exact byte
// equality; the cached seal remains a comparison target, never mint input.
// Installation/role selection stays with the batch.
pub(super) fn require_member_source<C: iroha_pasta::PastaCurve>(
    member: BuiltinSourceMemberV1,
    original: &OriginalBytesV1,
    params: &iroha_plonk::pcs::ipa::PinnedParams<C>,
    config: iroha_plonk::keys::pk::artifact::ReadConfig,
    expected: iroha_plonk::keys::SourceBoundViewV2<'_, C>,
    expected_seal: &iroha_plonk::keys::SourceAdmissionSealV2<C>,
) -> Result<(), Error> {
    let admitted = member
        .admit_originals_with_metadata_cancellable(
            &original.descriptor,
            &original.verifying_key,
            &original.proving_key,
            expected.binding(),
            expected.verifying_key(),
            params,
            config,
            None,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Inventory
            }
        })?;
    let (binding, key, seal) = admitted.into_parts();
    if &binding != expected.binding()
        || key.to_bytes() != expected.verifying_key().to_bytes()
        || !seal.same_source(expected_seal)
    {
        return Err(Error::Inventory);
    }
    Ok(())
}

/// A complete graph accepted by the unconditional strict source importer.
///
/// Only the named strict constructor can produce this generator input. Built-in
/// source owners cannot be converted into it, so a registry cannot certify itself.
pub struct StrictQualifiedSourceProfileV1 {
    wallet: QualifiedWalletSourcesV1,
    profile: Vec<u8>,
}

impl AuthenticatedProducerInventoryV1 {
    /// Independently reconstruct every source and check all VK commitments before
    /// permitting the finite built-in profile generator to export public data.
    ///
    /// # Errors
    /// Any ordinary complete strict source, installation or native finality failure.
    pub fn qualify_strict_source_profile(
        self,
        installed: &InstalledVerifierPackV1,
        native_finality: &iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier,
        originals: &mut dyn OriginalSourceV1,
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
    ) -> Result<StrictQualifiedSourceProfileV1, WalletSourcesErrorV1> {
        let profile = profile_bytes(self.inventory(), installed.verifier().scheme())?;
        let wallet = self.qualify_wallet(installed, native_finality, originals, config)?;
        Ok(StrictQualifiedSourceProfileV1 { wallet, profile })
    }
}

impl StrictQualifiedSourceProfileV1 {
    /// Emit one immutable Rust registry entry after independent complete strict
    /// qualification and a fresh bounded read of every exact signed original.
    ///
    /// This exports public build input, never a runtime capability. The generator
    /// must include this entry in the next native build; it cannot register it in
    /// the running process. Ordinary app and proof APIs cannot create this owner.
    ///
    /// # Errors
    /// An incomplete build-input identity, changed/missing original or invalid
    /// canonical descriptor/compact-original envelope.
    pub fn export_builtin_entry_rust(
        &self,
        originals: &mut dyn OriginalSourceV1,
        config: iroha_plonk::keys::pk::artifact::ReadConfig,
    ) -> Result<String, WalletSourcesErrorV1> {
        use std::fmt::Write as _;
        let source_identity = iroha_plonk::keys::builtin_source_identity_v1()?;
        let inventory = self.wallet.inventory();
        let mut paths = Vec::new();
        for (selector, member) in inventory.sigma.iter().copied().enumerate() {
            paths.push((
                vec![1, u32::try_from(selector).map_err(|_| Error::Inventory)?],
                member,
            ));
        }
        for (program, record) in inventory.operations.iter().enumerate() {
            for (stage, member) in record.q.iter().copied().enumerate() {
                paths.push((
                    vec![
                        2,
                        u32::try_from(program).map_err(|_| Error::Inventory)?,
                        u32::try_from(stage).map_err(|_| Error::Inventory)?,
                    ],
                    member,
                ));
            }
        }
        for (route, program) in inventory.routes.iter().copied().enumerate() {
            let record = inventory
                .operations
                .get(usize::try_from(program).map_err(|_| Error::Inventory)?)
                .ok_or(Error::Inventory)?;
            for (tag, members) in [(3, &record.a), (4, &record.w)] {
                for (stage, member) in members.iter().copied().enumerate() {
                    paths.push((
                        vec![
                            tag,
                            u32::try_from(route).map_err(|_| Error::Inventory)?,
                            u32::try_from(stage).map_err(|_| Error::Inventory)?,
                        ],
                        member,
                    ));
                }
            }
        }
        paths.push((vec![5], inventory.omega));
        let mut text = String::new();
        writeln!(
            text,
            "BuiltinProfileEntry {{ profile: {}, source_identity: {:?}, members: &[",
            rust_blob(&self.profile),
            source_identity
        )
        .map_err(|_| Error::Inventory)?;
        for (role, member) in paths {
            // Re-reading is essential: no original supplied after strict admission
            // can substitute its fingerprint or commitment in generated DATA.
            let original = self.wallet.authenticated_inventory().read_original(
                member,
                originals,
                config.maximum_bytes,
            )?;
            let binding =
                DescriptorBinding::decode_v2(&original.descriptor).map_err(|_| Error::Inventory)?;
            let descriptor = binding.descriptor();
            if binding.n() > config.maximum_rows
                || original.proving_key.len() < 108
                || original.proving_key[..8] != iroha_plonk::keys::pk::artifact::MAGIC
                || original.proving_key[8..40] != binding.digest()[..]
            {
                return Err(Error::Inventory.into());
            }
            let vk_len = u32::from_le_bytes(
                original.proving_key[40..44]
                    .try_into()
                    .map_err(|_| Error::Inventory)?,
            ) as usize;
            let end = 44_usize.checked_add(vk_len).ok_or(Error::Inventory)?;
            if end.checked_add(64) != Some(original.proving_key.len())
                || original.proving_key[44..end] != original.verifying_key
            {
                return Err(Error::Inventory.into());
            }
            let copy_digest: [u8; 32] = original.proving_key[end..end + 32]
                .try_into()
                .map_err(|_| Error::Inventory)?;
            let source_digest: [u8; 32] = original.proving_key[end + 32..]
                .try_into()
                .map_err(|_| Error::Inventory)?;
            writeln!(text,
                "BuiltinMemberEntry {{ role_path: &{role:?}, curve: CurveV1::{:?}, k: {}, params_digest: {:?}, descriptor: {}, verifying_key: {}, compact_pk: {}, descriptor_digest: {:?}, copy_digest: {copy_digest:?}, source_digest: {source_digest:?} }},",
                descriptor.curve, descriptor.k, descriptor.params_digest,
                rust_blob(&original.descriptor), rust_blob(&original.verifying_key),
                rust_blob(&original.proving_key), binding.digest(),
            ).map_err(|_| Error::Inventory)?;
        }
        text.push_str("] },\n");
        Ok(text)
    }
}

fn rust_blob(bytes: &[u8]) -> String {
    let blob = BlobV1::of(bytes);
    format!(
        "BuiltinBlob {{ bytes: {}, sha256: {:?} }}",
        rust_decimal(blob.bytes),
        blob.sha256
    )
}

fn rust_decimal(value: u64) -> String {
    let digits = value.to_string();
    let mut literal = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            literal.push('_');
        }
        literal.push(digit);
    }
    literal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_literals_group_digits_without_changing_values() {
        for (value, expected) in [
            (0, "0"),
            (999, "999"),
            (1_000, "1_000"),
            (99_999, "99_999"),
            (100_000, "100_000"),
            (1_000_000, "1_000_000"),
            (u64::MAX, "18_446_744_073_709_551_615"),
        ] {
            let literal = rust_decimal(value);
            assert_eq!(literal, expected);
            assert_eq!(literal.replace('_', "").parse::<u64>().unwrap(), value);
        }
    }

    #[test]
    fn generated_blob_lengths_are_readable_and_preserve_original_values_and_hashes() {
        for (length, literal) in [
            (0, "0"),
            (1, "1"),
            (999, "999"),
            (1_000, "1_000"),
            (9_999, "9_999"),
            (10_000, "10_000"),
            (99_999, "99_999"),
            (100_000, "100_000"),
            (244_977, "244_977"),
            (1_000_000, "1_000_000"),
        ] {
            let bytes = vec![0x5a; length];
            let original = BlobV1::of(&bytes);
            assert_eq!(
                rust_blob(&bytes),
                format!(
                    "BuiltinBlob {{ bytes: {literal}, sha256: {:?} }}",
                    original.sha256
                )
            );
            assert_eq!(
                literal.replace('_', "").parse::<u64>().unwrap(),
                original.bytes
            );
        }
    }
}

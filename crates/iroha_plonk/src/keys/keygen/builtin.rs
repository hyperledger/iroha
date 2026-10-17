//! Closed compiled source profiles, separate from ordinary strict source intake.
//!
//! The generated table is immutable native code produced by a complete strict
//! source traversal. Public inputs only select an exact existing profile/member;
//! they cannot extend the table or provide expected identities. This capability
//! establishes source compatibility, never installation, finality or custody.

use iroha_pasta::{CancellationToken, PastaCurve};
use sha2::{Digest as _, Sha256};

use super::{DescriptorBinding, SourceBoundVerifyingKeyV2, VerifyingKey, rebuild};
use crate::{cs::CurveV1, keys::pk::artifact, pcs::ipa::PinnedParams};

mod generated;
mod source_identity {
    include!(concat!(env!("OUT_DIR"), "/native_source_identity.rs"));
}

const MAX_PROFILE_BYTES: usize = 32 << 20;
const MAX_ROLE_WORDS: usize = 8;

/// A closed native source profile or its exact originals were not admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuiltinSourceErrorV1 {
    /// Cooperative cancellation; no partial capability is returned.
    Cancelled,
    /// Actual complete profile is outside this native binary's finite set.
    UnsupportedProfile,
    /// Generated source identity differs from the actual compiled source closure.
    StaleSource,
    /// The current target is outside the implemented native support set.
    UnsupportedTarget,
    /// The build could not account for its complete required source closure.
    IncompleteSourceClosure,
    /// This exact role path is absent or ambiguous within the selected profile.
    Member,
    /// Complete descriptor, VK or compact original identity differs.
    Original,
    /// Canonical framing, parameters, dimensions or caller bounds failed.
    Artifact(artifact::Error),
}
impl BuiltinSourceErrorV1 {
    /// Whether cancellation ended the operation without an admission verdict.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
            || matches!(self, Self::Artifact(error) if error.is_cancelled())
    }
}
impl core::fmt::Display for BuiltinSourceErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("built-in source admission cancelled"),
            Self::UnsupportedProfile => f.write_str("unsupported built-in source profile"),
            Self::StaleSource => f.write_str("stale built-in source profile"),
            Self::UnsupportedTarget => f.write_str("unsupported built-in source target"),
            Self::IncompleteSourceClosure => f.write_str("incomplete native source closure"),
            Self::Member => f.write_str("built-in source member differs"),
            Self::Original => f.write_str("built-in source original differs"),
            Self::Artifact(error) => write!(f, "built-in source: {error}"),
        }
    }
}
impl std::error::Error for BuiltinSourceErrorV1 {}
impl From<iroha_pasta::Cancelled> for BuiltinSourceErrorV1 {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}
impl From<artifact::Error> for BuiltinSourceErrorV1 {
    fn from(error: artifact::Error) -> Self {
        Self::Artifact(error)
    }
}

/// Read the actual build-computed generator input identity as public DATA.
/// This grants no profile, member or source authority and remains available when
/// generated entries are empty or stale, so the strict generator can refresh them.
/// # Errors
/// The build could not account for its complete required source closure.
pub fn builtin_source_identity_v1() -> Result<[u8; 32], BuiltinSourceErrorV1> {
    if !source_identity::NATIVE_SOURCE_CLOSURE_COMPLETE {
        return Err(BuiltinSourceErrorV1::IncompleteSourceClosure);
    }
    Ok(source_identity::CURRENT_NATIVE_SOURCE_DIGEST)
}

#[derive(Debug)]
struct BuiltinBlob {
    bytes: u64,
    sha256: [u8; 32],
}
#[derive(Debug)]
struct BuiltinMemberEntry {
    role_path: &'static [u32],
    curve: CurveV1,
    k: u8,
    params_digest: [u8; 32],
    descriptor: BuiltinBlob,
    verifying_key: BuiltinBlob,
    compact_pk: BuiltinBlob,
    descriptor_digest: [u8; 32],
    copy_digest: [u8; 32],
    source_digest: [u8; 32],
}
#[derive(Debug)]
struct BuiltinProfileEntry {
    profile: BuiltinBlob,
    source_identity: [u8; 32],
    members: &'static [BuiltinMemberEntry],
}

/// Exact match to one immutable compiled source graph, not a wallet grant.
/// No decoder, raw-parts constructor or runtime registration API exists.
#[derive(Clone, Copy, Debug)]
pub struct BuiltinSourceProfileV1 {
    entry: &'static BuiltinProfileEntry,
}

/// One role-specific member of a selected immutable compiled source graph.
/// A member authorizes only its complete original identities under fixed parameters.
#[derive(Clone, Copy, Debug)]
pub struct BuiltinSourceMemberV1 {
    entry: &'static BuiltinMemberEntry,
}

// Only the all-original checks below construct this token. The separate seal
// module cannot be called with an opaque member and unrelated decoded metadata.
// `key_sha256` is the SHA-256 of the exact installed VK bytes, checked against the
// member's pin, and `key` encodes exactly those bytes.
pub(super) struct VerifiedBuiltinOriginal<C: PastaCurve> {
    binding: DescriptorBinding,
    key: VerifyingKey<C>,
    key_sha256: [u8; 32],
    source_digest: [u8; 32],
}
impl<C: PastaCurve> VerifiedBuiltinOriginal<C> {
    pub(super) fn into_parts(self) -> (DescriptorBinding, VerifyingKey<C>, [u8; 32], [u8; 32]) {
        (self.binding, self.key, self.key_sha256, self.source_digest)
    }
}

fn digest(
    bytes: &[u8],
    cancellation: Option<&CancellationToken>,
) -> Result<[u8; 32], BuiltinSourceErrorV1> {
    crate::keys::admission_work::record_builtin_hash(bytes.len());
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(4096) {
        CancellationToken::checkpoint(cancellation)?;
        hash.update(chunk);
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(hash.finalize().into())
}

fn equal_bytes(
    actual: &[u8],
    expected: &[u8],
    cancellation: Option<&CancellationToken>,
) -> Result<bool, BuiltinSourceErrorV1> {
    CancellationToken::checkpoint(cancellation)?;
    if actual.len() != expected.len() {
        return Ok(false);
    }
    for (actual, expected) in actual.chunks(4096).zip(expected.chunks(4096)) {
        CancellationToken::checkpoint(cancellation)?;
        if actual != expected {
            return Ok(false);
        }
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(true)
}

fn select_profile(
    profiles: &'static [BuiltinProfileEntry],
    actual_profile: &[u8],
    source_identity: &[u8; 32],
    closure_complete: bool,
    target_supported: bool,
    cancellation: Option<&CancellationToken>,
) -> Result<BuiltinSourceProfileV1, BuiltinSourceErrorV1> {
    CancellationToken::checkpoint(cancellation)?;
    if !closure_complete {
        return Err(BuiltinSourceErrorV1::IncompleteSourceClosure);
    }
    if !target_supported {
        return Err(BuiltinSourceErrorV1::UnsupportedTarget);
    }
    if actual_profile.is_empty() || actual_profile.len() > MAX_PROFILE_BYTES {
        return Err(BuiltinSourceErrorV1::UnsupportedProfile);
    }
    let actual_digest = digest(actual_profile, cancellation)?;
    let mut matches = profiles.iter().filter(|entry| {
        entry.profile.bytes == actual_profile.len() as u64 && entry.profile.sha256 == actual_digest
    });
    let entry = matches
        .next()
        .ok_or(BuiltinSourceErrorV1::UnsupportedProfile)?;
    if matches.next().is_some() {
        return Err(BuiltinSourceErrorV1::UnsupportedProfile);
    }
    if &entry.source_identity != source_identity {
        return Err(BuiltinSourceErrorV1::StaleSource);
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(BuiltinSourceProfileV1 { entry })
}

impl BuiltinSourceProfileV1 {
    /// Match actual complete profile DATA to a fresh closed compiled entry.
    /// The owning wallet must independently authenticate the installation and
    /// finish every graph/member check before granting monetary capabilities.
    /// # Errors
    /// Unknown, ambiguous, stale or unsupported profile, incomplete build closure,
    /// oversized input or cooperative cancellation. There is no strict fallback.
    pub fn match_actual(
        actual_profile: &[u8],
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, BuiltinSourceErrorV1> {
        select_profile(
            generated::PROFILES,
            actual_profile,
            &source_identity::CURRENT_NATIVE_SOURCE_DIGEST,
            source_identity::NATIVE_SOURCE_CLOSURE_COMPLETE,
            source_identity::BUILTIN_TARGET_SUPPORTED,
            cancellation,
        )
    }

    /// Select an exact ordered role path within this profile only.
    /// Path words are public DATA, not authority or a globally meaningful key ID.
    /// # Errors
    /// Empty, oversized, missing or ambiguous role path.
    pub fn member(
        self,
        actual_role_path: &[u32],
    ) -> Result<BuiltinSourceMemberV1, BuiltinSourceErrorV1> {
        if actual_role_path.is_empty() || actual_role_path.len() > MAX_ROLE_WORDS {
            return Err(BuiltinSourceErrorV1::Member);
        }
        let mut matches = self
            .entry
            .members
            .iter()
            .filter(|entry| entry.role_path == actual_role_path);
        let entry = matches.next().ok_or(BuiltinSourceErrorV1::Member)?;
        if matches.next().is_some() {
            return Err(BuiltinSourceErrorV1::Member);
        }
        Ok(BuiltinSourceMemberV1 { entry })
    }
}

impl BuiltinSourceMemberV1 {
    /// Admit all three exact canonical originals against this compiled member.
    /// This explicit build-qualified path performs no source synthesis or MSM.
    /// Ordinary artifact import remains strict; later proving still reconstructs
    /// and checks the source fingerprint before constructing proving buffers.
    /// # Errors
    /// Any original/parameter/profile/encoding/bound mismatch or cancellation.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_originals_cancellable<C: PastaCurve>(
        self,
        descriptor: &[u8],
        installed_vk: &[u8],
        compact_pk: &[u8],
        params: &PinnedParams<C>,
        config: artifact::ReadConfig,
        cancellation: Option<&CancellationToken>,
    ) -> Result<SourceBoundVerifyingKeyV2<C>, BuiltinSourceErrorV1> {
        let key_sha256 = self.check_originals::<C>(
            descriptor,
            installed_vk,
            compact_pk,
            params,
            config,
            cancellation,
        )?;
        let entry = self.entry;
        let binding =
            DescriptorBinding::decode_v2(descriptor).map_err(|_| artifact::Error::Encoding)?;
        let d = binding.descriptor();
        if binding.encoded() != descriptor
            || binding.digest() != &entry.descriptor_digest
            || d.curve != entry.curve
            || d.k != entry.k
            || d.params_digest != entry.params_digest
        {
            return Err(artifact::Error::Profile.into());
        }
        crate::keys::pk::QuotientDomain::<C::ScalarExt>::new(params.k(), usize::from(d.degree))
            .map_err(artifact::Error::from)?;
        let parts =
            artifact::read_bounded_original_v2::<C>(compact_pk, &binding, config, cancellation)?;
        if parts.key.to_bytes() != installed_vk
            || parts.copy_digest != entry.copy_digest
            || parts.source_digest != entry.source_digest
        {
            return Err(BuiltinSourceErrorV1::Original);
        }
        CancellationToken::checkpoint(cancellation)?;
        rebuild::from_builtin_member(
            VerifiedBuiltinOriginal {
                binding,
                key: parts.key,
                key_sha256,
                source_digest: entry.source_digest,
            },
            cancellation,
        )
        .map_err(artifact::Error::from)
        .map_err(Into::into)
    }
    /// Admit exact originals while reusing already validated immutable metadata.
    /// Every raw original is still matched against this current compiled member.
    /// Exact canonical byte equality binds the supplied typed values; neither the
    /// values nor a source seal can select a member or supply an expected digest.
    /// Ordinary strict import and later proof-time source reconstruction are unchanged.
    /// # Errors
    /// As [`Self::admit_originals_cancellable`], or supplied metadata differs from
    /// the current originals. Cancellation is checked during byte comparisons.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_originals_with_metadata_cancellable<C: PastaCurve>(
        self,
        descriptor: &[u8],
        installed_vk: &[u8],
        compact_pk: &[u8],
        binding: &DescriptorBinding,
        key: &VerifyingKey<C>,
        params: &PinnedParams<C>,
        config: artifact::ReadConfig,
        cancellation: Option<&CancellationToken>,
    ) -> Result<SourceBoundVerifyingKeyV2<C>, BuiltinSourceErrorV1> {
        let key_sha256 = self.check_originals::<C>(
            descriptor,
            installed_vk,
            compact_pk,
            params,
            config,
            cancellation,
        )?;
        let entry = self.entry;
        let d = binding.descriptor();
        let descriptor_digest = binding.digest();
        if !equal_bytes(binding.encoded(), descriptor, cancellation)?
            || descriptor_digest != &entry.descriptor_digest
            || d.curve != entry.curve
            || d.k != entry.k
            || d.params_digest != entry.params_digest
            || key.descriptor_digest() != descriptor_digest
        {
            return Err(artifact::Error::Profile.into());
        }
        if !equal_bytes(key.to_bytes(), installed_vk, cancellation)? {
            return Err(BuiltinSourceErrorV1::Original);
        }
        crate::keys::pk::QuotientDomain::<C::ScalarExt>::new(params.k(), usize::from(d.degree))
            .map_err(artifact::Error::from)?;
        let parts = artifact::read_bounded_original_with_key_v2(
            compact_pk,
            binding,
            key,
            config,
            cancellation,
        )?;
        if parts.copy_digest != entry.copy_digest || parts.source_digest != entry.source_digest {
            return Err(BuiltinSourceErrorV1::Original);
        }
        CancellationToken::checkpoint(cancellation)?;
        rebuild::from_builtin_member(
            VerifiedBuiltinOriginal {
                binding: binding.clone(),
                key: parts.key,
                key_sha256,
                source_digest: entry.source_digest,
            },
            cancellation,
        )
        .map_err(artifact::Error::from)
        .map_err(Into::into)
    }

    /// Check every original's length and SHA-256 against this member's pins.
    /// Returns the installed VK's SHA-256, which the loop proved equal to its pin;
    /// a VK that differs from its pin returns an error before any token exists.
    fn check_originals<C: PastaCurve>(
        self,
        descriptor: &[u8],
        installed_vk: &[u8],
        compact_pk: &[u8],
        params: &PinnedParams<C>,
        config: artifact::ReadConfig,
        cancellation: Option<&CancellationToken>,
    ) -> Result<[u8; 32], BuiltinSourceErrorV1> {
        CancellationToken::checkpoint(cancellation)?;
        let entry = self.entry;
        let rows = 1_usize
            .checked_shl(u32::from(entry.k))
            .ok_or(artifact::Error::Length)?;
        if compact_pk.len() > config.maximum_bytes || rows > config.maximum_rows {
            return Err(artifact::Error::Length.into());
        }
        for (actual, expected) in [
            (descriptor, &entry.descriptor),
            (installed_vk, &entry.verifying_key),
            (compact_pk, &entry.compact_pk),
        ] {
            if actual.is_empty() || actual.len() as u64 != expected.bytes {
                return Err(BuiltinSourceErrorV1::Original);
            }
        }
        if params.curve() != entry.curve
            || params.k() != u32::from(entry.k)
            || crate::cs::descriptor::pinned_params_digest(entry.curve, u32::from(entry.k))
                != Some(entry.params_digest)
        {
            return Err(artifact::Error::Profile.into());
        }
        for (actual, expected) in [
            (descriptor, &entry.descriptor),
            (installed_vk, &entry.verifying_key),
            (compact_pk, &entry.compact_pk),
        ] {
            if digest(actual, cancellation)? != expected.sha256 {
                return Err(BuiltinSourceErrorV1::Original);
            }
        }
        Ok(entry.verifying_key.sha256)
    }
}

#[cfg(test)]
mod tests;

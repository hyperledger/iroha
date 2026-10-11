//! Unauthenticated source recipes shared by offline construction and strict intake.
//!
//! These values select compiled sources only. They cannot construct an installed
//! capability, substitute a signed manifest or bypass original-key qualification.

use iroha_kagemusha_proof::a_relation::{bootstrap::BootstrapPolicy, own::OwnPolicy};
use iroha_plonk_gadgets::p256::native::{Affine, words_from_be};

use super::*;

/// Wallet-private strict-origin record, retained only by qualified installation owners.
/// This wrapper is never decoded from inventory DATA. Call sites create it only
/// after the complete source-specific original importer returned successfully.
/// Installation identity belongs to the enclosing qualified owner; member/role
/// selection must match before any original is opened.
#[derive(Clone, Debug)]
pub(super) struct InstalledSourceSealV1<C: PastaCurve> {
    member: u32,
    seal: iroha_plonk::keys::SourceAdmissionSealV2<C>,
}
impl<C: PastaCurve> InstalledSourceSealV1<C> {
    pub(super) fn new(member: u32, seal: iroha_plonk::keys::SourceAdmissionSealV2<C>) -> Self {
        Self { member, seal }
    }
    pub(super) fn seal(
        &self,
        expected_member: u32,
    ) -> Result<&iroha_plonk::keys::SourceAdmissionSealV2<C>, Error> {
        if self.member != expected_member {
            return Err(Error::Inventory);
        }
        Ok(&self.seal)
    }
    pub(super) fn bind<'a>(
        &'a self,
        expected_member: u32,
        key: &'a iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact<C>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<iroha_plonk::keys::SourceBoundViewV2<'a, C>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        self.seal(expected_member)?
            .bind(key.binding(), key.key(), cancellation)
            .map_err(|e| {
                if e.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Inventory
                }
            })
    }
}

/// Raw provider/root source policy, independent of the eventual scheme/manifest ID.
/// Offline tooling supplies its intended policy; installation derives the same
/// values from its authenticated scheme. Construction grants no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceScopeV1 {
    provider: [u128; 2],
    root: Affine,
}
impl SourceScopeV1 {
    /// Validate only the fixed provider and canonical finite root point.
    /// # Errors
    /// Zero provider or invalid P-256 point.
    pub fn new(provider: [u128; 2], root: Affine) -> Result<Self, Error> {
        OwnPolicy::new(provider, root).map_err(|_| Error::Authority)?;
        Ok(Self { provider, root })
    }

    pub(super) fn from_scheme(scheme: &KagemushaWalletSchemeV1) -> Result<Self, Error> {
        scheme
            .scheme_root_key
            .validate()
            .map_err(|_| Error::Authority)?;
        let key = scheme.scheme_root_key.as_sec1_bytes();
        let root = Affine {
            x: words_from_be(key[1..33].try_into().map_err(|_| Error::Authority)?),
            y: words_from_be(key[33..65].try_into().map_err(|_| Error::Authority)?),
        };
        let provider = [
            u128::from_le_bytes(
                scheme.provider_contract[..16]
                    .try_into()
                    .map_err(|_| Error::Authority)?,
            ),
            u128::from_le_bytes(
                scheme.provider_contract[16..]
                    .try_into()
                    .map_err(|_| Error::Authority)?,
            ),
        ];
        Self::new(provider, root)
    }
    pub(super) fn own(self) -> Result<OwnPolicy, Error> {
        OwnPolicy::new(self.provider, self.root).map_err(|_| Error::Authority)
    }
    pub(super) fn bootstrap(self) -> Result<BootstrapPolicy, Error> {
        BootstrapPolicy::new(self.provider, self.root).map_err(|_| Error::Authority)
    }
    /// Exact authenticated or offline-selected provider limbs in little-endian order.
    pub const fn provider(self) -> [u128; 2] {
        self.provider
    }
    /// Exact finite P-256 scheme-root point fixed into native source recipes.
    pub const fn root(self) -> Affine {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scheme_scope_preserves_sec1_point_and_provider_limb_byte_order() {
        let generator = Affine::GENERATOR;
        let mut sec1 = vec![4];
        for value in [generator.x, generator.y] {
            for word in value.iter().rev() {
                sec1.extend(word.to_be_bytes());
            }
        }
        let provider_contract = core::array::from_fn(|i| i as u8);
        let scheme = KagemushaWalletSchemeV1 {
            version: 1,
            network_id: [1; 32],
            scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(&sec1).unwrap(),
            relation_id: [2; 32],
            provider_contract,
        };
        let scope = SourceScopeV1::from_scheme(&scheme).unwrap();
        assert_eq!(scope.root(), generator);
        let mut restored = Vec::new();
        for limb in scope.provider {
            restored.extend(limb.to_le_bytes());
        }
        assert_eq!(restored, provider_contract);
    }

    #[test]
    fn raw_source_scope_checks_both_fixed_inputs_without_installation_identity() {
        assert!(SourceScopeV1::new([0; 2], Affine::GENERATOR).is_err());
        let invalid = Affine {
            x: [0; 4],
            y: [0; 4],
        };
        assert!(SourceScopeV1::new([1, 2], invalid).is_err());
        let scope = SourceScopeV1::new([1, 2], Affine::GENERATOR).unwrap();
        scope.own().unwrap();
        scope.bootstrap().unwrap();
        assert_eq!(scope.root(), Affine::GENERATOR);
    }
}

#[cfg(test)]
#[path = "recipe/seal_tests.rs"]
mod seal_tests;

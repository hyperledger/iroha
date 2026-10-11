//! One private registration capability owner for native finality authentication.
use super::*;
use iroha_data_model::{
    NetworkId, account::AccountId, kagemusha::KagemushaWalletAssetScopeV1,
    sumeragi_finality::VerifiedSumeragiBlock,
};

/// Exact immutable Register authenticated by the native signed-genesis finality owner.
/// There is no decoder, caller-verifier trait, public field or unchecked constructor.
#[derive(Clone, Debug)]
pub struct FinalizedKagemushaWalletRegistrationV1 {
    data: KagemushaWalletRegistrationDataV1,
    block_hash: [u8; 32],
    height: u64,
}
impl FinalizedKagemushaWalletRegistrationV1 {
    /// Exact independently selected and executed scheme.
    pub fn scheme(&self) -> &KagemushaWalletSchemeV1 {
        self.data.scheme()
    }
    /// Authoritative registered incarnation and scale.
    pub fn asset(&self) -> &KagemushaWalletAssetScopeV1 {
        self.data.asset()
    }
    /// Exact scheme frame in the authenticated transaction.
    pub fn scheme_original(&self) -> &[u8] {
        self.data.scheme_original()
    }
    /// Exact asset frame in the authenticated transaction.
    pub fn asset_original(&self) -> &[u8] {
        self.data.asset_original()
    }
    /// Signed consenting reserve.
    pub fn reserve(&self) -> &AccountId {
        self.data.reserve()
    }
    /// Authenticated original block header identity.
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }
    /// Account-signed registration transaction identity.
    pub fn transaction_hash(&self) -> [u8; 32] {
        self.data.transaction_hash()
    }
    /// Authenticated non-genesis registration height.
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// Exact direct instruction position.
    pub fn instruction_index(&self) -> usize {
        self.data.instruction_index()
    }
    pub(super) fn from_authenticated(
        data: KagemushaWalletRegistrationDataV1,
        block_hash: [u8; 32],
        height: u64,
    ) -> Self {
        Self {
            data,
            block_hash,
            height,
        }
    }
}

/// Authenticate exact direct Register DATA through the existing native global finality owner.
/// # Errors
/// Foreign native scope, failed execution or membership, or invalid Register terms.
pub fn verify_finalized_kagemusha_wallet_registration_v1(
    verified: &VerifiedSumeragiBlock,
    committed: &CommittedTransaction,
    expected_network: NetworkId,
    expected_chain: &str,
    expected_scheme: &KagemushaWalletSchemeV1,
    asset_digest: [u8; 32],
    instruction_index: usize,
) -> Result<FinalizedKagemushaWalletRegistrationV1, RegistrationErrorV1> {
    verified.verify_global_scope(expected_network, expected_chain)?;
    verified.verify_committed_transaction(&expected_network, committed)?;
    let data = project_kagemusha_wallet_registration_v1(
        committed,
        expected_network,
        expected_scheme,
        asset_digest,
        instruction_index,
    )?;
    Ok(FinalizedKagemushaWalletRegistrationV1::from_authenticated(
        data,
        *committed.block_hash().as_ref(),
        verified.height(),
    ))
}

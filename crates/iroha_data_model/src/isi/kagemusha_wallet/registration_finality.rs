//! Canonical direct Register semantic DATA for native finality admission.
//! Projection validates originals and terms; it never proves execution or grants registration.
use super::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1};
use crate::{
    NetworkId,
    account::AccountId,
    asset::AssetBalanceScope,
    kagemusha::{KagemushaWalletAssetScopeV1, KagemushaWalletSchemeV1},
    query::CommittedTransaction,
    transaction::{Executable, TransactionEntrypoint},
};

/// Canonical asset DATA is fixed-size apart from its standard frame; no path or metadata is allowed.
pub const KAGEMUSHA_WALLET_REGISTRATION_ASSET_MAX_BYTES_V1: usize = 4096;

/// Invalid signed Register DATA or selected semantic terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KagemushaWalletRegistrationErrorV1 {
    /// The original external transaction signature, network or reported result is invalid.
    #[error("registration DATA does not contain a signed successful external transaction")]
    Transaction,
    /// The exact selected direct instruction is not Register.
    #[error("selected successful instruction is not a direct KAGEMUSHA Register")]
    Instruction,
    /// A canonical scheme or asset original is malformed, foreign or changed.
    #[error("registration original differs from the selected scheme or asset")]
    Original,
    /// Only an unrestricted Global balance bucket is eligible for universal selection.
    #[error("universal wallet registration requires the Global balance scope")]
    Scope,
    /// The external transaction authority did not give the exact reserve consent.
    #[error("registration reserve differs from the signed transaction authority")]
    Reserve,
}

/// Validated direct Register DATA, with no finality, execution or registration authority.
/// The finality owner must authenticate the exact input/output membership and successful
/// result before selecting these terms. A caller can project this DATA from an unproved row.
#[derive(Debug, Clone)]
pub struct KagemushaWalletRegistrationDataV1 {
    scheme: KagemushaWalletSchemeV1,
    asset: KagemushaWalletAssetScopeV1,
    scheme_original: Vec<u8>,
    asset_original: Vec<u8>,
    reserve: AccountId,
    transaction_hash: [u8; 32],
    instruction_index: usize,
}
impl KagemushaWalletRegistrationDataV1 {
    /// Complete scheme selected independently and matched to the successful original.
    #[must_use]
    pub const fn scheme(&self) -> &KagemushaWalletSchemeV1 {
        &self.scheme
    }
    /// Claimed definition, incarnation and scale; execution must be authenticated separately.
    #[must_use]
    pub fn asset(&self) -> &KagemushaWalletAssetScopeV1 {
        &self.asset
    }
    /// Exact canonical scheme frame in the signed instruction.
    #[must_use]
    pub fn scheme_original(&self) -> &[u8] {
        &self.scheme_original
    }
    /// Exact canonical asset frame in the signed instruction.
    #[must_use]
    pub fn asset_original(&self) -> &[u8] {
        &self.asset_original
    }
    /// Reserve equal to the signed external transaction authority.
    #[must_use]
    pub fn reserve(&self) -> &AccountId {
        &self.reserve
    }
    /// Original account-signed registration transaction identity.
    #[must_use]
    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }
    /// Exact direct instruction selected in the authenticated transaction.
    #[must_use]
    pub const fn instruction_index(&self) -> usize {
        self.instruction_index
    }
}

/// Project exact direct Register terms from canonical signed transaction DATA.
///
/// This performs no finality or membership verification. A reported successful output is
/// only DATA until the native finality owner authenticates that exact output.
/// The native finality owner uses this projection for scheme, asset, reserve and Global scope.
/// # Errors
/// Wrong signed network/result, non-Register input, malformed/foreign scheme or asset,
/// restricted scope, or reserve different from transaction authority.
pub fn project_kagemusha_wallet_registration_v1(
    committed: &CommittedTransaction,
    expected_network: NetworkId,
    expected_scheme: &KagemushaWalletSchemeV1,
    asset_digest: [u8; 32],
    instruction_index: usize,
) -> Result<KagemushaWalletRegistrationDataV1, KagemushaWalletRegistrationErrorV1> {
    use KagemushaWalletRegistrationErrorV1 as Error;
    expected_scheme.validate().map_err(|_| Error::Original)?;
    if expected_scheme.network_id != *expected_network.as_bytes() || asset_digest == [0; 32] {
        return Err(Error::Original);
    }
    let TransactionEntrypoint::External(transaction) = committed.entrypoint() else {
        return Err(Error::Instruction);
    };
    if committed.result().is_err()
        || transaction.network_id() != Some(&expected_network)
        || transaction.verify_signature().is_err()
    {
        return Err(Error::Transaction);
    }
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(Error::Instruction);
    };
    let instruction = instructions
        .get(instruction_index)
        .and_then(|value| value.as_any().downcast_ref::<KagemushaWalletLedgerV1>())
        .ok_or(Error::Instruction)?;
    let KagemushaWalletLedgerActionV1::Register {
        scheme,
        asset,
        reserve,
        balance_scope,
    } = &instruction.action
    else {
        return Err(Error::Instruction);
    };
    if *balance_scope != AssetBalanceScope::Global {
        return Err(Error::Scope);
    }
    if reserve != transaction.authority() {
        return Err(Error::Reserve);
    }
    let selected_scheme = expected_scheme.scheme_id();
    let parsed_scheme = KagemushaWalletSchemeV1::decode_canonical(scheme, &selected_scheme)
        .map_err(|_| Error::Original)?;
    if instruction.scheme != selected_scheme
        || parsed_scheme != *expected_scheme
        || asset.is_empty()
        || asset.len() > KAGEMUSHA_WALLET_REGISTRATION_ASSET_MAX_BYTES_V1
    {
        return Err(Error::Original);
    }
    let parsed_asset: KagemushaWalletAssetScopeV1 =
        norito::decode_canonical_with_limits(asset, norito::canonical_decode_limits(asset.len()))
            .map_err(|_| Error::Original)?;
    parsed_asset.validate().map_err(|_| Error::Original)?;
    if parsed_asset.asset_digest() != asset_digest {
        return Err(Error::Original);
    }
    Ok(KagemushaWalletRegistrationDataV1 {
        scheme: parsed_scheme,
        asset: parsed_asset,
        scheme_original: scheme.clone(),
        asset_original: asset.clone(),
        reserve: reserve.clone(),
        transaction_hash: *transaction.hash().as_ref(),
        instruction_index,
    })
}

#[cfg(test)]
mod tests;

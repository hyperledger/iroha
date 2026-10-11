//! Routing reads the same permanent scope as execution. Routing is not proof authorization.
use super::*;
use crate::state::WorldReadOnly;
use iroha_data_model::isi::kagemusha_wallet::{
    KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1,
};
use iroha_model_base::topology::DataSpaceId;
use mv::storage::StorageReadOnly as _;

pub(crate) fn dataspace(
    world: &impl WorldReadOnly,
    instruction: &KagemushaWalletLedgerV1,
) -> Result<DataSpaceId> {
    let scheme = instruction.scheme;
    let asset = match &instruction.action {
        Action::Register { balance_scope, .. } => return exact_scope(*balance_scope),
        Action::Activate(bytes) => {
            KagemushaWalletActivationV1::decode_canonical(bytes, &scheme)?
                .credential
                .body
                .asset_digest
        }
        Action::Abandon(bytes) => {
            KagemushaWalletAbandonmentV1::decode_canonical(bytes, &scheme)?
                .control
                .body
                .asset_digest
        }
        Action::CloseLoads(bytes) => {
            KagemushaWalletCloseLoadsV1::decode_canonical(bytes, &scheme)?
                .credential
                .body
                .asset_digest
        }
        Action::IssueLoad { wallet, .. } => {
            let key = storage::key(storage::WALLET, scheme, *wallet);
            let bytes = world
                .kagemusha_wallet_ledger()
                .get(&key)
                .ok_or(Error::Unavailable)?;
            validate_row(&key, bytes)?;
            storage::decode::<WalletRecord>(bytes, bytes.len())?.asset
        }
        Action::Unload(bytes) => {
            KagemushaWalletUnloadClaimV1::decode_canonical(bytes, &scheme)?
                .credential
                .body
                .asset_digest
        }
        Action::ClaimFee(bytes) => {
            KagemushaWalletFeeClaimV1::decode_canonical(bytes, &scheme)?
                .payment
                .request
                .body
                .asset_digest
        }
        Action::InstallVerifierPack { asset, .. } | Action::RetainCertificate { asset, .. } => {
            *asset
        }
        Action::RetainCredential { credential, .. } => {
            KagemushaWalletCredentialV1::decode_canonical(credential, &scheme)?
                .body
                .asset_digest
        }
        Action::RetainRequest(bytes) => {
            let value: KagemushaWalletRequestV1 =
                storage::decode(bytes, KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1)?;
            if value.body.scheme_id != scheme {
                return Err(Error::Binding);
            }
            value.body.asset_digest
        }
    };
    let key = storage::key(storage::REGISTRATION, scheme, asset);
    let bytes = world
        .kagemusha_wallet_ledger()
        .get(&key)
        .ok_or(Error::Unavailable)?;
    validate_row(&key, bytes)?;
    exact_scope(storage::decode::<Registration>(bytes, bytes.len())?.balance_scope)
}
fn exact_scope(scope: AssetBalanceScope) -> Result<DataSpaceId> {
    match scope {
        AssetBalanceScope::Global => Ok(DataSpaceId::UNIVERSAL),
        AssetBalanceScope::Dataspace(id) if id != DataSpaceId::UNIVERSAL => Ok(id),
        _ => Err(Error::Binding),
    }
}

//! Shared account-activity extraction for Explorer filters and push notifications.
use iroha_data_model::{
    account::AccountId,
    isi::{
        AddSignatory, BurnBox, CustomInstruction, GrantBox, MintBox, RegisterBox,
        RemoveAssetKeyValue, RemoveKeyValueBox, RemoveSignatory, RevokeBox, SetAccountQuorum,
        SetAssetKeyValue, SetKeyValueBox, TransferAssetBatch, TransferBox, UnregisterBox,
    },
    prelude::InstructionBox,
};
use iroha_executor_data_model::isi::multisig::MultisigInstructionBox;
/// Role of an account within an activity payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountActivityRole {
    /// Account received value or a note.
    Incoming,
    /// Account sent value, burned value, or spent a note.
    Outgoing,
    /// Account appears as both source and destination.
    SelfActivity,
    /// Account was affected without a directional value transfer.
    Affected,
}
impl AccountActivityRole {
    /// Stable label used in push payloads.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Outgoing => "outgoing",
            Self::SelfActivity => "self",
            Self::Affected => "affected",
        }
    }
}
/// Account reference extracted from a committed instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountInstructionActivity {
    /// Canonical account affected by the instruction.
    pub(crate) account: AccountId,
    /// Account role within this instruction.
    pub(crate) role: AccountActivityRole,
}
/// Return true when an instruction affects the given account.
pub(crate) fn instruction_matches_account_id(instr: &InstructionBox, expected: &AccountId) -> bool {
    instruction_account_activities(instr)
        .iter()
        .any(|activity| &activity.account == expected)
}
/// Extract all account references from an instruction.
pub(crate) fn instruction_account_activities(
    instr: &InstructionBox,
) -> Vec<AccountInstructionActivity> {
    let mut out = Vec::new();
    collect_instruction_account_activities(instr, &mut out);
    out
}
fn collect_instruction_account_activities(
    instr: &InstructionBox,
    out: &mut Vec<AccountInstructionActivity>,
) {
    let any = instr.as_any();
    if let Some(register) = any.downcast_ref::<RegisterBox>() {
        match register {
            RegisterBox::Account(inner) => {
                push_unique(out, &inner.object.id, AccountActivityRole::Affected)
            }
            RegisterBox::Nft(_)
            | RegisterBox::Peer(_)
            | RegisterBox::Domain(_)
            | RegisterBox::AssetDefinition(_)
            | RegisterBox::Role(_)
            | RegisterBox::Trigger(_) => {}
        }
        return;
    }
    if let Some(unregister) = any.downcast_ref::<UnregisterBox>() {
        match unregister {
            UnregisterBox::Account(inner) => {
                push_unique(out, &inner.object, AccountActivityRole::Affected)
            }
            UnregisterBox::Nft(_)
            | UnregisterBox::Peer(_)
            | UnregisterBox::Domain(_)
            | UnregisterBox::AssetDefinition(_)
            | UnregisterBox::Role(_)
            | UnregisterBox::Trigger(_) => {}
        }
        return;
    }
    if let Some(transfer) = any.downcast_ref::<TransferBox>() {
        match transfer {
            TransferBox::Domain(inner) => {
                push_directional(out, inner.source(), inner.destination())
            }
            TransferBox::AssetDefinition(inner) => {
                push_directional(out, inner.source(), inner.destination());
            }
            TransferBox::Asset(inner) => {
                push_directional(out, inner.source().account(), inner.destination());
            }
            TransferBox::Nft(inner) => push_directional(out, inner.source(), inner.destination()),
        }
        return;
    }
    if let Some(batch) = any.downcast_ref::<TransferAssetBatch>() {
        for entry in batch.entries() {
            push_directional(out, entry.from(), entry.to());
        }
        return;
    }
    if let Some(mint) = any.downcast_ref::<MintBox>() {
        if let MintBox::Asset(asset_mint) = mint {
            push_unique(
                out,
                asset_mint.destination().account(),
                AccountActivityRole::Incoming,
            );
        }
        return;
    }
    if let Some(burn) = any.downcast_ref::<BurnBox>() {
        if let BurnBox::Asset(asset_burn) = burn {
            push_unique(
                out,
                asset_burn.destination().account(),
                AccountActivityRole::Outgoing,
            );
        }
        return;
    }
    if let Some(set) = any.downcast_ref::<SetAssetKeyValue>() {
        push_unique(out, set.asset().account(), AccountActivityRole::Affected);
        return;
    }
    if let Some(set) = any.downcast_ref::<SetKeyValueBox>() {
        match set {
            SetKeyValueBox::Account(inner) => {
                push_unique(out, inner.object(), AccountActivityRole::Affected);
            }
            SetKeyValueBox::Nft(_)
            | SetKeyValueBox::Domain(_)
            | SetKeyValueBox::AssetDefinition(_)
            | SetKeyValueBox::Trigger(_) => {}
        }
        return;
    }
    if let Some(remove) = any.downcast_ref::<RemoveAssetKeyValue>() {
        push_unique(out, remove.asset().account(), AccountActivityRole::Affected);
        return;
    }
    if let Some(remove) = any.downcast_ref::<RemoveKeyValueBox>() {
        match remove {
            RemoveKeyValueBox::Account(inner) => {
                push_unique(out, inner.object(), AccountActivityRole::Affected);
            }
            RemoveKeyValueBox::Nft(_)
            | RemoveKeyValueBox::Domain(_)
            | RemoveKeyValueBox::AssetDefinition(_)
            | RemoveKeyValueBox::Trigger(_) => {}
        }
        return;
    }
    if let Some(grant) = any.downcast_ref::<GrantBox>() {
        match grant {
            GrantBox::Permission(inner) => {
                push_unique(out, &inner.destination, AccountActivityRole::Affected);
            }
            GrantBox::Role(inner) => {
                push_unique(out, &inner.destination, AccountActivityRole::Affected);
            }
            GrantBox::RolePermission(_) => {}
        }
        return;
    }
    if let Some(revoke) = any.downcast_ref::<RevokeBox>() {
        match revoke {
            RevokeBox::Permission(inner) => {
                push_unique(out, &inner.destination, AccountActivityRole::Affected);
            }
            RevokeBox::Role(inner) => {
                push_unique(out, &inner.destination, AccountActivityRole::Affected);
            }
            RevokeBox::RolePermission(_) => {}
        }
        return;
    }
    if let Some(add) = any.downcast_ref::<AddSignatory>() {
        push_unique(out, &add.account, AccountActivityRole::Affected);
        return;
    }
    if let Some(remove) = any.downcast_ref::<RemoveSignatory>() {
        push_unique(out, &remove.account, AccountActivityRole::Affected);
        return;
    }
    if let Some(quorum) = any.downcast_ref::<SetAccountQuorum>() {
        push_unique(out, &quorum.account, AccountActivityRole::Affected);
        return;
    }
    if let Some(custom) = any.downcast_ref::<CustomInstruction>() {
        if let Ok(multisig) = MultisigInstructionBox::try_from(custom.payload()) {
            collect_multisig_account_activities(&multisig, out);
        }
    }
}
fn collect_multisig_account_activities(
    multisig: &MultisigInstructionBox,
    out: &mut Vec<AccountInstructionActivity>,
) {
    match multisig {
        MultisigInstructionBox::Register(register) => {
            push_unique(out, &register.account, AccountActivityRole::Affected);
        }
        MultisigInstructionBox::Approve(approve) => {
            push_unique(out, &approve.account, AccountActivityRole::Affected);
        }
        MultisigInstructionBox::Cancel(cancel) => {
            push_unique(out, &cancel.account, AccountActivityRole::Affected);
        }
        MultisigInstructionBox::InvalidateOutstanding(invalidate) => {
            push_unique(out, &invalidate.account, AccountActivityRole::Affected);
        }
        MultisigInstructionBox::Propose(propose) => {
            push_unique(out, &propose.account, AccountActivityRole::Affected);
            for nested in &propose.instructions {
                collect_instruction_account_activities(nested, out);
            }
        }
    }
}
fn push_directional(out: &mut Vec<AccountInstructionActivity>, from: &AccountId, to: &AccountId) {
    if from == to {
        push_unique(out, from, AccountActivityRole::SelfActivity);
    } else {
        push_unique(out, from, AccountActivityRole::Outgoing);
        push_unique(out, to, AccountActivityRole::Incoming);
    }
}
fn push_unique(
    out: &mut Vec<AccountInstructionActivity>,
    account: &AccountId,
    role: AccountActivityRole,
) {
    if !out
        .iter()
        .any(|activity| activity.account == *account && activity.role == role)
    {
        out.push(AccountInstructionActivity {
            account: account.clone(),
            role,
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use iroha_data_model::{
        account::AccountId,
        asset::{AssetDefinitionId, AssetId},
        isi::{Burn, Grant, Mint, RemoveKeyValue, SetKeyValue, Transfer},
        nft::{Nft, NftId},
        permission::Permission,
        role::RoleId,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    fn account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        AccountId::new(keypair.public_key().clone())
    }
    #[test]
    fn account_fixture_uses_checked_seed_derivation() {
        assert_ne!(account(1), account(2));
        assert!(
            KeyPair::try_from_seed(vec![0; 32], iroha_crypto::Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    fn asset_id(account: AccountId) -> AssetId {
        let domain = DomainId::try_new("wallet", "universal").expect("domain");
        let definition =
            AssetDefinitionId::derive_from_components(domain, "xor".parse().expect("asset name"));
        AssetId::new(definition, account)
    }
    #[test]
    fn transfer_marks_outgoing_and_incoming_accounts() {
        let alice = account(1);
        let bob = account(2);
        let instruction: InstructionBox =
            Transfer::asset_quantity(asset_id(alice.clone()), 10u32, bob.clone()).into();
        let activities = instruction_account_activities(&instruction);
        assert!(activities.contains(&AccountInstructionActivity {
            account: alice,
            role: AccountActivityRole::Outgoing,
        }));
        assert!(activities.contains(&AccountInstructionActivity {
            account: bob,
            role: AccountActivityRole::Incoming,
        }));
    }
    #[test]
    fn mint_burn_and_metadata_match_asset_owner() {
        let alice = account(3);
        let asset = asset_id(alice.clone());
        let mint: InstructionBox = Mint::asset_quantity(7u32, asset.clone()).into();
        let burn: InstructionBox = Burn::asset_quantity(2u32, asset.clone()).into();
        let metadata: InstructionBox = SetKeyValue::account(
            alice.clone(),
            "tier".parse::<Name>().expect("metadata key"),
            iroha_primitives::json::Json::new("gold"),
        )
        .into();
        assert!(instruction_matches_account_id(&mint, &alice));
        assert!(instruction_matches_account_id(&burn, &alice));
        assert!(instruction_matches_account_id(&metadata, &alice));
    }
    #[test]
    fn permissions_and_nft_transfer_match_accounts() {
        let alice = account(4);
        let bob = account(5);
        let permission = Permission::new(
            "can_read".parse().expect("permission name"),
            iroha_primitives::json::Json::new(()),
        );
        let grant: InstructionBox = Grant::account_permission(permission, alice.clone()).into();
        let role: InstructionBox = Grant::account_role(
            RoleId::new("auditor".parse().expect("role name")),
            bob.clone(),
        )
        .into();
        let nft_id = NftId::new(
            DomainId::try_new("art", "universal").expect("domain"),
            "mona".parse().expect("nft name"),
        );
        let nft: InstructionBox = Transfer::nft(alice.clone(), nft_id, bob.clone()).into();
        assert!(instruction_matches_account_id(&grant, &alice));
        assert!(instruction_matches_account_id(&role, &bob));
        assert!(instruction_matches_account_id(&nft, &alice));
        assert!(instruction_matches_account_id(&nft, &bob));
    }
    #[test]
    fn account_registration_and_removal_match_registered_account() {
        let alice = account(6);
        let register: InstructionBox =
            RegisterBox::Account(iroha_data_model::isi::Register::account(
                iroha_data_model::account::Account::new(alice.clone()),
            ))
            .into();
        let remove: InstructionBox =
            RemoveKeyValue::account(alice.clone(), "tier".parse::<Name>().expect("metadata key"))
                .into();
        assert!(instruction_matches_account_id(&register, &alice));
        assert!(instruction_matches_account_id(&remove, &alice));
    }
    #[test]
    fn nft_register_without_owner_metadata_is_not_account_activity() {
        let alice = account(7);
        let nft_id = NftId::new(
            DomainId::try_new("art", "universal").expect("domain"),
            "mona".parse().expect("nft name"),
        );
        let instruction: InstructionBox = RegisterBox::Nft(iroha_data_model::isi::Register::nft(
            Nft::new(nft_id, Metadata::default()),
        ))
        .into();
        assert!(!instruction_matches_account_id(&instruction, &alice));
    }
}

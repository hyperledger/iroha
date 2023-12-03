#include "CommandGenerator.hpp"
#include "model/converters/json_transaction_factory.hpp"


namespace iroha_lib {

std::shared_ptr<Command> CommandGenerator::generateAddAssetQuantity(
        const std::string& asset_id,
        const std::string& amount,
        const std::string& description)
{
    AddAssetQuantity addAssetQuantity;
    addAssetQuantity.set_asset_id(asset_id);
    addAssetQuantity.set_amount(amount);
    if (!description.empty()) {
      addAssetQuantity.set_description(description);
    }

    auto cmd = Command();
    cmd.set_allocated_add_asset_quantity(new AddAssetQuantity(addAssetQuantity));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateAddPeer(
        const std::string& address,
        const std::string& pubkey,
        const std::optional<std::string>& tls_certificate,
        bool syncing_peer)
{
    AddPeer pb_add_peer;
    auto peer = pb_add_peer.mutable_peer();

    Peer primitive_peer;
    primitive_peer.set_address(address);
    primitive_peer.set_peer_key(
                iroha::hexstringToArray<iroha::pubkey_t::size()>(pubkey)
                .value()
                .to_hexstring());

    if (tls_certificate.has_value()) {
        primitive_peer.set_tls_certificate(*std::move(tls_certificate));
    }
    primitive_peer.set_syncing_peer(syncing_peer);

    peer->CopyFrom(primitive_peer);

    auto cmd = Command();
    cmd.set_allocated_add_peer(new AddPeer(pb_add_peer));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateAddSignatory(
        const std::string& account_id,
        const std::string& pubkey)
{
    AddSignatory pb_add_signatory;
    pb_add_signatory.set_account_id(account_id);
    pb_add_signatory.set_public_key(
                iroha::hexstringToArray<iroha::pubkey_t::size()>(pubkey)
                .value()
                .to_hexstring());

    auto cmd = Command();
    cmd.set_allocated_add_signatory(new AddSignatory(pb_add_signatory));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateAppendRole(
        const std::string& account_id,
        const std::string& role_name)
{
    AppendRole append_role;
    append_role.set_account_id(account_id);
    append_role.set_role_name(role_name);

    auto cmd = Command();
    cmd.set_allocated_append_role(new AppendRole(append_role));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateCreateAccount(
        const std::string& account_name,
        const std::string& domain_id,
        const std::string& pubkey)
{
    CreateAccount pb_create_account;
    pb_create_account.set_account_name(account_name);
    pb_create_account.set_domain_id(domain_id);
    pb_create_account.set_public_key(iroha::hexstringToArray<iroha::pubkey_t::size()>(pubkey).value().to_hexstring());

    auto cmd = Command();
    cmd.set_allocated_create_account(new CreateAccount(pb_create_account));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateCreateAsset(
        const std::string& asset_name,
        const std::string& domain_id,
        uint8_t precision)
{

    CreateAsset pb_create_asset;
    pb_create_asset.set_asset_name(asset_name);
    pb_create_asset.set_domain_id(domain_id);
    pb_create_asset.set_precision(precision);

    auto cmd = Command();
    cmd.set_allocated_create_asset(new CreateAsset(pb_create_asset));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateCreateDomain(
        const std::string& domain_id,
        const std::string& default_role)
{
    CreateDomain pb_create_domain;
    pb_create_domain.set_domain_id(domain_id);
    pb_create_domain.set_default_role(default_role);

    auto cmdCreateDomain = Command();
    cmdCreateDomain.set_allocated_create_domain(new CreateDomain(pb_create_domain));
    return generateCommand<Command>(cmdCreateDomain);
}

std::shared_ptr<Command> CommandGenerator::generateCreateRole(
        const std::string& role_name,
        const std::unordered_set<RolePermission>& permissions)
{
    CreateRole createRole;
    createRole.set_role_name(role_name);
    std::for_each(permissions.begin(),
                  permissions.end(),
                  [&createRole](auto permission) {
        createRole.add_permissions(permission);
    });

    auto cmd = Command();
    cmd.set_allocated_create_role(new CreateRole(createRole));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateDetachRole(
        const std::string& account_id,
        const std::string& role_name)
{
    DetachRole detach_role;
    detach_role.set_account_id(account_id);
    detach_role.set_role_name(role_name);

    auto cmd = Command();
    cmd.set_allocated_detach_role(new DetachRole(detach_role));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateGrantPermission(
        const std::string& account_id,
        const GrantablePermission permission)
{
    GrantPermission grantPermission;
    grantPermission.set_account_id(account_id);
    grantPermission.set_permission(permission);

    auto cmd = Command();
    cmd.set_allocated_grant_permission(new GrantPermission(grantPermission));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateRemovePeer(const std::string& pubkey)
{
    RemovePeer removePeer;
    removePeer.set_public_key(pubkey);

    auto cmd = Command();
    cmd.set_allocated_remove_peer(new RemovePeer(removePeer));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateRemoveSignatory(
        const std::string& account_id,
        const std::string& pubkey)
{
    RemoveSignatory removeSignatory;
    removeSignatory.set_account_id(account_id);
    removeSignatory.set_public_key(iroha::hexstringToArray<iroha::pubkey_t::size()>(pubkey).value().to_hexstring());

    auto cmd = Command();
    cmd.set_allocated_remove_signatory(new RemoveSignatory(removeSignatory));
    return generateCommand<Command>(cmd);

}

std::shared_ptr<Command> CommandGenerator::generateRevokePermission(
        const std::string& account_id,
        const GrantablePermission permission)
{
    RevokePermission revokdePermission;
    revokdePermission.set_account_id(account_id);
    revokdePermission.set_permission(permission);

    auto cmd = Command();
    cmd.set_allocated_revoke_permission(new RevokePermission(revokdePermission));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateSetAccountDetail(
        const std::string& account_id,
        const std::string& key,
        const std::string& value)
{
    SetAccountDetail accountDetails;
    accountDetails.set_account_id(account_id);
    accountDetails.set_key(key);
    accountDetails.set_value(value);

    auto cmd = Command();
    cmd.set_allocated_set_account_detail(new SetAccountDetail(accountDetails));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateSetAccountQuorum(
        const std::string& account_id, uint32_t quorum)
{
    SetAccountQuorum setAccountQuorum;
    setAccountQuorum.set_account_id(account_id);
    setAccountQuorum.set_quorum(quorum);

    auto cmd = Command();
    cmd.set_allocated_set_account_quorum(new SetAccountQuorum(setAccountQuorum));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateSubtractAssetQuantity(
        const std::string& asset_id,
        const std::string& amount,
        const std::string& description)
{
    SubtractAssetQuantity subtractAssetQuantity;
    subtractAssetQuantity.set_asset_id(asset_id);
    subtractAssetQuantity.set_amount(amount);
    std::optional<std::string> description_optional = description;
    if (description_optional) {
        subtractAssetQuantity.set_description(*description_optional);
    }

    auto cmd = Command();
    cmd.set_allocated_subtract_asset_quantity(new SubtractAssetQuantity(subtractAssetQuantity));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateTransferAsset(
        const std::string& account_id,
        const std::string& dest_account_id,
        const std::string& asset_id,
        const std::string& description,
        const std::string& amount)
{
    TransferAsset transferAsset;
    transferAsset.set_src_account_id(account_id);
    transferAsset.set_dest_account_id(dest_account_id);
    transferAsset.set_asset_id(asset_id);
    transferAsset.set_description(description);
    transferAsset.set_amount(amount);

    auto cmd = Command();
    cmd.set_allocated_transfer_asset(new TransferAsset(transferAsset));
    return generateCommand<Command>(cmd);
}

std::shared_ptr<Command> CommandGenerator::generateCompareAndSetAccountDetail(
        const std::string& account_id,
        const std::string& key,
        const std::string& value,
        const std::optional<std::string>& old_value,
        bool check_empty)
{
    CompareAndSetAccountDetail compareAndSetAccountDetail;
    compareAndSetAccountDetail.set_account_id(account_id);
    compareAndSetAccountDetail.set_key(key);
    compareAndSetAccountDetail.set_value(value);
    if (old_value.has_value()) {
        compareAndSetAccountDetail.set_old_value(*std::move(old_value));
    }
    compareAndSetAccountDetail.set_check_empty(check_empty);

    auto cmd = Command();
    cmd.set_allocated_compare_and_set_account_detail(new CompareAndSetAccountDetail(compareAndSetAccountDetail));
    return generateCommand<Command>(cmd);
}

}

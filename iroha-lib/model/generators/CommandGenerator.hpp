#ifndef COMMAND_GENERATOR_HPP
#define COMMAND_GENERATOR_HPP

#include "commands.pb.h"
#include <optional>


namespace iroha_lib {

using namespace iroha::protocol;

class CommandGenerator {

public:
    template <class Type, class... ParamTypes>
    std::shared_ptr<Command> generateCommand(ParamTypes... args)
    {
        return std::make_shared<Type>(args...);
    }

    std::shared_ptr<Command> generateAddAssetQuantity(
            const std::string& asset_id,
            const std::string& amount,
            const std::string& title);
    std::shared_ptr<Command> generateAddPeer(
            const std::string& address,
            const std::string& pubkey,
            const std::optional<std::string>& tls_certificate,
            bool syncing_peer);
    std::shared_ptr<Command> generateAddSignatory(
            const std::string& account_id,
            const std::string& pubkey);
    std::shared_ptr<Command> generateAppendRole(
            const std::string& account_id,
            const std::string& role_name);
    std::shared_ptr<Command> generateCreateAccount(
            const std::string& account_name,
            const std::string& domain_id,
            const std::string& pubkey);
    std::shared_ptr<Command> generateCreateAsset(
            const std::string& asset_name,
            const std::string& domain_name,
            uint8_t precision);
    std::shared_ptr<Command> generateCreateDomain(
            const std::string& domain_id,
            const std::string& default_role);
    std::shared_ptr<Command> generateCreateRole(
            const std::string& role_name,
            const std::unordered_set<RolePermission>& permissions);
    std::shared_ptr<Command> generateDetachRole(
            const std::string& account_id,
            const std::string& role_name);
    std::shared_ptr<Command> generateGrantPermission(
            const std::string& account_id,
            const GrantablePermission permission);
    std::shared_ptr<Command> generateRemovePeer(const std::string& pubkey);
    std::shared_ptr<Command> generateRemoveSignatory(
            const std::string& account_id,
            const std::string& pubkey);
    std::shared_ptr<Command> generateRevokePermission(
            const std::string& account_id,
            const GrantablePermission permission);
    std::shared_ptr<Command> generateSetAccountDetail(
            const std::string& account_id,
            const std::string& key,
            const std::string& value);
    std::shared_ptr<Command> generateSetAccountQuorum(
            const std::string& account_id, uint32_t quorum);
    std::shared_ptr<Command> generateSubtractAssetQuantity(
            const std::string& asset_id,
            const std::string& amount,
            const std::string& title);
    std::shared_ptr<Command> generateTransferAsset(
            const std::string& account_id,
            const std::string& dest_account_id,
            const std::string& asset_id,
            const std::string& description,
            const std::string& amount);
    std::shared_ptr<Command> generateCompareAndSetAccountDetail(
            const std::string& account_id,
            const std::string& key,
            const std::string& value,
            const std::optional<std::string>& old_value,
            bool check_empty);
};

}

#endif

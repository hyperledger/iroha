#ifndef TX_HPP
#define TX_HPP

#include "transaction.pb.h"
#include <boost/bimap.hpp>
#include "crypto/keypair.hpp"
#include "generators/CommandGenerator.hpp"


namespace iroha_lib {

class Tx {

private:
    iroha::keypair_t keypair_;
    iroha::protocol::Transaction protobuf_transaction_;
    CommandGenerator cmd_generator_;

public:
    explicit Tx(
            const std::string& account_id,
            const iroha::keypair_t& keypair,
            uint64_t created_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(),
            uint32_t quorum = 1)
        : keypair_(keypair)
    {
        auto payload = protobuf_transaction_.mutable_payload()->mutable_reduced_payload();
        payload->set_created_time(created_time);
        payload->set_creator_account_id(account_id);
        payload->set_quorum(quorum);
    }

    void addCommand(const iroha::protocol::Command& command);

    Tx& addAssetQuantity(
            const std::string& asset_id,
            const std::string& amount,
            const std::string& title);
    Tx& addPeer(
            const std::string& address,
            const std::string& pubkey,
            const std::optional<std::string>& tls_certificate = {},
            bool syncing_peer = false);
    Tx& addSignatory(
            const std::string& account_id,
            const std::string& pubkey);
    Tx& appendRole(
            const std::string& account_id,
            const std::string& role_name);
    Tx& createAccount(
            const std::string& account_name,
            const std::string& domain_id,
            const std::string& pubkey);
    Tx& createAsset(
            const std::string& asset_name,
            const std::string& domain_id,
            uint32_t precision);
    Tx& createDomain(
            const std::string& domain_id,
            const std::string& user_default_role);
    Tx& createRole(
            const std::string& roleName,
            const std::unordered_set<iroha::protocol::RolePermission>& permissions);
    Tx& detachRole(
            const std::string& account_id,
            const std::string& role_name);
    Tx& grantPermission(
            const std::string& account_id,
            const iroha::protocol::GrantablePermission permission);
    Tx& removePeer(
            const std::string& pubkey);
    Tx& removeSignatory(
            const std::string& account_id,
            const std::string& pubkey);
    Tx& revokePermission(
            const std::string& account_id,
            const iroha::protocol::GrantablePermission permission);
    Tx& setAccountDetail(
            const std::string& account_id,
            const std::string& key,
            const std::string& value);
    Tx& setAccountQuorum(
            const std::string& account_id,
            uint32_t quorum);
    Tx& subtractAssetQuantity(
            const std::string& asset_id,
            const std::string& amount,
            const std::string& title);
    Tx& transferAsset(
            const std::string& account_id,
            const std::string& dest_account_id,
            const std::string& asset_id,
            const std::string& description,
            const std::string& amount);
    Tx& compareAndSetAccountDetail(
            const std::string& account_id,
            const std::string& key,
            const std::string& value,
            const std::optional<std::string>& old_value,
            bool check_empty);

    const iroha::protocol::Transaction signAndAddSignature();
};

}

#endif

#pragma once

#include "queries.pb.h"
#include <optional>


namespace iroha_lib {

using namespace iroha::protocol;

class QueryGenerator {
public:
    std::shared_ptr<iroha::protocol::Query> generateGetAccount(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time);
    std::shared_ptr<iroha::protocol::Query> generateGetAccountAssets(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time);
    std::shared_ptr<iroha::protocol::Query> generateGetAccountDetail(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time);
    std::shared_ptr<iroha::protocol::Query> generateGetAccountTransactions(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time,
            const std::optional<std::string*>& first_tx_hash={},
            const std::optional<google::protobuf::Timestamp*>& first_tx_time={},
            const std::optional<google::protobuf::Timestamp*>& last_tx_time={},
            const std::optional<uint64_t> first_tx_height={},
            const std::optional<uint64_t> last_tx_height={});
    std::shared_ptr<iroha::protocol::Query> generateGetAccountAssetTransactions(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time,
            const std::string& assetId,
            const std::optional<std::string*>& first_tx_hash={},
            const std::optional<google::protobuf::Timestamp*>& first_tx_time={},
            const std::optional<google::protobuf::Timestamp*>& last_tx_time={},
            const std::optional<uint64_t> first_tx_height={},
            const std::optional<uint64_t> last_tx_height={});
    std::shared_ptr<iroha::protocol::Query> generateGetTransactions(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time,
            const std::vector<std::string>& transaction_hashes);
    std::shared_ptr<iroha::protocol::Query> generateGetSignatories(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time);
    std::shared_ptr<iroha::protocol::Query> generateGetAssetInfo(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time,
            const std::string& assetId);
    std::shared_ptr<iroha::protocol::Query> generateGetRoles(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time);
    std::shared_ptr<iroha::protocol::Query> generateGetRolePermissions(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time,
            const std::string& role_id);
    std::shared_ptr<iroha::protocol::Query> generateGetPeers(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time);

private:
    std::shared_ptr<iroha::protocol::Query> generateQuery(
            const std::string& account_id,
            uint64_t counter,
            const uint64_t created_time);
};

} // namespace iroha_lib

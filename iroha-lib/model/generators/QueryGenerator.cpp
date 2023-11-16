#include "QueryGenerator.hpp"
#include "model/utils/Utils.h"


namespace iroha_lib {

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateQuery(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time)
{
    auto query = std::make_shared<iroha::protocol::Query>();
    auto* payload = query->mutable_payload()->mutable_meta();
    payload->set_creator_account_id(account_id);
    payload->set_query_counter(counter);
    payload->set_created_time(created_time);
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetAccount(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    auto queryPayload = query->mutable_payload();
    auto mutablePayload = queryPayload->mutable_get_account();
    mutablePayload->set_account_id(account_id);
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetAccountAssets(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    auto queryPayload = query->mutable_payload()->mutable_get_account_assets();
    queryPayload->set_account_id(account_id);
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetAccountDetail(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    auto queryPayload = query->mutable_payload()->mutable_get_account_detail();
    queryPayload->set_account_id(account_id);
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetAccountTransactions(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time,
        const std::optional<std::string*>& first_tx_hash,
        const std::optional<google::protobuf::Timestamp*>& first_tx_time,
        const std::optional<google::protobuf::Timestamp*>& last_tx_time,
        const std::optional<uint64_t> first_tx_height,
        const std::optional<uint64_t> last_tx_height)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    auto queryPayload = query->mutable_payload()->mutable_get_account_transactions();
    queryPayload->set_account_id(account_id);
    if (first_tx_hash.has_value()) {
        query->mutable_payload()->mutable_get_account_transactions()->mutable_pagination_meta()->set_allocated_first_tx_hash(first_tx_hash.value());
    }
    if (first_tx_time.has_value()) {
        query->mutable_payload()->mutable_get_account_transactions()->mutable_pagination_meta()->set_allocated_first_tx_time(first_tx_time.value());
    }
    if (last_tx_time.has_value()) {
        query->mutable_payload()->mutable_get_account_transactions()->mutable_pagination_meta()->set_allocated_last_tx_time(last_tx_time.value());
    }
    if (first_tx_height.has_value()) {
        query->mutable_payload()->mutable_get_account_transactions()->mutable_pagination_meta()->set_first_tx_height(first_tx_height.value());
    }
    if (last_tx_height.has_value()) {
        query->mutable_payload()->mutable_get_account_transactions()->mutable_pagination_meta()->set_last_tx_height(last_tx_height.value());
    }
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetAccountAssetTransactions(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time,
        const std::string& assetId,
        const std::optional<std::string*>& first_tx_hash,
        const std::optional<google::protobuf::Timestamp*>& first_tx_time,
        const std::optional<google::protobuf::Timestamp*>& last_tx_time,
        const std::optional<uint64_t> first_tx_height,
        const std::optional<uint64_t> last_tx_height)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    auto queryPayload = query->mutable_payload()->mutable_get_account_asset_transactions();
    queryPayload->set_account_id(account_id);
    queryPayload->set_asset_id(assetId);

    if (first_tx_hash.has_value()) {
        query->mutable_payload()->mutable_get_account_asset_transactions()->mutable_pagination_meta()->set_allocated_first_tx_hash(first_tx_hash.value());
    }
    if (first_tx_time.has_value()) {
        query->mutable_payload()->mutable_get_account_asset_transactions()->mutable_pagination_meta()->set_allocated_first_tx_time(first_tx_time.value());
    }
    if (last_tx_time.has_value()) {
        query->mutable_payload()->mutable_get_account_asset_transactions()->mutable_pagination_meta()->set_allocated_last_tx_time(last_tx_time.value());
    }
    if (first_tx_height.has_value()) {
        query->mutable_payload()->mutable_get_account_asset_transactions()->mutable_pagination_meta()->set_first_tx_height(first_tx_height.value());
    }
    if (last_tx_height.has_value()) {
        query->mutable_payload()->mutable_get_account_asset_transactions()->mutable_pagination_meta()->set_last_tx_height(last_tx_height.value());
    }
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetTransactions(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time,
        const std::vector<std::string>& transaction_hashes)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    auto queryPayload = query->mutable_payload()->mutable_get_transactions();

    std::for_each(
                transaction_hashes.begin(),
                transaction_hashes.end(),
                [&queryPayload](auto tx_hash) {
        auto adder = queryPayload->add_tx_hashes();
        *adder = string_to_hex(tx_hash);
    });
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetSignatories(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    auto queryPayload = query->mutable_payload()->mutable_get_signatories();
    queryPayload->set_account_id(account_id);
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetAssetInfo(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time,
        const std::string& assetId)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    auto queryPayload = query->mutable_payload()->mutable_get_asset_info();
    queryPayload->set_asset_id(assetId);
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetRoles(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    query->mutable_payload()->mutable_get_roles();
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetRolePermissions(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time,
        const std::string& role_id)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    auto queryPayload = query->mutable_payload()->mutable_get_role_permissions();
    queryPayload->set_role_id(role_id);
    return query;
}

std::shared_ptr<iroha::protocol::Query> QueryGenerator::generateGetPeers(
        const std::string& account_id,
        uint64_t counter,
        const uint64_t created_time)
{
    auto query = generateQuery(
                account_id,
                counter,
                created_time);
    query->mutable_payload()->mutable_get_peers();
    return query;
}

}

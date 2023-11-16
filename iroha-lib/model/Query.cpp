#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "Query.hpp"
#include "model/converters/pb_common.hpp"


namespace iroha_lib {

Query::Query(
        const iroha::keypair_t& keypair,
        uint64_t counter,
        uint64_t created_time) noexcept
    : counter_(counter),
      created_time_(created_time),
      keypair_(keypair)
{}

Query& Query::getAccount(const std::string& account_id)
{
    protobuf_query_ = *query_generator_.generateGetAccount(
                account_id,
                counter_,
                created_time_);
    return *this;
}

Query& Query::getAccountAssets(const std::string& account_id)
{
    protobuf_query_ = *query_generator_.generateGetAccountAssets(
                account_id,
                counter_,
                created_time_);
    return *this;
}

Query& Query::getAccountDetail(const std::string& account_id)
{
    protobuf_query_ = *query_generator_.generateGetAccountDetail(
                account_id,
                counter_,
                created_time_);
    return *this;
}

Query& Query::getAccountTransactions(const std::string& account_id,
                                     const std::optional<std::string*>& first_tx_hash,
                                     const std::optional<google::protobuf::Timestamp*>& first_tx_time,
                                     const std::optional<google::protobuf::Timestamp*>& last_tx_time,
                                     const std::optional<uint64_t> first_tx_height,
                                     const std::optional<uint64_t> last_tx_height)
{
    protobuf_query_ = *query_generator_.generateGetAccountTransactions(
                account_id,
                counter_,
                created_time_,
                first_tx_hash,
                first_tx_time,
                last_tx_time,
                first_tx_height,
                last_tx_height);
    return *this;
}

Query& Query::getAccountAssetTransactions(const std::string& account_id,
                                          const std::string& asset_id,
                                          const std::optional<std::string*>& first_tx_hash,
                                          const std::optional<google::protobuf::Timestamp*>& first_tx_time,
                                          const std::optional<google::protobuf::Timestamp*>& last_tx_time,
                                          const std::optional<uint64_t> first_tx_height,
                                          const std::optional<uint64_t> last_tx_height)
{
    protobuf_query_ = *query_generator_.generateGetAccountAssetTransactions(
                account_id,
                counter_,
                created_time_,
                asset_id,
                first_tx_hash,
                first_tx_time,
                last_tx_time,
                first_tx_height,
                last_tx_height);
    return *this;
}

Query& Query::getTransactions(
        const std::string& account_id,
        const std::vector<std::string>& tx_hashes)
{
    protobuf_query_ = *query_generator_.generateGetTransactions(
                account_id,
                counter_,
                created_time_,
                tx_hashes);
    return *this;
}

Query& Query::getSignatories(const std::string& account_id)
{
    protobuf_query_ = *query_generator_.generateGetSignatories(
                account_id,
                counter_,
                created_time_);
    return *this;
}

Query& Query::getAssetInfo(
        const std::string& account_id,
        const std::string& asset_id)
{
    protobuf_query_ = *query_generator_.generateGetAssetInfo(
                account_id,
                counter_,
                created_time_,
                asset_id);
    return *this;
}

Query& Query::getRoles(const std::string& account_id)
{
    protobuf_query_ = *query_generator_.generateGetRoles(
                account_id,
                counter_,
                created_time_);
    return *this;
}

Query& Query::getRolePermissions(
        const std::string& account_id,
        const std::string& role_id)
{
    protobuf_query_ = *query_generator_.generateGetRolePermissions(
                account_id,
                counter_,
                created_time_,
                role_id);
    return *this;
}

Query& Query::getPeers(const std::string& account_id)
{
    protobuf_query_ = *query_generator_.generateGetPeers(
                account_id,
                counter_,
                created_time_);
    return *this;
}


const iroha::protocol::Query Query::signAndAddSignature()
{
    auto signature = iroha::sign(
                iroha::hash(protobuf_query_).to_string(),
                keypair_.pubkey,
                keypair_.privkey);

    auto sig = protobuf_query_.mutable_signature();
    sig->set_signature(signature.to_hexstring());
    sig->set_public_key(keypair_.pubkey.to_hexstring());
    return protobuf_query_;
}

}

#include <iostream>
#include <string>
#include <cassert>

#include "model/Tx.hpp"
#include "model/Query.hpp"
#include "model/utils/Utils.h"


static constexpr const char* LINE = "-----------";


iroha_lib::Query generateQueryBase(const std::string& account_name, const std::string& key_path);
iroha::protocol::Query generateGetAccountAssetsQuery(const std::string& account_name, const std::string& key_path);
iroha::protocol::Query generateGetAccountTransactionsQuery(const std::string& account_name, const std::string& key_path);
iroha::protocol::Query generateGetAccountQuery(const std::string& account_name, const std::string& key_path);

template<typename Tx>
void sendTransaction(Tx& tx, const std::string& peer_ip, uint16_t torii_port);

iroha::protocol::Transaction generateTransactionWhichCreatesDomainAndAsset(
        const std::string& account_name,
        const std::string& key_path,
        const std::string& domain_id,
        const std::string& user_default_role,
        const std::string& asset_name);
iroha::protocol::Transaction generateTransactionWhichAddsAssetQuantiti(
        const std::string& account_name,
        const std::string& key_path,
        const std::string& assetIdWithDomain,
        const std::string& assetAmount);

void printAccountAssets(const std::string& account_name, const std::string& key_path, const std::string& peer_ip, uint16_t torii_port);
void printAccount(const std::string& account_name, const std::string& key_path, const std::string& peer_ip, uint16_t torii_port);

void run(const std::string& key_path);


int main(int argc, char** argv)
{
    if (argc > 1 && argc < 3) {
        run(argv[1]);
    } else {
        std::cout << "Usage: " << argv[0] << " key_path" << std::endl;
    }
}


void run(const std::string& key_path)
{
    const auto adminAccountName = "admin@test";
    const auto peer_ip = "127.0.0.1";
    uint16_t torii_port = 50051;
    const auto user_default_role = "user";

    const std::string assetName = "assetnamesamplev4";
    const std::string assetDomain = "domainsamplev4";
    const std::string assetFullname = assetName + "#" + assetDomain;

    const auto tx2CreateDomainAndAsset = generateTransactionWhichCreatesDomainAndAsset(
                adminAccountName,
                key_path,
                assetDomain,
                user_default_role,
                assetName);

    const auto tx2AddAssetQuantity = generateTransactionWhichAddsAssetQuantiti(
                adminAccountName,
                key_path,
                assetFullname,
                "100");

    sendTransaction(tx2CreateDomainAndAsset, peer_ip, torii_port);
    sendTransaction(tx2AddAssetQuantity, peer_ip, torii_port);

    /// querying:
    printAccountAssets(adminAccountName, key_path, peer_ip, torii_port);
    printAccount(adminAccountName, key_path, peer_ip, torii_port);
}

iroha::protocol::Transaction generateTransactionWhichCreatesDomainAndAsset(
        const std::string& account_name,
        const std::string& key_path,
        const std::string& domain_id,
        const std::string& user_default_role,
        const std::string& asset_name)
{
    auto log_manager = std::make_shared<logger::LoggerManagerTree>(
                logger::LoggerConfig{logger::LogLevel::kInfo,
                                     logger::getDefaultLogPatterns()})->getChild("CLI");
    const auto keypair = generateKeypair(
                account_name,
                key_path,
                log_manager);

    return iroha_lib::Tx(
                account_name,
                keypair)
            .createDomain(
                domain_id,
                user_default_role)
            .createAsset(
                asset_name,
                domain_id,
                0)
            .signAndAddSignature();
}

iroha::protocol::Transaction generateTransactionWhichAddsAssetQuantiti(
        const std::string& account_name,
        const std::string& key_path,
        const std::string& assetIdWithDomain,
        const std::string& assetAmount)
{
    auto log_manager = std::make_shared<logger::LoggerManagerTree>(
                logger::LoggerConfig{logger::LogLevel::kInfo,
                                     logger::getDefaultLogPatterns()})->getChild("CLI");
    const auto keypair = generateKeypair(
                account_name,
                key_path,
                log_manager);

    return iroha_lib::Tx(
                account_name,
                keypair)
            .addAssetQuantity(assetIdWithDomain, assetAmount)
            .signAndAddSignature();
}

template<typename Tx>
void sendTransaction(
        Tx& tx,
        const std::string& peer_ip,
        uint16_t torii_port)
{
    iroha_lib::GrpcClient(
                peer_ip,
                torii_port)
            .send(tx);

    printTransactionStatus(
                peer_ip,
                torii_port,
                getTransactionHash(tx));
}

void printAccountAssets(const std::string& account_name, const std::string& key_path, const std::string& peer_ip, uint16_t torii_port)
{
    std::cout << LINE << ">" << __FUNCTION__ << LINE << std::endl;

    const auto query_proto = generateGetAccountAssetsQuery(
                account_name,
                key_path);
    QueryResponse response = iroha_lib::GrpcClient(
                peer_ip,
                torii_port)
            .send(query_proto);
    auto payload = query_proto.payload();
    assert(payload.get_account_assets().account_id() == account_name);
    assert(payload.has_get_account_assets());

    if (response.has_error_response())
    {
        const auto errorResponse = response.error_response();
        std::cerr << errorResponse.error_code() << ": " << errorResponse.message() << std::endl;
        return;
    }

    assert(response.has_account_assets_response());
    auto accountAssetsResponce = response.account_assets_response();
    for (const auto& r : response.account_assets_response().account_assets())
    {
        std::cout << "\tasset:" << r.asset_id() << " " << r.balance() << std::endl;
    }

    std::cout << LINE << "<" << __FUNCTION__ << LINE << std::endl;
}

iroha::protocol::Query generateGetAccountAssetsQuery(
        const std::string& account_name,
        const std::string& key_path)
{
    return generateQueryBase(account_name, key_path)
            .getAccountAssets(account_name)
            .signAndAddSignature();
}

iroha_lib::Query generateQueryBase(
        const std::string& account_name,
        const std::string& key_path)
{
    static auto log_manager = std::make_shared<logger::LoggerManagerTree>(
                logger::LoggerConfig{logger::LogLevel::kInfo,
                                     logger::getDefaultLogPatterns()})->getChild("CLI");

    const auto keypair = generateKeypair(
                account_name,
                key_path,
                log_manager);
    return iroha_lib::Query(keypair);
}

iroha::protocol::Query generateGetAccountTransactionsQuery(
        const std::string& account_name,
        const std::string& key_path)
{
    return generateQueryBase(account_name, key_path)
            .getAccountTransactions(account_name)
            .signAndAddSignature();
}

iroha::protocol::Query generateGetAccountQuery(
        const std::string& account_name,
        const std::string& key_path)
{
    return generateQueryBase(account_name, key_path)
            .getAccount(account_name)
            .signAndAddSignature();
}

void printAccount(const std::string& account_name, const std::string& key_path, const std::string& peer_ip, uint16_t torii_port)
{
    std::cout << LINE << ">" << __FUNCTION__ << LINE << std::endl;

    const auto query_proto = generateGetAccountQuery(
                account_name,
                key_path);
    QueryResponse response = iroha_lib::GrpcClient(
                peer_ip,
                torii_port)
            .send(query_proto);
    auto payload = query_proto.payload();
    assert(payload.get_account().account_id() == account_name);
    assert(payload.has_get_account());

    if (response.has_error_response())
    {
        const auto errorResponse = response.error_response();
        std::cerr << errorResponse.error_code() << ": " << errorResponse.message() << std::endl;
        return;
    }

    assert(response.has_account_response());
    auto account = response.account_response().account();
    std::cout << "account_id=" << account.account_id() << '\n'
              << "domain_id=" << account.domain_id() << '\n'
              << "quorum=" << account.quorum() << '\n'
              << "json_data=" << account.json_data() << std::endl;

    std::cout << LINE << "<" << __FUNCTION__ << LINE << std::endl;
}

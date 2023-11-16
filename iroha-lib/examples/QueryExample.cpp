#include <iostream>
#include <cassert>

#include "model/Query.hpp"
#include "model/Tx.hpp"
#include "model/utils/Utils.h"


iroha_lib::Query generateSampleQuery(
        const std::string& account_name,
        const std::string& key_path,
        uint64_t counter=0u)
{
    auto log_manager = std::make_shared<logger::LoggerManagerTree>(
                logger::LoggerConfig{logger::LogLevel::kInfo,
                                     logger::getDefaultLogPatterns()})->getChild("CLI");
    const auto keypair = generateKeypair(
                account_name,
                key_path,
                log_manager);
    return iroha_lib::Query(
                keypair,
                counter);
}


iroha::protocol::Query generateGetAccountAssetsQuery(
        const std::string& account_name,
        const std::string& key_path,
        uint64_t counter=0u)
{
    return generateSampleQuery(
                account_name,
                key_path,
                counter)
            .getAccountAssets(account_name)
            .signAndAddSignature();
}


iroha::protocol::Query generateGetAccountTransactionsQuery(
        const std::string& account_name,
        const std::string& key_path,
        uint64_t counter=0u)
{
    return generateSampleQuery(account_name, key_path, counter)
            .getAccountTransactions(account_name)
            .signAndAddSignature();
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


void sendSampleTransaction(
        const std::string& account_name,
        const std::string& key_path,
        const std::string& peer_ip,
        uint16_t torii_port,
        const std::string& domain_id,
        const std::string& user_default_role,
        const std::string& asset_name)
{
    const auto tx_proto = generateTransactionWhichCreatesDomainAndAsset(
                account_name,
                key_path,
                domain_id,
                user_default_role,
                asset_name);

    iroha_lib::GrpcClient(
                peer_ip,
                torii_port)
            .send(tx_proto);
    printTransactionStatus(
                peer_ip,
                torii_port,
                getTransactionHash(tx_proto));
}


void runQueryWithSingleTransactionGenerated(const std::string& key_path)
{
    auto account_name = "admin@test";
    const auto peer_ip = "127.0.0.1";
    uint16_t torii_port = 50051;
    const auto user_default_role = "user";

    sendSampleTransaction(
                account_name,
                key_path,
                peer_ip,
                torii_port,
                "domainsamplev4",
                user_default_role,
                "assetnamesamplev4");

    const auto query_proto = generateGetAccountAssetsQuery(
                account_name,
                key_path);
    iroha_lib::GrpcClient(
                peer_ip,
                torii_port)
            .send(query_proto);
    assert(query_proto.payload().get_account_assets().account_id() == account_name);
}


void runQueryWithMultiplyTransactionsGenerated(const std::string& key_path)
{
    auto account_name = "admin@test";
    const auto peer_ip = "127.0.0.1";
    uint16_t torii_port = 50051;
    const auto user_default_role = "user";

    for(uint8_t txCounter = 4u; txCounter; --txCounter)
    {
        sendSampleTransaction(
                    account_name,
                    key_path,
                    peer_ip,
                    torii_port,
                    "domainsamplequeryv" + std::to_string(txCounter),
                    user_default_role,
                    "assetnamesamplequeryv" + std::to_string(txCounter));
    }

    const auto query_proto = generateGetAccountTransactionsQuery(
                account_name,
                key_path);
    iroha_lib::GrpcClient(
                peer_ip,
                torii_port)
            .send(query_proto);
    assert(query_proto.payload().get_account_transactions().account_id() == account_name);
}


void run(const std::string& key_path)
{
    runQueryWithSingleTransactionGenerated(key_path);
    runQueryWithMultiplyTransactionsGenerated(key_path);
}


int main(int argc, char** argv)
{
    if (argc > 1 && argc < 3) {
        run(argv[1]);
    } else {
        std::cout << "Usage: " << argv[0] << " key_path\n";
    }
    return 0;
}

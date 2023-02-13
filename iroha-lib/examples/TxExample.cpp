#include <iostream>

#include "model/Tx.hpp"
#include "model/utils/Utils.h"


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

    const auto tx_hash = getTransactionHash(tx_proto);
    printTransactionStatus(
                peer_ip,
                torii_port,
                tx_hash);
}


void run(const std::string& key_path)
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
                "domainsamplev1",
                user_default_role,
                "assetnamesamplev1");
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

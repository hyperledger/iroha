#include <boost/filesystem.hpp>
#include <iostream>
#include <fmt/core.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstdint>

#include "crypto/keys_manager_impl.hpp"
#include "logger/logger_manager.hpp"
#include "model/converters/pb_common.hpp"
#include "grpc_client/GrpcClient.hpp"
#include "Utils.h"


namespace fs = boost::filesystem;


void verifyPath(
        const fs::path& path,
        const logger::LoggerPtr& logger)
{
    if (not fs::exists(path)) {
        const auto error_message = "Path " + path.string() + " not found.";
        logger->error(error_message);
        throw error_message;
    }
}


void verifyKepair(
        const iroha::expected::Result<shared_model::crypto::Keypair, std::string>& keypair,
        const logger::LoggerPtr& logger,
        const fs::path& path,
        const std::string& account_name)
{
    if (auto error = iroha::expected::resultToOptionalError(keypair)) {
        const auto error_message = fmt::format(
                    "Keypair error= {}."
                    "\nKeypair path= {}, name= {}.\n",
                    error.value(),
                    path.string(),
                    account_name);
        logger->error(error_message);
        throw error_message;
    }
}


iroha::keypair_t generateKeypair(
        const std::string& account_name,
        const std::string& key_path,
        const logger::LoggerManagerTreePtr& log_manager)
{
    const auto logger = log_manager->getChild("Main")->getLogger();
    const auto keys_manager_log = log_manager->getChild("KeysManager")->getLogger();
    fs::path path(key_path);

    verifyPath(
                path,
                logger);

    iroha::KeysManagerImpl manager(
                (path / account_name)
                .string(),
                keys_manager_log);
    auto keypair = manager.loadKeys(boost::none);

    verifyKepair(
                keypair,
                logger,
                path,
                account_name);
    return iroha::keypair_t(
                iroha::pubkey_t::from_hexstring(keypair.assumeValue().publicKey()).assumeValue(),
                iroha::privkey_t::from_string(toBinaryString(keypair.assumeValue().privateKey())).assumeValue());
}


const std::string getTransactionHash(const Transaction& tx)
{
    return iroha::hash(tx).to_hexstring();
}


void printTransactionStatus(
        const std::string& peer_ip,
        uint16_t torii_port,
        const std::string& tx_hash)
{
    const auto status = iroha_lib::GrpcClient(
                peer_ip,
                torii_port)
            .getTxStatus(tx_hash);
    std::cout << "Tx hash=" << tx_hash
              << "  Status name=" << TxStatus_Name(status.tx_status())
              << "  Status code=" << status.tx_status()
              << "  Error code=" << status.error_code()
              << std::endl;
}


void printTransactionStatuses(
        const std::string& peer_ip,
        uint16_t torii_port,
        const std::vector<Transaction>& transactions)
{
    for (const auto& tx: transactions) {
        printTransactionStatus(
                    peer_ip,
                    torii_port,
                    getTransactionHash(tx));
    }
}


std::string string_to_hex(const std::string& in)
{
    std::stringstream ss;

    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < in.length(); ++i) {
        ss << std::setw(2) << static_cast<std::uint32_t>(static_cast<std::uint8_t>(in[i]));
    }
    return ss.str();
}

std::pair<std::string,std::string> splitAssetFullName(const std::string& assetFullName)
{
    constexpr const char nameDomainSeparator = '#';
    const auto separatorPosition = assetFullName.find(nameDomainSeparator);
    const std::string assetName = assetFullName.substr(0, separatorPosition);
    const std::string assetDomain = assetFullName.substr(separatorPosition+1);
    return {assetName, assetDomain};
}

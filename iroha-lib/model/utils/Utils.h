#include <boost/filesystem.hpp>
#include <iostream>

#include "crypto/keys_manager_impl.hpp"
#include "logger/logger_manager.hpp"
#include "model/converters/pb_common.hpp"
#include "grpc_client/GrpcClient.hpp"


using namespace iroha::protocol;
namespace fs = boost::filesystem;


void verifyPath(
        const fs::path& path,
        const logger::LoggerPtr& logger);

void verifyKepair(
        const iroha::expected::Result<shared_model::crypto::Keypair, std::string>& keypair,
        const logger::LoggerPtr& logger,
        const fs::path& path,
        const std::string& account_name);

iroha::keypair_t generateKeypair(
        const std::string& account_name,
        const std::string& key_path,
        const logger::LoggerManagerTreePtr& log_manager);

const std::string getTransactionHash(const Transaction& tx);

void printTransactionStatus(
        const std::string& peer_ip,
        uint16_t torii_port,
        const std::string& tx_hash);

void printTransactionStatuses(
        const std::string& peer_ip,
        uint16_t torii_port,
        const std::vector<Transaction>& transactions);

std::string string_to_hex(const std::string& in);

std::pair<std::string,std::string> splitAssetFullName(const std::string& assetFullName);

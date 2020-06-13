/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/hsm_utimaco/init.hpp"

#include <unordered_map>

#include <boost/range/adaptor/map.hpp>
#include "cryptography/crypto_init/from_config.hpp"
#include "cryptography/hsm_utimaco/common.hpp"
#include "cryptography/hsm_utimaco/connection.hpp"
#include "cryptography/hsm_utimaco/formatters.hpp"
#include "cryptography/hsm_utimaco/safe_cxi.hpp"
#include "cryptography/hsm_utimaco/signer.hpp"
#include "cryptography/hsm_utimaco/verifier.hpp"

using namespace shared_model::crypto;

namespace {
  constexpr int kActionTimeoutMs{5000};
  constexpr int kConnectTimeoutMs{10000};

  // throws InitCryptoProviderException
  cxi::Log::levels const &getCxiLogLevel(std::string const &level) {
    static std::unordered_map<std::string, cxi::Log::levels> map{
        {"none", cxi::Log::LEVEL_NONE},
        {"error", cxi::Log::LEVEL_ERROR},
        {"warning", cxi::Log::LEVEL_WARNING},
        {"info", cxi::Log::LEVEL_INFO},
        {"trace", cxi::Log::LEVEL_TRACE},
        {"debug", cxi::Log::LEVEL_DEBUG}};
    auto it = map.find(level);
    if (it == map.end()) {
      throw iroha::InitCryptoProviderException{
          fmt::format("Unknown log level specified. Allowed values are: '{}'.",
                      fmt::join(map | boost::adaptors::map_keys, "', '"))};
    }
    return it->second;
  }

  // throws InitCryptoProviderException
  std::unique_ptr<hsm_utimaco::Connection> makeConnection(
      IrohadConfig::Crypto::HsmUtimaco const &config) {
    std::vector<char const *> devices_raw;
    devices_raw.reserve(config.devices.size());
    for (auto const &device : config.devices) {
      devices_raw.emplace_back(device.c_str());
    }

    auto connection = std::make_unique<hsm_utimaco::Connection>();

    connection->cxi = std::make_unique<cxi::Cxi>(devices_raw.data(),
                                                 devices_raw.size(),
                                                 kActionTimeoutMs,
                                                 kConnectTimeoutMs);

    for (auto const &auth : config.auth) {
      if (auth.key) {
        char const *password = nullptr;
        if (auth.password) {
          password = auth.password.value().c_str();
        }
        connection->cxi->logon_sign(
            auth.user.c_str(), auth.key.value().c_str(), password, true);
      } else if (auth.password) {
        connection->cxi->logon_pass(
            auth.user.c_str(), auth.password.value().c_str(), true);
      }
    }

    return connection;
  }

  // throws InitCryptoProviderException
  std::unique_ptr<shared_model::crypto::CryptoSigner> makeSigner(
      IrohadConfig::Crypto::HsmUtimaco const &config,
      std::shared_ptr<hsm_utimaco::Connection> connection) {
    auto const &signer_config = config.signer.value();

    // get the signature type
    iroha::multihash::Type multihash_type = signer_config.type;
    auto cxi_algo = hsm_utimaco::multihashToCxiHashAlgo(signer_config.type);
    if (not cxi_algo) {
      throw iroha::InitCryptoProviderException{"Unsupported signature type."};
    }

    // prepare the signing key
    cxi::PropertyList key_descr;
    auto const &key_id = signer_config.signing_key;
    key_descr.setName(key_id.name.c_str());
    if (key_id.group) {
      key_descr.setGroup(key_id.group->c_str());
    }
    std::unique_ptr<cxi::Key> key;
    try {
      key = std::make_unique<cxi::Key>(connection->cxi->key_open(0, key_descr));
      if (not key) {
        throw iroha::InitCryptoProviderException{"Could not open signing key."};
      }

      return std::make_unique<hsm_utimaco::Signer>(std::move(connection),
                                                   std::move(key),
                                                   multihash_type,
                                                   cxi_algo.value());
    } catch (const cxi::Exception &e) {
      throw iroha::InitCryptoProviderException{
          fmt::format("Could not open signing key: {}", e)};
    }
  }
}  // namespace

void iroha::initCryptoProviderUtimaco(
    iroha::PartialCryptoInit initializer,
    IrohadConfig::Crypto::HsmUtimaco const &config,
    logger::LoggerManagerTreePtr log_manager) {
  if (config.log) {
    cxi::Log::getInstance().init(config.log->path.c_str(),
                                 getCxiLogLevel(config.log->level));
  }

  std::shared_ptr<hsm_utimaco::Connection> connection = makeConnection(config);

  if (initializer.init_signer) {
    initializer.init_signer.value()(makeSigner(config, connection));
  }

  if (initializer.init_verifier) {
    initializer.init_verifier.value()(std::make_unique<hsm_utimaco::Verifier>(
        connection, config.temporary_key.name, config.temporary_key.group));
  }
}

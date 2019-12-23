/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/binary/launchers.hpp"

#include <filesystem>
#include <future>
#include <sstream>
#include <string>

#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include "common/byteutils.hpp"
#include "cryptography/keypair.hpp"
#include "cryptography/seed.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace boost::process;

namespace {
  shared_model::crypto::Keypair fromPrivateKey(const std::string &private_key) {
    auto byte_string = iroha::hexstringToBytestring(private_key);
    if (not byte_string) {
      throw std::invalid_argument("invalid seed");
    }
    if (byte_string->size()
        != shared_model::crypto::DefaultCryptoAlgorithmType::
               kPrivateKeyLength) {
      throw std::invalid_argument(
          "input bytestring has incorrect length "
          + std::to_string(byte_string->size()) + ", expected "
          + std::to_string(shared_model::crypto::DefaultCryptoAlgorithmType::
                               kPrivateKeyLength));
    }
    return shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair(
        shared_model::crypto::Seed(*byte_string));
  }
}  // namespace

namespace binary_test {

  constexpr auto cTimeToKill = std::chrono::minutes(15);

  void Launcher::operator()(const std::string &example) {
    const auto &command = launchCommand(example);
    if (command.empty()) {
      FAIL() << "Launcher provided empty command";
    }

    boost::asio::io_service ios;

    std::future<std::string> data;

    child c(command, std_out > data, ios);
    ios.run_for(cTimeToKill);
    if (not ios.stopped()) {
      c.terminate();
      FAIL() << "Child process was terminated because execution time limit "
                "has been exceeded";
    }
    readBinaries(data.get());
  }

  void Launcher::readBinaries(const std::string &data) {
    transactions.clear();
    queries.clear();
    std::istringstream iss(data);
    std::string packed_line;
    std::string raw_payload;
    while (iss and std::getline(iss, packed_line) and packed_line.size() > 1) {
      raw_payload = packed_line.substr(1);
      if (raw_payload.back() == '\r') {
        raw_payload.pop_back();
      }
      if (auto byte_string = iroha::hexstringToBytestring(raw_payload)) {
        auto binary_type = packed_line.at(0);
        switch (binary_type) {
          case 'K': {
            if (not admin_key) {
              admin_key = fromPrivateKey(raw_payload);
            }
            break;
          }
          case 'T': {
            iroha::protocol::Transaction proto_tx;
            if (proto_tx.ParseFromString(*byte_string)) {
              transactions.emplace_back(std::move(proto_tx));
            }
            break;
          }
          case 'Q': {
            iroha::protocol::Query proto_query;
            if (proto_query.ParseFromString(*byte_string)) {
              queries.emplace_back(std::move(proto_query));
            }
            break;
          }
        }  // switch (binary_type)
      }
    }
  }

  bool Launcher::initialized(const unsigned &transactions_expected,
                             const unsigned &queries_expected) {
    checkAsserts(transactions_expected, queries_expected);
    return admin_key and transactions.size() == transactions_expected
        and queries.size() == queries_expected;
  }

  void Launcher::checkAsserts(const unsigned &transactions_expected,
                              const unsigned &queries_expected) {
    ASSERT_TRUE(admin_key);
    ASSERT_EQ(transactions.size(), transactions_expected);
    ASSERT_EQ(queries.size(), queries_expected);
  }

  std::string PythonLauncher::launchCommand(const std::string &example) {
    std::stringstream s;
    s << std::filesystem::path(PYTHON_INTERPRETER).string() << " "
      << (std::filesystem::path(ROOT_DIR) / "example" / "python" / "permissions"
          / example)
             .replace_extension(".py")
             .string();
    return s.str();
  }

  std::string JavaLauncher::launchCommand(const std::string &example) {
    return "";
    // TODO, igor-egorov, 2018-06-20, IR-1389
  }

}  // namespace binary_test

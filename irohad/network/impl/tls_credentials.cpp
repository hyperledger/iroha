/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/tls_credentials.hpp"

#include <fstream>
#include <sstream>

#include "common/bind.hpp"

using namespace iroha::expected;
using namespace iroha::network;

using iroha::operator|;

TlsCredentials::TlsCredentials(std::string private_key, std::string certificate)
    : private_key(std::move(private_key)),
      certificate(std::move(certificate)) {}

Result<std::unique_ptr<TlsCredentials>, std::string> TlsCredentials::load(
    const std::string &path) {
  static const auto read_file = [](const std::string &path) {
    std::ifstream certificate_file(path);
    std::stringstream ss;
    ss << certificate_file.rdbuf();
    return ss.str();
  };
  std::unique_ptr<TlsCredentials> creds;
  try {
    creds = std::make_unique<TlsCredentials>(read_file(path + ".key"),
                                             read_file(path + ".crt"));
  } catch (std::exception e) {
    return makeError(e.what());
  }
  return makeValue(std::move(creds));
}

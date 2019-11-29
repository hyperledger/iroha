/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/tls_credentials.hpp"

#include <fstream>
#include <sstream>

#include "common/bind.hpp"
#include "common/files.hpp"
#include "common/result.hpp"

using namespace iroha::expected;
using namespace iroha::network;

using iroha::operator|;

TlsCredentials::TlsCredentials(std::string private_key, std::string certificate)
    : private_key(std::move(private_key)),
      certificate(std::move(certificate)) {}

Result<std::unique_ptr<TlsCredentials>, std::string> TlsCredentials::load(
    const std::string &path) {
  std::unique_ptr<TlsCredentials> creds;
  return iroha::readTextFile(path + ".key") | [&](auto &&key) {
    return iroha::readTextFile(path + ".crt") | [&](auto &&cert) {
      return std::make_unique<TlsCredentials>(std::move(key), std::move(cert));
    };
  };
}

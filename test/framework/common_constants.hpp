/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_FRAMEWORK_COMMON_CONSTANTS_HPP_
#define IROHA_TEST_FRAMEWORK_COMMON_CONSTANTS_HPP_

#include <string>

#include "cryptography/keypair.hpp"

using shared_model::crypto::Keypair;

namespace common_constants {

  /// user names
  extern const std::string kAdminName;
  extern const std::string kUser;
  extern const std::string kSpectator;

  /// role names
  extern const std::string kAdminRole;
  extern const std::string kDefaultRole;
  extern const std::string kRole;

  /// asset names
  extern const std::string kAssetName;

  /// domain names
  extern const std::string kDomain;
  extern const std::string kSecondDomain;

  /// ids
  extern const std::string kAdminId;
  extern const std::string kUserId;
  extern const std::string kCloseSpectatorId;
  extern const std::string kRemoteSpectatorId;
  extern const std::string kAssetId;

  /// keypairs
  extern const Keypair kAdminKeypair;
  extern const Keypair kUserKeypair;
  extern const Keypair kCloseSpectatorKeypair;
  extern const Keypair kRemoteSpectatorKeypair;
}

#endif /* IROHA_TEST_FRAMEWORK_COMMON_CONSTANTS_HPP_ */

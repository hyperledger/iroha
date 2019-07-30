/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_FRAMEWORK_COMMON_CONSTANTS_HPP_
#define IROHA_TEST_FRAMEWORK_COMMON_CONSTANTS_HPP_

#include <limits>
#include <string>

#include "cryptography/keypair.hpp"

static const uint32_t kMaxPageSize = std::numeric_limits<uint32_t>::max();
using shared_model::crypto::Keypair;

namespace common_constants {

  /// user names
  extern const std::string kAdminName;
  extern const std::string kUser;
  extern const std::string kAnotherUser;

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
  extern const std::string kSameDomainUserId;
  extern const std::string kAnotherDomainUserId;
  extern const std::string kAssetId;

  /// keypairs
  extern const Keypair kAdminKeypair;
  extern const Keypair kUserKeypair;
  extern const Keypair kSameDomainUserKeypair;
  extern const Keypair kAnotherDomainUserKeypair;
}  // namespace common_constants

#endif /* IROHA_TEST_FRAMEWORK_COMMON_CONSTANTS_HPP_ */

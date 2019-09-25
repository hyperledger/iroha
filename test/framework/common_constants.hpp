/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_FRAMEWORK_COMMON_CONSTANTS_HPP_
#define IROHA_TEST_FRAMEWORK_COMMON_CONSTANTS_HPP_

#include <limits>
#include <string>

#include "cryptography/keypair.hpp"
#include "interfaces/common_objects/amount.hpp"

static const uint32_t kMaxPageSize = std::numeric_limits<uint32_t>::max();
using shared_model::crypto::Keypair;

namespace common_constants {

  /// user names
  extern const std::string kAdminName;
  extern const std::string kUser;
  extern const std::string kSecondUser;

  /// role names
  extern const std::string kAdminRole;
  extern const std::string kMoneyCreator;
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
  extern const std::string kSecondDomainUserId;
  extern const std::string kAssetId;
  extern const std::string kSecondDomainAssetId;

  /// keypairs
  extern const Keypair kAdminKeypair;
  extern const Keypair kUserKeypair;
  extern const Keypair kSameDomainUserKeypair;
  extern const Keypair kSecondDomainUserKeypair;

  // misc
  extern const shared_model::interface::Amount
      kAmountPrec1Max;  // maximum amount of asset with precision 1
  extern const shared_model::interface::Amount
      kAmountPrec2Max;  // maximum amount of asset with precision 2
}  // namespace common_constants

#endif /* IROHA_TEST_FRAMEWORK_COMMON_CONSTANTS_HPP_ */

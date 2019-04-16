/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ACCOUNT_ASSET_HPP
#define IROHA_ACCOUNT_ASSET_HPP

#include <string>

namespace iroha {
  namespace model {
    /**
     * Account has Asset model representation
     */
    struct AccountAsset {
      AccountAsset() = default;

      AccountAsset(const std::string &asset_id,
                   const std::string &account_id,
                   const std::string &balance)
          : asset_id(asset_id), account_id(account_id), balance(balance) {}

      /**
       * Asset identifier
       */
      std::string asset_id;

      /**
       * Account identifier
       */
      std::string account_id;

      /**
       * Current balance
       */
      std::string balance;
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_ACCOUNT_ASSET_HPP

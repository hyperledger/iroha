/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GET_TRANSACTIONS_HPP
#define IROHA_GET_TRANSACTIONS_HPP

#include <string>
#include <vector>

#include "crypto/hash_types.hpp"
#include "model/query.hpp"

namespace iroha {
  namespace model {

    /**
     * Query for getting transactions of given asset of an account
     */
    struct GetAccountAssetTransactions : Query {
      /**
       * Account identifier
       */
      std::string account_id{};

      /**
       * Asset identifier
       */
      std::string asset_id{};
    };

    /**
     * Query for getting transactions of account
     */
    struct GetAccountTransactions : Query {
      /**
       * Account identifier
       */
      std::string account_id{};
    };

    /**
     * Query for getting transactions of given transactions' hashes
     */
    struct GetTransactions : Query {
      using TxHashType = iroha::hash256_t;
      using TxHashCollectionType = std::vector<TxHashType>;
      /**
       * Hashes of the transaction to be retrieved
       */
      TxHashCollectionType tx_hashes{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_GET_TRANSACTIONS_HPP

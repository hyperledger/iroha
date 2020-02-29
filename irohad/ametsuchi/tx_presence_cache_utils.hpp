/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TX_PRESENCE_CACHE_UTILS_HPP
#define IROHA_TX_PRESENCE_CACHE_UTILS_HPP

#include "ametsuchi/tx_cache_response.hpp"
#include "common/visitor.hpp"

namespace iroha {
  namespace ametsuchi {
    /**
     * Determine if transaction was already processed by its status
     * @param tx_status - status obtained from transaction cache
     * @return true if transaction was committed or rejected
     */
    inline bool isAlreadyProcessed(
        const TxCacheStatusType &tx_status) noexcept {
      return std::visit(
          make_visitor(
              [](const ametsuchi::tx_cache_status_responses::Missing &) {
                return false;
              },
              [](const auto &) { return true; }),
          tx_status);
    }

    /**
     * Retrieve hash from status
     * @param status - transaction status obtained from cache
     * @return hash of the transaction
     */
    inline tx_cache_response_details::HashType getHash(
        const TxCacheStatusType &status) noexcept {
      return std::visit(
          make_visitor([](const auto &status) { return status.hash; }), status);
    }
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_TX_PRESENCE_CACHE_HPP

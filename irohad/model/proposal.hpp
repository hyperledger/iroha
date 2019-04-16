/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROPOSAL_HPP
#define IROHA_PROPOSAL_HPP

#include <vector>
#include "model/transaction.hpp"

namespace iroha {
  namespace model {

    /**
     * Proposal is a Model-structure that provides a bunch of transactions
     * emitted by ordering service. Proposal has no signatures and other meta
     * information.
     */
    struct Proposal {
      explicit Proposal(std::vector<Transaction> txs)
          : transactions(txs), height(0) {}

      /**
       * Bunch of transactions provided by ordering service.
       */
      const std::vector<Transaction> transactions{};

      /**
       * Height of current proposal.
       * Note: This height must be consistent with your last block height
       */
      uint64_t height{};

      /**
       * Time when the proposal have been created
       */
      uint64_t created_time{};

      bool operator==(const Proposal &rhs) const;
      bool operator!=(const Proposal &rhs) const;
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_PROPOSAL_HPP

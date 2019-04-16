/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_HPP
#define IROHA_TRANSACTION_HPP

#include <memory>
#include <string>
#include <vector>

#include "crypto/hash_types.hpp"
#include "datetime/time.hpp"
#include "model/command.hpp"
#include "model/signature.hpp"

namespace iroha {
  namespace model {

    /**
     * Transaction is a Model-structure that provides abstraction to bunch of
     * commands with signatures and meta-data.
     * Transaction can be divided to {Header, Meta, Body}.
     */
    struct Transaction {
      /**
       * List of signatories that sign transaction
       * HEADER field
       */
      std::vector<Signature> signatures{};

      using SignaturesType = decltype(signatures);

      using TimeType = ts64_t;

      /**
       * Creation timestamp
       * HEADER field
       */
      TimeType created_ts{};

      /**
       * Account id of transaction creator.
       * META field
       */
      std::string creator_account_id{};

      /**
       * Quorum means number of signatures required for processing transaction
       * in system.
       * This field should be > 0.
       */
      uint8_t quorum = 1;

      /**
       * Bunch of commands attached to transaction
       * shared_ptr is used since Proposal has to be copied
       * BODY field
       */
      std::vector<std::shared_ptr<Command>> commands{};

      using CommandsType = decltype(commands);

      bool operator==(const Transaction &rhs) const;
      bool operator!=(const Transaction &rhs) const;
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_TRANSACTION_HPP

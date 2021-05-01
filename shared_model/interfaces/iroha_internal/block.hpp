/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BLOCK_HPP
#define IROHA_SHARED_MODEL_BLOCK_HPP

#include "common/cloneable.hpp"
#include "interfaces/base/signable.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    class Block : public Signable<Block>, public Cloneable<Block> {
     public:
      /**
       * @return block number in the ledger
       */
      virtual types::HeightType height() const = 0;

      /**
       * @return hash of a previous block
       */
      virtual const types::HashType &prevHash() const = 0;

      /**
       * @return collection of transactions
       */
      virtual types::TransactionsCollectionType transactions() const = 0;

      /**
       * @return collection of rejected transactions' hashes
       */
      virtual interface::types::HashCollectionType
      rejected_transactions_hashes() const = 0;

      std::string toString() const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_BLOCK_HPP

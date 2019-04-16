/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BLOCK_INDEX_HPP
#define IROHA_POSTGRES_BLOCK_INDEX_HPP

#include <boost/format.hpp>

#include "ametsuchi/impl/block_index.hpp"
#include "ametsuchi/impl/soci_utils.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PostgresBlockIndex : public BlockIndex {
     public:
      PostgresBlockIndex(soci::session &sql, logger::LoggerPtr log);

      /**
       * Create several indices for block. Namely:
       * transaction hash -> block, where this transaction is stored
       * transaction creator -> block where his transaction is located
       *
       * Additionally, for each Transfer Asset command:
       *   1. (account, asset) -> block for each:
       *     a. creator of the transaction
       *     b. source account
       *     c. destination account
       *   2. account -> block for source and destination accounts
       *   3. (account, height) -> list of txes
       */
      void index(const shared_model::interface::Block &block) override;

     private:
      soci::session &sql_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_BLOCK_INDEX_HPP

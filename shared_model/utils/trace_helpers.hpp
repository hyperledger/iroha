/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_TRACE_HELPERS_HPP
#define IROHA_SHARED_MODEL_TRACE_HELPERS_HPP

#include "interfaces/common_objects/range_types.hpp"

namespace shared_model {
  namespace interface {

    class TxHashesPrinter {
     public:
      TxHashesPrinter(const types::TransactionsCollectionType &txs);

      std::string toString() const;
     private:
      const types::TransactionsCollectionType &txs_;
    };

  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_TRACE_HELPERS_HPP

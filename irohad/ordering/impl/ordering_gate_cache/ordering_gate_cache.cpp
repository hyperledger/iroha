/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/ordering_gate_cache/ordering_gate_cache.hpp"

#include "interfaces/iroha_internal/transaction_batch.hpp"

namespace iroha {
  namespace ordering {
    namespace cache {

      size_t OrderingGateCache::BatchPointerHasher::operator()(
          const std::shared_ptr<shared_model::interface::TransactionBatch> &a)
          const {
        return hasher_(a->reducedHash());
      }

    }  // namespace cache
  }    // namespace ordering
}  // namespace iroha

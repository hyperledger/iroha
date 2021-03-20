/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PENDING_TRANSACTION_STORAGE_INIT_HPP
#define IROHA_PENDING_TRANSACTION_STORAGE_INIT_HPP

#include <memory>

#include <rxcpp/rx-lite.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class TransactionBatch;
  }
}  // namespace shared_model

namespace iroha {

  class MstProcessor;
  class MstState;
  class PendingTransactionStorage;

  namespace network {
    class PeerCommunicationService;
  }

  class PendingTransactionStorageInit {
   public:
    PendingTransactionStorageInit();

    std::shared_ptr<PendingTransactionStorage>
    createPendingTransactionsStorage();

    ~PendingTransactionStorageInit() = default;
  };
}  // namespace iroha

#endif  // IROHA_PENDING_TRANSACTION_STORAGE_INIT_HPP

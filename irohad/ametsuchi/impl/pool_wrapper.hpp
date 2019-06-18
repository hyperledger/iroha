/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POOL_WRAPPER_HPP
#define IROHA_POOL_WRAPPER_HPP

#include <memory>

namespace soci {
  class connection_pool;
}

namespace iroha {
  namespace ametsuchi {
    class FailoverCallbackHolder;

    struct PoolWrapper {
      PoolWrapper(
          std::shared_ptr<soci::connection_pool> connection_pool,
          std::unique_ptr<FailoverCallbackHolder> failover_callback_holder,
          bool enable_prepared_transactions);

      std::shared_ptr<soci::connection_pool> connection_pool_;
      std::unique_ptr<FailoverCallbackHolder> failover_callback_holder_;
      bool enable_prepared_transactions_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POOL_WRAPPER_HPP

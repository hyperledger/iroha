/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>

#include <soci/soci.h>

#ifndef IROHA_POOL_WRAPPER_HPP
#define IROHA_POOL_WRAPPER_HPP

namespace iroha {
  namespace ametsuchi {
    class FailoverCallbackFactory;

    struct PoolWrapper {
      PoolWrapper(std::shared_ptr<soci::connection_pool>,
                  std::unique_ptr<FailoverCallbackFactory>,
                  bool enable_prepared_transactions);

      PoolWrapper(PoolWrapper &&) = default;
      ~PoolWrapper() = default;

      std::shared_ptr<soci::connection_pool> connection_pool_;
      std::unique_ptr<FailoverCallbackFactory> failover_callback_factory_;
      bool enable_prepared_transactions_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POOL_WRAPPER_HPP

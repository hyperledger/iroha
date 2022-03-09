/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_HPP
#define TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_HPP

#include "framework/executor_itf/executor_itf_param.hpp"

#include <gtest/gtest.h>
#include "interfaces/common_objects/types.hpp"
#include "main/subscription.hpp"

namespace iroha::ametsuchi {
  class BlockIndex;
  class BurrowStorage;
  class MockVmCaller;
}  // namespace iroha::ametsuchi

namespace executor_testing {

  struct ExecutorTestParam {
    enum struct ExecutorType {
      kPostgres,
      kRocksDb,
    };

    ExecutorTestParam();

    virtual ~ExecutorTestParam();

    virtual ExecutorType getType() const = 0;

    /// Implementations must define this to clear WSV completely between tests.
    virtual void clearBackendState() = 0;

    /// Implementations must define this to provide backend parameter for
    /// ExecutorItf.
    virtual iroha::integration_framework::ExecutorItfTarget
    getExecutorItfParam() const = 0;

    /// Make a BurrowStorage for this backend.
    virtual std::unique_ptr<iroha::ametsuchi::BurrowStorage> makeBurrowStorage(
        std::string const &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index) const = 0;

    /// Get block indexer for this backend.
    virtual std::shared_ptr<iroha::ametsuchi::BlockIndex> getBlockIndexer()
        const = 0;

    /// Implementations must define this to provide backend description.
    virtual std::string toString() const = 0;

    std::unique_ptr<iroha::ametsuchi::MockVmCaller> vm_caller_;
    std::shared_ptr<iroha::Subscription> subscription_manager_;
  };

}  // namespace executor_testing

#endif /* TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_HPP */

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_HPP
#define TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_HPP

#include "framework/executor_itf/executor_itf_param.hpp"

#include <gtest/gtest.h>

namespace executor_testing {

  struct ExecutorTestParam {
    virtual ~ExecutorTestParam();

    /// Implementations must define this to clear WSV completely between tests.
    virtual void clearBackendState() = 0;

    /// Implementations must define this to provide backend parameter for
    /// ExecutorItf.
    virtual iroha::integration_framework::ExecutorItfTarget
    getExecutorItfParam() const = 0;

    /// Implementations must define this to provide backend description.
    virtual std::string toString() const = 0;
  };

  std::string paramToString(
      testing::TestParamInfo<std::shared_ptr<ExecutorTestParam>> param);

}  // namespace executor_testing

#endif /* TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_HPP */

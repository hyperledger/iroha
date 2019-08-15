/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture_param.hpp"

using namespace executor_testing;

ExecutorTestParam::~ExecutorTestParam() = default;

std::string executor_testing::paramToString(
    testing::TestParamInfo<std::shared_ptr<ExecutorTestParam>> param) {
  return param.param->toString();
}

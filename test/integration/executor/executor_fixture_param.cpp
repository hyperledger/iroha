/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture_param.hpp"

#include "module/irohad/ametsuchi/mock_vm_caller.hpp"

using namespace executor_testing;

ExecutorTestParam::ExecutorTestParam()
    : vm_caller_(std::make_unique<iroha::ametsuchi::MockVmCaller>()) {}

ExecutorTestParam::~ExecutorTestParam() = default;

std::string executor_testing::paramToString(
    testing::TestParamInfo<std::shared_ptr<ExecutorTestParam>> param) {
  return param.param->toString();
}

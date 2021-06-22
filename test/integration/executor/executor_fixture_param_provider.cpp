/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture_param_provider.hpp"

#include "integration/executor/executor_fixture_param.hpp"
#include "integration/executor/executor_fixture_param_postgres.hpp"
#include "integration/executor/executor_fixture_param_rocksdb.hpp"

namespace executor_testing {

  std::vector<ExecutorTestParamProvider> getExecutorTestParamProvidersVector() {
    return std::vector<ExecutorTestParamProvider>{&getExecutorTestParamPostgres,
                                                  &getExecutorTestParamRocksDB};
  }

  auto getExecutorTestParams()
      -> decltype(::testing::ValuesIn(getExecutorTestParamProvidersVector())) {
    static auto params =
        ::testing::ValuesIn(getExecutorTestParamProvidersVector());
    return params;
  }

  std::string paramToString(
      testing::TestParamInfo<ExecutorTestParamProvider> param) {
    return param.param().get().toString();
  }
}  // namespace executor_testing

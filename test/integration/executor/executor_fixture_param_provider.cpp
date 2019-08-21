#include "integration/executor/executor_fixture_param_provider.hpp"

#include "integration/executor/executor_fixture_param.hpp"
#include "integration/executor/executor_fixture_param_postgres.hpp"

namespace executor_testing {

  std::vector<std::shared_ptr<ExecutorTestParam>>
  getExecutorTestParamsVector() {
    return std::vector<std::shared_ptr<ExecutorTestParam>>{
        {std::make_shared<PostgresExecutorTestParam>()}};
  }

  auto getExecutorTestParams()
      -> decltype(::testing::ValuesIn(getExecutorTestParamsVector())) {
    static auto params = ::testing::ValuesIn(getExecutorTestParamsVector());
    return params;
  }
}  // namespace executor_testing

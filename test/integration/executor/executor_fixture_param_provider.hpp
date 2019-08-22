#ifndef TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_PROVIDER_HPP
#define TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_PROVIDER_HPP

#include <gtest/gtest-param-test.h>

namespace executor_testing {
  struct ExecutorTestParam;

  std::vector<std::shared_ptr<ExecutorTestParam>> getExecutorTestParamsVector();

  auto getExecutorTestParams()
      -> decltype(::testing::ValuesIn(getExecutorTestParamsVector()));

}  // namespace executor_testing

#endif /* TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_PROVIDER_HPP */

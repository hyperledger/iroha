#ifndef TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_PROVIDER_HPP
#define TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_PROVIDER_HPP

#include <functional>

#include <gtest/gtest-param-test.h>

namespace executor_testing {
  struct ExecutorTestParam;

  using ExecutorTestParamProvider =
      std::reference_wrapper<ExecutorTestParam> (*)();

  std::vector<ExecutorTestParamProvider> getExecutorTestParamProvidersVector();

  auto getExecutorTestParams()
      -> decltype(::testing::ValuesIn(getExecutorTestParamProvidersVector()));

  std::string paramToString(
      testing::TestParamInfo<ExecutorTestParamProvider> param);

}  // namespace executor_testing

#endif /* TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_PROVIDER_HPP */

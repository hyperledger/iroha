/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RESULT_GTEST_CHECKERS_HPP
#define IROHA_RESULT_GTEST_CHECKERS_HPP

#include "common/result.hpp"

#include <gtest/gtest.h>
#include "common/bind.hpp"

namespace framework {
  namespace expected {
    namespace detail {
      const auto kValueAssumer = [](auto &&r) { r.assumeValue(); };
      const auto kErrorAssumer = [](auto &&r) { r.assumeError(); };

      template <typename V, typename E, typename Assumer>
      inline void checkResultValue(
          const iroha::expected::Result<V, E> &r,
          Assumer assumer,
          ::testing::TestPartResult::Type failure_type) {
        try {
          (*assumer)(r);
        } catch (const iroha::expected::ResultException &e) {
          GTEST_MESSAGE_("Result assumption failed", failure_type) << e.what();
        }
      }
    }  // namespace detail

    template <typename V, typename E>
    inline void expectResultValue(const iroha::expected::Result<V, E> &r) {
      checkResultValue(r,
                       &detail::kValueAssumer,
                       ::testing::TestPartResult::kNonFatalFailure);
    }

    template <typename V, typename E>
    inline void expectResultError(const iroha::expected::Result<V, E> &r) {
      checkResultValue(r,
                       &detail::kErrorAssumer,
                       ::testing::TestPartResult::kNonFatalFailure);
    }
  }  // namespace expected
}  // namespace framework

#define IROHA_ASSERT_RESULT_VALUE(result)                                  \
  ASSERT_NO_FATAL_FAILURE(::framework::expected::detail::checkResultValue( \
      result,                                                              \
      &::framework::expected::detail::kValueAssumer,                       \
      ::testing::TestPartResult::kFatalFailure))

#define IROHA_ASSERT_RESULT_ERROR(result)                                  \
  ASSERT_NO_FATAL_FAILURE(::framework::expected::detail::checkResultValue( \
      result,                                                              \
      &::framework::expected::detail::kErrorAssumer,                       \
      ::testing::TestPartResult::kFatalFailure))

#endif  // IROHA_RESULT_GTEST_CHECKERS_HPP

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RESULT_GTEST_CHECKERS_HPP
#define IROHA_RESULT_GTEST_CHECKERS_HPP

#include "common/result.hpp"

#include <gtest/gtest.h>
#include "common/bind.hpp"
#include "common/to_string.hpp"

namespace framework {
  namespace expected {
    namespace detail {
      template <typename V, typename E>
      inline std::string getValueMessage(
          const iroha::expected::Result<V, E> &r) {
        return iroha::to_string::tryToString(r.assumeValue())
            .value_or("(could not get text info)");
      }

      template <typename E>
      inline std::string getValueMessage(
          const iroha::expected::Result<void, E> &r) {
        return "void value";
      }

      template <typename V, typename E>
      inline auto getErrorMessage(const iroha::expected::Result<V, E> &r) {
        return iroha::to_string::tryToString(r.assumeError())
            .value_or("(could not get text info)");
      }

      template <typename V>
      inline std::string getErrorMessage(
          const iroha::expected::Result<V, void> &r) {
        return "void error";
      }

      template <typename V, typename E>
      inline void assertResultValue(const iroha::expected::Result<V, E> &r) {
        ASSERT_TRUE(iroha::expected::hasValue(r))
            << "Value expected, but got error: " << detail::getErrorMessage(r);
      }

      template <typename V, typename E>
      inline void assertResultError(const iroha::expected::Result<V, E> &r) {
        ASSERT_TRUE(iroha::expected::hasError(r))
            << "Error expected, but got value: " << detail::getValueMessage(r);
      }
    }  // namespace detail

    template <typename V, typename E>
    inline void expectResultValue(const iroha::expected::Result<V, E> &r) {
      EXPECT_TRUE(iroha::expected::hasValue(r))
          << "Value expected, but got error: " << detail::getErrorMessage(r);
    }

    template <typename V, typename E>
    inline void expectResultError(const iroha::expected::Result<V, E> &r) {
      EXPECT_TRUE(iroha::expected::hasError(r))
          << "Error expected, but got value: " << detail::getValueMessage(r);
    }
  }  // namespace expected
}  // namespace framework

#define IROHA_ASSERT_RESULT_VALUE(result) \
  ASSERT_NO_FATAL_FAILURE(                \
      ::framework::expected::detail::assertResultValue(result))

#define IROHA_ASSERT_RESULT_ERROR(result) \
  ASSERT_NO_FATAL_FAILURE(                \
      ::framework::expected::detail::assertResultError(result))

#endif  // IROHA_RESULT_GTEST_CHECKERS_HPP

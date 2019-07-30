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
      inline std::string getMessage(const std::string &s) {
        return s;
      }

      template <typename T>
      inline auto getMessage(const T &o) -> std::enable_if_t<
          std::is_same<decltype(o.toString()), std::string>::value,
          std::string> {
        return o.toString();
      }

      template <typename T>
      inline auto getMessage(const T &o) -> std::enable_if_t<
          std::is_same<decltype(o->toString()), std::string>::value,
          std::string> {
        return o->toString();
      }

      template <typename V, typename E>
      inline auto getValueMessage(const iroha::expected::Result<V, E> &r)
          -> decltype(getMessage(std::declval<V>())) {
        using iroha::operator|;
        return iroha::expected::resultToOptionalValue(r) |
            [](const auto v) { return getMessage(v); };
      }

      template <typename E>
      inline std::string getValueMessage(
          const iroha::expected::Result<void, E> &r) {
        return "void value";
      }

      template <typename V, typename E>
      inline auto getErrorMessage(const iroha::expected::Result<V, E> &r)
          -> decltype(getMessage(std::declval<E>())) {
        using iroha::operator|;
        return iroha::expected::resultToOptionalError(r) |
            [](const auto e) { return getMessage(e); };
      }

      template <typename V>
      inline std::string getErrorMessage(
          const iroha::expected::Result<V, void> &r) {
        return "void error";
      }
    }  // namespace detail

    template <typename V, typename E>
    inline void expectResultValue(const iroha::expected::Result<V, E> &r) {
      EXPECT_TRUE(iroha::expected::hasValue(r))
          << "Value expected, but got error: " << detail::getErrorMessage(r);
    }

    template <typename V, typename E>
    inline void assertResultValue(const iroha::expected::Result<V, E> &r) {
      ASSERT_TRUE(iroha::expected::hasValue(r))
          << "Value expected, but got error: " << detail::getErrorMessage(r);
    }

    template <typename V, typename E>
    inline void expectResultError(const iroha::expected::Result<V, E> &r) {
      EXPECT_TRUE(iroha::expected::hasError(r))
          << "Error expected, but got value: " << detail::getValueMessage(r);
    }

    template <typename V, typename E>
    inline void assertResultError(const iroha::expected::Result<V, E> &r) {
      ASSERT_TRUE(iroha::expected::hasError(r))
          << "Error expected, but got value: " << detail::getValueMessage(r);
    }

  }  // namespace expected
}  // namespace framework

#endif  // IROHA_RESULT_GTEST_CHECKERS_HPP

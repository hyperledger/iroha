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

      template <typename R>
      inline std::enable_if_t<
          iroha::expected::isResult<R>,
          decltype(
              getMessage(std::declval<iroha::expected::InnerValueOf<R>>()))>
      getValueMessage(R &&r) {
        using iroha::operator|;
        return iroha::expected::resultToOptionalValue(std::forward<R>(r)) |
            [](const auto &v) { return getMessage(v); };
      }

      template <typename E>
      inline std::string getValueMessage(
          const iroha::expected::Result<void, E> &r) {
        return "void value";
      }

      template <typename R>
      inline std::enable_if_t<
          iroha::expected::isResult<R>,
          decltype(
              getMessage(std::declval<iroha::expected::InnerErrorOf<R>>()))>
      getErrorMessage(R &&r) {
        using iroha::operator|;
        return iroha::expected::resultToOptionalError(std::forward<R>(r)) |
            [](const auto &e) { return getMessage(e); };
      }

      template <typename V>
      inline std::string getErrorMessage(
          const iroha::expected::Result<V, void> &r) {
        return "void error";
      }
    }  // namespace detail

    template <typename R>
    inline std::enable_if_t<iroha::expected::isResult<R>> expectResultValue(
        R &&r) {
      EXPECT_TRUE(iroha::expected::hasValue(r))
          << "Value expected, but got error: "
          << detail::getErrorMessage(std::forward<R>(r));
    }

    template <typename R>
    inline std::enable_if_t<iroha::expected::isResult<R>> assertResultValue(
        R &&r) {
      ASSERT_TRUE(iroha::expected::hasValue(r))
          << "Value expected, but got error: "
          << detail::getErrorMessage(std::forward<R>(r));
    }

    template <typename R>
    inline std::enable_if_t<iroha::expected::isResult<R>> expectResultError(
        R &&r) {
      EXPECT_TRUE(iroha::expected::hasError(r))
          << "Error expected, but got value: "
          << detail::getValueMessage(std::forward<R>(r));
    }

    template <typename R>
    inline std::enable_if_t<iroha::expected::isResult<R>> assertResultError(
        R &&r) {
      ASSERT_TRUE(iroha::expected::hasError(r))
          << "Error expected, but got value: "
          << detail::getValueMessage(std::forward<R>(r));
    }

    template <typename R>
    inline std::enable_if_t<iroha::expected::isResult<R>,
                            iroha::expected::InnerValueOf<R>>
    assertAndGetResultValue(R &&r) {
      if (not iroha::expected::hasValue(r)) {
        ADD_FAILURE() << "Value expected, but got error: "
                      << detail::getErrorMessage(std::forward<R>(r));
        assert(false);
      }
      return iroha::expected::resultToOptionalValue(std::forward<R>(r)).value();
    }

  }  // namespace expected
}  // namespace framework

#endif  // IROHA_RESULT_GTEST_CHECKERS_HPP

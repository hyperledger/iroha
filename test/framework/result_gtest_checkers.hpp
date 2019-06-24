/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RESULT_GTEST_CHECKERS_HPP
#define IROHA_RESULT_GTEST_CHECKERS_HPP

#include "common/result.hpp"

#include <gtest/gtest.h>

namespace framework {
  namespace expected {
    namespace detail {
      std::string getMessage(const std::string &s) {
        return s;
      }

      template <typename T>
      auto getMessage(const T &o) -> std::enable_if_t<
          std::is_same<decltype(o.toString()), std::string>::value,
          std::string> {
        return o.toString();
      }

      template <typename T>
      auto getMessage(const T &o) -> std::enable_if_t<
          std::is_same<decltype(o->toString()), std::string>::value,
          std::string> {
        return o->toString();
      }
    }  // namespace detail

    template <typename V, typename E>
    void expectResultValue(const iroha::expected::Result<V, E> &r) {
      EXPECT_TRUE(iroha::expected::hasValue(r))
          << "Value expected, but got error: "
          << detail::getMessage(
                 iroha::expected::resultToOptionalError(r).value());
    }

    template <typename V, typename E>
    void assertResultValue(const iroha::expected::Result<V, E> &r) {
      ASSERT_TRUE(iroha::expected::hasValue(r))
          << "Value expected, but got error: "
          << detail::getMessage(
                 iroha::expected::resultToOptionalError(r).value());
    }

    template <typename V, typename E>
    void expectResultError(const iroha::expected::Result<V, E> &r) {
      EXPECT_TRUE(iroha::expected::hasError(r))
          << "Error expected, but got value: "
          << detail::getMessage(
                 iroha::expected::resultToOptionalValue(r).value());
    }

    template <typename V, typename E>
    void assertResultError(const iroha::expected::Result<V, E> &r) {
      ASSERT_TRUE(iroha::expected::hasError(r))
          << "Error expected, but got value: "
          << detail::getMessage(
                 iroha::expected::resultToOptionalValue(r).value());
    }

  }  // namespace expected
}  // namespace framework

#endif  // IROHA_RESULT_GTEST_CHECKERS_HPP

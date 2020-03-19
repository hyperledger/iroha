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
      template <typename T>
      class ObjectToMessage {
        using MessageType = std::string;
        using NoMessageType = void;

       public:
        static NoMessageType getMessage(...);

        static MessageType getMessage(const std::string &s) {
          return s;
        }

        template <typename T2>
        static auto getMessage(const T2 &o) -> std::enable_if_t<
            std::is_same<decltype(o.toString()), std::string>::value,
            MessageType> {
          return o.toString();
        }

        template <typename T2>
        static auto getMessage(const T2 &o) -> std::enable_if_t<
            std::is_same<decltype(o->toString()), std::string>::value,
            MessageType> {
          return o->toString();
        }

        static constexpr bool HasMessage =
            std::is_same<decltype(getMessage(std::declval<T>())),
                         MessageType>::value;
      };

      template <typename T, bool has_message = ObjectToMessage<T>::HasMessage>
      struct ObjectDescription {
        static std::string describe(const T &o) {
          return ObjectToMessage<T>::getMessage(o);
        }
      };

      template <typename T>
      struct ObjectDescription<T, false> {
        static std::string describe(const T &o) {
          return "Could not get the message from Result.";
        }
      };

      template <typename V, typename E>
      inline std::string getValueMessage(
          const iroha::expected::Result<V, E> &r) {
        return ObjectDescription<std::remove_reference_t<V>>::describe(
            r.assumeValue());
      }

      template <typename E>
      inline std::string getValueMessage(
          const iroha::expected::Result<void, E> &r) {
        return "void value";
      }

      template <typename V, typename E>
      inline auto getErrorMessage(const iroha::expected::Result<V, E> &r) {
        return ObjectDescription<std::remove_reference_t<E>>::describe(
            r.assumeError());
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

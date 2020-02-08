/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LIBS_TO_STRING_HPP
#define IROHA_LIBS_TO_STRING_HPP

#include <ciso646>
#include <memory>
#include <string>

#include <boost/optional.hpp>

namespace iroha {
  namespace to_string {
    namespace detail {
      const std::string kBeginBlockMarker = "[";
      const std::string kEndBlockMarker = "]";
      const std::string kSingleFieldsSeparator = ", ";
      const std::string kNotSet = "(not set)";

      /// Print pointers and optionals.
      template <typename T>
      inline std::string toStringDereferenced(const T &o);

      template <typename T, typename = void>
      constexpr bool kToStringStd = false;

      template <typename T>
      constexpr bool kToStringStd<
          T,
          std::enable_if_t<
              std::is_same<decltype(std::to_string(std::declval<T>())),
                           std::string>::value>> = true;

      template <typename T, typename = void>
      constexpr bool kToStringMethod = false;

      template <typename T>
      constexpr bool kToStringMethod<
          T,
          std::enable_if_t<std::is_same<
              typename std::decay_t<decltype(std::declval<T>().toString())>,
              std::string>::value>> = true;

      template <typename T>
      constexpr bool kIsDereferenceable = false;
      template <typename... T>
      constexpr bool kIsDereferenceable<std::shared_ptr<T...>> = true;
      template <typename... T>
      constexpr bool kIsDereferenceable<std::unique_ptr<T...>> = true;
      template <typename... T>
      constexpr bool kIsDereferenceable<boost::optional<T...>> = true;

      template <typename T, typename = void>
      constexpr bool kIsCollection = false;

      template <typename T>
      constexpr bool kIsCollection<
          T,
          std::enable_if_t<
              std::is_same<decltype(*std::declval<T>().begin()),
                           decltype(*std::declval<T>().end())>::value
              and std::is_same<decltype(std::next(std::declval<T>().begin())),
                               decltype(std::declval<T>().end())>::value>> =
          true;

      template <typename T>
      constexpr bool kIsBoostNone =
          std::is_same<std::decay_t<T>, boost::none_t>::value;

      template <typename T>
      constexpr bool kToStringApplicable();

      template <typename T, typename = void>
      constexpr bool kToStringTryDereference = false;
      template <typename T>
      constexpr bool kToStringTryDereference<
          T,
          std::enable_if_t<kIsDereferenceable<std::decay_t<T>>>> =
          kToStringApplicable<decltype(*std::declval<T>())>();
      template <typename T>
      constexpr bool
          kToStringTryDereference<T, std::enable_if_t<kIsBoostNone<T>>> = true;

      template <typename T, typename = void>
      constexpr bool kToStringCollection = false;
      template <typename T>
      constexpr bool kToStringCollection<
          T,
          std::enable_if_t<kIsCollection<std::decay_t<T>>>> =
          kToStringApplicable<decltype(*std::declval<T>().begin())>();

      template <typename T>
      constexpr bool kToStringApplicable() {
        return std::is_same<std::decay_t<T>, std::string>::value
            or kToStringStd<
                   T> or kToStringMethod<T> or kToStringTryDereference<T> or kToStringCollection<T>;
      }

    }  // namespace detail

    // ------------------------------- forwards -------------------------------

    /**
     * toString family of functions aims to prettily print any object as text.
     * Primarily for logging and debugging, but can also be used in error
     * descriptions returned to client.
     */

    inline std::string toString(const std::string &o);

    template <typename T>
    inline std::enable_if_t<detail::kToStringStd<T>, std::string> toString(
        const T &o);

    template <typename T>
    inline std::enable_if_t<detail::kToStringMethod<T>, std::string> toString(
        const T &o);

    template <typename T>
    inline std::enable_if_t<detail::kToStringTryDereference<T>, std::string>
    toString(const T &o);

    template <typename T>
    inline std::enable_if_t<detail::kToStringCollection<T>, std::string>
    toString(const T &c);

    /// Try to call toString() on given object.
    /// @return toString result if toString accepts this object or boost::none
    /// otherwise.
    template <typename T>
    inline boost::optional<std::string> tryToString(const T &o);

    // ----------------------------- definitions ------------------------------

    inline std::string toString(const std::string &o) {
      return o;
    }

    template <typename T>
    inline std::enable_if_t<detail::kToStringStd<T>, std::string> toString(
        const T &o) {
      return std::to_string(o);
    }

    template <typename T>
    inline std::enable_if_t<detail::kToStringMethod<T>, std::string> toString(
        const T &o) {
      return o.toString();
    }

    template <typename T>
    inline std::enable_if_t<detail::kToStringTryDereference<T>, std::string>
    toString(const T &o) {
      return detail::toStringDereferenced(o);
    }

    template <typename T>
    inline std::enable_if_t<detail::kToStringCollection<T>, std::string>
    toString(const T &c) {
      std::string result = detail::kBeginBlockMarker;
      bool need_field_separator = false;
      for (auto &o : c) {
        if (need_field_separator) {
          result.append(detail::kSingleFieldsSeparator);
        }
        result.append(toString(o));
        need_field_separator = true;
      }
      result.append(detail::kEndBlockMarker);
      return result;
    }

    namespace detail {
      template <typename T, bool HasMessage = detail::kToStringApplicable<T>()>
      struct ObjectDescription {
        static boost::optional<std::string> describe(const T &o) {
          return toString(o);
        }
      };

      template <typename T>
      struct ObjectDescription<T, false> {
        static boost::optional<std::string> describe(const T &o) {
          return boost::none;
        }
      };
    }  // namespace detail

    template <typename T>
    inline boost::optional<std::string> tryToString(const T &o) {
      return detail::ObjectDescription<T>::describe(o);
    }

    namespace detail {
      /// Print pointers and optionals.
      template <typename T>
      inline std::string toStringDereferenced(const T &o) {
        if (o) {
          return ::iroha::to_string::toString(*o);
        } else {
          return kNotSet;
        }
      }

      template <>
      inline std::string toStringDereferenced<boost::none_t>(
          const boost::none_t &) {
        return kNotSet;
      }
    }  // namespace detail
  }    // namespace to_string
}  // namespace iroha

#endif

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LIBS_TO_STRING_HPP
#define IROHA_LIBS_TO_STRING_HPP

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

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
    }  // namespace detail

    inline std::string toString(std::string const &o) {
      return o;
    }

    inline std::string toString(std::string_view o) {
      return std::string{o};
    }

    template <typename T>
    inline auto toString(const T &o) -> std::enable_if_t<
        std::is_same<decltype(std::to_string(o)), std::string>::value,
        std::string> {
      return std::to_string(o);
    }

    template <typename T>
    inline auto toString(const T &o) -> std::enable_if_t<
        std::is_same<typename std::decay_t<decltype(o.toString())>,
                     std::string>::value,
        std::string> {
      return o.toString();
    }

    template <typename... T>
    inline std::string toString(const std::reference_wrapper<T...> &o) {
      return ::iroha::to_string::toString(o.get());
    }

    template <typename... T>
    inline std::string toString(const std::optional<T...> &o) {
      return detail::toStringDereferenced(o);
    }

    template <typename... T>
    inline std::string toString(const std::unique_ptr<T...> &o) {
      return detail::toStringDereferenced(o);
    }

    template <typename... T>
    inline std::string toString(const std::shared_ptr<T...> &o) {
      return detail::toStringDereferenced(o);
    }

    template <typename T>
    inline std::string toString(const T *o) {
      return detail::toStringDereferenced(o);
    }

    template <typename T>
    inline auto toString(const T &o) -> std::enable_if_t<
        boost::optional_detail::is_optional_related<T>::value,
        std::string> {
      return detail::toStringDereferenced(o);
    }

    /// Print a plain collection.
    template <typename T, typename = decltype(*std::declval<T>().begin())>
    inline std::string toString(const T &c) {
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

      template <>
      inline std::string toStringDereferenced<std::nullopt_t>(
          const std::nullopt_t &) {
        return kNotSet;
      }
    }  // namespace detail
  }    // namespace to_string
}  // namespace iroha

#endif

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_STRING_BUILDER_HPP
#define IROHA_SHARED_MODEL_STRING_BUILDER_HPP

#include <string>

namespace shared_model {
  namespace detail {
    /**
     * A simple string builder class for building pretty looking strings
     */
    class PrettyStringBuilder {
     public:
      /**
       * Initializes new string with a provided name
       * @param name - name to initialize
       */
      PrettyStringBuilder &init(const std::string &name);

      /**
       * Inserts new level marker
       */
      PrettyStringBuilder &insertLevel();

      /**
       * Closes new level marker
       */
      PrettyStringBuilder &removeLevel();

      ///  ----------  Single element undecorated append.  ----------  ///

      PrettyStringBuilder &append(const std::string &o);

      template <typename T>
      auto append(const T &o) -> std::enable_if_t<
          std::is_same<decltype(std::to_string(o)), std::string>::value,
          PrettyStringBuilder &>;

      template <typename T>
      auto append(const T &o) -> std::enable_if_t<
          std::is_same<typename std::decay_t<decltype(o.toString())>,
                       std::string>::value,
          PrettyStringBuilder &>;

      /// Append pointers and optionals.
      template <typename T>
      auto append(const T &o) -> std::enable_if_t<not std::is_array<T>::value,
                                                  decltype(append(*o))>;

      ///  ----------     Augmented appending functions.   ----------  ///

      /// Append a plain collection.
      template <typename T>
      auto append(const T &c) -> decltype(append(*c.begin()));

      /**
       * Appends new field to string as a "name=value" pair
       * @param name - field name to append
       * @param value - field value
       */
      template <typename Value>
      PrettyStringBuilder &appendNamed(const std::string &name,
                                       const Value &value);

      /**
       * Finalizes appending and returns constructed string.
       * @return resulted string
       */
      std::string finalize();

     private:
      void appendPartial(const std::string &);
      void setElementBoundary();
      std::string result_;
      bool need_field_separator_;
      static const std::string beginBlockMarker;
      static const std::string endBlockMarker;
      static const std::string keyValueSeparator;
      static const std::string singleFieldsSeparator;
      static const std::string initSeparator;
      static const std::string spaceSeparator;
    };

    template <typename T>
    auto PrettyStringBuilder::append(const T &o) -> std::enable_if_t<
        std::is_same<decltype(std::to_string(o)), std::string>::value,
        PrettyStringBuilder &> {
      return append(std::to_string(o));
    }

    template <typename T>
    auto PrettyStringBuilder::append(const T &o) -> std::enable_if_t<
        std::is_same<typename std::decay_t<decltype(o.toString())>,
                     std::string>::value,
        PrettyStringBuilder &> {
      return append(o.toString());
    }

    /// Append pointers and optionals.
    template <typename T>
    auto PrettyStringBuilder::append(const T &o)
        -> std::enable_if_t<not std::is_array<T>::value, decltype(append(*o))> {
      if (o) {
        return append(*o);
      } else {
        return append("(not set)");
      }
    }

    ///  ----------     Augmented appending functions.   ----------  ///

    /// Append a plain collection.
    template <typename T>
    auto PrettyStringBuilder::append(const T &c)
        -> decltype(append(*c.begin())) {
      insertLevel();
      for (auto &o : c) {
        append(o);
      }
      removeLevel();
      return *this;
    }

    /**
     * Appends new field to string as a "name=value" pair
     * @param name - field name to append
     * @param value - field value
     */
    template <typename Value>
    PrettyStringBuilder &PrettyStringBuilder::appendNamed(
        const std::string &name, const Value &value) {
      appendPartial(name);
      appendPartial(keyValueSeparator);
      return append(value);
    }

  }  // namespace detail
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_STRING_BUILDER_HPP

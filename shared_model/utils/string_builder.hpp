/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_STRING_BUILDER_HPP
#define IROHA_SHARED_MODEL_STRING_BUILDER_HPP

#include <string>

#include "common/to_string.hpp"

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
      PrettyStringBuilder &append(const T &o) {
        return append(iroha::to_string::toString(o));
      }

      ///  ----------     Augmented appending functions.   ----------  ///

      /**
       * Appends new field to string as a "name=value" pair
       * @param name - field name to append
       * @param value - field value
       */
      template <typename Name, typename Value>
      PrettyStringBuilder &appendNamed(const Name &name, const Value &value) {
        appendPartial(name);
        appendPartial(keyValueSeparator);
        return append(iroha::to_string::toString(value));
      }

      /**
       * Finalizes appending and returns constructed string.
       * @return resulted string
       */
      std::string finalize();

     private:
      std::string result_;
      bool need_field_separator_;
      static const std::string beginBlockMarker;
      static const std::string endBlockMarker;
      static const std::string keyValueSeparator;
      static const std::string singleFieldsSeparator;
      static const std::string initSeparator;
      static const std::string spaceSeparator;

      template <typename T>
      inline void appendPartial(T const &value) {
        if (need_field_separator_) {
          result_.append(singleFieldsSeparator);
          need_field_separator_ = false;
        }
        result_.append(value);
      }
    };
  }  // namespace detail
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_STRING_BUILDER_HPP

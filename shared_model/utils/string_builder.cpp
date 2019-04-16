/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace detail {

    const std::string PrettyStringBuilder::beginBlockMarker = "[";
    const std::string PrettyStringBuilder::endBlockMarker = "]";
    const std::string PrettyStringBuilder::keyValueSeparator = "=";
    const std::string PrettyStringBuilder::singleFieldsSeparator = ",";
    const std::string PrettyStringBuilder::initSeparator = ":";
    const std::string PrettyStringBuilder::spaceSeparator = " ";

    PrettyStringBuilder &PrettyStringBuilder::init(const std::string &name) {
      result_.append(name);
      result_.append(initSeparator);
      result_.append(spaceSeparator);
      result_.append(beginBlockMarker);
      return *this;
    }

    PrettyStringBuilder &PrettyStringBuilder::insertLevel() {
      result_.append(beginBlockMarker);
      return *this;
    }

    PrettyStringBuilder &PrettyStringBuilder::removeLevel() {
      result_.append(endBlockMarker);
      return *this;
    }

    PrettyStringBuilder &PrettyStringBuilder::append(const std::string &name,
                                                     const std::string &value) {
      result_.append(name);
      result_.append(keyValueSeparator);
      result_.append(value);
      result_.append(singleFieldsSeparator);
      result_.append(spaceSeparator);
      return *this;
    }

    PrettyStringBuilder &PrettyStringBuilder::append(const std::string &value) {
      result_.append(value);
      result_.append(spaceSeparator);
      return *this;
    }

    std::string PrettyStringBuilder::finalize() {
      result_.append(endBlockMarker);
      return result_;
    }

  }  // namespace detail
}  // namespace shared_model

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
    const std::string PrettyStringBuilder::singleFieldsSeparator = ", ";
    const std::string PrettyStringBuilder::initSeparator = ":";
    const std::string PrettyStringBuilder::spaceSeparator = " ";

    PrettyStringBuilder &PrettyStringBuilder::init(const std::string &name) {
      result_.append(name);
      result_.append(initSeparator);
      result_.append(spaceSeparator);
      insertLevel();
      return *this;
    }

    PrettyStringBuilder &PrettyStringBuilder::insertLevel() {
      need_field_separator_ = false;
      result_.append(beginBlockMarker);
      return *this;
    }

    PrettyStringBuilder &PrettyStringBuilder::removeLevel() {
      result_.append(endBlockMarker);
      need_field_separator_ = true;
      return *this;
    }

    PrettyStringBuilder &PrettyStringBuilder::append(const std::string &value) {
      appendPartial(value);
      need_field_separator_ = true;
      return *this;
    }

    std::string PrettyStringBuilder::finalize() {
      removeLevel();
      return result_;
    }

  }  // namespace detail
}  // namespace shared_model

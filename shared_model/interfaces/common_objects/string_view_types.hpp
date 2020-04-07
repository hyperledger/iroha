/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_STRING_VIEW_TYPES_HPP
#define IROHA_SHARED_MODEL_STRING_VIEW_TYPES_HPP

#include <string_view>

#include <boost/serialization/strong_typedef.hpp>

namespace shared_model {
  namespace interface {
    namespace types {
      BOOST_STRONG_TYPEDEF(std::string_view, SignedHexStringView)
      BOOST_STRONG_TYPEDEF(std::string_view, PublicKeyHexStringView)
    }  // namespace types
  }    // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_STRING_VIEW_TYPES_HPP

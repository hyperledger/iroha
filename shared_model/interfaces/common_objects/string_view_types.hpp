/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_STRING_VIEW_TYPES_HPP
#define IROHA_SHARED_MODEL_STRING_VIEW_TYPES_HPP

#include <string_view>

#include <boost/serialization/strong_typedef.hpp>
#include "interfaces/common_objects/byte_range.hpp"

namespace shared_model {
  namespace interface {
    namespace types {
      BOOST_STRONG_TYPEDEF(std::string_view, SignedHexStringView)
      BOOST_STRONG_TYPEDEF(ByteRange, SignatureByteRangeView)

      BOOST_STRONG_TYPEDEF(std::string_view, PublicKeyHexStringView)
      BOOST_STRONG_TYPEDEF(ByteRange, PublicKeyByteRangeView)

      template <
          typename Dest,
          typename Source,
          typename Underlying = std::decay_t<decltype(std::declval<Dest>().t)>>
      inline Dest makeStrongView(const Source &str) {
        return Dest{Underlying{
            reinterpret_cast<decltype(std::declval<Underlying>().data())>(
                str.data()),
            str.size()}};
      }
    }  // namespace types
  }    // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_STRING_VIEW_TYPES_HPP

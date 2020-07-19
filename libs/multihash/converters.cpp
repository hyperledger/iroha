/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multihash/converters.hpp"

#include <boost/preprocessor/comparison/equal.hpp>
#include <boost/preprocessor/control/if.hpp>
#include <boost/preprocessor/punctuation/comma.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <boost/preprocessor/tuple/elem.hpp>

namespace iroha::multihash {
  char const *toString(Type type) {
    switch (type) {
#define IROHA_MULTIHASH_MAP_TYPE(_, i, ...)                      \
  case Type::BOOST_PP_TUPLE_ELEM(3, 1, IROHA_MULTIHASH_TYPE(i)): \
    return BOOST_PP_STRINGIZE(                                   \
        BOOST_PP_TUPLE_ELEM(3, 1, IROHA_MULTIHASH_TYPE(i)));
      BOOST_PP_REPEAT(IROHA_MULTIHASH_TYPES_NUMBER, IROHA_MULTIHASH_MAP_TYPE, )
#undef IROHA_MULTIHASH_MAP_TYPE
    }
  }

  std::optional<Type> fromString(std::string_view source) {
#define IROHA_MULTIHASH_MAP_TYPE(_, i, ...)                    \
  if (source.compare(BOOST_PP_STRINGIZE(                       \
          BOOST_PP_TUPLE_ELEM(3, 1, IROHA_MULTIHASH_TYPE(i)))) \
      == 0)                                                    \
    return Type::BOOST_PP_TUPLE_ELEM(3, 1, IROHA_MULTIHASH_TYPE(i));
    BOOST_PP_REPEAT(IROHA_MULTIHASH_TYPES_NUMBER, IROHA_MULTIHASH_MAP_TYPE, )
#undef IROHA_MULTIHASH_MAP_TYPE
    return std::nullopt;
  }

  std::vector<Type> getAllSignatureTypes() {
    return std::vector<Type>{
#define IROHA_MULTIHASH_GET_TYPE(_, i, is_signature)                      \
  BOOST_PP_IF(IROHA_MULTIHASH_TYPE_IS_SIGNATURE(i),                       \
              Type::BOOST_PP_TUPLE_ELEM(3, 1, IROHA_MULTIHASH_TYPE(i)), ) \
  BOOST_PP_COMMA_IF(IROHA_MULTIHASH_TYPE_IS_SIGNATURE(i))
        BOOST_PP_REPEAT(IROHA_MULTIHASH_TYPES_NUMBER,
                        IROHA_MULTIHASH_GET_TYPE, )
#undef IROHA_MULTIHASH_GET_TYPE
    };
  }
}  // namespace iroha::multihash

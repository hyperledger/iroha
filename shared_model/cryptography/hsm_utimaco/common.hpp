/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_HSM_UTIMACO_COMMON_HPP
#define IROHA_CRYPTO_HSM_UTIMACO_COMMON_HPP

#include <memory>
#include <mutex>
#include <optional>

#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/tuple/elem.hpp>
#include <utility>
#include "cryptography/hsm_utimaco/safe_cxi.hpp"
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/type.hpp"

namespace shared_model::crypto::hsm_utimaco {

  inline cxi::ByteArray irohaToCxiBuffer(
      shared_model::interface::types::ByteRange range) {
    static_assert(sizeof(*range.data()) == sizeof(char), "type mismatch");
    return cxi::ByteArray{reinterpret_cast<char const *>(range.data()),
                          static_cast<int>(range.length())};
  }

  inline shared_model::interface::types::ByteRange cxiToIrohaBufferView(
      cxi::ByteArray const &buffer) {
    return shared_model::interface::types::makeByteRange(
        buffer.get(), static_cast<size_t>(buffer.length()));
  }

#define ALGOS_EL0 (Type::ed25519_sha2_224, CXI_MECH_HASH_ALGO_SHA224)
#define ALGOS_EL1 (Type::ed25519_sha2_256, CXI_MECH_HASH_ALGO_SHA256)
#define ALGOS_EL2 (Type::ed25519_sha2_384, CXI_MECH_HASH_ALGO_SHA384)
#define ALGOS_EL3 (Type::ed25519_sha2_512, CXI_MECH_HASH_ALGO_SHA512)
#define ALGOS_EL4 (Type::ed25519_sha3_224, CXI_MECH_HASH_ALGO_SHA3_224)
#define ALGOS_EL5 (Type::ed25519_sha3_256, CXI_MECH_HASH_ALGO_SHA3_256)
#define ALGOS_EL6 (Type::ed25519_sha3_384, CXI_MECH_HASH_ALGO_SHA3_384)
#define ALGOS_EL7 (Type::ed25519_sha3_512, CXI_MECH_HASH_ALGO_SHA3_512)

#define NUM_ALGOS 8

#define SWL(z, i, ...)                         \
  case BOOST_PP_TUPLE_ELEM(2, 0, ALGOS_EL##i): \
    return BOOST_PP_TUPLE_ELEM(2, 1, ALGOS_EL##i);
#define SWR(z, i, ...)                         \
  case BOOST_PP_TUPLE_ELEM(2, 1, ALGOS_EL##i): \
    return BOOST_PP_TUPLE_ELEM(2, 0, ALGOS_EL##i);

#define SW_ALL_LEFT(v) \
  switch (v) { BOOST_PP_REPEAT(NUM_ALGOS, SWL, ) }

#define SW_ALL_RIGHT(v) \
  switch (v) { BOOST_PP_REPEAT(NUM_ALGOS, SWR, ) }

  inline std::optional<iroha::multihash::Type> CxiHashAlgoToMultihashEcdsaType(
      int algo) {
    using iroha::multihash::Type;
    SW_ALL_RIGHT(algo)
    return std::nullopt;
  }

  inline std::optional<int> multihashToCxiHashAlgo(
      iroha::multihash::Type type) {
    using iroha::multihash::Type;
    SW_ALL_LEFT(type)
    return std::nullopt;
  }

#undef SWL
#undef SWR
#undef SW_ALL_LEFT
#undef SW_ALL_RIGHT

}  // namespace shared_model::crypto::hsm_utimaco

#endif

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/pkcs11/algorithm_identifier.hpp"

#include <string_view>

#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/tuple/elem.hpp>
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/type.hpp"

namespace shared_model::crypto::pkcs11 {

// clang-format off
// - iroha::multihash::Type
// - Emsa::name() -> Botan::get_emsa(%s)
// - Public_Key::algo_name() -> Botan::load_public_key(Botan::AlgorithmIdentifier{Botan::OID::from_string(%s), {}})
#define ALGOS_EL0 (Type::kEcdsaSha2_224, "EMSA1(SHA-224)" "Curve25519")
#define ALGOS_EL1 (Type::kEcdsaSha2_256, "EMSA1(SHA-256)" "Curve25519")
#define ALGOS_EL2 (Type::kEcdsaSha2_384, "EMSA1(SHA-384)" "Curve25519")
#define ALGOS_EL3 (Type::kEcdsaSha2_512, "EMSA1(SHA-512)" "Curve25519")
#define ALGOS_EL4 (Type::kEcdsaSha3_224, "EMSA1(SHA-3(224))" "Curve25519")
#define ALGOS_EL5 (Type::kEcdsaSha3_256, "EMSA1(SHA-3(256))" "Curve25519")
#define ALGOS_EL6 (Type::kEcdsaSha3_384, "EMSA1(SHA-3(384))" "Curve25519")
#define ALGOS_EL7 (Type::kEcdsaSha3_512, "EMSA1(SHA-3(512))" "Curve25519")
  // clang-format on

#define NUM_ALGOS 8

  std::optional<iroha::multihash::Type> getMultihashType(
      Botan::EMSA const &emsa, Botan::AlgorithmIdentifier const &alg_id) {
    using iroha::multihash::Type;

    std::string emsa_name = emsa.name();
    std::string algo_name = alg_id.get_oid().to_formatted_string();

    // TODO optimize comparisons
#define SWR(z, i, ...)                                                      \
  if (emsa_name.compare(BOOST_PP_TUPLE_ELEM(2, 1, ALGOS_EL##i)) == 0        \
      and algo_name.compare(BOOST_PP_TUPLE_ELEM(2, 2, ALGOS_EL##i)) == 0) { \
    return BOOST_PP_TUPLE_ELEM(2, 0, ALGOS_EL##i);                          \
  }

    BOOST_PP_REPEAT(NUM_ALGOS, SWR, )
#undef SWR

    return std::nullopt;
  }

  std::optional<AlgorithmIdentifier> getAlgorithmIdentifier(
      iroha::multihash::Type multihash_type) {
    using iroha::multihash::Type;
    AlgorithmIdentifier id;
    id.multihash_type = multihash_type;

#define SWL(z, i, ...)                                                        \
  case BOOST_PP_TUPLE_ELEM(2, 0, ALGOS_EL##i):                                \
    id.alg_id = Botan::AlgorithmIdentifier{                                   \
        Botan::OID::from_string(BOOST_PP_TUPLE_ELEM(2, 1, ALGOS_EL##i)), {}}; \
    id.emsa = Botan::get_emsa(BOOST_PP_TUPLE_ELEM(2, 2, ALGOS_EL##i));        \
    return id;

    switch (multihash_type) { BOOST_PP_REPEAT(NUM_ALGOS, SWL, ) }
#undef SWL

    return std::nullopt;
  }

}  // namespace shared_model::crypto::pkcs11

#endif

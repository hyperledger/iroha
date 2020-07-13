/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/pkcs11/algorithm_identifier.hpp"

#include <memory>
#include <optional>
#include <string_view>

#include <botan/alg_id.h>
#include <botan/emsa.h>
#include <botan/p11.h>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/tuple/elem.hpp>
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/type.hpp"

namespace shared_model::crypto::pkcs11 {

// clang-format off
// - iroha::multihash::Type
// - Emsa::name() -> Botan::get_emsa(%s)
// - Botan::PKCS11::KeyType
#define MULTIHASH_EL0 (Type::kEcdsaSha2_224, "EMSA1(SHA-224)",    KeyType::Ecdsa)
#define MULTIHASH_EL1 (Type::kEcdsaSha2_256, "EMSA1(SHA-256)",    KeyType::Ecdsa)
#define MULTIHASH_EL2 (Type::kEcdsaSha2_384, "EMSA1(SHA-384)",    KeyType::Ecdsa)
#define MULTIHASH_EL3 (Type::kEcdsaSha2_512, "EMSA1(SHA-512)",    KeyType::Ecdsa)
#define MULTIHASH_EL4 (Type::kEcdsaSha3_224, "EMSA1(SHA-3(224))", KeyType::Ecdsa)
#define MULTIHASH_EL5 (Type::kEcdsaSha3_256, "EMSA1(SHA-3(256))", KeyType::Ecdsa)
#define MULTIHASH_EL6 (Type::kEcdsaSha3_384, "EMSA1(SHA-3(384))", KeyType::Ecdsa)
#define MULTIHASH_EL7 (Type::kEcdsaSha3_512, "EMSA1(SHA-3(512))", KeyType::Ecdsa)

#define NUM_MULTIHASH 8

// - Botan::PKCS11::KeyType
// - Public_Key::algo_name()
// - Botan::PKCS11 private key class
// - Botan::PKCS11 public key class
#define KEY_TYPE_EL0 (KeyType::Ecdsa, "ECDSA", PKCS11_EC_PrivateKey, PKCS11_EC_PublicKey)
  // clang-format on

#define NUM_KEY_TYPES 1

  std::optional<char const *> getEmsaName(
      iroha::multihash::Type multihash_type) {
    using iroha::multihash::Type;

#define SW(z, i, ...)                              \
  case BOOST_PP_TUPLE_ELEM(3, 0, MULTIHASH_EL##i): \
    return BOOST_PP_TUPLE_ELEM(3, 1, MULTIHASH_EL##i);

    switch (multihash_type) { BOOST_PP_REPEAT(NUM_MULTIHASH, SW, ) }
#undef SW

    return std::nullopt;
  }

  std::optional<Botan::PKCS11::KeyType> getPkcs11KeyType(
      iroha::multihash::Type multihash_type) {
    using iroha::multihash::Type;

#define SW(z, i, ...)                              \
  case BOOST_PP_TUPLE_ELEM(3, 0, MULTIHASH_EL##i): \
    return BOOST_PP_TUPLE_ELEM(3, 2, MULTIHASH_EL##i);

    switch (multihash_type) { BOOST_PP_REPEAT(NUM_MULTIHASH, SW, ) }
#undef SW

    return std::nullopt;
  }

  std::optional<std::unique_ptr<Botan::Private_Key>> loadPrivateKeyOfType(
      iroha::multihash::Type multihash_type,
      Botan::PKCS11::Session &session,
      Botan::PKCS11::ObjectHandle object) {
    auto opt_pkcs11_key_type = getPkcs11KeyType(multihash_type);
    if (not opt_pkcs11_key_type) {
      return std::nullopt;
    }

    using Botan::PKCS11::KeyType;
#define SW(z, i, ...)                                                   \
  case BOOST_PP_TUPLE_ELEM(4, 0, KEY_TYPE_EL##i):                       \
    return std::make_unique<BOOST_PP_TUPLE_ELEM(4, 3, KEY_TYPE_EL##i)>( \
        session, object);

    switch (opt_pkcs11_key_type.value()) {
      BOOST_PP_REPEAT(NUM_KEY_TYPES, SW, )
    }
#undef SW

    return std::nullopt;
  }

  std::optional<std::unique_ptr<Botan::Public_Key>> makePublicKeyOfType(
      iroha::multihash::Type multihash_type,
      shared_model::interface::types::PublicKeyByteRangeView raw_data) {
    auto opt_pkcs11_key_type = getPkcs11KeyType(multihash_type);
    if (not opt_pkcs11_key_type) {
      return std::nullopt;
    }

    using Botan::PKCS11::KeyType;
    //#define SW(z, i, ...)                                                   \
//  case BOOST_PP_TUPLE_ELEM(4, 0, KEY_TYPE_EL##i):                       \
//    return std::make_unique<BOOST_PP_TUPLE_ELEM(4, 4, KEY_TYPE_EL##i)>( \
//        session, object);
    //
    //    switch (opt_pkcs11_key_type.value()) { BOOST_PP_REPEAT(NUM_KEY_TYPES,
    //    SW, ) }
    //#undef SW

    return std::nullopt;
  }

  inline std::optional<Botan::PKCS11::KeyType> getPkcs11KeyType(
      Botan::AlgorithmIdentifier const &alg_id) {
    std::string const algo_name = alg_id.get_oid().to_formatted_string();

    using Botan::PKCS11::KeyType;
#define SW(z, i, ...)                                                      \
  if (algo_name.compare(BOOST_PP_TUPLE_ELEM(4, 1, KEY_TYPE_EL##i)) == 0) { \
    return BOOST_PP_TUPLE_ELEM(4, 0, KEY_TYPE_EL##i);                      \
  }

    BOOST_PP_REPEAT(NUM_KEY_TYPES, SW, )
#undef SW

    return std::nullopt;
  }

  std::optional<iroha::multihash::Type> getMultihashType(
      Botan::EMSA const &emsa, Botan::AlgorithmIdentifier const &alg_id) {
    auto opt_pkcs11_key_type = getPkcs11KeyType(alg_id);
    if (not opt_pkcs11_key_type) {
      return std::nullopt;
    }

    std::string const emsa_name = emsa.name();

    using Botan::PKCS11::KeyType;
    using iroha::multihash::Type;
#define SW(z, i, ...)                                                   \
  if (opt_pkcs11_key_type.value()                                       \
          == BOOST_PP_TUPLE_ELEM(3, 2, MULTIHASH_EL##i)                 \
      and emsa_name.compare(BOOST_PP_TUPLE_ELEM(3, 1, MULTIHASH_EL##i)) \
          == 0) {                                                       \
    return BOOST_PP_TUPLE_ELEM(2, 0, MULTIHASH_EL##i);                  \
  }

    BOOST_PP_REPEAT(NUM_MULTIHASH, SW, )
#undef SW

    return std::nullopt;
  }

}  // namespace shared_model::crypto::pkcs11

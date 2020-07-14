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

using P11KeyType = Botan::PKCS11::P11KeyType;
using MhType = iroha::multihash::Type;

namespace shared_model::crypto::pkcs11 {
  enum class KeyType {
    kEcdsaSecp256r1,
  };

// clang-format off
// - iroha::multihash::Type
// - Emsa::name() -> Botan::get_emsa(%s)
// - Botan::PKCS11::KeyType
#define MULTIHASH_EL0 (MhType::kEcdsaSecp256r1Sha2_224, "EMSA1(SHA-224)",    KEY_TYPE_EL0)
#define MULTIHASH_EL1 (MhType::kEcdsaSecp256r1Sha2_256, "EMSA1(SHA-256)",    KEY_TYPE_EL0)
#define MULTIHASH_EL2 (MhType::kEcdsaSecp256r1Sha2_384, "EMSA1(SHA-384)",    KEY_TYPE_EL0)
#define MULTIHASH_EL3 (MhType::kEcdsaSecp256r1Sha2_512, "EMSA1(SHA-512)",    KEY_TYPE_EL0)
#define MULTIHASH_EL4 (MhType::kEcdsaSecp256r1Sha3_224, "EMSA1(SHA-3(224))", KEY_TYPE_EL0)
#define MULTIHASH_EL5 (MhType::kEcdsaSecp256r1Sha3_256, "EMSA1(SHA-3(256))", KEY_TYPE_EL0)
#define MULTIHASH_EL6 (MhType::kEcdsaSecp256r1Sha3_384, "EMSA1(SHA-3(384))", KEY_TYPE_EL0)
#define MULTIHASH_EL7 (MhType::kEcdsaSecp256r1Sha3_512, "EMSA1(SHA-3(512))", KEY_TYPE_EL0)

#define NUM_MULTIHASH 8

// - Botan::PKCS11::KeyType
// - Public_Key::algo_name()
// - Botan::PKCS11 private key class
// - Botan::PKCS11 public key class
// - other key-specific values
#define KEY_TYPE_EL0 (P11KeyType::Ec, "ECDSA", PKCS11_EC_PrivateKey, PKCS11_EC_PublicKey, "secp256r1")
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
#define SW(z, i, ...)                              \
  case BOOST_PP_TUPLE_ELEM(3, 0, MULTIHASH_EL##i): \
    return BOOST_PP_TUPLE_ELEM(                    \
        5, 0, BOOST_PP_TUPLE_ELEM(3, 2, MULTIHASH_EL##i));

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

    Botan::PKCS11::ObjectProperties public_key_attrs{
        Botan::PKCS11::ObjectClass::PublicKey};
    public_key_attrs.add_numeric(
        Botan::PKCS11::AttributeType::KeyType,
        static_cast<CK_ATTRIBUTE_TYPE>(opt_pkcs11_key_type.value()));
    public_key_attrs.add_bool(Botan::PKCS11::AttributeType::Token, false);
    public_key_attrs.add_bool(Botan::PKCS11::AttributeType::Private, false);

    if (opt_pkcs11_key_type.value() == P11KeyType::Ec
    public_key_attrs.add_binary(Botan::PKCS11::AttributeType::EcdsaParams,
                                reinterpret_cast<uint8_t const *>(kSecp256r1),
                                sizeof(kSecp256r1));
    public_key_attrs.add_binary(Botan::PKCS11::AttributeType::EcPoint,
                                pubkey_raw);

#define SW(z, i, ...)                                                   \
  case BOOST_PP_TUPLE_ELEM(4, 0, KEY_TYPE_EL##i):                       \
    return std::make_unique<BOOST_PP_TUPLE_ELEM(4, 4, KEY_TYPE_EL##i)>( \
        session, object);

    switch (opt_pkcs11_key_type.value()) {
      BOOST_PP_REPEAT(NUM_KEY_TYPES, SW, ) }
#undef SW

    return std::nullopt;
  }

  inline std::optional<Botan::PKCS11::KeyType> getPkcs11KeyType(
      Botan::AlgorithmIdentifier const &alg_id) {
    std::string const algo_name = alg_id.get_oid().to_formatted_string();

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

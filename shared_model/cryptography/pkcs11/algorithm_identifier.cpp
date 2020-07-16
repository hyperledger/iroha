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
#include <botan/p11_ecdsa.h>
#include <botan/p11_object.h>
#include <botan/pkcs11t.h>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/tuple/elem.hpp>
#include <utility>
#include <vector>
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/type.hpp"

using P11KeyType = Botan::PKCS11::KeyType;
using MhType = iroha::multihash::Type;

namespace shared_model::crypto::pkcs11 {

// clang-format off
// - iroha::multihash::Type
// - Emsa::name() -> Botan::get_emsa(%s)
// - KEY_TYPE_EL#
#define MULTIHASH_EL0  (MhType::ecdsa_secp256r1_sha2_224, "EMSA1(SHA-224)",    0)
#define MULTIHASH_EL1  (MhType::ecdsa_secp256r1_sha2_256, "EMSA1(SHA-256)",    0)
#define MULTIHASH_EL2  (MhType::ecdsa_secp256r1_sha2_384, "EMSA1(SHA-384)",    0)
#define MULTIHASH_EL3  (MhType::ecdsa_secp256r1_sha2_512, "EMSA1(SHA-512)",    0)
#define MULTIHASH_EL4  (MhType::ecdsa_secp256r1_sha3_224, "EMSA1(SHA-3(224))", 0)
#define MULTIHASH_EL5  (MhType::ecdsa_secp256r1_sha3_256, "EMSA1(SHA-3(256))", 0)
#define MULTIHASH_EL6  (MhType::ecdsa_secp256r1_sha3_384, "EMSA1(SHA-3(384))", 0)
#define MULTIHASH_EL7  (MhType::ecdsa_secp256r1_sha3_512, "EMSA1(SHA-3(512))", 0)

#define MULTIHASH_EL8  (MhType::ecdsa_secp384r1_sha2_224, "EMSA1(SHA-224)",    1)
#define MULTIHASH_EL9  (MhType::ecdsa_secp384r1_sha2_256, "EMSA1(SHA-256)",    1)
#define MULTIHASH_EL10 (MhType::ecdsa_secp384r1_sha2_384, "EMSA1(SHA-384)",    1)
#define MULTIHASH_EL11 (MhType::ecdsa_secp384r1_sha2_512, "EMSA1(SHA-512)",    1)
#define MULTIHASH_EL12 (MhType::ecdsa_secp384r1_sha3_224, "EMSA1(SHA-3(224))", 1)
#define MULTIHASH_EL13 (MhType::ecdsa_secp384r1_sha3_256, "EMSA1(SHA-3(256))", 1)
#define MULTIHASH_EL14 (MhType::ecdsa_secp384r1_sha3_384, "EMSA1(SHA-3(384))", 1)
#define MULTIHASH_EL15 (MhType::ecdsa_secp384r1_sha3_512, "EMSA1(SHA-3(512))", 1)

#define NUM_MULTIHASH 16

// - Botan::PKCS11::KeyType
// - Botan::PKCS11 private key class
// - Botan::PKCS11 public key creator function (session, multihash_type, raw_pubkey)
#define KEY_TYPE_EL0 (P11KeyType::Ec, Botan::PKCS11::PKCS11_ECDSA_PrivateKey, createEcPublicKey)
#define KEY_TYPE_EL1 (P11KeyType::Ec, Botan::PKCS11::PKCS11_ECDSA_PrivateKey, createEcPublicKey)

// - Botan::PKCS11::AttributeType
// - Attribute value, currently only binary data supported
#define ATTRS_FOR_KEY_TYPE_EL0 ((Botan::PKCS11::AttributeType::EcdsaParams, "secp256r1"))
#define ATTRS_FOR_KEY_TYPE_EL1 ((Botan::PKCS11::AttributeType::EcdsaParams, "secp384r1"))

#define NUM_KEY_TYPES 1

  // clang-format on

#define KEY_TYPE_FOR_MULTIHASH_EL(i) \
  BOOST_PP_TUPLE_ELEM(3, 2, BOOST_PP_CAT(MULTIHASH_EL, i))
#define KEY_TYPE_DATA_FOR_MULTIHASH_EL(mh_i, key_i) \
  BOOST_PP_TUPLE_ELEM(                              \
      3, key_i, BOOST_PP_CAT(KEY_TYPE_EL, KEY_TYPE_FOR_MULTIHASH_EL(mh_i)))

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
    return KEY_TYPE_DATA_FOR_MULTIHASH_EL(i, 0);

    switch (multihash_type) { BOOST_PP_REPEAT(NUM_MULTIHASH, SW, ) }
#undef SW

    return std::nullopt;
  }

  inline void setPkcs11KeyAttrs(iroha::multihash::Type multihash_type,
                                Botan::PKCS11::AttributeContainer &dest) {
#define SET_BINARY_ATTR_FROM_LITERAL(r, props, attr)                      \
  props.add_binary(                                                       \
      BOOST_PP_TUPLE_ELEM(2, 0, attr),                                    \
      reinterpret_cast<uint8_t const *>(BOOST_PP_TUPLE_ELEM(2, 1, attr)), \
      sizeof(BOOST_PP_TUPLE_ELEM(2, 1, attr)));

#define SET_ATTRS_FOR_KEY_TYPE(key_type, props)       \
  BOOST_PP_SEQ_FOR_EACH(SET_BINARY_ATTR_FROM_LITERAL, \
                        props,                        \
                        BOOST_PP_CAT(ATTRS_FOR_KEY_TYPE_EL, key_type))

#define SW(z, i, ...)                                                        \
  case BOOST_PP_TUPLE_ELEM(3, 0, MULTIHASH_EL##i):                           \
    SET_ATTRS_FOR_KEY_TYPE(BOOST_PP_TUPLE_ELEM(3, 2, MULTIHASH_EL##i), dest) \
    break;

    switch (multihash_type) { BOOST_PP_REPEAT(NUM_MULTIHASH, SW, ) }
#undef SW
#undef SET_ATTRS_FOR_KEY_TYPE
#undef SET_BINARY_ATTR_FROM_LITERAL
  }

  std::optional<Botan::PKCS11::ObjectProperties> getPkcs11KeyProperties(
      Botan::PKCS11::ObjectClass key_type,
      iroha::multihash::Type multihash_type) {
    auto opt_pkcs11_key_type = pkcs11::getPkcs11KeyType(multihash_type);
    if (not opt_pkcs11_key_type) {
      return std::nullopt;
    }

    Botan::PKCS11::ObjectProperties props{
        Botan::PKCS11::ObjectClass::PrivateKey};

    props.add_numeric(Botan::PKCS11::AttributeType::KeyType,
                      static_cast<CK_KEY_TYPE>(opt_pkcs11_key_type.value()));

    setPkcs11KeyAttrs(multihash_type, props);

    return props;
  }

  std::optional<Botan::PKCS11::ObjectProperties> getPkcs11PrivateKeyProperties(
      iroha::multihash::Type multihash_type) {
    return getPkcs11KeyProperties(Botan::PKCS11::ObjectClass::PrivateKey,
                                  multihash_type);
  }

  std::optional<std::unique_ptr<Botan::Private_Key>> loadPrivateKeyOfType(
      iroha::multihash::Type multihash_type,
      Botan::PKCS11::Session &session,
      Botan::PKCS11::ObjectHandle object_handle) {
#define SW(z, i, ...)                                              \
  case BOOST_PP_TUPLE_ELEM(3, 0, MULTIHASH_EL##i):                 \
    return std::make_unique<KEY_TYPE_DATA_FOR_MULTIHASH_EL(i, 1)>( \
        session, object_handle);

    switch (multihash_type) { BOOST_PP_REPEAT(NUM_MULTIHASH, SW, ) }
#undef SW

    return std::nullopt;
  }

  std::unique_ptr<Botan::Public_Key> createEcPublicKey(
      Botan::PKCS11::Session &session,
      iroha::multihash::Type multihash_type,
      shared_model::interface::types::PublicKeyByteRangeView pubkey_raw) {
    Botan::PKCS11::ObjectProperties public_key_attrs{
        Botan::PKCS11::ObjectClass::PublicKey};
    public_key_attrs.add_numeric(
        Botan::PKCS11::AttributeType::KeyType,
        static_cast<CK_ATTRIBUTE_TYPE>(Botan::PKCS11::KeyType::Ec));
    public_key_attrs.add_bool(Botan::PKCS11::AttributeType::Token, false);
    public_key_attrs.add_bool(Botan::PKCS11::AttributeType::Private, false);
    setPkcs11KeyAttrs(multihash_type, public_key_attrs);
    interface::types::ByteRange pubkey_raw_br;
    public_key_attrs.add_binary(
        Botan::PKCS11::AttributeType::EcPoint,
        reinterpret_cast<uint8_t const *>(pubkey_raw_br.data()),
        pubkey_raw_br.size());
    Botan::PKCS11::Object pkcs11_pubkey_obj{session, public_key_attrs};
    return std::make_unique<Botan::PKCS11::PKCS11_ECDSA_PublicKey>(
        session, pkcs11_pubkey_obj.handle());
  }

  std::optional<std::unique_ptr<Botan::Public_Key>> createPublicKeyOfType(
      iroha::multihash::Type multihash_type,
      Botan::PKCS11::Session &session,
      shared_model::interface::types::PublicKeyByteRangeView pubkey_raw) {
#define SW(z, i, ...)                              \
  case BOOST_PP_TUPLE_ELEM(3, 0, MULTIHASH_EL##i): \
    return KEY_TYPE_DATA_FOR_MULTIHASH_EL(i, 2)(   \
        session, multihash_type, pubkey_raw);

    switch (multihash_type) { BOOST_PP_REPEAT(NUM_MULTIHASH, SW, ) }
#undef SW

    return std::nullopt;
  }

  std::optional<std::pair<std::unique_ptr<Botan::Private_Key>,
                          std::unique_ptr<Botan::Public_Key>>>
  generateKeypairOfType(OperationContext &op_ctx,
                        iroha::multihash::Type multihash_type) {
    auto priv_key_props = getPkcs11PrivateKeyProperties(multihash_type);
    auto pub_key_props = getPkcs11KeyProperties(
        Botan::PKCS11::ObjectClass::PublicKey, multihash_type);

    if (not priv_key_props or not pub_key_props) {
      return std::nullopt;
    }

#define SET_KEY_PROPS_BOOL(key, val)                                \
  priv_key_props->add_bool(Botan::PKCS11::AttributeType::key, val); \
  pub_key_props->add_bool(Botan::PKCS11::AttributeType::key, val);

    SET_KEY_PROPS_BOOL(Token, false);
    SET_KEY_PROPS_BOOL(Private, false);
    SET_KEY_PROPS_BOOL(Sign, true);
    SET_KEY_PROPS_BOOL(Verify, true);
#undef SET_KEY_PROPS_BOOL

    Botan::PKCS11::ObjectHandle pub_key_handle = CK_INVALID_HANDLE;
    Botan::PKCS11::ObjectHandle priv_key_handle = CK_INVALID_HANDLE;
    Botan::PKCS11::Mechanism mechanism = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
    op_ctx.module->C_GenerateKeyPair(op_ctx.session.handle(),
                                     &mechanism,
                                     const_cast<Botan::PKCS11::Attribute *>(
                                         pub_key_props->attributes().data()),
                                     pub_key_props->attributes().size(),
                                     const_cast<Botan::PKCS11::Attribute *>(
                                         priv_key_props->attributes().data()),
                                     priv_key_props->attributes().size(),
                                     &pub_key_handle,
                                     &priv_key_handle);

    if (pub_key_handle != CK_INVALID_HANDLE
        and priv_key_handle != CK_INVALID_HANDLE) {
      return std::make_pair(
          std::make_unique<Botan::PKCS11::PKCS11_ECDSA_PrivateKey>(
              op_ctx.session, pub_key_handle),
          std::make_unique<Botan::PKCS11::PKCS11_ECDSA_PublicKey>(
              op_ctx.session, pub_key_handle));
    }

    return std::nullopt;
  }

  std::vector<iroha::multihash::Type> getAllMultihashTypes() {
    return std::vector<iroha::multihash::Type>{
#define GET_MH_TYPE(_, i, ...) BOOST_PP_TUPLE_ELEM(3, 0, MULTIHASH_EL##i),
        BOOST_PP_REPEAT(NUM_MULTIHASH, GET_MH_TYPE, )
#undef GET_MH_TYPE
    };
  }

}  // namespace shared_model::crypto::pkcs11

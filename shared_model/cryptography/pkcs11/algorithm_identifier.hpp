/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_PKCS11_ALGORITHM_IDENTIFIER_HPP
#define IROHA_CRYPTO_PKCS11_ALGORITHM_IDENTIFIER_HPP

#include <memory>
#include <optional>

//#include <botan/emsa.h>
#include <botan/p11.h>
//#include <botan/pk_keys.h>
//#include "cryptography/pkcs11/signer.hpp"
#include "cryptography/pkcs11/signer.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "multihash/type.hpp"

namespace Botan {
  class Private_Key;
  class Public_Key;

  namespace PKCS11 {
    class Session;
  }
}  // namespace Botan

namespace shared_model::crypto::pkcs11 {

  /*
  struct AlgorithmIdentifier {
    iroha::multihash::Type multihash_type;
    std::function<std::unique_ptr<Botan::Public_Key>(
        shared_model::interface::types::ByteRange)>
        pubkey_factory;
    std::string emsa_name;
  };
  */

  std::optional<char const *> getEmsaName(
      iroha::multihash::Type multihash_type);

  std::optional<Botan::PKCS11::KeyType> getPkcs11KeyType(
      iroha::multihash::Type multihash_type);

  std::optional<std::unique_ptr<Botan::Private_Key>> loadPrivateKeyOfType(
      iroha::multihash::Type multihash_type,
      Botan::PKCS11::Session &session,
      Botan::PKCS11::ObjectHandle object);

  std::optional<std::unique_ptr<Botan::Public_Key>> makePublicKeyOfType(
      iroha::multihash::Type multihash_type,
      shared_model::interface::types::PublicKeyByteRangeView raw_data);

  std::optional<iroha::multihash::Type> getMultihashType(
      Botan::PKCS11::MechanismType mech_type);

}  // namespace shared_model::crypto::pkcs11

#endif

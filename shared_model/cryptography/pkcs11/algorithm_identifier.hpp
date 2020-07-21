/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_PKCS11_ALGORITHM_IDENTIFIER_HPP
#define IROHA_CRYPTO_PKCS11_ALGORITHM_IDENTIFIER_HPP

#include <memory>
#include <optional>
#include <vector>

//#include <botan/emsa.h>
#include <botan/p11.h>
//#include <botan/p11_object.h>
//#include <botan/pk_keys.h>
//#include "cryptography/pkcs11/signer.hpp"
#include "cryptography/pkcs11/signer.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "multihash/type.hpp"

namespace Botan {
  class Private_Key;
  class Public_Key;

  namespace PKCS11 {
    class ObjectProperties;
    class Session;
  }  // namespace PKCS11
}  // namespace Botan

namespace shared_model::crypto::pkcs11 {

  std::optional<char const *> getEmsaName(
      iroha::multihash::Type multihash_type);

  std::optional<Botan::PKCS11::KeyType> getPkcs11KeyType(
      iroha::multihash::Type multihash_type);

  std::optional<Botan::PKCS11::ObjectProperties> getPkcs11KeyProperties(
      Botan::PKCS11::ObjectClass key_type,
      iroha::multihash::Type multihash_type);

  std::optional<Botan::PKCS11::ObjectProperties> getPkcs11PrivateKeyProperties(
      iroha::multihash::Type multihash_type);

  std::optional<std::unique_ptr<Botan::Private_Key>> loadPrivateKeyOfType(
      iroha::multihash::Type multihash_type,
      Botan::PKCS11::Session &session,
      Botan::PKCS11::ObjectHandle object_handle);

  std::optional<std::unique_ptr<Botan::Public_Key>> loadPublicKeyOfType(
      iroha::multihash::Type multihash_type,
      Botan::PKCS11::Session &session,
      Botan::PKCS11::ObjectHandle object_handle);

  std::optional<std::unique_ptr<Botan::Public_Key>> createPublicKeyOfType(
      iroha::multihash::Type multihash_type,
      Botan::PKCS11::Session &session,
      shared_model::interface::types::PublicKeyByteRangeView raw_data);

  // generates temporary objects, lost after session closed
  std::optional<std::pair<std::unique_ptr<Botan::Private_Key>,
                          std::unique_ptr<Botan::Public_Key>>>
  generateKeypairOfType(OperationContext &op_ctx,
                        iroha::multihash::Type multihash_type);

  std::vector<iroha::multihash::Type> getAllMultihashTypes();

}  // namespace shared_model::crypto::pkcs11

#endif

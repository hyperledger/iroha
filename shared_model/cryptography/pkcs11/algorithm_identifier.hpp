/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_PKCS11_ALGORITHM_IDENTIFIER_HPP
#define IROHA_CRYPTO_PKCS11_ALGORITHM_IDENTIFIER_HPP

#include <memory>
#include <optional>

#include <botan/alg_id.h>
#include <botan/emsa.h>
#include "multihash/type.hpp"

namespace shared_model::crypto::pkcs11 {

  struct AlgorithmIdentifier {
    iroha::multihash::Type multihash_type;
    std::unique_ptr<Botan::EMSA> emsa;
    Botan::AlgorithmIdentifier alg_id;
  };

  std::optional<AlgorithmIdentifier> getAlgorithmIdentifier(
      iroha::multihash::Type multihash_type);

  std::optional<iroha::multihash::Type> getMultihashType(
      Botan::EMSA const &emsa, Botan::AlgorithmIdentifier const &alg_id);

}  // namespace shared_model::crypto::pkcs11

#endif

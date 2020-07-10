/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_SIGNER_PKCS11_HPP
#define IROHA_CRYPTO_SIGNER_PKCS11_HPP

#include "cryptography/crypto_provider/crypto_signer.hpp"

#include <memory>

#include "multihash/type.hpp"

namespace Botan {
  class EMSA;
  class PK_Signer;
  class Private_Key;
  class RandomNumberGenerator;
}  // namespace Botan

namespace shared_model::crypto::pkcs11 {
  struct Data;

  /**
   * Signer - wrapper for Utimaco HSM crypto singing
   */
  class Signer : public CryptoSigner {
   public:
    Signer(std::shared_ptr<Data> data,
           std::unique_ptr<Botan::Private_Key> private_key,
           Botan::EMSA const &emsa,
           iroha::multihash::Type multihash_type);

    virtual ~Signer();

    std::string sign(const shared_model::crypto::Blob &blob) const override;

    shared_model::interface::types::PublicKeyHexStringView publicKey()
        const override;

    std::string toString() const override;

   private:
    std::shared_ptr<Data> data_;
    std::unique_ptr<Botan::Private_Key> private_key_;
    std::unique_ptr<Botan::RandomNumberGenerator> rng_;
    std::unique_ptr<Botan::PK_Signer> signer_;
    std::string public_key_;
    std::string description_;
  };
}  // namespace shared_model::crypto::pkcs11

#endif

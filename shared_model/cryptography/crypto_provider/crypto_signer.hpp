/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_SIGNER_HPP
#define IROHA_CRYPTO_SIGNER_HPP

#include "cryptography/blob.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/keypair.hpp"
#include "cryptography/signed.hpp"
#include "multihash/multihash.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * CryptoSigner - wrapper for generalization signing for different
     * cryptographic algorithms
     * @tparam Algorithm - cryptographic algorithm for singing
     */
    class CryptoSigner {
     public:
      /**
       * Generate signature for target data
       * @param blob - data for signing
       * @param keypair - (public, private) keys for signing
       * @return hex signature
       */
      static std::string sign(const Blob &blob, const Keypair &keypair) {
        if (keypair.publicKey().blob().size()
            == shared_model::crypto::CryptoProviderEd25519Sha3::
                   kPublicKeyLength) {
          return CryptoProviderEd25519Sha3::sign(blob, keypair);
        } else if (auto opt_multihash = iroha::expected::resultToOptionalValue(
                       libp2p::multi::Multihash::createFromBuffer(
                           kagome::common::Buffer{
                               keypair.publicKey().blob()}))) {
          if (opt_multihash->getType() == libp2p::multi::HashType::ed25519pub
              && opt_multihash->getHash().size()
                  == shared_model::crypto::CryptoProviderEd25519Ursa::
                         kPublicKeyLength) {
            return CryptoProviderEd25519Ursa::sign(blob, keypair);
          }
        }
        return Signed{""};
      }

      /// close constructor for forbidding instantiation
      CryptoSigner() = delete;
    };
  }  // namespace crypto
}  // namespace shared_model
#endif  // IROHA_CRYPTO_SIGNER_HPP

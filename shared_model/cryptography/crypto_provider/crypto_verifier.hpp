/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_VERIFIER_HPP
#define IROHA_CRYPTO_VERIFIER_HPP

#include <functional>
#include <map>
#include <memory>
#include <vector>

#include "common/result_fwd.hpp"
#include "cryptography/crypto_provider/crypto_verifier_multihash.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "multihash/type.hpp"

namespace shared_model {
  namespace crypto {
    class Blob;

    /**
     * CryptoVerifier - adapter for generalization verification of cryptographic
     * signatures
     * @tparam Algorithm - cryptographic algorithm for verification
     */
    class CryptoVerifier {
     public:
      /**
       * Verify signature attached to source data
       * @param signedData - cryptographic signature
       * @param source - data that was signed
       * @param pubKey - public key of signatory
       * @return a result of void if signature is correct or error message
       * otherwise or if verification could not be completed
       */
      iroha::expected::Result<void, std::string> verify(
          shared_model::interface::types::SignedHexStringView signature,
          const Blob &source,
          shared_model::interface::types::PublicKeyHexStringView public_key)
          const;

      void addSpecificVerifier(
          std::unique_ptr<CryptoVerifierMultihash> verifier);

      // TODO get from specific verifiers
      enum { kMaxPublicKeySize = 68 };
      enum { kMaxSignatureSize = 68 };

     private:
      std::vector<std::unique_ptr<CryptoVerifierMultihash>> specific_verifiers_;
      std::map<iroha::multihash::Type,
               std::reference_wrapper<CryptoVerifierMultihash>>
          specific_verifiers_by_type_;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_CRYPTO_VERIFIER_HPP

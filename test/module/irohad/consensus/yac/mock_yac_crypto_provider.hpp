/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_CRYPTO_PROVIDER_HPP
#define IROHA_MOCK_YAC_CRYPTO_PROVIDER_HPP

#include <gmock/gmock.h>

#include "backend/plain/signature.hpp"
#include "consensus/yac/yac_crypto_provider.hpp"
#include "framework/crypto_dummies.hpp"
#include "framework/stateless_valid_field_helpers.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      /**
       * Creates test signature with empty signed data, and provided pubkey
       * @param pub_key - public key to put in the signature
       * @return new signature
       */
      inline std::shared_ptr<shared_model::interface::Signature> createSig(
          const std::string &pub_key = "7EC7",
          const std::string &signature = "516A") {
        return std::make_shared<shared_model::plain::Signature>(signature,
                                                                pub_key);
      }

      class MockYacCryptoProvider : public YacCryptoProvider {
       public:
        MOCK_METHOD1(verify, bool(const std::vector<VoteMessage> &));

        VoteMessage getVote(YacHash hash) override {
          return getVote(hash, public_key_);
        }

        VoteMessage getVote(YacHash hash, const std::string &pub_key) {
          VoteMessage vote;
          vote.hash = std::move(hash);
          vote.signature = createSig(pub_key);
          return vote;
        }

        MockYacCryptoProvider() = default;

        MockYacCryptoProvider(std::string public_key)
            : public_key_(public_key) {}

        MockYacCryptoProvider(shared_model::crypto::PublicKey public_key)
            : MockYacCryptoProvider(public_key.hex()) {}

        std::string public_key_{""};
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_MOCK_YAC_CRYPTO_PROVIDER_HPP

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_CRYPTO_PROVIDER_HPP
#define IROHA_MOCK_YAC_CRYPTO_PROVIDER_HPP

#include <gmock/gmock.h>

#include "backend/plain/signature.hpp"
#include "consensus/yac/vote_message.hpp"
#include "consensus/yac/yac_crypto_provider.hpp"
#include "framework/stateless_valid_field_helpers.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
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
          shared_model::interface::types::PublicKeyHexStringView pub_key =
              shared_model::interface::types::PublicKeyHexStringView{
                  std::string_view{"7EC7"}},
          shared_model::interface::types::SignedHexStringView signature =
              shared_model::interface::types::SignedHexStringView{
                  std::string_view{"516A"}}) {
        return std::make_shared<shared_model::plain::Signature>(signature,
                                                                pub_key);
      }

      class MockYacCryptoProvider : public YacCryptoProvider {
       public:
        MOCK_METHOD1(verify, bool(const std::vector<VoteMessage> &));

        VoteMessage getVote(YacHash hash) override {
          return getVote(hash,
                         shared_model::interface::types::PublicKeyHexStringView{
                             public_key_});
        }

        VoteMessage getVote(
            YacHash hash,
            shared_model::interface::types::PublicKeyHexStringView pub_key) {
          VoteMessage vote;
          vote.hash = std::move(hash);
          vote.signature = createSig(pub_key);
          return vote;
        }

        MockYacCryptoProvider() = default;

        MockYacCryptoProvider(
            shared_model::interface::types::PublicKeyHexStringView public_key)
            : public_key_(public_key) {}

        std::string public_key_{""};
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_MOCK_YAC_CRYPTO_PROVIDER_HPP

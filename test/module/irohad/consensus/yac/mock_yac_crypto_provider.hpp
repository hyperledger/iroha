/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_CRYPTO_PROVIDER_HPP
#define IROHA_MOCK_YAC_CRYPTO_PROVIDER_HPP

#include <gmock/gmock.h>

#include "consensus/yac/yac_crypto_provider.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/crypto_dummies.hpp"
#include "framework/stateless_valid_field_helpers.hpp"
#include "module/shared_model/interface_mocks.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      // TODO 15.03.2019 mboldyrev IR-402
      // fix the tests that impose requirements on mock public key format
      std::string padPubKeyString(const std::string &str) {
        using shared_model::crypto::DefaultCryptoAlgorithmType;
        assert(str.size() <= DefaultCryptoAlgorithmType::kPublicKeyLength);
        std::string padded(DefaultCryptoAlgorithmType::kPublicKeyLength, '0');
        std::copy(str.begin(), str.end(), padded.begin());
        return padded;
      }

      /**
       * Creates test signature with empty signed data, and provided pubkey
       * @param pub_key - public key to put in the signature
       * @return new signature
       */
      std::shared_ptr<shared_model::interface::Signature> createSig(
          shared_model::crypto::PublicKey pub_key) {
        auto sig = std::make_shared<MockSignature>();
        EXPECT_CALL(*sig, publicKey())
            .WillRepeatedly(::testing::ReturnRefOfCopy(std::move(pub_key)));
        EXPECT_CALL(*sig, signedData())
            .WillRepeatedly(
                ::testing::ReturnRefOfCopy(iroha::createSignedPadded()));

        return sig;
      }

      /**
       * Creates test signature with empty signed data, and provided pubkey
       * @param pub_key - public key to put in the signature
       * @return new signature
       */
      std::shared_ptr<shared_model::interface::Signature> createSig(
          const std::string &pub_key) {
        return createSig(shared_model::crypto::PublicKey{
            shared_model::crypto::Blob::fromBinaryString(
                padPubKeyString(pub_key))});
      }

      class MockYacCryptoProvider : public YacCryptoProvider {
       public:
        MOCK_METHOD1(verify, bool(const std::vector<VoteMessage> &));

        VoteMessage getVote(YacHash hash) override {
          VoteMessage vote;
          vote.hash = std::move(hash);
          vote.signature = createSig(public_key_);
          return vote;
        }

        VoteMessage getVote(YacHash hash, std::string pub_key) {
          VoteMessage vote;
          vote.hash = std::move(hash);
          vote.signature = createSig(std::move(pub_key));
          return vote;
        }

        MockYacCryptoProvider() = default;

        MockYacCryptoProvider(shared_model::crypto::PublicKey public_key)
            : public_key_(std::move(public_key)) {}

        MockYacCryptoProvider(const MockYacCryptoProvider &) {}

        MockYacCryptoProvider &operator=(const MockYacCryptoProvider &) {
          return *this;
        }

        shared_model::crypto::PublicKey public_key_{
            shared_model::crypto::Blob::fromBinaryString("")};
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_MOCK_YAC_CRYPTO_PROVIDER_HPP

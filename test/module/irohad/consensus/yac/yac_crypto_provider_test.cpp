/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_crypto_provider_impl.hpp"

#include <gtest/gtest.h>

#include "consensus/yac/outcome_messages.hpp"
#include "framework/test_crypto_verifier.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "module/shared_model/cryptography/make_default_crypto_signer.hpp"
#include "module/shared_model/interface_mocks.hpp"

using ::testing::_;
using ::testing::Invoke;
using ::testing::ReturnRefOfCopy;
using namespace shared_model::interface::types;

const auto pubkey = std::string(32, '0');
const auto signed_data = std::string(64, '1');

namespace iroha {
  namespace consensus {
    namespace yac {

      // TODO use mock crypto verifier
      class YacCryptoProviderTest : public ::testing::Test {
       public:
        void SetUp() override {
          using namespace shared_model::crypto;
          crypto_provider = std::make_shared<CryptoProviderImpl>(
              shared_model::crypto::CryptoProvider{
                  makeDefaultSigner(), iroha::test::getTestCryptoVerifier()},
              getTestLogger("CryptoProviderImpl"));
        }

        std::unique_ptr<shared_model::interface::Signature> makeSignature(
            PublicKeyHexStringView public_key,
            SignedHexStringView signed_value) {
          auto sig = std::make_unique<MockSignature>();
          EXPECT_CALL(*sig, publicKey())
              .WillRepeatedly(ReturnRefOfCopy(std::string{public_key}));
          EXPECT_CALL(*sig, signedData())
              .WillRepeatedly(ReturnRefOfCopy(std::string{signed_value}));
          return sig;
        }

        std::unique_ptr<shared_model::interface::Signature> makeSignature() {
          return makeSignature(PublicKeyHexStringView{pubkey},
                               SignedHexStringView{signed_data});
        }

        std::shared_ptr<CryptoProviderImpl> crypto_provider;
      };

      TEST_F(YacCryptoProviderTest, ValidWhenSameMessage) {
        YacHash hash(Round{1, 1}, "1", "1");

        hash.block_signature = makeSignature();

        auto vote = crypto_provider->getVote(hash);

        ASSERT_TRUE(crypto_provider->verify({vote}));
      }

      TEST_F(YacCryptoProviderTest, InvalidWhenMessageChanged) {
        YacHash hash(Round{1, 1}, "1", "1");

        hash.block_signature = makeSignature();

        auto vote = crypto_provider->getVote(hash);

        vote.hash.vote_hashes.block_hash = "hash changed";

        ASSERT_FALSE(crypto_provider->verify({vote}));
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

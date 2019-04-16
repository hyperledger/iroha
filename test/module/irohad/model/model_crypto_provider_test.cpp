/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "common/blob.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "model/generators/query_generator.hpp"
#include "model/generators/transaction_generator.hpp"
#include "model/model_crypto_provider_impl.hpp"

namespace iroha {
  namespace model {
    class CryptoProviderTest : public ::testing::Test {
     public:
      CryptoProviderTest() : provider(create_keypair()) {}

      ModelCryptoProviderImpl provider;
    };

    TEST_F(CryptoProviderTest, SignAndVerifyTransaction) {
      auto model_tx =
          generators::TransactionGenerator().generateTransaction("test", {});

      provider.sign(model_tx);
      ASSERT_TRUE(provider.verify(model_tx));

      // now modify transaction's meta, so verify should fail
      model_tx.creator_account_id = "test1";
      ASSERT_FALSE(provider.verify(model_tx));
    }

    TEST_F(CryptoProviderTest, SignAndVerifyQuery) {
      auto query =
          generators::QueryGenerator().generateGetAccount(0, "test", 0, "test");

      provider.sign(*query);
      ASSERT_TRUE(provider.verify(*query));

      // modify account id, verification should fail
      query->account_id = "kappa";
      ASSERT_FALSE(provider.verify(*query));
    }

    TEST_F(CryptoProviderTest, SameQueryHashAfterSign) {
      auto query =
          iroha::model::generators::QueryGenerator().generateGetAccount(
              0, "test", 0, "test");

      auto hash = iroha::hash(*query);
      provider.sign(*query);

      auto hash_signed = iroha::hash(*query);
      ASSERT_EQ(hash_signed, hash);
    }
  }  // namespace model
}  // namespace iroha

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "module/shared_model/builders/protobuf/block.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace shared_model::proto;

/**
 * @given BlockBuilder
 * @when Block with transactions is built using given BlockBuilder
 * @then no exception is thrown
 */
TEST(BlockBuilderTest, BlockWithTransactions) {
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(TestUnsignedTransactionBuilder()
                    .createdTime(iroha::time::now())
                    .creatorAccountId("admin@test")
                    .quorum(1)
                    .addAssetQuantity("coin#test", "1.0")
                    .build()
                    .signAndAddSignature(
                        shared_model::crypto::DefaultCryptoAlgorithmType::
                            generateKeypair())
                    .finish());

  ASSERT_NO_THROW(
      BlockBuilder()
          .createdTime(iroha::time::now())
          .prevHash(shared_model::crypto::Hash(std::string(
              shared_model::crypto::DefaultCryptoAlgorithmType::kHashLength,
              '0')))
          .height(1)
          .transactions(txs)
          .build());
}

/**
 * @given BlockBuilder
 * @when Block with no transactions is built using given BlockBuilder
 * @then exception is thrown
 */
// TODO IR-1295 10.05.18 Remove disabled when 1295 is
// implemented
TEST(BlockBuilderTest, DISABLED_BlockWithNoTransactions) {
  ASSERT_ANY_THROW(
      BlockBuilder()
          .createdTime(iroha::time::now())
          .prevHash(shared_model::crypto::Hash(std::string(
              shared_model::crypto::DefaultCryptoAlgorithmType::kHashLength,
              '0')))
          .height(1)
          .transactions(std::vector<shared_model::proto::Transaction>())
          .build());
}

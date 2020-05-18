/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_sequence_factory.hpp"

#include <gmock/gmock.h>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/irange.hpp>
#include "framework/batch_helper.hpp"
#include "framework/result_fixture.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace shared_model;
using ::testing::_;
using ::testing::A;
using ::testing::Return;
using ::testing::Test;

class TransactionSequenceTestFixture : public ::testing::Test {
 public:
  TransactionSequenceTestFixture()
      : txs_collection_validator(iroha::test::kTestsValidatorsConfig),
        field_validator(iroha::test::kTestsValidatorsConfig) {}

  validation::DefaultUnsignedTransactionsValidator txs_collection_validator;
  validation::FieldValidator field_validator;
};

/**
 * @given Valid transaction collection of several transactions
 * @when create transaction sequence
 * @and transactions validator returns empty answer
 * @then TransactionSequence is created
 */
TEST_F(TransactionSequenceTestFixture, CreateTransactionSequenceWhenValid) {
  size_t transactions_size = 3;
  auto transactions =
      framework::batch::createValidBatch(transactions_size)->transactions();

  std::shared_ptr<interface::Transaction> tx(clone(
      framework::batch::prepareTransactionBuilder("account@domain")
          .batchMeta(shared_model::interface::types::BatchType::ATOMIC,
                     std::vector<shared_model::interface::types::HashType>{})
          .build()));

  auto tx_sequence =
      interface::TransactionSequenceFactory::createTransactionSequence(
          transactions, txs_collection_validator, field_validator);

  ASSERT_TRUE(framework::expected::val(tx_sequence));
}

/**
 * @given Invalid transaction collection of several transactions
 * @when create transaction sequence
 * @and transactions validator returns non empty answer
 * @then TransactionSequence is not created
 */
TEST_F(TransactionSequenceTestFixture, CreateTransactionSequenceWhenInvalid) {
  std::shared_ptr<interface::Transaction> tx(
      clone(framework::batch::prepareTransactionBuilder("invalid@#account#name")
                .build()));

  auto tx_sequence =
      interface::TransactionSequenceFactory::createTransactionSequence(
          std::vector<decltype(tx)>{tx, tx, tx},
          txs_collection_validator,
          field_validator);

  ASSERT_TRUE(framework::expected::err(tx_sequence));
}

/**
 * @given Transaction collection of several transactions, including some of them
 * united into the batches
 * @when transactions validator returns empty answer
 * @and create transaction sequence
 * @then expected number of batches is created and transactions
 */
TEST_F(TransactionSequenceTestFixture, CreateBatches) {
  size_t batches_number = 3;
  size_t txs_in_batch = 2;
  size_t single_transactions = 1;

  interface::types::SharedTxsCollectionType tx_collection;
  auto now = iroha::time::now();
  for (size_t i = 0; i < batches_number; i++) {
    auto batch = framework::batch::createValidBatch(txs_in_batch, now + i)
                     ->transactions();
    tx_collection.insert(tx_collection.begin(), batch.begin(), batch.end());
  }

  for (size_t i = 0; i < single_transactions; i++) {
    auto tx = std::shared_ptr<interface::Transaction>(
        clone(framework::batch::prepareTransactionBuilder(
                  "single_tx_account@domain" + std::to_string(i))
                  .build()));
    auto keypair = crypto::DefaultCryptoAlgorithmType::generateKeypair();
    auto signed_blob =
        crypto::DefaultCryptoAlgorithmType::sign(tx->payload(), keypair);
    using namespace shared_model::interface::types;
    tx->addSignature(SignedHexStringView{signed_blob},
                     PublicKeyHexStringView{keypair.publicKey()});

    tx_collection.emplace_back(tx);
  }

  auto tx_sequence_opt =
      interface::TransactionSequenceFactory::createTransactionSequence(
          tx_collection, txs_collection_validator, field_validator);

  auto tx_sequence = framework::expected::val(tx_sequence_opt);
  ASSERT_TRUE(tx_sequence)
      << framework::expected::err(tx_sequence_opt).value().error;

  EXPECT_EQ(boost::size(tx_sequence->value.batches()),
            batches_number + single_transactions);

  size_t total_transactions = 0;
  for (const auto &batch : tx_sequence->value.batches()) {
    total_transactions += boost::size(batch->transactions());
  }
  EXPECT_EQ(total_transactions,
            batches_number * txs_in_batch + single_transactions);
}

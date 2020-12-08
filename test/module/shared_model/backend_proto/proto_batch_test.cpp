/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include "builders/protobuf/transaction.hpp"
#include "framework/batch_helper.hpp"
#include "framework/result_fixture.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "validators/default_validator.hpp"

using namespace shared_model;
using ::testing::_;
using ::testing::Return;
using ::testing::Test;
using ::testing::Truly;

class TransactionBatchTest : public Test {
 public:
  TransactionBatchTest() {
    auto batch_validator =
        std::make_shared<shared_model::validation::DefaultBatchValidator>(
            iroha::test::kTestsValidatorsConfig);
    factory_ = std::make_shared<interface::TransactionBatchFactoryImpl>(
        batch_validator);
  }

  /**
   * Creates valid unsigned transaction
   * @param created_time assigned to transactions
   * @return valid unsigned transaction
   */
  auto createValidUnsignedTransaction(
      size_t created_time = iroha::time::now()) {
    return std::shared_ptr<interface::Transaction>(
        clone(framework::batch::prepareTransactionBuilder("valid@account",
                                                          created_time)
                  .build()));
  }

  /**
   * Creates invalid unsigned transaction
   * @param created_time assigned to transactions
   * @return invalid unsigned transaction
   */
  auto createInvalidUnsignedTransaction(
      size_t created_time = iroha::time::now()) {
    return std::shared_ptr<interface::Transaction>(
        clone(framework::batch::prepareTransactionBuilder("invalid#@account",
                                                          created_time)
                  .build()));
  }

  /**
   * Creates batch from transactions with provided quorum size and one signature
   * @param quorum quorum size
   * @return batch with transactions with one signature and quorum size
   */
  auto createBatchWithTransactionsWithQuorum(
      const interface::types::QuorumType &quorum) {
    auto keypair = crypto::DefaultCryptoAlgorithmType::generateKeypair();

    auto now = iroha::time::now();

    auto batch_type = shared_model::interface::types::BatchType::ATOMIC;
    std::string userone = "a@domain";
    std::string usertwo = "b@domain";

    auto transactions = framework::batch::createBatchOneSignTransactions(
        std::vector<std::pair<decltype(batch_type), std::string>>{
            std::make_pair(batch_type, userone),
            std::make_pair(batch_type, usertwo)},
        now,
        quorum);

    return factory_->createTransactionBatch(transactions);
  }

  /**
   * Create test transaction builder
   * @param acc_quorum - quorum number for setAccountDetail
   * @param created_time - time of creation
   * @param quorum - tx quorum number
   * @return test tx builder
   */
  inline auto makeTxBuilder(
      const shared_model::interface::types::QuorumType &acc_quorum = 1,
      uint64_t created_time = iroha::time::now(),
      uint8_t quorum = 3) {
    return framework::batch::prepareTransactionBuilder(
        "user@test", created_time, quorum);
  }

  inline auto makeSignedTxBuilder(
      const shared_model::interface::types::QuorumType &acc_quorum = 1,
      uint64_t created_time = iroha::time::now(),
      uint8_t quorum = 3) {
    return framework::batch::prepareUnsignedTransactionBuilder(
        "user@test", created_time, quorum);
  }

  std::shared_ptr<interface::TransactionBatchFactory> factory_;
};

/**
 * @given valid transactions sequence from the single batch
 * @when createTransactionBatch is invoked on that sequence
 * @then transaction batch is created
 */
TEST_F(TransactionBatchTest, CreateTransactionBatchWhenValid) {
  using BatchTypeAndCreatorPair =
      std::pair<interface::types::BatchType, std::string>;

  auto txs = framework::batch::createBatchOneSignTransactions(
      std::vector<BatchTypeAndCreatorPair>{
          BatchTypeAndCreatorPair{interface::types::BatchType::ATOMIC,
                                  "a@domain"},
          BatchTypeAndCreatorPair{interface::types::BatchType::ATOMIC,
                                  "b@domain"}});

  auto transaction_batch = factory_->createTransactionBatch(txs);
  ASSERT_TRUE(framework::expected::val(transaction_batch))
      << framework::expected::err(transaction_batch).value().error;
}

/**
 * @given transactions sequence from the single batch containing valid
 * transactions but with different batch types
 * @when createTransactionBatch is invoked on that sequence
 * @then transaction batch is not created
 */
TEST_F(TransactionBatchTest, CreateTransactionBatchWhenDifferentBatchType) {
  auto tx1_fields = std::make_pair(interface::types::BatchType::ORDERED,
                                   std::string("a@domain"));
  auto tx2_fields = std::make_pair(interface::types::BatchType::ATOMIC,
                                   std::string("b@domain"));

  auto txs = framework::batch::createUnsignedBatchTransactions(
      std::vector<decltype(tx1_fields)>{tx1_fields, tx2_fields});

  auto transaction_batch = factory_->createTransactionBatch(txs);
  ASSERT_TRUE(framework::expected::err(transaction_batch));
}

/**
 * @given transactions sequence from the single batch containing one valid and
 * one invalid transactions
 * @when createTransactionBatch is invoked on that sequence
 * @then transaction batch is not created
 */
TEST_F(TransactionBatchTest, CreateBatchWithValidAndInvalidTx) {
  auto txs = framework::batch::createUnsignedBatchTransactions(
      interface::types::BatchType::ATOMIC,
      std::vector<std::string>{"valid@name", "invalid#@name"});

  auto transaction_batch = factory_->createTransactionBatch(txs);
  ASSERT_TRUE(framework::expected::err(transaction_batch));
}

/**
 * @given single valid transaction
 * @when createTransactionBatch is invoked on that transaction
 * @then transaction batch is created
 */
TEST_F(TransactionBatchTest, CreateSingleTxBatchWhenValid) {
  auto tx1 = createValidUnsignedTransaction();
  auto keypair = crypto::DefaultCryptoAlgorithmType::generateKeypair();
  auto signed_blob =
      crypto::DefaultCryptoAlgorithmType::sign(tx1->payload(), keypair);
  tx1->addSignature(
      interface::types::SignedHexStringView{signed_blob},
      interface::types::PublicKeyHexStringView{keypair.publicKey()});

  auto transaction_batch = factory_->createTransactionBatch(tx1);

  ASSERT_TRUE(framework::expected::val(transaction_batch))
      << framework::expected::err(transaction_batch).value().error;
}

/**
 * @given single invalid transaction
 * @when createTransactionBatch is invoked on that transaction
 * @then transaction batch is not created
 */
TEST_F(TransactionBatchTest, CreateSingleTxBatchWhenInvalid) {
  auto transaction_batch =
      factory_->createTransactionBatch(createInvalidUnsignedTransaction());
  ASSERT_TRUE(framework::expected::err(transaction_batch));
}

/**
 * @given transactions with transaction with quorum size 1 @and signatures size
 * equals 1, @and all transactions are from the same batch
 * @when transaction batch is created from that transactions
 * @then created batch has all signatures
 */
TEST_F(TransactionBatchTest, BatchWithAllSignatures) {
  auto quorum = 1;
  auto transaction_batch = createBatchWithTransactionsWithQuorum(quorum);
  auto transaction_batch_val = framework::expected::val(transaction_batch);
  ASSERT_TRUE(transaction_batch_val)
      << framework::expected::err(transaction_batch).value().error;
  ASSERT_TRUE(transaction_batch_val->value->hasAllSignatures());
}

/**
 * @given transactions with transaction with quorum size 2 @and signatures size
 * equals 1, @and all transactions are from the same batch
 * @when transaction batch is created from that transactions
 * @then created batch does not have all signatures
 */
TEST_F(TransactionBatchTest, BatchWithMissingSignatures) {
  auto quorum = 2;
  auto transaction_batch = createBatchWithTransactionsWithQuorum(quorum);
  auto transaction_batch_val = framework::expected::val(transaction_batch);
  ASSERT_TRUE(transaction_batch_val)
      << framework::expected::err(transaction_batch).value().error;
  ASSERT_FALSE(transaction_batch_val->value->hasAllSignatures());
}

/**
 * @given list of transactions from the same batch with no signatures
 * @when create transaction batch is invoked
 * @then returned result contains error
 */
TEST_F(TransactionBatchTest, BatchWithNoSignatures) {
  const size_t batch_size = 5;
  auto unsigned_transactions =
      framework::batch::createUnsignedBatchTransactions(
          interface::types::BatchType::ATOMIC, batch_size);
  auto transaction_batch =
      factory_->createTransactionBatch(unsigned_transactions);
  ASSERT_TRUE(framework::expected::err(transaction_batch));
}

/**
 * @given list of transactions from the same batch. Only one of them is signed
 * @when create transaction batch is invoked
 * @then transaction batch is successfully created
 */
TEST_F(TransactionBatchTest, BatchWithOneSignature) {
  uint64_t created_time = iroha::time::now();
  auto unsigned_transactions = framework::batch::makeTestBatchTransactions(
      makeTxBuilder(1, created_time),
      makeTxBuilder(2, created_time + 1),
      makeSignedTxBuilder(1, created_time + 2));
  auto transaction_batch =
      factory_->createTransactionBatch(unsigned_transactions);
  ASSERT_TRUE(framework::expected::val(transaction_batch))
      << framework::expected::err(transaction_batch).value().error;
}

/**
 * @given one tx-builder
 * @when  try to fetch hash
 * @then  got only one hash
 */
TEST_F(TransactionBatchTest, TemplateHasherOne) {
  ASSERT_EQ(
      1,
      framework::batch::internal::fetchReducedHashes(makeTxBuilder()).size());
}

/**
 * @given 3 tx-builders
 * @when  try to fetch hashes
 * @then  got exactly 3 hashes
 */
TEST_F(TransactionBatchTest, TemplateHasherVariadic) {
  ASSERT_EQ(3,
            framework::batch::internal::fetchReducedHashes(
                makeTxBuilder(), makeTxBuilder(), makeTxBuilder())
                .size());
}

/**
 * @given one tx-builder
 * @when  try to create transaction
 * @then  got exactly one tx
 */
TEST_F(TransactionBatchTest, MakeTxBatchCollectionOne) {
  ASSERT_EQ(1,
            framework::batch::internal::makeTxBatchCollection(
                framework::batch::internal::BatchMeta{}, makeTxBuilder())
                .size());
}

/**
 * @given three tx-builders
 * @when  try to create transaction collection
 * @then  got exactly 3 txes
 */
TEST_F(TransactionBatchTest, MakeTxBatchCollectionMany) {
  ASSERT_EQ(3,
            framework::batch::internal::makeTxBatchCollection(
                framework::batch::internal::BatchMeta{},
                makeTxBuilder(),
                makeTxBuilder(),
                makeTxBuilder())
                .size());
}

/**
 * @given two tx-builders
 * @when  try to create batch
 * @then  batch contains two transactions
 */
TEST_F(TransactionBatchTest, CreateTestBatchTest) {
  ASSERT_EQ(3,
            framework::batch::makeTestBatch(
                makeTxBuilder(2), makeTxBuilder(), makeSignedTxBuilder(1))
                ->transactions()
                .size());
}

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validation/impl/stateful_validator_impl.hpp"

#include <gtest/gtest.h>
#include "backend/protobuf/proto_proposal_factory.hpp"
#include "common/result.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "interfaces/transaction.hpp"
#include "module/irohad/ametsuchi/ametsuchi_mocks.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_proposal_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "validation/utils.hpp"

using namespace iroha::validation;
using namespace shared_model::crypto;

using ::testing::_;
using ::testing::A;
using ::testing::ByMove;
using ::testing::ByRef;
using ::testing::Eq;
using ::testing::Return;
using ::testing::ReturnArg;

class SignaturesSubset : public testing::Test {
 public:
  std::vector<std::string> keys{"0a", "0b", "0c"};
};

auto makePublicKeyHexStringView(std::string const &x) {
  return shared_model::interface::types::PublicKeyHexStringView{x};
}

/**
 * @given three different keys and three signatures with the same keys
 * @when signaturesSubset is executed
 * @then returned true
 */
TEST_F(SignaturesSubset, Equal) {
  std::array<MockSignature, 3> signatures;
  for (size_t i = 0; i < signatures.size(); ++i) {
    EXPECT_CALL(signatures[i], publicKey())
        .WillRepeatedly(testing::ReturnRefOfCopy(keys[i]));
  }
  ASSERT_TRUE(signaturesSubset(
      signatures,
      keys | boost::adaptors::transformed(makePublicKeyHexStringView)));
}

/**
 * @given two different keys and two signatures with the same keys plus
 * additional one
 * @when signaturesSubset is executed
 * @then returned false
 */
TEST_F(SignaturesSubset, Lesser) {
  std::vector<std::string> subkeys{keys.begin(), keys.end() - 1};
  std::array<MockSignature, 3> signatures;
  for (size_t i = 0; i < signatures.size(); ++i) {
    EXPECT_CALL(signatures[i], publicKey())
        .WillRepeatedly(testing::ReturnRefOfCopy(keys[i]));
  }
  ASSERT_FALSE(signaturesSubset(
      signatures,
      subkeys | boost::adaptors::transformed(makePublicKeyHexStringView)));
}

/**
 * @given three different keys and two signatures with the first pair of keys
 * @when signaturesSubset is executed
 * @then returned true
 */
TEST_F(SignaturesSubset, StrictSubset) {
  std::array<MockSignature, 2> signatures;
  for (size_t i = 0; i < signatures.size(); ++i) {
    EXPECT_CALL(signatures[i], publicKey())
        .WillRepeatedly(testing::ReturnRefOfCopy(keys[i]));
  }
  ASSERT_TRUE(signaturesSubset(
      signatures,
      keys | boost::adaptors::transformed(makePublicKeyHexStringView)));
}

/**
 * @given two same keys and two signatures with different keys
 * @when signaturesSubset is executed
 * @then returned false
 */
TEST_F(SignaturesSubset, PublickeyUniqueness) {
  std::vector<std::string> repeated_keys{2, keys[0]};
  std::array<MockSignature, 2> signatures;
  for (size_t i = 0; i < signatures.size(); ++i) {
    EXPECT_CALL(signatures[i], publicKey())
        .WillRepeatedly(testing::ReturnRefOfCopy(keys[i]));
  }
  ASSERT_FALSE(signaturesSubset(
      signatures,
      repeated_keys
          | boost::adaptors::transformed(makePublicKeyHexStringView)));
}

class Validator : public testing::Test {
 public:
  void SetUp() override {
    factory = std::make_unique<shared_model::proto::ProtoProposalFactory<
        shared_model::validation::DefaultProposalValidator>>(
        iroha::test::kTestsValidatorsConfig);
    parser =
        std::make_shared<shared_model::interface::TransactionBatchParserImpl>();
    sfv = std::make_shared<StatefulValidatorImpl>(
        std::move(factory),
        std::move(parser),
        getTestLogger("StatefulValidator"));
    temp_wsv_mock = std::make_shared<iroha::ametsuchi::MockTemporaryWsv>();
  }

  auto createBatch(std::vector<std::string> creators,
                   shared_model::interface::types::BatchType batch_type) {
    std::vector<shared_model::interface::types::HashType> reduced_hashes;
    std::vector<shared_model::proto::Transaction> txs;
    auto current_time = iroha::time::now();

    for (size_t i = 0; i < creators.size(); ++i) {
      auto tx = TestTransactionBuilder()
                    .creatorAccountId(creators[i])
                    .createdTime(current_time + i)
                    .quorum(1)
                    .createAsset("doge", "coin", 1)
                    .build();
      reduced_hashes.push_back(tx.reducedHash());
    }

    for (size_t i = 0; i < creators.size(); ++i) {
      txs.push_back(TestTransactionBuilder()
                        .creatorAccountId(creators[i])
                        .createdTime(current_time + i)
                        .quorum(1)
                        .createAsset("doge", "coin", 1)
                        .batchMeta(batch_type, reduced_hashes)
                        .build());
    }
    return txs;
  }

  std::shared_ptr<StatefulValidator> sfv;
  std::unique_ptr<shared_model::interface::UnsafeProposalFactory> factory;
  std::shared_ptr<iroha::ametsuchi::MockTemporaryWsv> temp_wsv_mock;
  std::shared_ptr<shared_model::interface::TransactionBatchParser> parser;

  const uint32_t sample_error_code = 2;
  const std::string sample_error_extra = "account_id: doge@account";
};

/**
 * @given several valid transactions
 * @when statefully validating these transactions
 * @then all of them will appear in verified proposal @and errors will be empty
 */
TEST_F(Validator, AllTxsValid) {
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId("doge@master")
                    .createdTime(iroha::time::now())
                    .quorum(1)
                    .createAsset("doge", "coin", 1)
                    .build());
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId("doge@master")
                    .createdTime(iroha::time::now())
                    .quorum(1)
                    .createAsset("doge", "coin", 1)
                    .build());
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId("doge@master")
                    .createdTime(iroha::time::now())
                    .quorum(1)
                    .createAsset("doge", "coin", 1)
                    .build());
  auto proposal = TestProposalBuilder()
                      .createdTime(iroha::time::now())
                      .height(3)
                      .transactions(txs)
                      .build();

  EXPECT_CALL(*temp_wsv_mock, apply(_))
      .WillRepeatedly(Return(iroha::expected::Value<void>({})));

  auto verified_proposal_and_errors = sfv->validate(proposal, *temp_wsv_mock);
  ASSERT_EQ(
      verified_proposal_and_errors->verified_proposal->transactions().size(),
      3);
  ASSERT_TRUE(verified_proposal_and_errors->rejected_transactions.empty());
}

/**
 * @given several valid and a couple of invalid transactions
 * @when statefully validating these transactions
 * @then valid transactions will appear in verified proposal @and invalid ones
 * will appear in errors
 */
TEST_F(Validator, SomeTxsFail) {
  std::vector<shared_model::proto::Transaction> txs;

  // valid tx
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId("doge@master")
                    .createdTime(iroha::time::now())
                    .quorum(1)
                    .createAsset("doge", "coin", 1)
                    .build());
  // invalid tx
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId("doge@master")
                    .createdTime(iroha::time::now())
                    .quorum(1)
                    .createAsset("cate", "coin", 1)
                    .build());

  // valid tx
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId("doge@master")
                    .createdTime(iroha::time::now())
                    .quorum(1)
                    .createAsset("doge", "coin", 1)
                    .build());
  auto proposal = TestProposalBuilder()
                      .createdTime(iroha::time::now())
                      .height(3)
                      .transactions(txs)
                      .build();

  EXPECT_CALL(*temp_wsv_mock, apply(Eq(ByRef(txs.at(0)))))
      .WillRepeatedly(Return(iroha::expected::Value<void>({})));
  EXPECT_CALL(*temp_wsv_mock, apply(Eq(ByRef(txs.at(1)))))
      .WillOnce(Return(iroha::expected::makeError(
          CommandError{"", sample_error_code, sample_error_extra, true})));
  EXPECT_CALL(*temp_wsv_mock, apply(Eq(ByRef(txs.at(2)))))
      .WillRepeatedly(Return(iroha::expected::Value<void>({})));

  auto verified_proposal_and_errors = sfv->validate(proposal, *temp_wsv_mock);
  ASSERT_EQ(
      verified_proposal_and_errors->verified_proposal->transactions().size(),
      2);
  ASSERT_EQ(verified_proposal_and_errors->rejected_transactions.size(), 1);
  EXPECT_EQ(verified_proposal_and_errors->rejected_transactions.begin()
                ->error.error_code,
            sample_error_code);
  EXPECT_EQ(verified_proposal_and_errors->rejected_transactions.begin()
                ->error.error_extra,
            sample_error_extra);
}

/**
 * @given two atomic batches @and one ordered @and several single transactions
 * @when failing one of the atomic batched @and transaction from ordered batch
 * @and transaction from single group
 * @then verified proposal will contain transactions from non-failed atomic
 * batch, non-failed part of ordered batch, non-failed transactions from single
 * group @and errors will contain exactly one error (for failed atomic batch)
 */
TEST_F(Validator, Batches) {
  auto single_tx = TestTransactionBuilder()
                       .creatorAccountId("doge@master")
                       .createdTime(iroha::time::now())
                       .quorum(1)
                       .createAsset("doge", "coin", 1)
                       .build();
  auto success_atomic_batch =
      createBatch(std::vector<std::string>{"creator@d1", "creator@d2"},
                  shared_model::interface::types::BatchType::ATOMIC);
  auto failed_atomic_batch =
      createBatch(std::vector<std::string>{"creator@d3", "creator@d4"},
                  shared_model::interface::types::BatchType::ATOMIC);
  auto ordered_batch =
      createBatch(std::vector<std::string>{"creator@d5", "creator@d6"},
                  shared_model::interface::types::BatchType::ORDERED);

  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(std::move(single_tx));
  txs.push_back(ordered_batch[0]);
  txs.push_back(ordered_batch[1]);
  txs.push_back(failed_atomic_batch[0]);
  txs.push_back(failed_atomic_batch[1]);
  txs.push_back(success_atomic_batch[0]);
  txs.push_back(success_atomic_batch[1]);

  auto proposal = TestProposalBuilder()
                      .createdTime(iroha::time::now())
                      .height(1)
                      .transactions(txs)
                      .build();

  // calls to create savepoints, one per each atomic batch
  EXPECT_CALL(*temp_wsv_mock,
              createSavepoint("batch_" + failed_atomic_batch[0].hash().hex()))
      .WillOnce(Return(
          ByMove(std::make_unique<
                 iroha::ametsuchi::MockTemporaryWsvSavepointWrapper>())));
  EXPECT_CALL(*temp_wsv_mock,
              createSavepoint("batch_" + success_atomic_batch[0].hash().hex()))
      .WillOnce(Return(
          ByMove(std::make_unique<
                 iroha::ametsuchi::MockTemporaryWsvSavepointWrapper>())));

  // calls to validate transactions, one per each transaction except those,
  // which are in failed atomic batch - there only calls before the failed
  // transaction are needed
  EXPECT_CALL(*temp_wsv_mock, apply(Eq(ByRef(txs[0]))))
      .WillOnce(Return(iroha::expected::Value<void>({})));
  EXPECT_CALL(*temp_wsv_mock, apply(Eq(ByRef(txs[1]))))
      .WillOnce(Return(iroha::expected::Value<void>({})));
  EXPECT_CALL(*temp_wsv_mock, apply(Eq(ByRef(txs[2]))))
      .WillOnce(Return(iroha::expected::Value<void>({})));
  EXPECT_CALL(*temp_wsv_mock, apply(Eq(ByRef(txs[3]))))
      .WillOnce(Return(iroha::expected::makeError(
          CommandError({"", sample_error_code, sample_error_extra, false}))));
  EXPECT_CALL(*temp_wsv_mock, apply(Eq(ByRef(txs[5]))))
      .WillOnce(Return(iroha::expected::Value<void>({})));
  EXPECT_CALL(*temp_wsv_mock, apply(Eq(ByRef(txs[6]))))
      .WillOnce(Return(iroha::expected::Value<void>({})));

  auto verified_proposal_and_errors = sfv->validate(proposal, *temp_wsv_mock);
  ASSERT_EQ(
      verified_proposal_and_errors->verified_proposal->transactions().size(),
      5);
  ASSERT_EQ(verified_proposal_and_errors->rejected_transactions.size(),
            failed_atomic_batch.size());
  EXPECT_EQ(
      verified_proposal_and_errors->rejected_transactions[0].error.error_code,
      sample_error_code);
  EXPECT_EQ(
      verified_proposal_and_errors->rejected_transactions[0].error.error_extra,
      sample_error_extra);
  EXPECT_EQ(verified_proposal_and_errors->rejected_transactions[0].tx_hash,
            txs[3].hash());
  EXPECT_EQ(
      verified_proposal_and_errors->rejected_transactions[1].error.error_code,
      1);
  EXPECT_EQ(
      verified_proposal_and_errors->rejected_transactions[1].error.error_extra,
      "Another transaction failed the batch");
  EXPECT_EQ(verified_proposal_and_errors->rejected_transactions[1].tx_hash,
            txs[4].hash());
}

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <boost/range/irange.hpp>
#include "common/bind.hpp"
#include "endpoint.pb.h"
#include "framework/batch_helper.hpp"
#include "framework/result_fixture.hpp"
#include "interfaces/common_objects/types.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"
#include "module/shared_model/builders/protobuf/proposal.hpp"
#include "module/shared_model/builders/protobuf/queries.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_proposal_builder.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/builders/protobuf/transaction.hpp"
#include "module/shared_model/builders/protobuf/transport_builder.hpp"
#include "validators/default_validator.hpp"
#include "validators/transactions_collection/batch_order_validator.hpp"

using namespace shared_model;
using namespace shared_model::proto;
using namespace iroha::expected;
using iroha::operator|;

class TransportBuilderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    created_time = iroha::time::now();
    invalid_created_time = 123;
    account_id = "account@domain";
    account_id2 = "acccount@domain";
    quorum = 2;
    counter = 1048576;
    hash = shared_model::crypto::Hash(std::string(32, '0'));
    invalid_hash = shared_model::crypto::Hash("");
    height = 1;
    invalid_account_id = "some#invalid?account@@id";
  }

  //-------------------------------------Transaction-------------------------------------
  template <typename TransactionBuilder>
  auto getBaseTransactionBuilder() {
    return TestUnsignedTransactionBuilder()
        .createdTime(created_time)
        .quorum(quorum)
        .setAccountQuorum(account_id, quorum);
  }
  auto createUnbuildTransaction() {
    return getBaseTransactionBuilder<shared_model::proto::TransactionBuilder>()
        .creatorAccountId(account_id);
  }
  auto createTransaction() {
    return getBaseTransactionBuilder<shared_model::proto::TransactionBuilder>()
        .creatorAccountId(account_id)
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }

  auto createInvalidTransaction() {
    return getBaseTransactionBuilder<TestTransactionBuilder>()
        .creatorAccountId(invalid_account_id)
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }

  //-------------------------------------Query-------------------------------------
  template <typename QueryBuilder>
  auto getBaseQueryBuilder() {
    return QueryBuilder()
        .createdTime(created_time)
        .getAccount(account_id)
        .queryCounter(counter);
  }

  auto createQuery() {
    return getBaseQueryBuilder<shared_model::proto::QueryBuilder>()
        .creatorAccountId(account_id)
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }

  auto createInvalidQuery() {
    return getBaseQueryBuilder<TestUnsignedQueryBuilder>()
        .creatorAccountId(invalid_account_id)
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }

  //-------------------------------------Block-------------------------------------
  template <typename BlockBuilder>
  auto getBaseBlockBuilder() {
    std::vector<shared_model::proto::Transaction> txs;
    txs.push_back(createTransaction());
    return BlockBuilder().transactions(txs).height(1).createdTime(created_time);
  }

  auto createBlock() {
    return getBaseBlockBuilder<shared_model::proto::BlockBuilder>()
        .prevHash(hash)
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }

  auto createInvalidBlock() {
    return getBaseBlockBuilder<TestBlockBuilder>()
        .prevHash(invalid_hash)
        .build();
  }

  //-------------------------------------Proposal-------------------------------------
  template <typename ProposalBuilder>
  auto getBaseProposalBuilder() {
    return ProposalBuilder().createdTime(created_time).height(1);
  }

  auto createProposal() {
    std::vector<shared_model::proto::Transaction> txs;
    txs.push_back(createTransaction());
    return getBaseProposalBuilder<shared_model::proto::ProposalBuilder>()
        .transactions(txs)
        .build();
  }

  auto createInvalidProposal() {
    std::vector<shared_model::proto::Transaction> txs;
    txs.push_back(createInvalidTransaction());
    return getBaseProposalBuilder<TestProposalBuilder>()
        .transactions(txs)
        .build();
  }

  auto createEmptyProposal() {
    return getBaseProposalBuilder<TestProposalBuilder>()
        .transactions(std::vector<Transaction>())
        .build();
  }
  /**
   * Receives model object, gets transport from it, converts transport into
   * model object and checks if original and obtained model objects are the same
   * @tparam ObjectOriginalModel - model object type
   * @tparam Validator - validator type
   * @param orig_model
   * @param successCase function invoking if value exists
   * @param failCase function invoking when error returned
   */
  template <typename Validator,
            typename ObjectOriginalModel,
            typename SuccessCase,
            typename FailCase>
  void testTransport(const ObjectOriginalModel &orig_model,
                     SuccessCase &&successCase,
                     FailCase &&failCase,
                     bool txs_duplicates_allowed = false) {
    auto proto_model = orig_model.getTransport();

    auto built_model = txs_duplicates_allowed
        ? TransportBuilder<ObjectOriginalModel, Validator>(
              iroha::test::kProposalTestsValidatorsConfig)
              .build(proto_model)
        : TransportBuilder<ObjectOriginalModel, Validator>(
              iroha::test::kTestsValidatorsConfig)
              .build(proto_model);

    built_model.match(successCase, failCase);
  }

 protected:
  decltype(iroha::time::now()) created_time;
  decltype(created_time) invalid_created_time;
  std::string account_id;
  std::string account_id2;
  uint8_t quorum;
  uint64_t counter;
  shared_model::crypto::Hash hash;
  shared_model::crypto::Hash invalid_hash;
  uint64_t height;

  std::string invalid_account_id;
  shared_model::crypto::Keypair keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
};

//-------------------------------------TRANSACTION-------------------------------------

/**
 * @given valid proto object of transaction
 * @when transport builder constructs model object from it
 * @then original and built objects are equal
 */
TEST_F(TransportBuilderTest, TransactionCreationTest) {
  auto orig_model = createTransaction();
  testTransport<validation::DefaultSignedTransactionValidator>(
      orig_model,
      [&orig_model](const Value<decltype(orig_model)> &model) {
        ASSERT_EQ(model.value.getTransport().SerializeAsString(),
                  orig_model.getTransport().SerializeAsString());
      },
      [](const Error<std::string> &msg) {
        std::cout << msg.error << std::endl;
        FAIL();
      });
}

/**
 * @given invalid proto object of transaction
 * @when transport builder constructs model object from it
 * @then error case is executed
 */
TEST_F(TransportBuilderTest, InvalidTransactionCreationTest) {
  auto orig_model = createInvalidTransaction();
  testTransport<validation::DefaultSignedTransactionValidator>(
      orig_model,
      [](const Value<decltype(orig_model)> &) { FAIL(); },
      [](const Error<std::string> &) { SUCCEED(); });
}

//-------------------------------------QUERY-------------------------------------

/**
 * @given valid proto object of query
 * @when transport builder constructs model object from it
 * @then original and built objects are equal
 */
TEST_F(TransportBuilderTest, QueryCreationTest) {
  auto orig_model = createQuery();
  testTransport<validation::DefaultSignedQueryValidator>(
      orig_model,
      [&orig_model](const Value<decltype(orig_model)> &model) {
        ASSERT_EQ(model.value.getTransport().SerializeAsString(),
                  orig_model.getTransport().SerializeAsString());
      },
      [](const Error<std::string> &) { FAIL(); });
}

/**
 * @given invalid proto object of query
 * @when transport builder constructs model object from it
 * @then error case is executed
 */
TEST_F(TransportBuilderTest, InvalidQueryCreationTest) {
  auto orig_model = createInvalidQuery();
  testTransport<validation::DefaultSignedQueryValidator>(
      orig_model,
      [](const Value<decltype(orig_model)>) { FAIL(); },
      [](const Error<std::string> &) { SUCCEED(); });
}

//-------------------------------------BLOCK-------------------------------------

/**
 * @given valid proto object of block
 * @when transport builder constructs model object from it
 * @then original and built objects are equal
 */
TEST_F(TransportBuilderTest, BlockCreationTest) {
  auto orig_model = createBlock();
  testTransport<validation::DefaultUnsignedBlockValidator>(
      orig_model,
      [&orig_model](const Value<decltype(orig_model)> &model) {
        ASSERT_EQ(model.value.getTransport().SerializeAsString(),
                  orig_model.getTransport().SerializeAsString());
      },
      [](const Error<std::string> &) { FAIL(); });
}

/**
 * @given invalid proto object of block
 * @when transport builder constructs model object from it
 * @then error is occured
 */
TEST_F(TransportBuilderTest, InvalidBlockCreationTest) {
  auto orig_model = createInvalidBlock();
  testTransport<validation::DefaultUnsignedBlockValidator>(
      orig_model,
      [](const Value<std::decay_t<decltype(orig_model)>> &) { FAIL(); },
      [](const Error<const std::string> &) { SUCCEED(); });
}

//-------------------------------------PROPOSAL-------------------------------------

/**
 * @given valid proto object of proposal
 * @when transport builder constructs model object from it
 * @then original and built objects are equal
 */
TEST_F(TransportBuilderTest, ProposalCreationTest) {
  auto orig_model = createProposal();
  testTransport<validation::DefaultProposalValidator>(
      orig_model,
      [&orig_model](const Value<decltype(orig_model)> &model) {
        ASSERT_EQ(model.value.getTransport().SerializeAsString(),
                  orig_model.getTransport().SerializeAsString());
      },
      [](const Error<std::string> &) { FAIL(); },
      true);
}

/**
 * TODO 21/05/2018 andrei IR-1345 Enable when verified proposal is introduced
 * @given empty proto object of proposal
 * @when transport builder constructs model object from it
 * @then error occurred due to empty transactions
 */
TEST_F(TransportBuilderTest, DISABLED_EmptyProposalCreationTest) {
  auto orig_model = createEmptyProposal();
  testTransport<validation::DefaultProposalValidator>(
      orig_model,
      [](const Value<decltype(orig_model)> &) { FAIL(); },
      [](const Error<std::string> &) { SUCCEED(); },
      true);
}

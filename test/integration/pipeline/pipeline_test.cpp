/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "builders/protobuf/queries.hpp"
#include "builders/protobuf/transaction.hpp"
#include "datetime/time.hpp"
#include "framework/batch_helper.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/interface/transaction_sequence_factory.hpp"
#include "utils/query_error_response_visitor.hpp"

using namespace common_constants;

class PipelineIntegrationTest : public AcceptanceFixture {
 public:
  /**
   * prepares signed transaction with CreateDomain command
   * @param domain_name name of the domain
   * @return Transaction with CreateDomain command
   */
  auto prepareCreateDomainTransaction(
      std::string domain_name = "anotherdomain") {
    return shared_model::proto::TransactionBuilder()
        .createdTime(getUniqueTime())
        .quorum(1)
        .creatorAccountId(kAdminId)
        .createDomain(domain_name, kDefaultRole)
        .build()
        .signAndAddSignature(*kAdminSigner)
        .finish();
  }

  /**
   * prepares transaction sequence
   * @param tx_size the size of transaction sequence
   * @return  transaction sequence
   */
  auto prepareTransactionSequence(size_t tx_size) {
    shared_model::interface::types::SharedTxsCollectionType txs;

    for (size_t i = 0; i < tx_size; i++) {
      auto &&tx = prepareCreateDomainTransaction(std::string("domain")
                                                 + std::to_string(i));
      txs.push_back(
          std::make_shared<shared_model::proto::Transaction>(std::move(tx)));
    }

    auto tx_sequence_result = shared_model::interface::
        TransactionSequenceFactory::createTransactionSequence(
            txs,
            shared_model::validation::DefaultSignedTransactionsValidator(
                iroha::test::getTestsValidatorsConfig()),
            shared_model::validation::FieldValidator(
                iroha::test::getTestsValidatorsConfig()));

    return framework::expected::val(tx_sequence_result).value().value;
  }
};
/**
 * @given GetAccount query with non-existing user
 * AND default-initialized IntegrationTestFramework
 * @when query is sent to the framework
 * @then query response is ErrorResponse with STATEFUL_INVALID reason
 */
TEST_F(PipelineIntegrationTest, SendQuery) {
  auto query = shared_model::proto::QueryBuilder()
                   .createdTime(iroha::time::now())
                   .creatorAccountId(kAdminId)
                   .queryCounter(1)
                   .getAccount(kAdminId)
                   .build()
                   .signAndAddSignature(
                       // TODO: 30/03/17 @l4l use keygen adapter IR-1189
                       *kUserSigner)
                   .finish();

  auto check = [](auto &status) {
    ASSERT_TRUE(boost::apply_visitor(
        shared_model::interface::QueryErrorResponseChecker<
            shared_model::interface::StatefulFailedErrorResponse>(),
        status.get()));
  };
  integration_framework::IntegrationTestFramework(1)
      .setInitialState(kAdminSigner)
      .sendQuery(query, check);
}

/**
 * @given some user
 * @when sending sample CreateDomain transaction to the ledger
 * @then receive ENOUGH_SIGNATURES_COLLECTED status on that tx AND
 * tx is committed, thus non-empty verified proposal
 */
TEST_F(PipelineIntegrationTest, SendTx) {
  auto tx = prepareCreateDomainTransaction();

  auto check_stateless_valid_status = [](auto &status) {
    ASSERT_NO_THROW(
        boost::get<const shared_model::interface::StatelessValidTxResponse &>(
            status.get()));
  };
  auto check_proposal = [](auto &proposal) {
    ASSERT_EQ(proposal->transactions().size(), 1);
  };

  auto check_verified_proposal = [](auto &proposal) {
    ASSERT_EQ(proposal->transactions().size(), 1);
  };

  auto check_block = [](auto &block) {
    ASSERT_EQ(block->transactions().size(), 1);
  };

  integration_framework::IntegrationTestFramework(1)
      .setInitialState(kAdminSigner)
      .sendTx(tx, check_stateless_valid_status)
      .checkProposal(check_proposal)
      .checkVerifiedProposal(check_verified_proposal)
      .checkBlock(check_block);
}

/**
 * @given some user
 * @when sending sample create domain transactions to the ledger
 * @then receive STATELESS_VALIDATION_SUCCESS status on that transactions,
 * all transactions are passed to proposal and appear in verified proposal and
 * block
 * TODO andrei 31.10.18 IR-1784 Refactor MST to batches
 */
TEST_F(PipelineIntegrationTest, DISABLED_SendTxSequence) {
  size_t tx_size = 5;
  const auto &tx_sequence = prepareTransactionSequence(tx_size);

  auto check_stateless_valid = [](auto &statuses) {
    for (const auto &status : statuses) {
      EXPECT_NO_THROW(
          boost::get<const shared_model::interface::StatelessValidTxResponse &>(
              status.get()));
    }
  };
  auto check_proposal = [&tx_size](auto &proposal) {
    ASSERT_EQ(proposal->transactions().size(), tx_size);
  };
  auto check_verified_proposal = [&tx_size](auto &proposal) {
    ASSERT_EQ(proposal->transactions().size(), tx_size);
  };
  auto check_block = [&tx_size](auto &block) {
    ASSERT_EQ(block->transactions().size(), tx_size);
  };

  integration_framework::IntegrationTestFramework(
      tx_size)  // make all transactions to fit into a single proposal
      .setInitialState(kAdminSigner)
      .sendTxSequence(tx_sequence, check_stateless_valid)
      .checkProposal(check_proposal)
      .checkVerifiedProposal(check_verified_proposal)
      .checkBlock(check_block);
}

/**
 * @give some user
 * @when sending transaction sequence with stateful valid transactions to the
 * ledger using sendTxSequence await method
 * @then all transactions appear in the block
 * TODO andrei 31.10.18 IR-1784 Refactor MST to batches
 */
TEST_F(PipelineIntegrationTest, DISABLED_SendTxSequenceAwait) {
  size_t tx_size = 5;
  const auto &tx_sequence = prepareTransactionSequence(tx_size);

  auto check_block = [&tx_size](auto &block) {
    ASSERT_EQ(block->transactions().size(), tx_size);
  };
  integration_framework::IntegrationTestFramework(
      tx_size)  // make all transactions to fit into a single proposal
      .setInitialState(kAdminSigner)
      .sendTxSequenceAwait(tx_sequence, check_block);
}

/**
 * Check that after no transactions were committed we are able to send and apply
 * new transactions
 *
 * @given createFirstDomain and createSecondDomain transactions
 * @when first domain is created second time
 * @then block with no transactions is created
 * AND after that createSecondDomain transaction can be executed and applied
 */
TEST_F(PipelineIntegrationTest, SuccessfulCommitAfterEmptyBlock) {
  auto createFirstDomain = [this] {
    return prepareCreateDomainTransaction("domain1");
  };
  auto createSecondDomain = [this] {
    return prepareCreateDomainTransaction("domain2");
  };

  integration_framework::IntegrationTestFramework(1)
      .setInitialState(kAdminSigner)
      .sendTxAwait(
          createFirstDomain(),
          [](const auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTxAwait(
          createFirstDomain(),
          [](const auto &block) { ASSERT_EQ(block->transactions().size(), 0); })
      .sendTxAwait(createSecondDomain(), [](const auto &block) {
        ASSERT_EQ(block->transactions().size(), 1);
      });
}

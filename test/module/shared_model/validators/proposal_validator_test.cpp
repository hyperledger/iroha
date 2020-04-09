/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/validators/validators_fixture.hpp"

#include <gtest/gtest.h>

#include <optional>
#include "builders/protobuf/transaction.hpp"
#include "framework/batch_helper.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/proposal.hpp"
#include "module/shared_model/builders/protobuf/test_proposal_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "validators/default_validator.hpp"
#include "validators/validation_error_output.hpp"

using namespace shared_model::validation;

class ProposalValidatorTest : public ValidatorsTest {
 public:
  ProposalValidatorTest() : validator_(iroha::test::kTestsValidatorsConfig) {}

  using BatchTypeAndCreatorPair =
      std::pair<shared_model::interface::types::BatchType, std::string>;

  DefaultProposalValidator validator_;

  template <typename TransactionBuilder>
  auto getBaseTransactionBuilder() {
    return TestUnsignedTransactionBuilder()
        .createdTime(created_time)
        .quorum(quorum)
        .setAccountQuorum(account_id, quorum);
  }

  auto createTransaction() {
    return getBaseTransactionBuilder<shared_model::proto::TransactionBuilder>()
        .creatorAccountId(account_id)
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }

  template <typename ProposalBuilder>
  auto getBaseProposalBuilder(bool transport_proposal) {
    return ProposalBuilder(transport_proposal)
        .createdTime(created_time)
        .height(1);
  }

  auto createProposalWithDuplicateTransactions() {
    std::vector<shared_model::proto::Transaction> txs;
    txs.push_back(createTransaction());
    txs.push_back(createTransaction());
    return getBaseProposalBuilder<shared_model::proto::ProposalBuilder>(true)
        .transactions(txs)
        .build();
  }

 protected:
  shared_model::crypto::Keypair keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
};

/**
 * @given a proposal with a transaction
 * @when transaction's batch meta contains info about two transactions
 * @then such proposal should be rejected
 */
TEST_F(ProposalValidatorTest, IncompleteBatch) {
  auto txs = framework::batch::createBatchOneSignTransactions(
      std::vector<BatchTypeAndCreatorPair>{
          BatchTypeAndCreatorPair{
              shared_model::interface::types::BatchType::ATOMIC, "a@domain"},
          BatchTypeAndCreatorPair{
              shared_model::interface::types::BatchType::ATOMIC, "b@domain"}});
  std::vector<shared_model::proto::Transaction> proto_txs;
  proto_txs.push_back(*std::move(
      std::static_pointer_cast<shared_model::proto::Transaction>(txs[0])));
  auto proposal = std::make_shared<shared_model::proto::Proposal>(
      TestProposalBuilder()
          .height(1)
          .createdTime(txs[0]->createdTime())
          .transactions(proto_txs)
          .build());

  ASSERT_TRUE(validator_.validate(*proposal));
}

/**
 * @given a transport proposal with duplicate transactions
 * @when proposal is validated
 * @then result is OK
 */
TEST_F(ProposalValidatorTest, TransportProposalWithDuplicateTransactions) {
  auto proposal = createProposalWithDuplicateTransactions();

  shared_model::validation::DefaultProposalValidator validator(
      iroha::test::kProposalTestsValidatorsConfig);

  ASSERT_EQ(validator.validate(proposal), std::nullopt);
}

/**
 * @given a proposal with duplicate transactions
 * @when proposal is validated
 * @then error appears after validation
 */
TEST_F(ProposalValidatorTest, ProposalWithDuplicateTransactions) {
  auto proposal = createProposalWithDuplicateTransactions();

  auto error = validator_.validate(proposal);
  ASSERT_TRUE(error);
  ASSERT_THAT(error->toString(), testing::HasSubstr("Duplicates transaction"));
}

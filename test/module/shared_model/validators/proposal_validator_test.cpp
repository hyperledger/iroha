/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/validators/validators_fixture.hpp"

#include <gtest/gtest.h>

#include "framework/batch_helper.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_proposal_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "validators/default_validator.hpp"

using namespace shared_model::validation;

class ProposalValidatorTest : public ValidatorsTest {
 public:
  ProposalValidatorTest() : validator_(iroha::test::kTestsValidatorsConfig) {}

  using BatchTypeAndCreatorPair =
      std::pair<shared_model::interface::types::BatchType, std::string>;

  DefaultProposalValidator validator_;
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

  auto answer = validator_.validate(*proposal);
  ASSERT_TRUE(answer);
}

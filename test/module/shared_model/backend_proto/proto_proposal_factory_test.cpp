/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "backend/protobuf/proto_proposal_factory.hpp"
#include "backend/protobuf/transaction.hpp"
#include "framework/result_fixture.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/validators/validators.hpp"
#include "validators/default_validator.hpp"
#include "validators/field_validator.hpp"

using namespace shared_model;
using namespace framework::expected;

class ProposalFactoryTest : public ::testing::Test {
 public:
  ProposalFactoryTest()
      : valid_factory(iroha::test::kTestsValidatorsConfig),
        factory(iroha::test::kTestsValidatorsConfig) {}

  shared_model::proto::ProtoProposalFactory<validation::AlwaysValidValidator>
      valid_factory;
  shared_model::proto::ProtoProposalFactory<
      validation::DefaultProposalValidator>
      factory;

  interface::types::HeightType height{1};
  iroha::time::time_t time{iroha::time::now()};

  std::vector<proto::Transaction> txs;

  void SetUp() override {
    txs.emplace_back(iroha::protocol::Transaction{});
  }

  void TearDown() override {
    txs.clear();
  }
};

/**
 * @given proposal factory and valid data
 * @when proposal is created using factory
 * @then proposal is successfully created
 */
TEST_F(ProposalFactoryTest, ValidProposalTest) {
  std::vector<proto::Transaction> txs;
  iroha::protocol::Transaction proto_tx;
  txs.emplace_back(proto_tx);
  auto proposal = valid_factory.createProposal(height, time, txs);

  proposal.match(
      [&](const auto &v) {
        ASSERT_EQ(txs, v.value->transactions());
        ASSERT_EQ(height, v.value->height());
        ASSERT_EQ(time, v.value->createdTime());
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given proposal factory and invalid data (empty transaction)
 * @when proposal is created using factory
 * @then proposal is not created successfully
 */
TEST_F(ProposalFactoryTest, InvalidProposalTest) {
  auto proposal = factory.createProposal(height, time, txs);

  proposal.match([&](const auto &) { FAIL() << "unexpected value case"; },
                 [](const auto &) { SUCCEED(); });
}

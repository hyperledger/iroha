/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_os_server_grpc.hpp"

#include <gtest/gtest.h>
#include "backend/protobuf/proposal.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/transaction.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "main/subscription.hpp"
#include "module/irohad/ordering/mock_on_demand_os_notification.hpp"
#include "module/shared_model/interface/mock_transaction_batch_factory.hpp"
#include "module/shared_model/validators/validators.hpp"

using namespace iroha;
using namespace iroha::ordering;
using namespace iroha::ordering::transport;

using ::testing::_;
using ::testing::A;
using ::testing::ByMove;
using ::testing::Invoke;
using ::testing::Return;

struct OnDemandOsServerGrpcTest : public ::testing::Test {
  std::shared_ptr<Subscription> se_ = getSubscription();
  ~OnDemandOsServerGrpcTest() {
    se_->dispose();
  }

  void SetUp() override {
    notification = std::make_shared<MockOdOsNotification>();
    std::unique_ptr<shared_model::validation::AbstractValidator<
        shared_model::interface::Transaction>>
        interface_transaction_validator =
            std::make_unique<shared_model::validation::MockValidator<
                shared_model::interface::Transaction>>();
    std::unique_ptr<
        shared_model::validation::AbstractValidator<protocol::Transaction>>
        proto_transaction_validator = std::make_unique<
            shared_model::validation::MockValidator<protocol::Transaction>>();
    auto transaction_factory =
        std::make_shared<shared_model::proto::ProtoTransportFactory<
            shared_model::interface::Transaction,
            shared_model::proto::Transaction>>(
            std::move(interface_transaction_validator),
            std::move(proto_transaction_validator));
    auto batch_parser =
        std::make_shared<shared_model::interface::TransactionBatchParserImpl>();
    batch_factory = std::make_shared<MockTransactionBatchFactory>();
    server =
        std::make_shared<OnDemandOsServerGrpc>(notification,
                                               std::move(transaction_factory),
                                               std::move(batch_parser),
                                               batch_factory,
                                               getTestLogger("OdOsServerGrpc"));
  }

  std::shared_ptr<MockOdOsNotification> notification;
  std::shared_ptr<MockTransactionBatchFactory> batch_factory;
  std::shared_ptr<OnDemandOsServerGrpc> server;
  consensus::Round round{1, 2};
};

/**
 * Separate action required because CollectionType is non-copyable
 */
ACTION_P(SaveArg0Move, var) {
  *var = std::move(arg0);
}

/**
 * @given server
 * @when collection is received from the network
 * @then it is correctly deserialized and passed
 */
TEST_F(OnDemandOsServerGrpcTest, SendBatches) {
  OdOsNotification::CollectionType collection;
  auto creator = "test";

  EXPECT_CALL(
      *batch_factory,
      createTransactionBatch(
          A<const shared_model::interface::types::SharedTxsCollectionType &>()))
      .WillOnce(Invoke(
          [](const shared_model::interface::types::SharedTxsCollectionType
                 &cand)
              -> shared_model::interface::TransactionBatchFactory::
                  FactoryResult<std::unique_ptr<
                      shared_model::interface::TransactionBatch>> {
                    return iroha::expected::makeValue<std::unique_ptr<
                        shared_model::interface::TransactionBatch>>(
                        std::make_unique<
                            shared_model::interface::TransactionBatchImpl>(
                            cand));
                  }));
  EXPECT_CALL(*notification, onBatches(_)).WillOnce(SaveArg0Move(&collection));
  proto::BatchesRequest request;
  request.add_transactions()
      ->mutable_payload()
      ->mutable_reduced_payload()
      ->set_creator_account_id(creator);

  server->SendBatches(nullptr, &request, nullptr);

  ASSERT_EQ(collection.at(0)->transactions().at(0)->creatorAccountId(),
            creator);
}

/**
 * @given server
 * @when proposal is requested
 * AND proposal returned
 * @then it is correctly serialized
 */
TEST_F(OnDemandOsServerGrpcTest, RequestProposal) {
  auto creator = "test";
  proto::ProposalRequest request;
  request.mutable_round()->set_block_round(round.block_round);
  request.mutable_round()->set_reject_round(round.reject_round);
  proto::ProposalResponse response;
  protocol::Proposal proposal;
  proposal.add_transactions()
      ->mutable_payload()
      ->mutable_reduced_payload()
      ->set_creator_account_id(creator);

  std::shared_ptr<const shared_model::interface::Proposal> iproposal(
      std::make_shared<const shared_model::proto::Proposal>(proposal));
  EXPECT_CALL(*notification, onRequestProposal(round))
      .WillOnce(Return(ByMove(std::move(iproposal))));

  server->RequestProposal(nullptr, &request, &response);

  ASSERT_TRUE(response.has_proposal());
  ASSERT_EQ(response.proposal()
                .transactions()
                .Get(0)
                .payload()
                .reduced_payload()
                .creator_account_id(),
            creator);
}

/**
 * @given server
 * @when proposal is requested
 * AND no proposal returned
 * @then the result is correctly serialized
 */
TEST_F(OnDemandOsServerGrpcTest, RequestProposalNone) {
  proto::ProposalRequest request;
  request.mutable_round()->set_block_round(round.block_round);
  request.mutable_round()->set_reject_round(round.reject_round);
  proto::ProposalResponse response;
  EXPECT_CALL(*notification, onRequestProposal(round))
      .WillOnce(Return(ByMove(std::move(boost::none))));

  server->RequestProposal(nullptr, &request, &response);

  ASSERT_FALSE(response.has_proposal());
}

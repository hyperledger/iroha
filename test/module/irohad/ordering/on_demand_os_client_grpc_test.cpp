/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_os_client_grpc.hpp"

#include <gtest/gtest.h>
#include "backend/protobuf/proposal.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/transaction.hpp"
#include "framework/mock_stream.h"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/shared_model/validators/validators.hpp"
#include "ordering/impl/os_executor_keepers.hpp"
#include "ordering_mock.grpc.pb.h"

using namespace iroha;
using namespace iroha::ordering;
using namespace iroha::ordering::transport;

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;

class OnDemandOsClientGrpcTest : public ::testing::Test {
 public:
  using ProtoProposalTransportFactory =
      shared_model::proto::ProtoTransportFactory<
          shared_model::interface::Proposal,
          shared_model::proto::Proposal>;
  using ProposalTransportFactory =
      shared_model::interface::AbstractTransportFactory<
          shared_model::interface::Proposal,
          shared_model::proto::Proposal::TransportType>;
  using MockProposalValidator = shared_model::validation::MockValidator<
      shared_model::interface::Proposal>;
  using MockProtoProposalValidator =
      shared_model::validation::MockValidator<iroha::protocol::Proposal>;

  void TearDown() override {
    proposals_subscription_->unsubscribe();
    proposals_subscription_.reset();
    subscription->dispose();
  }

  void SetUp() override {
    subscription = iroha::getSubscription();
    auto ustub = std::make_unique<proto::MockOnDemandOrderingStub>();
    stub = ustub.get();
    auto validator = std::make_unique<MockProposalValidator>();
    proposal_validator = validator.get();
    auto proto_validator = std::make_unique<MockProtoProposalValidator>();
    proto_proposal_validator = proto_validator.get();
    proposal_factory = std::make_shared<ProtoProposalTransportFactory>(
        std::move(validator), std::move(proto_validator));
    auto exec_keeper = std::make_shared<ExecutorKeeper>();

    struct Peer {
      std::string pk;
      Peer(std::string_view p) : pk(p) {}
      std::string &pubkey() {
        return pk;
      }
    };

    std::shared_ptr<Peer> pk[] = {std::make_shared<Peer>("123")};
    exec_keeper->syncronize(&pk[0], &pk[1]);

    proposals_subscription_ =
        SubscriberCreator<bool, ProposalEvent>::template create<
            EventTypes::kOnProposalResponse>(
            iroha::SubscriptionEngineHandlers::kYac,
            [this](auto, auto event) { received_event = event; });

    client =
        std::make_shared<OnDemandOsClientGrpc>(std::move(ustub),
                                               proposal_factory,
                                               [&] { return timepoint; },
                                               timeout,
                                               getTestLogger("OdOsClientGrpc"),
                                               exec_keeper,
                                               "123");
  }

  proto::MockOnDemandOrderingStub *stub;
  OnDemandOsClientGrpc::TimepointType timepoint;
  std::chrono::milliseconds timeout{1};
  std::shared_ptr<OnDemandOsClientGrpc> client;
  consensus::Round round{1, 2};
  ProposalEvent received_event;
  std::shared_ptr<BaseSubscriber<bool, ProposalEvent>> proposals_subscription_;
  std::shared_ptr<iroha::Subscription> subscription;

  MockProposalValidator *proposal_validator;
  MockProtoProposalValidator *proto_proposal_validator;
  std::shared_ptr<ProposalTransportFactory> proposal_factory;
};

/**
 * @given client
 * @when onBatches is called
 * @then data is correctly serialized and sent
 */
TEST_F(OnDemandOsClientGrpcTest, onBatches) {
  auto manager = getSubscription();

  proto::BatchesRequest request;
  EXPECT_CALL(*stub, SendBatches(_, _, _))
      .WillOnce(DoAll(SaveArg<1>(&request), Return(grpc::Status::OK)));

  OdOsNotification::CollectionType collection;
  auto creator = "test";
  protocol::Transaction tx;
  tx.mutable_payload()->mutable_reduced_payload()->set_creator_account_id(
      creator);
  collection.push_back(
      std::make_unique<shared_model::interface::TransactionBatchImpl>(
          shared_model::interface::types::SharedTxsCollectionType{
              std::make_unique<shared_model::proto::Transaction>(tx)}));

  auto scheduler = std::make_shared<subscription::SchedulerBase>();
  auto tid = getSubscription()->dispatcher()->bind(scheduler);

  uint64_t txCount = 1ull;
  auto batches_subscription =
      SubscriberCreator<bool, uint64_t>::template create<
          EventTypes::kSendBatchComplete>(
          static_cast<iroha::SubscriptionEngineHandlers>(*tid),
          [scheduler(utils::make_weak(scheduler)), &txCount](auto,
                                                             uint64_t count) {
            assert(count <= txCount);
            txCount -= count;
            if (txCount == 0ull)
              if (auto maybe_scheduler = scheduler.lock())
                maybe_scheduler->dispose();
          });

  client->onBatches(std::move(collection));

  scheduler->process();
  getSubscription()->dispatcher()->unbind(*tid);

  ASSERT_EQ(request.transactions()
                .Get(0)
                .payload()
                .reduced_payload()
                .creator_account_id(),
            creator);

  manager->dispose();
}

/**
 * Separate action required because ClientContext is non-copyable
 */
ACTION_P(SaveClientContextDeadline, deadline) {
  *deadline = arg0->deadline();
}

/**
 * @given client
 * @when onRequestProposal is called
 * AND proposal returned
 * @then data is correctly serialized and sent
 * AND reply is correctly deserialized
 */
TEST_F(OnDemandOsClientGrpcTest, onRequestProposal) {
  std::chrono::system_clock::time_point deadline;
  proto::ProposalRequest request;
  auto creator = "test";
  proto::ProposalResponse response;
  auto prop = response.add_proposal();
  prop->add_transactions()
      ->mutable_payload()
      ->mutable_reduced_payload()
      ->set_creator_account_id(creator);
#if USE_BLOOM_FILTER
  prop->set_proposal_hash("hash_1");
#endif  // USE_BLOOM_FILTER
  EXPECT_CALL(*stub, RequestProposal(_, _, _))
      .WillOnce(DoAll(SaveClientContextDeadline(&deadline),
                      SaveArg<1>(&request),
                      SetArgPointee<2>(response),
                      Return(grpc::Status::OK)));

  client->onRequestProposal(round, std::nullopt);

  ASSERT_EQ(timepoint + timeout, deadline);
  ASSERT_EQ(request.round().block_round(), round.block_round);
  ASSERT_EQ(request.round().reject_round(), round.reject_round);
  ASSERT_TRUE(!received_event.proposal_pack.empty());
  ASSERT_TRUE(received_event.proposal_pack[0]);
  ASSERT_EQ(
      received_event.proposal_pack[0]->transactions()[0].creatorAccountId(),
      creator);
}

/**
 * @given client
 * @when onRequestProposal is called
 * AND no proposal returned
 * @then data is correctly serialized and sent
 * AND reply is correctly deserialized
 */
TEST_F(OnDemandOsClientGrpcTest, onRequestProposalNone) {
  std::chrono::system_clock::time_point deadline;
  proto::ProposalRequest request;
  proto::ProposalResponse response;
  EXPECT_CALL(*stub, RequestProposal(_, _, _))
      .WillOnce(DoAll(SaveClientContextDeadline(&deadline),
                      SaveArg<1>(&request),
                      SetArgPointee<2>(response),
                      Return(grpc::Status::OK)));

  client->onRequestProposal(round, std::nullopt);

  ASSERT_EQ(timepoint + timeout, deadline);
  ASSERT_EQ(request.round().block_round(), round.block_round);
  ASSERT_EQ(request.round().reject_round(), round.reject_round);
  ASSERT_TRUE(received_event.proposal_pack.empty());
}

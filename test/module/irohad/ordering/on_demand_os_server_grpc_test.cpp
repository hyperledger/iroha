/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_os_server_grpc.hpp"

#include <grpcpp/impl/grpc_library.h>
#include <gtest/gtest.h>
#include <utility>

#include "backend/protobuf/proposal.hpp"
#include "backend/protobuf/proto_proposal_factory.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/transaction.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/ordering/mst_test_helpers.hpp"
#include "module/irohad/ordering/ordering_mocks.hpp"
#include "module/shared_model/interface/mock_transaction_batch_factory.hpp"
#include "module/shared_model/validators/validators.hpp"
#include "validators/default_validator.hpp"
#include "validators/field_validator.hpp"

using namespace iroha;
using namespace iroha::ordering;
using namespace iroha::ordering::transport;

using ::testing::_;
using ::testing::A;
using ::testing::ByMove;
using ::testing::Invoke;
using ::testing::Return;

// required for g_core_codegen_interface intialization
static grpc::internal::GrpcLibraryInitializer g_gli_initializer;

struct OnDemandOsServerGrpcTest : public ::testing::Test {
  void SetUp() override {
    notification = std::make_shared<MockOnDemandOrderingService>();
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
                                               getTestLogger("OdOsServerGrpc"),
                                               std::chrono::seconds(0));
  }

  std::shared_ptr<MockOnDemandOrderingService> notification;
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

  grpc::ServerContext context;
  server->SendBatches(&context, &request, nullptr);

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

  PackedProposalData p{{std::make_pair(
      std::shared_ptr<const shared_model::interface::Proposal>(
          std::make_shared<const shared_model::proto::Proposal>(proposal)),
      ordering::BloomFilter256{})}};
  std::chrono::milliseconds delay(0);
  EXPECT_CALL(*notification, waitForLocalProposal(round, delay))
      .WillOnce(Return(ByMove(std::move(p))));

  grpc::ServerContext context;
  server->RequestProposal(&context, &request, &response);

  ASSERT_TRUE(!response.proposal().empty());
  ASSERT_EQ(response.proposal()[0]
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
  std::chrono::milliseconds delay(0);
  EXPECT_CALL(*notification, waitForLocalProposal(round, delay))
      .WillOnce(Return(ByMove(std::move(std::nullopt))));

  grpc::ServerContext context;
  server->RequestProposal(&context, &request, &response);

  ASSERT_FALSE(!response.proposal().empty());
}

void add2Proposal(
    iroha::protocol::Proposal &to,
    ordering::BloomFilter256 &bf,
    std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
  bf.set(batch->reducedHash());
  for (auto const &transaction : batch->transactions())
    *to.add_transactions() =
        static_cast<shared_model::proto::Transaction *>(transaction.get())
            ->getTransport();
}

std::tuple<iroha::protocol::Proposal, ordering::BloomFilter256> makeProposal(
    size_t batchCount,
    std::vector<shared_model::crypto::Hash> &hashes,
    shared_model::interface::types::TimestampType ts) {
  auto result =
      std::make_tuple(iroha::protocol::Proposal{}, ordering::BloomFilter256{});
  for (size_t ix = 1; ix <= batchCount; ++ix) {
    auto batch = makeTestBatch(txBuilder(ix, ts + ix, 1));
    hashes.emplace_back(batch->reducedHash());
    add2Proposal(std::get<0>(result), std::get<1>(result), batch);
  }
  return result;
}

#if USE_BLOOM_FILTER
TEST_F(OnDemandOsServerGrpcTest, DiffCalculation_wholeIntersection) {
  shared_model::proto::ProtoProposalFactory<
      shared_model::validation::DefaultProposalValidator>
      factory(iroha::test::kTestsValidatorsConfig);
  std::vector<shared_model::crypto::Hash> hashes;
  auto proposal = makeProposal(2, hashes, 10);

  proto::ProposalRequest request;
  request.mutable_round()->set_block_round(round.block_round);
  request.mutable_round()->set_reject_round(round.reject_round);
  request.set_bloom_filter(std::get<1>(proposal).load().data(),
                           std::get<1>(proposal).load().size());

  proto::ProposalResponse response;
  std::chrono::milliseconds delay(0);

  auto result = std::make_optional(
      std::make_pair(std::shared_ptr<shared_model::interface::Proposal>(
                         std::make_shared<shared_model::proto::Proposal>(
                             std::move(std::get<0>(proposal)))),
                     std::get<1>(proposal)));

  result->first->mut_transactions()[0].storeBatchHash(hashes[0]);
  result->first->mut_transactions()[1].storeBatchHash(hashes[1]);

  EXPECT_CALL(*notification, waitForLocalProposal(round, delay))
      .WillOnce(Return(ByMove(std::move(result))));

  grpc::ServerContext context;
  server->RequestProposal(&context, &request, &response);

  ASSERT_TRUE(response.has_proposal());
  ASSERT_TRUE(response.proposal().transactions().empty());
}
#endif  // USE_BLOOM_FILTER

TEST_F(OnDemandOsServerGrpcTest, DiffCalculation_noIntersection) {
  shared_model::proto::ProtoProposalFactory<
      shared_model::validation::DefaultProposalValidator>
      factory(iroha::test::kTestsValidatorsConfig);
  std::vector<shared_model::crypto::Hash> hashes_1;
  auto proposal_pack_1 = makeProposal(2, hashes_1, 10);

  std::vector<shared_model::crypto::Hash> hashes_2;
  auto proposal_pack_2 = makeProposal(2, hashes_2, 100);

  proto::ProposalRequest request;
  request.mutable_round()->set_block_round(round.block_round);
  request.mutable_round()->set_reject_round(round.reject_round);

#if USE_BLOOM_FILTER
  request.set_bloom_filter(std::get<1>(proposal_pack_1).load().data(),
                           std::get<1>(proposal_pack_1).load().size());
#endif  // USE_BLOOM_FILTER

  proto::ProposalResponse response;
  std::chrono::milliseconds delay(0);

  auto m = std::make_pair(std::shared_ptr<shared_model::interface::Proposal>(
                              std::make_shared<shared_model::proto::Proposal>(
                                  std::get<0>(proposal_pack_2))),
                          std::get<1>(proposal_pack_2));
  m.first->mut_transactions()[0].storeBatchHash(hashes_2[0]);
  m.first->mut_transactions()[1].storeBatchHash(hashes_2[1]);

  PackedProposalData result{{std::move(m)}};

  EXPECT_CALL(*notification, waitForLocalProposal(round, delay))
      .WillOnce(Return(ByMove(result)));

  grpc::ServerContext context;
  server->RequestProposal(&context, &request, &response);

  ASSERT_TRUE(!response.proposal().empty());
  assert(response.proposal()[0].transactions().size() == 2);
  ASSERT_TRUE(response.proposal()[0].transactions().size() == 2);

  ASSERT_TRUE(
      shared_model::proto::Transaction(response.proposal()[0].transactions()[0])
      == shared_model::proto::Transaction(
             std::get<0>(proposal_pack_2).transactions()[0]));
  ASSERT_TRUE(
      shared_model::proto::Transaction(response.proposal()[0].transactions()[1])
      == shared_model::proto::Transaction(
             std::get<0>(proposal_pack_2).transactions()[1]));
}

#if USE_BLOOM_FILTER
TEST_F(OnDemandOsServerGrpcTest, DiffCalculation_partIntersection) {
  shared_model::proto::ProtoProposalFactory<
      shared_model::validation::DefaultProposalValidator>
      factory(iroha::test::kTestsValidatorsConfig);
  std::vector<shared_model::crypto::Hash> hashes;
  auto proposal_pack = makeProposal(2, hashes, 10);

  proto::ProposalRequest request;
  request.mutable_round()->set_block_round(round.block_round);
  request.mutable_round()->set_reject_round(round.reject_round);
  request.set_bloom_filter(std::get<1>(proposal_pack).load().data(),
                           std::get<1>(proposal_pack).load().size());

  auto addition_batch = makeTestBatch(txBuilder(3, 100, 1));
  add2Proposal(
      std::get<0>(proposal_pack), std::get<1>(proposal_pack), addition_batch);

  proto::ProposalResponse response;
  std::chrono::milliseconds delay(0);

  auto result = std::make_optional(
      std::make_pair(std::shared_ptr<shared_model::interface::Proposal>(
                         std::make_shared<shared_model::proto::Proposal>(
                             std::get<0>(proposal_pack))),
                     std::get<1>(proposal_pack)));

  result->first->mut_transactions()[0].storeBatchHash(hashes[0]);
  result->first->mut_transactions()[1].storeBatchHash(hashes[1]);
  result->first->mut_transactions()[2].storeBatchHash(
      addition_batch->reducedHash());

  EXPECT_CALL(*notification, waitForLocalProposal(round, delay))
      .WillOnce(Return(ByMove(result)));

  grpc::ServerContext context;
  server->RequestProposal(&context, &request, &response);

  ASSERT_TRUE(response.has_proposal());
  assert(response.proposal().transactions().size() == 1);
  ASSERT_TRUE(response.proposal().transactions().size() == 1);

  ASSERT_TRUE(
      shared_model::proto::Transaction(response.proposal().transactions()[0])
      == shared_model::proto::Transaction(
             std::get<0>(proposal_pack).transactions()[2]));
}
#endif  // USE_BLOOM_FILTER

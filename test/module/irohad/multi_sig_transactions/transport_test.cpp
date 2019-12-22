/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/transport/mst_transport_grpc.hpp"

#include <gtest/gtest.h>
#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "framework/mock_stream.h"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "module/irohad/ametsuchi/ametsuchi_mocks.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/multi_sig_transactions/mst_mocks.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "module/shared_model/validators/validators.hpp"
#include "mst_mock.grpc.pb.h"
#include "multi_sig_transactions/state/mst_state.hpp"
#include "validators/default_validator.hpp"
#include "validators/field_validator.hpp"
#include "validators/protobuf/proto_transaction_validator.hpp"

using namespace iroha::network;
using namespace iroha::model;
using namespace shared_model::interface;

using ::testing::_;
using ::testing::A;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;

class TransportTest : public ::testing::Test {
 public:
  TransportTest()
      : my_key_(makeKey()),
        stub(new iroha::network::transport::MockMstTransportGrpcStub()) {}
  void SetUp() override {
    async_call_ = std::make_shared<AsyncGrpcClient<google::protobuf::Empty>>(
        getTestLogger("AsyncClient"));
    parser_ = std::make_shared<TransactionBatchParserImpl>();
    batch_validator_ =
        std::make_shared<shared_model::validation::DefaultBatchValidator>(
            iroha::test::kTestsValidatorsConfig);
    batch_factory_ =
        std::make_shared<TransactionBatchFactoryImpl>(batch_validator_);
    tx_presence_cache_ =
        std::make_shared<iroha::ametsuchi::MockTxPresenceCache>();
    completer_ =
        std::make_shared<iroha::DefaultCompleter>(std::chrono::minutes(0));
    mst_notification_transport_ =
        std::make_shared<iroha::MockMstTransportNotification>();
    interface_tx_validator =
        std::make_unique<shared_model::validation::MockValidator<
            shared_model::interface::Transaction>>();
    proto_tx_validator =
        std::make_unique<shared_model::validation::MockValidator<
            iroha::protocol::Transaction>>();
    tx_factory = std::make_shared<shared_model::proto::ProtoTransportFactory<
        shared_model::interface::Transaction,
        shared_model::proto::Transaction>>(std::move(interface_tx_validator),
                                           std::move(proto_tx_validator));
    // TODO 18.06.19 (@alex9430) fix the test so that neither boost::none, nor
    // nullptr is in use with sender_factory
    MstTransportGrpc::SenderFactory sender_factory_(
        [this](const shared_model::interface::Peer &peer) {
          return std::unique_ptr<transport::MstTransportGrpc::StubInterface>(
              stub);
        });
    transport =
        std::make_shared<MstTransportGrpc>(async_call_,
                                           tx_factory,
                                           parser_,
                                           batch_factory_,
                                           tx_presence_cache_,
                                           completer_,
                                           my_key_.publicKey(),
                                           getTestLogger("MstState"),
                                           getTestLogger("MstTransportGrpc"),
                                           sender_factory_);
    transport->subscribe(mst_notification_transport_);

    shared_model::interface::types::PubkeyType pk(
        shared_model::crypto::Hash::fromHexString(
            "abcdabcdabcdabcdabcdabcdabcdabcd"));
    peer = makePeer("localhost:0", pk);
  }

  std::shared_ptr<AsyncGrpcClient<google::protobuf::Empty>> async_call_;
  std::shared_ptr<TransactionBatchParserImpl> parser_;
  std::shared_ptr<shared_model::validation::AbstractValidator<
      shared_model::interface::TransactionBatch>>
      batch_validator_;
  std::shared_ptr<TransactionBatchFactoryImpl> batch_factory_;
  std::shared_ptr<iroha::ametsuchi::MockTxPresenceCache> tx_presence_cache_;
  shared_model::crypto::Keypair my_key_;
  std::shared_ptr<iroha::DefaultCompleter> completer_;
  std::shared_ptr<iroha::MockMstTransportNotification>
      mst_notification_transport_;
  std::unique_ptr<shared_model::validation::MockValidator<
      shared_model::interface::Transaction>>
      interface_tx_validator;
  std::unique_ptr<
      shared_model::validation::MockValidator<iroha::protocol::Transaction>>
      proto_tx_validator;
  std::shared_ptr<shared_model::proto::ProtoTransportFactory<
      shared_model::interface::Transaction,
      shared_model::proto::Transaction>>
      tx_factory;
  std::shared_ptr<MstTransportGrpc> transport;
  std::shared_ptr<shared_model::interface::Peer> peer;
  // stub will be deleted by unique_ptr created in client_creator
  iroha::network::transport::MockMstTransportGrpcStub *stub;
};

static bool statesEqual(const iroha::MstState &a, const iroha::MstState &b) {
  // treat them like sets of batches:
  return (a - b).isEmpty() and (b - a).isEmpty();
}

/**
 * @brief Sends data over MstTransportGrpc (MstState and Peer objects) and
 * receives them. When received deserializes them end ensures that deserialized
 * objects equal to objects before sending.
 *
 * @given Initialized transport
 * AND MstState for transfer
 * @when Send state via transport
 * @then Assume that received state same as sent
 */
TEST_F(TransportTest, SendAndReceive) {
  EXPECT_CALL(*tx_presence_cache_,
              check(A<const shared_model::interface::TransactionBatch &>()))
      .WillRepeatedly(Invoke([](const auto &batch) {
        iroha::ametsuchi::TxPresenceCache::BatchStatusCollectionType result;
        std::transform(
            batch.transactions().begin(),
            batch.transactions().end(),
            std::back_inserter(result),
            [](auto &tx) {
              return iroha::ametsuchi::tx_cache_status_responses::Missing{
                  tx->hash()};
            });
        return result;
      }));
  auto time = iroha::time::now();
  auto state = iroha::MstState::empty(getTestLogger("MstState"), completer_);
  state += addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, time)), 0, makeKey());
  state += addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(2, time)), 0, makeKey());
  state += addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(3, time)), 0, makeKey());
  state += addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(3, time)), 0, makeKey());
  ASSERT_EQ(3, state.getBatches().size());
  // we want to ensure that server side will call onNewState()
  // with same parameters as on the client side
  EXPECT_CALL(*mst_notification_transport_, onNewState(_, _))
      .WillOnce(Invoke(
          [this, &state](const auto &from_key, auto const &target_state) {
            EXPECT_EQ(this->my_key_.publicKey(), from_key);
            EXPECT_TRUE(statesEqual(state, target_state));
          }));

  ::grpc::ServerContext context;
  ::iroha::network::transport::MstState request;
  auto r = std::make_unique<
      grpc::testing::MockClientAsyncResponseReader<google::protobuf::Empty>>();
  EXPECT_CALL(*stub, AsyncSendStateRaw(_, _, _))
      .WillOnce(DoAll(SaveArg<1>(&request), Return(r.get())));
  transport->sendState(*peer, state);
  auto response = transport->SendState(&context, &request, nullptr);
  ASSERT_EQ(response.error_code(), grpc::StatusCode::OK);
}

/**
 * Checks that replayed transactions would not pass MST
 * (receiving of already processed transactions would not cause new state
 * generation)
 * @given an instance of MstTransportGrpc
 * @when exactly the same state reaches MST two times (in general, the state can
 * be different but should contain exactly the same batch both times)
 * @then for the first time the mock of tx_presence_cache says that the
 * transactions of the batch are not found in cache, and mst produced and
 * propagated new state that contains the batch. At the second time, the mock of
 * tx_presence cache says that the transactions from the batch were previously
 * rejected, so the state propagated via onNewState call would not contain the
 * test batch.
 */
TEST_F(TransportTest, ReplayAttack) {
  auto batch = makeTestBatch(txBuilder(1), txBuilder(2));
  auto state = iroha::MstState::empty(getTestLogger("MstState"), completer_);
  state += addSignaturesFromKeyPairs(
      addSignaturesFromKeyPairs(batch, 0, makeKey()), 1, makeKey());

  EXPECT_CALL(*mst_notification_transport_, onNewState(_, _))
      .Times(1)  // an empty state should not be propagated
      .WillOnce(
          Invoke([&batch](::testing::Unused, const iroha::MstState &state) {
            auto batches = state.getBatches();
            ASSERT_EQ(batches.size(), 1);
            ASSERT_EQ(**batches.begin(), *batch);
          }));

  auto transactions = batch->transactions();
  auto first_hash = transactions.at(0)->hash();
  auto second_hash = transactions.at(0)->hash();
  iroha::ametsuchi::TxPresenceCache::BatchStatusCollectionType
      first_mock_response{
          iroha::ametsuchi::tx_cache_status_responses::Missing{first_hash},
          iroha::ametsuchi::tx_cache_status_responses::Missing{second_hash}};
  iroha::ametsuchi::TxPresenceCache::BatchStatusCollectionType
      second_mock_response{
          iroha::ametsuchi::tx_cache_status_responses::Rejected{first_hash},
          iroha::ametsuchi::tx_cache_status_responses::Rejected{second_hash}};

  transport::MstState proto_state;
  proto_state.set_source_peer_key(
      shared_model::crypto::toBinaryString(my_key_.publicKey()));

  state.iterateTransactions([&proto_state](const auto &tx) {
    *proto_state.add_transactions() =
        std::static_pointer_cast<shared_model::proto::Transaction>(tx)
            ->getTransport();
  });

  grpc::ServerContext context;
  google::protobuf::Empty response;

  EXPECT_CALL(
      *tx_presence_cache_,
      check(
          ::testing::Matcher<const shared_model::interface::TransactionBatch &>(
              _)))
      .WillOnce(::testing::Return(first_mock_response))
      .WillOnce(::testing::Return(second_mock_response));

  transport->SendState(&context, &proto_state, &response);
  transport->SendState(&context, &proto_state, &response);
}

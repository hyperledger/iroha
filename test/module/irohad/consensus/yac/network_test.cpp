/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/transport/impl/consensus_service_impl.hpp"
#include "consensus/yac/transport/impl/network_impl.hpp"

#include <grpc++/grpc++.h>

#include "consensus/yac/transport/yac_pb_converters.hpp"
#include "framework/mock_stream.h"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/mock_client_factory.hpp"
#include "module/irohad/consensus/yac/mock_yac_crypto_provider.hpp"
#include "module/irohad/consensus/yac/mock_yac_network.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"
#include "yac_mock.grpc.pb.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::SaveArg;

namespace iroha::consensus::yac {
  class YacNetworkTest : public ::testing::Test {
   public:
    static constexpr auto default_ip = "0.0.0.0";
    static constexpr auto default_address = "0.0.0.0:0";

    template <typename ExpectationsSetter>
    auto expectConnection(const shared_model::interface::Peer &peer,
                          ExpectationsSetter &&set_expectations) {
      using namespace ::testing;
      auto stub = std::make_unique<iroha::consensus::yac::proto::MockYacStub>();
      std::forward<ExpectationsSetter>(set_expectations)(*stub);
      EXPECT_CALL(*mock_client_factory_, createClient(Ref(peer)))
          .WillOnce(Return(ByMove(std::move(stub))));
    }

    void SetUp() override {
      mock_client_factory_ =
          new iroha::network::MockClientFactory<NetworkImpl::Service>();
      network = std::make_shared<NetworkImpl>(
          std::unique_ptr<NetworkImpl::ClientFactory>(mock_client_factory_),
          getTestLogger("YacNetwork"));
      service =
          std::make_shared<ServiceImpl>(getTestLogger("Service"), [](auto) {});

      message.hash.vote_hashes.proposal_hash = "proposal";
      message.hash.vote_hashes.block_hash = "block";

      // getTransport is not used in network at the moment, please check if
      // test fails
      message.hash.block_signature = createSig();
      message.signature = createSig();
      message.hash.vote_round = {};

      int port = 0;
      peer = makePeer(std::string(default_ip) + ":" + std::to_string(port));
    }

    iroha::network::MockClientFactory<NetworkImpl::Service>
        *mock_client_factory_;
    std::shared_ptr<NetworkImpl> network;
    std::shared_ptr<ServiceImpl> service;
    std::shared_ptr<shared_model::interface::Peer> peer;
    VoteMessage message;
  };

  /**
   * @given initialized network
   * @when send vote to itself
   * @then vote handled
   */
  TEST_F(YacNetworkTest, MessageHandledWhenMessageSent) {
    proto::State request;
    expectConnection(*peer, [&request](auto &stub) {
      EXPECT_CALL(stub, SendState(_, _, _))
          .WillOnce(DoAll(SaveArg<1>(&request), Return(grpc::Status::OK)));
    });

    network->sendState(*peer, {message});

    ASSERT_EQ(request.votes_size(), 1);
  }

  /**
   * @given initialized network
   * @when send request with one vote
   * @then status OK
   */
  TEST_F(YacNetworkTest, SendMessage) {
    proto::State request;
    grpc::ServerContext context;

    auto pb_vote = request.add_votes();
    *pb_vote = PbConverters::serializeVote(message);

    auto response = service->SendState(&context, &request, nullptr);
    ASSERT_EQ(response.error_code(), grpc::StatusCode::OK);
  }

  /**
   * @given initialized network
   * @when send request with no votes
   * @then status CANCELLED
   */
  TEST_F(YacNetworkTest, SendMessageEmptyKeys) {
    proto::State request;
    grpc::ServerContext context;
    auto response = service->SendState(&context, &request, nullptr);
    ASSERT_EQ(response.error_code(), grpc::StatusCode::CANCELLED);
  }
}  // namespace iroha::consensus::yac

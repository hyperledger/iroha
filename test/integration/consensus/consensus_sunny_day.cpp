/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <thread>

#include <gmock/gmock.h>
#include <grpc++/grpc++.h>

#include "common/common.hpp"
#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/impl/timer_impl.hpp"
#include "consensus/yac/storage/buffered_cleanup_strategy.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "consensus/yac/storage/yac_vote_storage.hpp"
#include "consensus/yac/transport/impl/consensus_service_impl.hpp"
#include "consensus/yac/transport/impl/network_impl.hpp"
#include "consensus/yac/yac.hpp"
#include "main/subscription.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

#include "framework/stateless_valid_field_helpers.hpp"
#include "framework/test_client_factory.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "module/irohad/consensus/yac/mock_yac_crypto_provider.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "network/impl/client_factory.hpp"

using ::testing::_;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;

using namespace iroha::consensus::yac;

// TODO mboldyrev 14.02.2019 IR-324 Use supermajority checker mock
static const iroha::consensus::yac::ConsistencyModel kConsistencyModel =
    iroha::consensus::yac::ConsistencyModel::kBft;

static size_t num_peers = 1, my_num = 0;

auto mk_local_peer(uint64_t num) {
  auto address = "127.0.0.1:" + std::to_string(num);
  return iroha::consensus::yac::makePeer(address);
}

class ConsensusSunnyDayTest : public ::testing::Test {
 public:
  std::shared_ptr<iroha::Subscription> subscription;
  std::shared_ptr<CleanupStrategy> cleanup_strategy;
  std::unique_ptr<grpc::Server> server;
  std::shared_ptr<NetworkImpl> network;
  std::shared_ptr<ServiceImpl> service;
  std::shared_ptr<MockYacCryptoProvider> crypto;
  std::shared_ptr<TimerImpl> timer;
  uint64_t delay = 3 * 1000;
  std::shared_ptr<Yac> yac;

  static const size_t port = 50541;

  ConsensusSunnyDayTest() : my_peer(mk_local_peer(port + my_num)) {
    for (decltype(num_peers) i = 0; i < num_peers; ++i) {
      default_peers.push_back(mk_local_peer(port + i));
    }
    if (num_peers == 1) {
      delay_before = 0;
      delay_after = 5 * 1000;
    } else {
      delay_before = 10 * 1000;
      delay_after = 3 * default_peers.size() + 10 * 1000;
    }
  }

  void SetUp() override {
    subscription = iroha::getSubscription();
    cleanup_strategy =
        std::make_shared<iroha::consensus::yac::BufferedCleanupStrategy>();
    network = std::make_shared<NetworkImpl>(
        std::make_unique<
            iroha::network::ClientFactoryImpl<NetworkImpl::Service>>(
            iroha::network::getTestInsecureClientFactory(std::nullopt)),
        getTestLogger("YacNetwork"));
    crypto = std::make_shared<MockYacCryptoProvider>(
        shared_model::interface::types::PublicKeyHexStringView{
            my_peer->pubkey()});
    timer = std::make_shared<TimerImpl>(std::chrono::milliseconds(delay));
    auto order = ClusterOrdering::create(default_peers);
    ASSERT_TRUE(order);

    yac = Yac::create(
        YacVoteStorage(cleanup_strategy,
                       getSupermajorityChecker(kConsistencyModel),
                       getTestLoggerManager()->getChild("YacVoteStorage")),
        network,
        crypto,
        timer,
        order->getPeers(),
        initial_round,
        getTestLogger("Yac"));

    service = std::make_shared<ServiceImpl>(
        getTestLogger("Service"),
        [yac(iroha::utils::make_weak(yac)),
         this](std::vector<VoteMessage> state) {
          auto maybe_yac = yac.lock();
          if (not maybe_yac) {
            return;
          }
          auto maybe_answer = maybe_yac->onState(std::move(state));
          if (maybe_answer) {
            complete.set();
          }
        });

    grpc::ServerBuilder builder;
    int port = 0;
    builder.AddListeningPort(
        my_peer->address(), grpc::InsecureServerCredentials(), &port);
    builder.RegisterService(service.get());
    server = builder.BuildAndStart();
    ASSERT_TRUE(server);
    ASSERT_NE(port, 0);
  }

  void TearDown() override {
    server->Shutdown();
    subscription->dispose();
  }

  uint64_t delay_before, delay_after;
  std::shared_ptr<shared_model::interface::Peer> my_peer;
  std::vector<std::shared_ptr<shared_model::interface::Peer>> default_peers;
  iroha::consensus::Round initial_round{1, 1};
  iroha::utils::WaitForSingleObject complete;
};

/**
 * @given num_peers peers with initialized YAC
 * @when peers vote for same hash
 * @then commit is achieved
 */
TEST_F(ConsensusSunnyDayTest, SunnyDayTest) {
  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  // Wait for other peers to start
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_before));

  YacHash my_hash(initial_round, "proposal_hash", "block_hash");
  my_hash.block_signature =
      createSig(shared_model::interface::types::PublicKeyHexStringView{
          my_peer->pubkey()});
  auto order = ClusterOrdering::create(default_peers);
  ASSERT_TRUE(order);

  yac->vote(my_hash, *order);

  ASSERT_TRUE(complete.wait(std::chrono::milliseconds(delay_after)));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  if (argc == 3) {
    num_peers = std::stoul(argv[1]);
    my_num = std::stoul(argv[2]) + 1;
  }
  return RUN_ALL_TESTS();
}

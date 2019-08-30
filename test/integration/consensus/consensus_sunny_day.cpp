/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>
#include <grpc++/grpc++.h>

#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/impl/timer_impl.hpp"
#include "consensus/yac/storage/buffered_cleanup_strategy.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "consensus/yac/storage/yac_vote_storage.hpp"
#include "consensus/yac/transport/impl/network_impl.hpp"
#include "consensus/yac/yac.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"

#include "framework/test_logger.hpp"
#include "framework/test_subscriber.hpp"
#include "logger/logger_manager.hpp"
#include "module/irohad/consensus/yac/mock_yac_crypto_provider.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "network/impl/client_factory.hpp"

using ::testing::_;
using ::testing::An;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;

using namespace iroha::consensus::yac;
using namespace framework::test_subscriber;

// TODO mboldyrev 14.02.2019 IR-324 Use supermajority checker mock
static const iroha::consensus::yac::ConsistencyModel kConsistencyModel =
    iroha::consensus::yac::ConsistencyModel::kBft;

static size_t num_peers = 1, my_num = 0;

auto mk_local_peer(uint64_t num) {
  auto address = "0.0.0.0:" + std::to_string(num);
  return iroha::consensus::yac::makePeer(address);
}

class FixedCryptoProvider : public MockYacCryptoProvider {
 public:
  explicit FixedCryptoProvider(const std::string &public_key) {
    std::string key(
        shared_model::crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, 0);
    std::copy(public_key.begin(), public_key.end(), key.begin());
    pubkey = clone(shared_model::crypto::PublicKey(key));
    data = std::make_unique<shared_model::crypto::Signed>("");
  }

  VoteMessage getVote(YacHash hash) override {
    auto vote = MockYacCryptoProvider::getVote(hash);
    auto signature = std::make_shared<MockSignature>();
    EXPECT_CALL(*signature, publicKey())
        .WillRepeatedly(testing::ReturnRef(*pubkey));
    EXPECT_CALL(*signature, signedData())
        .WillRepeatedly(testing::ReturnRef(*data));
    vote.signature = signature;
    return vote;
  }

  std::unique_ptr<shared_model::crypto::PublicKey> pubkey;
  std::unique_ptr<shared_model::crypto::Signed> data;
};

class ConsensusSunnyDayTest : public ::testing::Test {
 public:
  std::shared_ptr<CleanupStrategy> cleanup_strategy;
  std::unique_ptr<grpc::Server> server;
  std::shared_ptr<NetworkImpl> network;
  std::shared_ptr<MockYacCryptoProvider> crypto;
  std::shared_ptr<TimerImpl> timer;
  uint64_t delay = 3 * 1000;
  std::shared_ptr<Yac> yac;

  static const size_t port = 50541;

  ConsensusSunnyDayTest()
      : my_peer(mk_local_peer(port + my_num)),
        my_pub_key(shared_model::crypto::toBinaryString(my_peer->pubkey())) {
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
    cleanup_strategy =
        std::make_shared<iroha::consensus::yac::BufferedCleanupStrategy>();
    auto async_call = std::make_shared<
        iroha::network::AsyncGrpcClient<google::protobuf::Empty>>(
        getTestLogger("AsyncCall"));
    iroha::network::ClientFactory client_factory;
    network = std::make_shared<NetworkImpl>(
        async_call,
        [&client_factory](const shared_model::interface::Peer &peer) {
          return client_factory.createClient<proto::Yac>(peer.address());
        },
        getTestLogger("YacNetwork"));
    crypto = std::make_shared<FixedCryptoProvider>(my_pub_key);
    timer = std::make_shared<TimerImpl>(std::chrono::milliseconds(delay),
                                        rxcpp::observe_on_new_thread());
    auto order = ClusterOrdering::create(default_peers);
    ASSERT_TRUE(order);

    yac = Yac::create(
        YacVoteStorage(cleanup_strategy,
                       getSupermajorityChecker(kConsistencyModel),
                       getTestLoggerManager()->getChild("YacVoteStorage")),
        network,
        crypto,
        timer,
        order.value(),
        initial_round,
        rxcpp::observe_on_new_thread(),
        getTestLogger("Yac"));
    network->subscribe(yac);

    grpc::ServerBuilder builder;
    int port = 0;
    builder.AddListeningPort(
        my_peer->address(), grpc::InsecureServerCredentials(), &port);
    builder.RegisterService(network.get());
    server = builder.BuildAndStart();
    ASSERT_TRUE(server);
    ASSERT_NE(port, 0);
  }

  void TearDown() override {
    server->Shutdown();
  }

  uint64_t delay_before, delay_after;
  std::shared_ptr<shared_model::interface::Peer> my_peer;
  const std::string my_pub_key;
  std::vector<std::shared_ptr<shared_model::interface::Peer>> default_peers;
  iroha::consensus::Round initial_round{1, 1};
};

/**
 * @given num_peers peers with initialized YAC
 * @when peers vote for same hash
 * @then commit is achieved
 */
TEST_F(ConsensusSunnyDayTest, SunnyDayTest) {
  auto wrapper = make_test_subscriber<CallExact>(
      yac->onOutcome()
          .timeout(std::chrono::milliseconds(delay_after),
                   rxcpp::observe_on_new_thread())
          .take(1)
          .as_blocking(),
      1);

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  // Wait for other peers to start
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_before));

  YacHash my_hash(initial_round, "proposal_hash", "block_hash");
  my_hash.block_signature = createSig(my_pub_key);
  auto order = ClusterOrdering::create(default_peers);
  ASSERT_TRUE(order);

  yac->vote(my_hash, *order);

  wrapper.subscribe([](auto) { std::cout << "^_^ COMMITTED!!!" << std::endl; },
                    [](std::exception_ptr ep) {
                      try {
                        std::rethrow_exception(ep);
                      } catch (const std::exception &e) {
                        FAIL() << "Error waiting for outcome: " << e.what();
                      }
                    });

  ASSERT_TRUE(wrapper.validate());
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  if (argc == 3) {
    num_peers = std::stoul(argv[1]);
    my_num = std::stoul(argv[2]) + 1;
  }
  return RUN_ALL_TESTS();
}

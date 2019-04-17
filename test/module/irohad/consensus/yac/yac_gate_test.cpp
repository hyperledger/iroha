/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_gate_impl.hpp"

#include <memory>

#include <rxcpp/rx.hpp>
#include "consensus/consensus_block_cache.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/test_logger.hpp"
#include "framework/test_subscriber.hpp"
#include "module/irohad/consensus/yac/mock_yac_hash_gate.hpp"
#include "module/irohad/consensus/yac/mock_yac_hash_provider.hpp"
#include "module/irohad/consensus/yac/mock_yac_peer_orderer.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"
#include "module/irohad/simulator/simulator_mocks.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace iroha::consensus::yac;
using namespace iroha::network;
using namespace iroha::simulator;
using namespace framework::test_subscriber;
using namespace shared_model::crypto;
using iroha::consensus::ConsensusResultCache;

using ::testing::_;
using ::testing::An;
using ::testing::AtLeast;
using ::testing::Return;
using ::testing::ReturnRefOfCopy;

class YacGateTest : public ::testing::Test {
 public:
  void SetUp() override {
    auto keypair =
        shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();

    expected_hash = YacHash(round, "proposal", "block");

    auto block = std::make_shared<MockBlock>();
    EXPECT_CALL(*block, payload())
        .WillRepeatedly(ReturnRefOfCopy(Blob(std::string())));
    EXPECT_CALL(*block, addSignature(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*block, height()).WillRepeatedly(Return(1));
    EXPECT_CALL(*block, txsNumber()).WillRepeatedly(Return(0));
    EXPECT_CALL(*block, createdTime()).WillRepeatedly(Return(1));
    EXPECT_CALL(*block, transactions())
        .WillRepeatedly(
            Return<shared_model::interface::types::TransactionsCollectionType>(
                {}));
    EXPECT_CALL(*block, signatures())
        .WillRepeatedly(
            Return<shared_model::interface::types::SignatureRangeType>({}));
    auto prev_hash = Hash("prev hash");
    auto current_hash = Hash("current hash");
    EXPECT_CALL(*block, prevHash())
        .WillRepeatedly(testing::ReturnRefOfCopy(prev_hash));
    EXPECT_CALL(*block, hash())
        .WillRepeatedly(testing::ReturnRefOfCopy(current_hash));
    expected_block = block;

    auto signature = std::make_shared<MockSignature>();
    EXPECT_CALL(*signature, publicKey())
        .WillRepeatedly(ReturnRefOfCopy(expected_pubkey));
    EXPECT_CALL(*signature, signedData())
        .WillRepeatedly(ReturnRefOfCopy(expected_signed));

    expected_hash.block_signature = signature;
    message.hash = expected_hash;
    message.signature = signature;
    commit_message = CommitMessage({message});
    expected_commit = commit_message;

    auto hash_gate_ptr = std::make_unique<MockHashGate>();
    hash_gate = hash_gate_ptr.get();
    auto peer_orderer_ptr = std::make_unique<MockYacPeerOrderer>();
    peer_orderer = peer_orderer_ptr.get();
    hash_provider = std::make_shared<MockYacHashProvider>();
    block_creator = std::make_shared<MockBlockCreator>();
    block_cache = std::make_shared<ConsensusResultCache>();

    ON_CALL(*hash_gate, onOutcome())
        .WillByDefault(Return(outcome_notifier.get_observable()));

    ON_CALL(*block_creator, onBlock())
        .WillByDefault(Return(block_notifier.get_observable()));

    gate = std::make_shared<YacGateImpl>(std::move(hash_gate_ptr),
                                         std::move(peer_orderer_ptr),
                                         hash_provider,
                                         block_creator,
                                         block_cache,
                                         getTestLogger("YacGateImpl"));

    auto peer = makePeer("127.0.0.1", shared_model::crypto::PublicKey("111"));
    auto ledger_peers =
        std::make_shared<iroha::PeerList>(iroha::PeerList{peer});
    ledger_state = std::make_shared<iroha::LedgerState>(std::move(ledger_peers),
                                                        block->height());
  }

  iroha::consensus::Round round{1, 1};
  PublicKey expected_pubkey{"expected_pubkey"};
  Signed expected_signed{"expected_signed"};
  Hash prev_hash{"prev hash"};
  YacHash expected_hash;
  std::shared_ptr<const shared_model::interface::Proposal> expected_proposal;
  std::shared_ptr<shared_model::interface::Block> expected_block;
  VoteMessage message;
  CommitMessage commit_message;
  Answer expected_commit{commit_message};
  rxcpp::subjects::subject<BlockCreatorEvent> block_notifier;
  rxcpp::subjects::subject<Answer> outcome_notifier;

  MockHashGate *hash_gate;
  MockYacPeerOrderer *peer_orderer;
  std::shared_ptr<MockYacHashProvider> hash_provider;
  std::shared_ptr<MockBlockCreator> block_creator;
  std::shared_ptr<ConsensusResultCache> block_cache;

  std::shared_ptr<YacGateImpl> gate;
  std::shared_ptr<iroha::LedgerState> ledger_state;

 protected:
  YacGateTest() : commit_message(std::vector<VoteMessage>{}) {}
};

/**
 * @given yac gate
 * @when voting for the block @and receiving it on commit
 * @then yac gate will emit this block
 */
TEST_F(YacGateTest, YacGateSubscriptionTest) {
  // yac consensus
  EXPECT_CALL(*hash_gate, vote(expected_hash, _)).Times(1);

  // generate order of peers
  EXPECT_CALL(*peer_orderer, getOrdering(_, _))
      .WillOnce(Return(ClusterOrdering::create({makePeer("fake_node")})));

  // make hash from block
  EXPECT_CALL(*hash_provider, makeHash(_)).WillOnce(Return(expected_hash));

  block_notifier.get_subscriber().on_next(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});

  // verify that block we voted for is in the cache
  auto cache_block = block_cache->get();
  ASSERT_EQ(cache_block, expected_block);

  // verify that yac gate emit expected block
  auto gate_wrapper = make_test_subscriber<CallExact>(gate->onOutcome(), 1);
  gate_wrapper.subscribe([this](auto outcome) {
    auto block = boost::get<iroha::consensus::PairValid>(outcome).block;
    ASSERT_EQ(block, expected_block);

    // verify that gate has put to cache block received from consensus
    auto cache_block = block_cache->get();
    ASSERT_EQ(block, cache_block);
  });

  outcome_notifier.get_subscriber().on_next(expected_commit);

  ASSERT_TRUE(gate_wrapper.validate());
}

/**
 * @given yac gate, voting for the block @and receiving it on commit
 * @when voting for nothing
 * @then block cache is released
 */
TEST_F(YacGateTest, CacheReleased) {
  YacHash empty_hash;

  // yac consensus
  EXPECT_CALL(*hash_gate, vote(expected_hash, _)).Times(1);
  EXPECT_CALL(*hash_gate, vote(empty_hash, _)).Times(1);

  // generate order of peers
  EXPECT_CALL(*peer_orderer, getOrdering(_, _))
      .Times(2)
      .WillRepeatedly(Return(ClusterOrdering::create({makePeer("fake_node")})));

  // make hash from block
  EXPECT_CALL(*hash_provider, makeHash(_))
      .WillOnce(Return(expected_hash))
      .WillOnce(Return(empty_hash));

  block_notifier.get_subscriber().on_next(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});

  outcome_notifier.get_subscriber().on_next(expected_commit);
  round.reject_round++;

  gate->vote({boost::none, round, ledger_state});

  ASSERT_EQ(block_cache->get(), nullptr);
}

/**
 * @given yac gate
 * @when unsuccesfully trying to retrieve peers order
 * @then system will not crash
 */
TEST_F(YacGateTest, YacGateSubscribtionTestFailCase) {
  // yac consensus
  EXPECT_CALL(*hash_gate, vote(_, _)).Times(0);

  // generate order of peers
  EXPECT_CALL(*peer_orderer, getOrdering(_, _)).WillOnce(Return(boost::none));

  // make hash from block
  EXPECT_CALL(*hash_provider, makeHash(_)).WillOnce(Return(expected_hash));

  block_notifier.get_subscriber().on_next(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});
}

/**
 * @given yac gate
 * @when voted on nothing
 * @then cache isn't changed
 */
TEST_F(YacGateTest, AgreementOnNone) {
  EXPECT_CALL(*hash_gate, vote(_, _)).Times(1);

  EXPECT_CALL(*peer_orderer, getOrdering(_, _))
      .WillOnce(Return(ClusterOrdering::create({makePeer("fake_node")})));

  ASSERT_EQ(block_cache->get(), nullptr);

  gate->vote({boost::none, round, ledger_state});

  ASSERT_EQ(block_cache->get(), nullptr);
}

/**
 * @given yac gate
 * @when voting for one block @and receiving another
 * @then yac gate will emit the data of block, for which consensus voted
 */
TEST_F(YacGateTest, DifferentCommit) {
  // make hash from block
  EXPECT_CALL(*hash_provider, makeHash(_)).WillOnce(Return(expected_hash));

  // generate order of peers
  EXPECT_CALL(*peer_orderer, getOrdering(_, _))
      .WillOnce(Return(ClusterOrdering::create({makePeer("fake_node")})));

  EXPECT_CALL(*hash_gate, vote(expected_hash, _)).Times(1);

  block_notifier.get_subscriber().on_next(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});

  // create another block, which will be "received", and generate a commit
  // message with it
  decltype(expected_block) actual_block = std::make_shared<MockBlock>();
  Hash actual_hash("actual_hash");
  PublicKey actual_pubkey("actual_pubkey");
  auto signature = std::make_shared<MockSignature>();
  EXPECT_CALL(*signature, publicKey())
      .WillRepeatedly(ReturnRefOfCopy(actual_pubkey));

  message.hash = YacHash(round, "actual_proposal", "actual_block");
  message.signature = signature;
  commit_message = CommitMessage({message});
  expected_commit = commit_message;

  // convert yac hash to model hash
  EXPECT_CALL(*hash_provider, toModelHash(message.hash))
      .WillOnce(Return(actual_hash));

  // verify that block we voted for is in the cache
  auto cache_block = block_cache->get();
  ASSERT_EQ(cache_block, expected_block);

  // verify that yac gate emit expected block
  auto gate_wrapper = make_test_subscriber<CallExact>(gate->onOutcome(), 1);
  gate_wrapper.subscribe([actual_hash, actual_pubkey](auto outcome) {
    auto concrete_outcome = boost::get<iroha::consensus::VoteOther>(outcome);
    auto public_keys = concrete_outcome.public_keys;
    auto hash = concrete_outcome.hash;

    ASSERT_EQ(1, public_keys.size());
    ASSERT_EQ(actual_pubkey, public_keys.front());
    ASSERT_EQ(hash, actual_hash);
  });

  outcome_notifier.get_subscriber().on_next(expected_commit);

  ASSERT_TRUE(gate_wrapper.validate());
}

/**
 * The fixture checks the following case for different types of commit messages
 * (VoteOther, AgreementOnNone, BlockReject, ProposalReject):
 * @given yac gate, in round (i, j) -> last block height is (i - 1)
 * @when reject for round (i, j + 1) is received
 * @then peer goes to round (i, j + 1)
 */
class CommitFromTheFuture : public YacGateTest {
 public:
  void SetUp() override {
    YacGateTest::SetUp();
    // make hash from block
    EXPECT_CALL(*hash_provider, makeHash(_)).WillOnce(Return(expected_hash));

    // generate order of peers
    EXPECT_CALL(*peer_orderer, getOrdering(_, _))
        .WillOnce(Return(ClusterOrdering::create({makePeer("fake_node")})));

    EXPECT_CALL(*hash_gate, vote(expected_hash, _)).Times(1);

    block_notifier.get_subscriber().on_next(BlockCreatorEvent{
        RoundData{expected_proposal, expected_block}, round, ledger_state});

    Hash actual_hash("actual_hash");
    PublicKey actual_pubkey("actual_pubkey");
    auto signature = std::make_shared<MockSignature>();
    EXPECT_CALL(*signature, publicKey())
        .WillRepeatedly(ReturnRefOfCopy(actual_pubkey));

    future_round =
        iroha::consensus::Round(round.block_round, round.reject_round + 1);
    message.hash = YacHash(future_round, "actual_proposal", "actual_block");
    message.signature = signature;
  }

  template <typename CommitType>
  void validate() {
    // verify that yac gate emit expected block
    auto gate_wrapper = make_test_subscriber<CallExact>(gate->onOutcome(), 1);
    gate_wrapper.subscribe([this](auto outcome) {
      auto concrete_outcome = boost::get<CommitType>(outcome);

      ASSERT_EQ(future_round, concrete_outcome.round);
    });

    outcome_notifier.get_subscriber().on_next(expected_commit);
    ASSERT_TRUE(gate_wrapper.validate());
  }

  iroha::consensus::Round future_round;
};

/**
 * @given yac gate, in round (i, j) -> last block height is (i - 1)
 * @when reject for round (i, j + 1) is received
 * @then peer goes to round (i, j + 1)
 */
TEST_F(CommitFromTheFuture, BlockReject) {
  expected_commit = RejectMessage({message});

  validate<iroha::consensus::BlockReject>();
}

/**
 * @given yac gate, in round (i, j) -> last block height is (i - 1)
 * @when reject with two proposals for round (i, j + 1) is received
 * @then peer goes to round (i, j + 1)
 */
TEST_F(CommitFromTheFuture, ProposalReject) {
  PublicKey second_actual_pubkey("actual_pubkey_2");
  auto second_signature = std::make_shared<MockSignature>();
  EXPECT_CALL(*second_signature, publicKey())
      .WillRepeatedly(ReturnRefOfCopy(second_actual_pubkey));

  VoteMessage second_message;
  second_message.hash =
      YacHash(future_round, "actual_proposal_2", "actual_block_2");
  second_message.signature = second_signature;
  expected_commit = RejectMessage({message, second_message});

  validate<iroha::consensus::ProposalReject>();
}

/**
 * @given yac gate, in round (i, j) -> last block height is (i - 1)
 * @when commit for round (i, j + 1) is received
 * @then peer goes to round (i, j + 1)
 */
TEST_F(CommitFromTheFuture, VoteOther) {
  expected_commit = CommitMessage({message});

  validate<iroha::consensus::VoteOther>();
}

/**
 * @given yac gate, in round (i, j) -> last block height is (i - 1)
 * @when commit without proposal (empty proposal hash) for round (i, j + 1) is
 * received
 * @then peer goes to round (i, j + 1)
 */
TEST_F(CommitFromTheFuture, AgreementOnNone) {
  message.hash = YacHash(future_round, "", "");
  expected_commit = CommitMessage({message});

  validate<iroha::consensus::AgreementOnNone>();
}

class YacGateOlderTest : public YacGateTest {
  void SetUp() override {
    YacGateTest::SetUp();

    // generate order of peers
    ON_CALL(*peer_orderer, getOrdering(_, _))
        .WillByDefault(
            Return(ClusterOrdering::create({makePeer("fake_node")})));

    // make hash from block
    ON_CALL(*hash_provider, makeHash(_)).WillByDefault(Return(expected_hash));

    block_notifier.get_subscriber().on_next(BlockCreatorEvent{
        RoundData{expected_proposal, expected_block}, round, ledger_state});
  }
};

/**
 * @given yac gate with current round initialized
 * @when vote for older round is called
 * @then vote is ignored
 */
TEST_F(YacGateOlderTest, OlderVote) {
  EXPECT_CALL(*hash_gate, vote(expected_hash, _)).Times(0);

  EXPECT_CALL(*peer_orderer, getOrdering(_, _)).Times(0);

  EXPECT_CALL(*hash_provider, makeHash(_)).Times(0);

  block_notifier.get_subscriber().on_next(BlockCreatorEvent{
      boost::none, {round.block_round - 1, round.reject_round}, ledger_state});
}

/**
 * @given yac gate with current round initialized
 * @when commit for older round is received
 * @then commit is ignored
 */
TEST_F(YacGateOlderTest, OlderCommit) {
  auto signature = std::make_shared<MockSignature>();
  EXPECT_CALL(*signature, publicKey())
      .WillRepeatedly(ReturnRefOfCopy(PublicKey("actual_pubkey")));

  VoteMessage message{YacHash({round.block_round - 1, round.reject_round},
                              "actual_proposal",
                              "actual_block"),
                      signature};
  Answer commit{CommitMessage({message})};

  auto gate_wrapper = make_test_subscriber<CallExact>(gate->onOutcome(), 0);
  gate_wrapper.subscribe();

  outcome_notifier.get_subscriber().on_next(commit);

  ASSERT_TRUE(gate_wrapper.validate());
}

/**
 * @given yac gate with current round initialized
 * @when reject for older round is received
 * @then reject is ignored
 */
TEST_F(YacGateOlderTest, OlderReject) {
  auto signature1 = std::make_shared<MockSignature>(),
       signature2 = std::make_shared<MockSignature>();
  EXPECT_CALL(*signature1, publicKey())
      .WillRepeatedly(ReturnRefOfCopy(PublicKey("actual_pubkey1")));
  EXPECT_CALL(*signature2, publicKey())
      .WillRepeatedly(ReturnRefOfCopy(PublicKey("actual_pubkey2")));

  VoteMessage message1{YacHash({round.block_round - 1, round.reject_round},
                               "actual_proposal1",
                               "actual_block1"),
                       signature1},
      message2{YacHash({round.block_round - 1, round.reject_round},
                       "actual_proposal2",
                       "actual_block2"),
               signature2};
  Answer reject{RejectMessage({message1, message2})};

  auto gate_wrapper = make_test_subscriber<CallExact>(gate->onOutcome(), 0);
  gate_wrapper.subscribe();

  outcome_notifier.get_subscriber().on_next(reject);

  ASSERT_TRUE(gate_wrapper.validate());
}

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>

#include "consensus/consensus_block_cache.hpp"
#include "consensus/yac/impl/yac_gate_impl.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "framework/crypto_literals.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "module/irohad/consensus/yac/mock_yac_crypto_provider.hpp"
#include "module/irohad/consensus/yac/mock_yac_hash_gate.hpp"
#include "module/irohad/consensus/yac/mock_yac_hash_provider.hpp"
#include "module/irohad/consensus/yac/mock_yac_peer_orderer.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"
#include "module/irohad/simulator/simulator_mocks.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace std::literals;
using namespace iroha::consensus::yac;
using namespace iroha::network;
using namespace iroha::simulator;
using namespace shared_model::crypto;
using namespace shared_model::interface::types;
using iroha::consensus::ConsensusResultCache;

using ::testing::_;
using ::testing::A;
using ::testing::AtLeast;
using ::testing::InSequence;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::ReturnRefOfCopy;

static const std::string kExpectedPubkey{"expected_hex_pubkey"};
static const std::string kActualPubkey{"actual_hex_pubkey"};
static const std::string kActualPubkey2{"actual_hex_pubkey_2"};

class YacGateTest : public ::testing::Test {
 public:
  void SetUp() override {
    auto keypair =
        shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();

    expected_hash = YacHash(round, "proposal", "block");

    auto block = std::make_shared<MockBlock>();
    EXPECT_CALL(*block, payload())
        .WillRepeatedly(ReturnRefOfCopy(Blob(std::string())));
    EXPECT_CALL(
        *block,
        addSignature(
            A<shared_model::interface::types::SignedHexStringView>(),
            A<shared_model::interface::types::PublicKeyHexStringView>()))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*block, height()).WillRepeatedly(Return(round.block_round));
    EXPECT_CALL(*block, createdTime()).WillRepeatedly(Return(1));
    EXPECT_CALL(*block, transactions())
        .WillRepeatedly(
            Return<shared_model::interface::types::TransactionsCollectionType>(
                {}));
    EXPECT_CALL(*block, signatures())
        .WillRepeatedly(
            Return<shared_model::interface::types::SignatureRangeType>({}));
    auto prev_hash = Hash(std::string("prev hash"));
    auto current_hash = Hash(std::string("current hash"));
    EXPECT_CALL(*block, prevHash())
        .WillRepeatedly(testing::ReturnRefOfCopy(prev_hash));
    EXPECT_CALL(*block, hash())
        .WillRepeatedly(testing::ReturnRefOfCopy(current_hash));
    expected_block = block;

    auto signature = std::make_shared<MockSignature>();
    EXPECT_CALL(*signature, publicKey())
        .WillRepeatedly(ReturnRefOfCopy(kExpectedPubkey));
    EXPECT_CALL(*signature, signedData())
        .WillRepeatedly(ReturnRef(expected_signed));

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
    block_cache = std::make_shared<ConsensusResultCache>();

    auto peer = makePeer("127.0.0.1", "111"_hex_pubkey);
    ledger_state = std::make_shared<iroha::LedgerState>(
        shared_model::interface::types::PeerList{std::move(peer)},
        shared_model::interface::types::PeerList{
            makePeer("127.0.0.1", "222"_hex_pubkey)},
        block->height() - 1,
        block->prevHash());

    gate = std::make_shared<YacGateImpl>(std::move(hash_gate_ptr),
                                         std::move(peer_orderer_ptr),
                                         alternative_order,
                                         ledger_state,
                                         hash_provider,
                                         block_cache,
                                         getTestLogger("YacGateImpl"));
  }

  iroha::consensus::Round round{2, 1};
  std::optional<ClusterOrdering> alternative_order;
  std::string expected_signed{"expected_signed"};
  Hash prev_hash{std::string{"prev hash"}};
  YacHash expected_hash;
  std::shared_ptr<const shared_model::interface::Proposal> expected_proposal;
  std::shared_ptr<shared_model::interface::Block> expected_block;
  VoteMessage message;
  CommitMessage commit_message;
  Answer expected_commit{commit_message};

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
  EXPECT_CALL(*hash_gate, vote(expected_hash, _, _)).Times(1);

  // generate order of peers
  EXPECT_CALL(*peer_orderer, getOrdering(_, _))
      .WillOnce(Return(ClusterOrdering::create({makePeer("fake_node")})));

  // make hash from block
  EXPECT_CALL(*hash_provider, makeHash(_)).WillOnce(Return(expected_hash));

  gate->processRoundSwitch(round, ledger_state);
  gate->vote(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});

  // verify that block we voted for is in the cache
  auto cache_block = block_cache->get();
  ASSERT_EQ(cache_block, expected_block);

  // verify that yac gate emit expected block
  auto outcome = *gate->processOutcome(expected_commit);
  auto block = std::get<iroha::consensus::PairValid>(outcome).block;
  ASSERT_EQ(block, expected_block);

  // verify that gate has put to cache block received from consensus
  cache_block = block_cache->get();
  ASSERT_EQ(block, cache_block);
}

/**
 * @given yac gate, voting for the block @and receiving it on commit
 * @when voting for nothing
 * @then block cache is released
 */
TEST_F(YacGateTest, CacheReleased) {
  YacHash empty_hash({round.block_round, round.reject_round + 1},
                     ProposalHash(""),
                     BlockHash(""));

  // yac consensus
  EXPECT_CALL(*hash_gate, vote(expected_hash, _, _)).Times(1);
  EXPECT_CALL(*hash_gate, vote(empty_hash, _, _)).Times(1);

  // generate order of peers
  EXPECT_CALL(*peer_orderer, getOrdering(_, _))
      .Times(2)
      .WillRepeatedly(Return(ClusterOrdering::create({makePeer("fake_node")})));

  // make hash from block
  EXPECT_CALL(*hash_provider, makeHash(_))
      .WillOnce(Return(expected_hash))
      .WillOnce(Return(empty_hash));

  gate->processRoundSwitch(round, ledger_state);
  gate->vote(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});

  gate->processOutcome(expected_commit);
  round.reject_round++;

  gate->processRoundSwitch(round, ledger_state);
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
  EXPECT_CALL(*hash_gate, vote(_, _, _)).Times(0);

  // generate order of peers
  EXPECT_CALL(*peer_orderer, getOrdering(_, _)).WillOnce(Return(std::nullopt));

  // make hash from block
  EXPECT_CALL(*hash_provider, makeHash(_)).WillOnce(Return(expected_hash));

  gate->processRoundSwitch(round, ledger_state);
  gate->vote(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});
}

/**
 * @given yac gate
 * @when voted on nothing
 * @then cache isn't changed
 */
TEST_F(YacGateTest, AgreementOnNone) {
  EXPECT_CALL(*hash_gate, vote(_, _, _)).Times(1);

  EXPECT_CALL(*peer_orderer, getOrdering(_, _))
      .WillOnce(Return(ClusterOrdering::create({makePeer("fake_node")})));

  EXPECT_CALL(*hash_provider, makeHash(_))
      .WillOnce(Return(YacHash{round, ProposalHash(""), BlockHash("")}));

  ASSERT_EQ(block_cache->get(), nullptr);

  gate->processRoundSwitch(round, ledger_state);
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

  EXPECT_CALL(*hash_gate, vote(expected_hash, _, _)).Times(1);

  gate->processRoundSwitch(round, ledger_state);
  gate->vote(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});

  // create another block, which will be "received", and generate a commit
  // message with it
  decltype(expected_block) actual_block = std::make_shared<MockBlock>();
  Hash actual_hash(std::string("actual_hash"));
  auto signature = std::make_shared<MockSignature>();
  EXPECT_CALL(*signature, publicKey()).WillRepeatedly(ReturnRef(kActualPubkey));

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
  auto outcome = *gate->processOutcome(expected_commit);
  auto concrete_outcome = std::get<iroha::consensus::VoteOther>(outcome);
  auto public_keys = concrete_outcome.public_keys;
  auto hash = concrete_outcome.hash;

  ASSERT_EQ(1, public_keys.size());
  ASSERT_EQ(kActualPubkey, public_keys.front());
  ASSERT_EQ(hash, actual_hash);
}

/**
 * @given yac gate, in round (i, j) -> last block height is (i - 1)
 * @when vote for round (i + 1, j) is received
 * @then peer goes to round (i + 1, j)
 */
TEST_F(YacGateTest, Future) {
  // yac consensus
  EXPECT_CALL(*hash_gate, vote(expected_hash, _, _)).Times(1);

  // generate order of peers
  EXPECT_CALL(*peer_orderer, getOrdering(_, _))
      .WillOnce(Return(ClusterOrdering::create({makePeer("fake_node")})));

  // make hash from block
  EXPECT_CALL(*hash_provider, makeHash(_)).WillOnce(Return(expected_hash));

  gate->processRoundSwitch(round, ledger_state);
  gate->vote(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});

  iroha::consensus::Round future_round{round.block_round + 1,
                                       round.reject_round};
  auto signature = createSig(PublicKeyHexStringView{kActualPubkey});

  VoteMessage future_message{};
  future_message.hash =
      YacHash(future_round, "actual_proposal", "actual_block");
  future_message.signature = signature;

  // verify that yac gate emit expected block
  auto outcome = *gate->processOutcome(FutureMessage{future_message});
  auto concrete_outcome = std::get<iroha::consensus::Future>(outcome);

  ASSERT_EQ(future_round, concrete_outcome.round);
}

/**
 * @given yac gate, in round (i - 1, j)
 * @when another vote for round (i, j) is received while it is already being
 * processed
 * @then vote is ignored
 */
TEST_F(YacGateTest, OutdatedFuture) {
  // yac consensus
  EXPECT_CALL(*hash_gate, vote(expected_hash, _, _)).Times(1);

  // generate order of peers
  EXPECT_CALL(*peer_orderer, getOrdering(_, _))
      .WillOnce(Return(ClusterOrdering::create({makePeer("fake_node")})));

  // make hash from block
  EXPECT_CALL(*hash_provider, makeHash(_)).WillOnce(Return(expected_hash));

  gate->processRoundSwitch(round, ledger_state);
  gate->vote(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});

  // verify that yac gate does not emit anything
  auto outcome = gate->processOutcome(FutureMessage{message});
  ASSERT_FALSE(outcome);
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

    EXPECT_CALL(*hash_gate, vote(expected_hash, _, _)).Times(1);

    gate->processRoundSwitch(round, ledger_state);
    gate->vote(BlockCreatorEvent{
        RoundData{expected_proposal, expected_block}, round, ledger_state});

    Hash actual_hash(std::string("actual_hash"));
    auto signature = std::make_shared<MockSignature>();
    EXPECT_CALL(*signature, publicKey())
        .WillRepeatedly(ReturnRef(kActualPubkey));

    future_round =
        iroha::consensus::Round(round.block_round, round.reject_round + 1);
    message.hash = YacHash(future_round, "actual_proposal", "actual_block");
    message.signature = signature;
  }

  template <typename CommitType>
  void validate() {
    // verify that yac gate emit expected block
    auto outcome = *gate->processOutcome(expected_commit);
    auto concrete_outcome = std::get<CommitType>(outcome);

    ASSERT_EQ(future_round, concrete_outcome.round);
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
  auto second_signature = std::make_shared<MockSignature>();
  EXPECT_CALL(*second_signature, publicKey())
      .WillRepeatedly(ReturnRef(kActualPubkey2));

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

    gate->processRoundSwitch(round, ledger_state);
    gate->vote(BlockCreatorEvent{
        RoundData{expected_proposal, expected_block}, round, ledger_state});
  }
};

/**
 * @given yac gate with current round initialized
 * @when vote for older round is called
 * @then vote is ignored
 */
TEST_F(YacGateOlderTest, OlderVote) {
  EXPECT_CALL(*hash_gate, vote(expected_hash, _, _)).Times(0);

  EXPECT_CALL(*peer_orderer, getOrdering(_, _)).Times(0);

  EXPECT_CALL(*hash_provider, makeHash(_)).Times(0);

  gate->processRoundSwitch(round, ledger_state);

  --round.block_round;
  gate->vote(BlockCreatorEvent{boost::none, round, ledger_state});
}

/**
 * @given yac gate with current round initialized
 * @when commit for older round is received
 * @then commit is ignored
 */
TEST_F(YacGateOlderTest, OlderCommit) {
  auto signature = std::make_shared<MockSignature>();
  EXPECT_CALL(*signature, publicKey()).WillRepeatedly(ReturnRef(kActualPubkey));

  VoteMessage message{YacHash({round.block_round - 1, round.reject_round},
                              "actual_proposal",
                              "actual_block"),
                      signature};
  Answer commit{CommitMessage({message})};

  auto outcome = gate->processOutcome(commit);
  ASSERT_FALSE(outcome);
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
      .WillRepeatedly(ReturnRef(kActualPubkey));
  EXPECT_CALL(*signature2, publicKey())
      .WillRepeatedly(ReturnRef(kActualPubkey2));

  VoteMessage message1{YacHash({round.block_round - 1, round.reject_round},
                               "actual_proposal1",
                               "actual_block1"),
                       signature1},
      message2{YacHash({round.block_round - 1, round.reject_round},
                       "actual_proposal2",
                       "actual_block2"),
               signature2};
  Answer reject{RejectMessage({message1, message2})};

  auto outcome = gate->processOutcome(reject);
  ASSERT_FALSE(outcome);
}

class YacGateAlternativeOrderTest : public YacGateTest {
 protected:
  YacGateAlternativeOrderTest() {
    alternative_order = ClusterOrdering::create({makePeer("alternative_node")});
  }

  void SetUp() override {
    YacGateTest::SetUp();

    // generate order of peers
    EXPECT_CALL(*peer_orderer, getOrdering(_, _))
        .WillRepeatedly(
            Return(ClusterOrdering::create({makePeer("fake_node")})));

    // make hash from block
    EXPECT_CALL(*hash_provider, makeHash(_))
        .WillRepeatedly(Return(expected_hash));
  }
};

namespace iroha {
  namespace consensus {
    namespace yac {
      bool operator==(const ClusterOrdering &lhs, const ClusterOrdering &rhs) {
        return lhs.getPeers() == rhs.getPeers();
      }
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

/**
 * @given yac gate with initialized alternative order
 * @when vote is called
 * @then alternative order is used
 */
TEST_F(YacGateAlternativeOrderTest, AlternativeOrderUsed) {
  // yac consensus
  EXPECT_CALL(*hash_gate, vote(expected_hash, _, alternative_order)).Times(1);

  gate->processRoundSwitch(round, ledger_state);
  gate->vote(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});
}

/**
 * @given yac gate with initialized alternative order
 * @when vote is called twice
 * @then alternative order is used only the first time
 */
TEST_F(YacGateAlternativeOrderTest, AlternativeOrderUsedOnce) {
  // yac consensus
  {
    InSequence s;  // ensures the call order
    EXPECT_CALL(*hash_gate, vote(expected_hash, _, alternative_order)).Times(1);
    EXPECT_CALL(*hash_gate,
                vote(expected_hash, _, std::optional<ClusterOrdering>{}))
        .Times(1);
  }

  gate->processRoundSwitch(round, ledger_state);
  gate->vote(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, round, ledger_state});
  iroha::consensus::Round next_round{round.block_round + 1, 0};
  gate->processRoundSwitch(next_round, ledger_state);
  gate->vote(BlockCreatorEvent{
      RoundData{expected_proposal, expected_block}, next_round, ledger_state});
}

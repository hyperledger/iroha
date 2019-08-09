/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_ordering_gate.hpp"

#include <gtest/gtest.h>
#include <boost/range/adaptor/indirected.hpp>
#include "framework/test_logger.hpp"
#include "framework/test_subscriber.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/irohad/ametsuchi/mock_tx_presence_cache.hpp"
#include "module/irohad/ordering/mock_on_demand_os_notification.hpp"
#include "module/irohad/ordering/mock_proposal_creation_strategy.hpp"
#include "module/irohad/ordering/ordering_mocks.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "ordering/impl/on_demand_common.hpp"

using namespace iroha;
using namespace iroha::ordering;
using namespace iroha::ordering::transport;
using namespace iroha::network;
using namespace framework::test_subscriber;

using ::testing::_;
using ::testing::AtMost;
using ::testing::ByMove;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRefOfCopy;
using ::testing::Truly;
using ::testing::UnorderedElementsAre;
using ::testing::UnorderedElementsAreArray;

class OnDemandOrderingGateTest : public ::testing::Test {
 public:
  void SetUp() override {
    ordering_service = std::make_shared<MockOnDemandOrderingService>();
    notification = std::make_shared<MockOdOsNotification>();
    cache = std::make_shared<cache::MockOrderingGateCache>();
    auto ufactory = std::make_unique<NiceMock<MockUnsafeProposalFactory>>();
    factory = ufactory.get();
    tx_cache = std::make_shared<ametsuchi::MockTxPresenceCache>();
    proposal_creation_strategy =
        std::make_shared<MockProposalCreationStrategy>();
    ON_CALL(*tx_cache,
            check(testing::Matcher<const shared_model::crypto::Hash &>(_)))
        .WillByDefault(
            Return(boost::make_optional<ametsuchi::TxCacheStatusType>(
                iroha::ametsuchi::tx_cache_status_responses::Missing())));
    ordering_gate = std::make_shared<OnDemandOrderingGate>(
        ordering_service,
        notification,
        processed_tx_hashes.get_observable(),
        rounds.get_observable(),
        cache,
        std::move(ufactory),
        tx_cache,
        proposal_creation_strategy,
        1000,
        getTestLogger("OrderingGate"));

    auto peer = makePeer("127.0.0.1", shared_model::crypto::PublicKey("111"));
    ledger_state = std::make_shared<LedgerState>(
        shared_model::interface::types::PeerList{std::move(peer)},
        round.block_round,
        shared_model::crypto::Hash{"hash"});
  }

  rxcpp::subjects::subject<
      std::shared_ptr<const cache::OrderingGateCache::HashesSetType>>
      processed_tx_hashes;
  rxcpp::subjects::subject<OnDemandOrderingGate::RoundSwitch> rounds;
  std::shared_ptr<MockOnDemandOrderingService> ordering_service;
  std::shared_ptr<MockOdOsNotification> notification;
  NiceMock<MockUnsafeProposalFactory> *factory;
  std::shared_ptr<ametsuchi::MockTxPresenceCache> tx_cache;
  std::shared_ptr<MockProposalCreationStrategy> proposal_creation_strategy;
  std::shared_ptr<OnDemandOrderingGate> ordering_gate;

  std::shared_ptr<cache::MockOrderingGateCache> cache;

  const consensus::Round round = {2, kFirstRejectRound};

  std::shared_ptr<LedgerState> ledger_state;
};

/**
 * @given initialized ordering gate
 * @when a batch is received
 * @then it is passed to the ordering service
 */
TEST_F(OnDemandOrderingGateTest, propagateBatch) {
  auto hash1 = shared_model::interface::types::HashType("");
  auto batch = createMockBatchWithHash(hash1);
  OdOsNotification::CollectionType collection{batch};

  EXPECT_CALL(*cache, addToBack(UnorderedElementsAre(batch))).Times(1);
  EXPECT_CALL(*notification, onBatches(collection)).Times(1);

  ordering_gate->propagateBatch(batch);
}

/**
 * @given initialized ordering gate
 * @when a block round event with height is received from the PCS
 * AND a proposal is successfully retrieved from the network
 * @then new proposal round based on the received height is initiated
 */
TEST_F(OnDemandOrderingGateTest, BlockEvent) {
  auto mproposal = std::make_unique<MockProposal>();
  auto proposal = mproposal.get();
  boost::optional<std::shared_ptr<const OdOsNotification::ProposalType>>
      oproposal(std::move(mproposal));
  std::vector<std::shared_ptr<MockTransaction>> txs{
      std::make_shared<MockTransaction>()};
  ON_CALL(*txs[0], hash())
      .WillByDefault(ReturnRefOfCopy(shared_model::crypto::Hash("")));
  ON_CALL(*proposal, transactions())
      .WillByDefault(Return(txs | boost::adaptors::indirected));

  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);
  EXPECT_CALL(*notification, onRequestProposal(round))
      .WillOnce(Return(ByMove(std::move(oproposal))));

  auto event = OnDemandOrderingGate::RoundSwitch(round, ledger_state);

  auto gate_wrapper =
      make_test_subscriber<CallExact>(ordering_gate->onProposal(), 1);
  gate_wrapper.subscribe([&](auto val) {
    ASSERT_EQ(proposal, getProposalUnsafe(val).get());
    EXPECT_EQ(val.ledger_state->ledger_peers, event.ledger_state->ledger_peers);
  });

  rounds.get_subscriber().on_next(event);

  ASSERT_TRUE(gate_wrapper.validate());
}

/**
 * @given initialized ordering gate
 * @when an empty block round event is received from the PCS
 * AND a proposal is successfully retrieved from the network
 * @then new proposal round based on the received height is initiated
 */
TEST_F(OnDemandOrderingGateTest, EmptyEvent) {
  auto mproposal = std::make_unique<MockProposal>();
  auto proposal = mproposal.get();
  boost::optional<std::shared_ptr<const OdOsNotification::ProposalType>>
      oproposal(std::move(mproposal));
  std::vector<std::shared_ptr<MockTransaction>> txs{
      std::make_shared<MockTransaction>()};
  ON_CALL(*txs[0], hash())
      .WillByDefault(ReturnRefOfCopy(shared_model::crypto::Hash("")));
  ON_CALL(*proposal, transactions())
      .WillByDefault(Return(txs | boost::adaptors::indirected));

  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);
  EXPECT_CALL(*notification, onRequestProposal(round))
      .WillOnce(Return(ByMove(std::move(oproposal))));

  auto event = OnDemandOrderingGate::RoundSwitch(round, ledger_state);

  auto gate_wrapper =
      make_test_subscriber<CallExact>(ordering_gate->onProposal(), 1);
  gate_wrapper.subscribe([&](auto val) {
    ASSERT_EQ(proposal, getProposalUnsafe(val).get());
    EXPECT_EQ(val.ledger_state->ledger_peers, event.ledger_state->ledger_peers);
  });

  rounds.get_subscriber().on_next(event);

  ASSERT_TRUE(gate_wrapper.validate());
}

/**
 * @given initialized ordering gate
 * @when a block round event with height is received from the PCS
 * AND a proposal is not retrieved from the network
 * @then new empty proposal round based on the received height is initiated
 */
TEST_F(OnDemandOrderingGateTest, BlockEventNoProposal) {
  boost::optional<std::shared_ptr<const OdOsNotification::ProposalType>>
      proposal;

  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);
  EXPECT_CALL(*notification, onRequestProposal(round))
      .WillOnce(Return(ByMove(std::move(proposal))));

  auto gate_wrapper =
      make_test_subscriber<CallExact>(ordering_gate->onProposal(), 1);
  gate_wrapper.subscribe([&](auto val) { ASSERT_FALSE(val.proposal); });

  rounds.get_subscriber().on_next(
      OnDemandOrderingGate::RoundSwitch(round, ledger_state));

  ASSERT_TRUE(gate_wrapper.validate());
}

/**
 * @given initialized ordering gate
 * @when an empty block round event is received from the PCS
 * AND a proposal is not retrieved from the network
 * @then new empty proposal round based on the received height is initiated
 */
TEST_F(OnDemandOrderingGateTest, EmptyEventNoProposal) {
  boost::optional<std::shared_ptr<const OdOsNotification::ProposalType>>
      proposal;

  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);
  EXPECT_CALL(*notification, onRequestProposal(round))
      .WillOnce(Return(ByMove(std::move(proposal))));

  auto gate_wrapper =
      make_test_subscriber<CallExact>(ordering_gate->onProposal(), 1);
  gate_wrapper.subscribe([&](auto val) { ASSERT_FALSE(val.proposal); });

  rounds.get_subscriber().on_next(
      OnDemandOrderingGate::RoundSwitch(round, ledger_state));

  ASSERT_TRUE(gate_wrapper.validate());
}

/**
 * @given initialized ordering gate
 * @when new proposal arrives and the transaction was already committed
 * @then the resulting proposal emitted by ordering gate does not contain
 * this transaction
 */
TEST_F(OnDemandOrderingGateTest, ReplayedTransactionInProposal) {
  // initialize mock transaction
  auto tx1 = std::make_shared<NiceMock<MockTransaction>>();
  auto hash = shared_model::crypto::Hash("mock code is readable");
  ON_CALL(*tx1, hash()).WillByDefault(testing::ReturnRef(testing::Const(hash)));
  std::vector<decltype(tx1)> txs{tx1};
  auto tx_range = txs | boost::adaptors::indirected;

  // initialize mock proposal
  auto proposal = std::make_shared<const NiceMock<MockProposal>>();
  ON_CALL(*proposal, transactions()).WillByDefault(Return(tx_range));
  auto arriving_proposal = boost::make_optional(
      std::static_pointer_cast<const shared_model::interface::Proposal>(
          std::move(proposal)));

  // set expectations for ordering service
  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);
  EXPECT_CALL(*notification, onRequestProposal(round))
      .WillOnce(Return(ByMove(std::move(arriving_proposal))));
  EXPECT_CALL(*tx_cache,
              check(testing::Matcher<const shared_model::crypto::Hash &>(_)))
      .WillOnce(Return(boost::make_optional<ametsuchi::TxCacheStatusType>(
          iroha::ametsuchi::tx_cache_status_responses::Committed())));
  // expect proposal to be created without any transactions because it was
  // removed by tx cache
  auto ufactory_proposal = std::make_unique<MockProposal>();
  auto factory_proposal = ufactory_proposal.get();

  ON_CALL(*factory_proposal, transactions())
      .WillByDefault(
          Return<shared_model::interface::types::TransactionsCollectionType>(
              {}));
  EXPECT_CALL(
      *factory,
      unsafeCreateProposal(
          _, _, MockUnsafeProposalFactory::TransactionsCollectionType()))
      .Times(AtMost(1))
      .WillOnce(Return(ByMove(std::move(ufactory_proposal))));

  auto gate_wrapper =
      make_test_subscriber<CallExact>(ordering_gate->onProposal(), 1);
  gate_wrapper.subscribe([&](auto proposal) {});
  rounds.get_subscriber().on_next(
      OnDemandOrderingGate::RoundSwitch(round, ledger_state));

  ASSERT_TRUE(gate_wrapper.validate());
}

/**
 * @given initialized ordering gate
 * @when block event with no batches is emitted @and cache contains batch1 and
 * batch2 on the head
 * @then batch1 and batch2 are propagated to network
 */
TEST_F(OnDemandOrderingGateTest, PopNonEmptyBatchesFromTheCache) {
  // prepare internals of mock batches
  shared_model::interface::types::HashType hash1("hash1");
  auto tx1 = createMockTransactionWithHash(hash1);

  shared_model::interface::types::HashType hash2("hash2");
  auto tx2 = createMockTransactionWithHash(hash2);

  // prepare batches
  auto batch1 = createMockBatchWithTransactions({tx1}, "a");
  auto batch2 = createMockBatchWithTransactions({tx2}, "b");

  cache::OrderingGateCache::BatchesSetType collection{batch1, batch2};

  EXPECT_CALL(*cache, pop()).WillOnce(Return(collection));

  EXPECT_CALL(*cache, addToBack(UnorderedElementsAreArray(collection)))
      .Times(1);
  EXPECT_CALL(*notification, onBatches(UnorderedElementsAreArray(collection)))
      .Times(1);

  rounds.get_subscriber().on_next(
      OnDemandOrderingGate::RoundSwitch(round, ledger_state));
}

/**
 * @given initialized ordering gate
 * @when block event with no batches is emitted @and cache contains no batches
 * on the head
 * @then nothing is propagated to the network
 */
TEST_F(OnDemandOrderingGateTest, PopEmptyBatchesFromTheCache) {
  cache::OrderingGateCache::BatchesSetType empty_collection{};

  EXPECT_CALL(*cache, pop()).WillOnce(Return(empty_collection));
  EXPECT_CALL(*cache, addToBack(UnorderedElementsAreArray(empty_collection)))
      .Times(1);
  EXPECT_CALL(*notification, onBatches(_)).Times(0);

  rounds.get_subscriber().on_next(
      OnDemandOrderingGate::RoundSwitch(round, ledger_state));
}

/**
 * @given initialized ordering gate
 * @when an block round event is received from the PCS
 * @then all batches from that event are removed from the cache
 */
TEST_F(OnDemandOrderingGateTest, BatchesRemoveFromCache) {
  // prepare hashes for mock batches
  shared_model::interface::types::HashType hash1("hash1");
  shared_model::interface::types::HashType hash2("hash2");

  // prepare batches
  auto batch1 = createMockBatchWithHash(hash1);
  auto batch2 = createMockBatchWithHash(hash2);

  EXPECT_CALL(*cache, pop()).Times(1);
  EXPECT_CALL(*cache, remove(UnorderedElementsAre(hash1, hash2))).Times(1);

  auto hashes =
      std::make_shared<ordering::cache::OrderingGateCache::HashesSetType>();
  hashes->emplace(hash1);
  hashes->emplace(hash2);
  processed_tx_hashes.get_subscriber().on_next(hashes);
  rounds.get_subscriber().on_next(
      OnDemandOrderingGate::RoundSwitch(round, ledger_state));
}

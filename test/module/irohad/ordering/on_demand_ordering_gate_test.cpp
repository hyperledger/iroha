/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_ordering_gate.hpp"

#include <functional>

#include <gtest/gtest.h>
#include <boost/range/adaptor/indirected.hpp>
#include "framework/crypto_literals.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/irohad/ametsuchi/mock_tx_presence_cache.hpp"
#include "module/irohad/ordering/mock_on_demand_os_notification.hpp"
#include "module/irohad/ordering/ordering_mocks.hpp"
#include "module/shared_model/builders/protobuf/test_proposal_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "ordering/impl/on_demand_common.hpp"

using namespace iroha;
using namespace iroha::ordering;
using namespace iroha::ordering::transport;
using namespace iroha::network;

using ::testing::_;
using ::testing::AtMost;
using ::testing::ByMove;
using ::testing::get;
using ::testing::InvokeArgument;
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
    auto ufactory = std::make_unique<NiceMock<MockUnsafeProposalFactory>>();
    factory = ufactory.get();
    tx_cache = std::make_shared<ametsuchi::MockTxPresenceCache>();
    ON_CALL(*tx_cache,
            check(testing::Matcher<const shared_model::crypto::Hash &>(_)))
        .WillByDefault(
            Return(boost::make_optional<ametsuchi::TxCacheStatusType>(
                iroha::ametsuchi::tx_cache_status_responses::Missing())));
    ordering_gate =
        std::make_shared<OnDemandOrderingGate>(ordering_service,
                                               notification,
                                               std::move(ufactory),
                                               tx_cache,
                                               1000,
                                               getTestLogger("OrderingGate"),
                                               false);
    ordering_gate->initialize();

    auto peer = makePeer("127.0.0.1", "111"_hex_pubkey);
    ledger_state = std::make_shared<LedgerState>(
        shared_model::interface::types::PeerList{std::move(peer)},
        shared_model::interface::types::PeerList{
            makePeer("127.0.0.1", "222"_hex_pubkey)},
        round.block_round,
        shared_model::crypto::Hash{std::string{"hash"}});
  }

  /**
   * Create a simple transaction
   * @return created transaction
   */
  auto generateTx() {
    const shared_model::crypto::Keypair kDefaultKey =
        shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
    std::string creator = "account@domain";

    return TestUnsignedTransactionBuilder()
        .creatorAccountId(creator)
        .setAccountQuorum(creator, 1)
        .createdTime(iroha::time::now())
        .quorum(1)
        .build()
        .signAndAddSignature(kDefaultKey)
        .finish();
  }

  std::shared_ptr<MockOnDemandOrderingService> ordering_service;
  std::shared_ptr<MockOdOsNotification> notification;
  NiceMock<MockUnsafeProposalFactory> *factory;
  std::shared_ptr<ametsuchi::MockTxPresenceCache> tx_cache;
  std::shared_ptr<OnDemandOrderingGate> ordering_gate;
  const consensus::Round round = {2, kFirstRejectRound};

  std::shared_ptr<LedgerState> ledger_state;
};

#define PROPOSAL_OR_EMPTY(proposal) (proposal ? *proposal : nullptr)

/**
 * @given initialized ordering gate
 * @when a batch is received
 * @then it is passed to the ordering service
 */
TEST_F(OnDemandOrderingGateTest, propagateBatch) {
  auto hash1 = shared_model::interface::types::HashType(std::string(""));
  auto batch = createMockBatchWithHash(hash1);
  OdOsNotification::CollectionType collection{batch};

  EXPECT_CALL(*notification, onBatchesToWholeNetwork(collection)).Times(1);
  ordering_gate->propagateBatch(batch);
}

/**
 * @given initialized ordering gate
 * @when a block round event with height is received from the PCS
 * AND a proposal is successfully retrieved from the network
 * @then new proposal round based on the received height is initiated
 */
TEST_F(OnDemandOrderingGateTest, BlockEvent) {
  auto proposal = std::make_shared<shared_model::proto::Proposal>(
      TestProposalBuilder()
          .createdTime(iroha::time::now())
          .height(round.block_round)
          .transactions(
              std::vector<shared_model::proto::Transaction>{generateTx()})
          .build());

  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);

  OnDemandOrderingService::BatchesSetType transactions;
  ordering::PackedProposalData p{};
  EXPECT_CALL(*notification, onRequestProposal(round, p)).Times(1);

  auto event = RoundSwitch(round, ledger_state);

  ordering_gate->processRoundSwitch(event);

  auto val =
      ordering_gate->processProposalEvent(std::make_tuple(round, proposal));

  ASSERT_EQ(*proposal, *getProposalUnsafe(*val));
  EXPECT_EQ(val->ledger_state->ledger_peers, event.ledger_state->ledger_peers);
}

/**
 * @given initialized ordering gate
 * @when an empty block round event is received from the PCS
 * AND a proposal is successfully retrieved from the network
 * @then new proposal round based on the received height is initiated
 */
TEST_F(OnDemandOrderingGateTest, EmptyEvent) {
  auto proposal = std::make_shared<shared_model::proto::Proposal>(
      TestProposalBuilder()
          .createdTime(iroha::time::now())
          .height(round.block_round)
          .transactions(
              std::vector<shared_model::proto::Transaction>{generateTx()})
          .build());

  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);

  ordering::PackedProposalData p{};
  EXPECT_CALL(*notification, onRequestProposal(round, p)).Times(1);

  auto event = RoundSwitch(round, ledger_state);

  ordering_gate->processRoundSwitch(event);

  auto val =
      ordering_gate->processProposalEvent(std::make_tuple(round, proposal));

  ASSERT_EQ(*proposal, *getProposalUnsafe(*val));
  EXPECT_EQ(val->ledger_state->ledger_peers, event.ledger_state->ledger_peers);
}

/**
 * @given initialized ordering gate
 * @when a block round event with height is received from the PCS
 * AND a proposal is not retrieved from the network
 * @then new empty proposal round based on the received height is initiated
 */
TEST_F(OnDemandOrderingGateTest, BlockEventNoProposal) {
  std::optional<std::shared_ptr<const shared_model::interface::Proposal>>
      proposal;

  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);

  ordering::PackedProposalData p{};
  EXPECT_CALL(*notification, onRequestProposal(round, p)).Times(1);

  ordering_gate->processRoundSwitch(RoundSwitch(round, ledger_state));

  auto val = ordering_gate->processProposalEvent(
      std::make_tuple(round, PROPOSAL_OR_EMPTY(proposal)));

  ASSERT_FALSE(val->proposal);
}

/**
 * @given initialized ordering gate
 * @when an empty block round event is received from the PCS
 * AND a proposal is not retrieved from the network
 * @then new empty proposal round based on the received height is initiated
 */
TEST_F(OnDemandOrderingGateTest, EmptyEventNoProposal) {
  std::optional<std::shared_ptr<const shared_model::interface::Proposal>>
      proposal;

  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);

  ordering::PackedProposalData p{};
  EXPECT_CALL(*notification, onRequestProposal(round, p)).Times(1);

  ordering_gate->processRoundSwitch(RoundSwitch(round, ledger_state));

  auto val = ordering_gate->processProposalEvent(
      std::make_tuple(round, PROPOSAL_OR_EMPTY(proposal)));

  ASSERT_FALSE(val->proposal);
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
  auto hash = shared_model::crypto::Hash(std::string("mock code is readable"));
  ON_CALL(*tx1, hash()).WillByDefault(testing::ReturnRef(testing::Const(hash)));
  std::vector<decltype(tx1)> txs{tx1};
  auto tx_range = txs | boost::adaptors::indirected;

  // initialize mock proposal
  auto proposal = std::make_shared<const NiceMock<MockProposal>>();
  ON_CALL(*proposal, transactions()).WillByDefault(Return(tx_range));
  auto arriving_proposal = std::make_optional(
      std::static_pointer_cast<const shared_model::interface::Proposal>(
          std::move(proposal)));

  // set expectations for ordering service
  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);

  ordering::PackedProposalData p{};
  EXPECT_CALL(*notification, onRequestProposal(round, p)).Times(1);
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

  ordering_gate->processRoundSwitch(RoundSwitch(round, ledger_state));

  auto val = ordering_gate->processProposalEvent(
      std::make_tuple(round, PROPOSAL_OR_EMPTY(arriving_proposal)));
  ASSERT_TRUE(val);
}

MATCHER_P(hashEq, arg1, "") {
  return boost::size(arg) == 1 && arg.begin()->hash().hex() == arg1;
}

/**
 * @given initialized ordering gate
 * @when new proposal arrives and has two same transactions
 * @then the resulting proposal emitted by ordering gate contain only one
 * this transaction
 */
TEST_F(OnDemandOrderingGateTest, RepeatedTransactionInProposal) {
  // initialize mock transaction
  auto tx1 = generateTx();
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(tx1);
  txs.push_back(tx1);

  auto proposal = std::make_shared<MockProposal>();
  ON_CALL(*proposal, transactions()).WillByDefault(Return(txs));

  auto arriving_proposal = std::make_optional(
      std::static_pointer_cast<const shared_model::interface::Proposal>(
          std::move(proposal)));

  // set expectations for ordering service
  EXPECT_CALL(*ordering_service, onCollaborationOutcome(round)).Times(1);

  ordering::PackedProposalData p{};
  EXPECT_CALL(*notification, onRequestProposal(round, p)).Times(1);
  EXPECT_CALL(*tx_cache,
              check(testing::Matcher<const shared_model::crypto::Hash &>(_)))
      .WillRepeatedly(Return(boost::make_optional<ametsuchi::TxCacheStatusType>(
          iroha::ametsuchi::tx_cache_status_responses::Missing())));

  auto ufactory_proposal = std::make_unique<MockProposal>();
  auto factory_proposal = ufactory_proposal.get();
  std::vector<shared_model::proto::Transaction> etxs;
  etxs.push_back(tx1);

  ON_CALL(*factory_proposal, transactions()).WillByDefault(Return(etxs));

  EXPECT_CALL(*factory, unsafeCreateProposal(_, _, hashEq(tx1.hash().hex())))
      .Times(AtMost(1))
      .WillOnce(Return(ByMove(std::move(ufactory_proposal))));

  ordering_gate->processRoundSwitch(RoundSwitch(round, ledger_state));

  auto val = ordering_gate->processProposalEvent(
      std::make_tuple(round, PROPOSAL_OR_EMPTY(arriving_proposal)));
  ASSERT_TRUE(val);
}

/**
 * @given initialized ordering gate
 * @when block event with no batches is emitted @and cache contains no batches
 * on the head
 * @then nothing is propagated to the network
 */
TEST_F(OnDemandOrderingGateTest, PopEmptyBatchesFromTheCache) {
  OnDemandOrderingService::BatchesSetType empty_collection{};

  EXPECT_CALL(*notification, onBatches(_)).Times(0);

  ordering_gate->processRoundSwitch(RoundSwitch(round, ledger_state));
}

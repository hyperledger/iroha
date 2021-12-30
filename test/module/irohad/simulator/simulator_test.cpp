/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "simulator/impl/simulator.hpp"

#include <vector>

#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/find.hpp>
#include "backend/protobuf/proto_block_factory.hpp"
#include "backend/protobuf/transaction.hpp"
#include "builders/protobuf/transaction.hpp"
#include "datetime/time.hpp"
#include "framework/crypto_literals.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/mock_command_executor.hpp"
#include "module/irohad/ametsuchi/mock_temporary_factory.hpp"
#include "module/irohad/validation/mock_stateful_validator.hpp"
#include "module/shared_model/builders/protobuf/proposal.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_proposal_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/cryptography/mock_abstract_crypto_model_signer.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "module/shared_model/validators/validators.hpp"

using namespace iroha;
using namespace iroha::validation;
using namespace iroha::ametsuchi;
using namespace iroha::simulator;
using namespace iroha::network;

using ::testing::_;
using ::testing::A;
using ::testing::ByMove;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnArg;

using wBlock = std::shared_ptr<shared_model::interface::Block>;

class SimulatorTest : public ::testing::Test {
 public:
  using CryptoSignerType = shared_model::crypto::MockAbstractCryptoModelSigner<
      shared_model::interface::Block>;

  void SetUp() override {
    auto command_executor = std::make_unique<MockCommandExecutor>();
    validator = std::make_shared<MockStatefulValidator>();
    factory = std::make_shared<NiceMock<MockTemporaryFactory>>();
    crypto_signer = std::make_shared<CryptoSignerType>();
    block_factory = std::make_unique<shared_model::proto::ProtoBlockFactory>(
        std::make_unique<shared_model::validation::MockValidator<
            shared_model::interface::Block>>(),
        std::make_unique<
            shared_model::validation::MockValidator<iroha::protocol::Block>>());

    simulator = std::make_shared<Simulator>(std::move(command_executor),
                                            validator,
                                            factory,
                                            crypto_signer,
                                            std::move(block_factory),
                                            getTestLogger("Simulator"));
  }

  std::shared_ptr<MockStatefulValidator> validator;
  std::shared_ptr<MockTemporaryFactory> factory;
  std::shared_ptr<CryptoSignerType> crypto_signer;
  std::unique_ptr<shared_model::interface::UnsafeBlockFactory> block_factory;

  std::shared_ptr<Simulator> simulator;
  shared_model::interface::types::PeerList ledger_peers{
      makePeer("127.0.0.1", "111"_hex_pubkey)};
  shared_model::interface::types::PeerList ledger_sync_peers{
      makePeer("127.0.0.1", "222"_hex_pubkey)};
};

auto makeProposal(int height) {
  auto tx = shared_model::proto::TransactionBuilder()
                .createdTime(iroha::time::now())
                .creatorAccountId("admin@ru")
                .addAssetQuantity("coin#coin", "1.0")
                .quorum(1)
                .build()
                .signAndAddSignature(
                    shared_model::crypto::DefaultCryptoAlgorithmType::
                        generateKeypair())
                .finish();
  std::vector<shared_model::proto::Transaction> txs = {tx, tx};
  auto proposal = shared_model::proto::ProposalBuilder()
                      .height(height)
                      .createdTime(iroha::time::now())
                      .transactions(txs)
                      .build();
  return std::shared_ptr<const shared_model::interface::Proposal>(
      std::make_shared<const shared_model::proto::Proposal>(
          std::move(proposal)));
}

auto makeTx(size_t created_time = iroha::time::now()) {
  return shared_model::proto::TransactionBuilder()
      .createdTime(created_time)
      .creatorAccountId("admin@ru")
      .addAssetQuantity("coin#coin", "1.0")
      .quorum(1)
      .build()
      .signAndAddSignature(
          shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair())
      .finish();
}

TEST_F(SimulatorTest, ValidWhenPreviousBlock) {
  // proposal with height 2 => height 1 block present => new block generated
  auto const now = iroha::time::now();
  std::vector<shared_model::proto::Transaction> txs = {makeTx(now),
                                                       makeTx(now + 1ull)};

  auto validation_result =
      std::make_unique<iroha::validation::VerifiedProposalAndErrors>();
  validation_result->verified_proposal =
      std::make_unique<shared_model::proto::Proposal>(
          shared_model::proto::ProposalBuilder()
              .height(2)
              .createdTime(iroha::time::now())
              .transactions(txs)
              .build());
  const auto &proposal = validation_result->verified_proposal;

  EXPECT_CALL(*factory, createTemporaryWsv(_)).Times(1);

  EXPECT_CALL(*validator, validate(_, _))
      .WillOnce(Invoke([&validation_result](const auto &p, auto &v) {
        return std::move(validation_result);
      }));

  EXPECT_CALL(*crypto_signer, sign(A<shared_model::interface::Block &>()))
      .Times(1);

  auto ledger_state = std::make_shared<LedgerState>(
      ledger_peers,
      ledger_sync_peers,
      proposal->height() - 1,
      shared_model::crypto::Hash{std::string("hash")});
  OrderingEvent ordering_event{proposal, consensus::Round{}, ledger_state};

  auto verified_proposal_event = simulator->processProposal(ordering_event);
  auto verification_result = getVerifiedProposalUnsafe(verified_proposal_event);
  auto verified_proposal = verification_result->verified_proposal;
  EXPECT_EQ(verified_proposal->height(), proposal->height());
  EXPECT_EQ(verified_proposal->transactions(), proposal->transactions());
  EXPECT_TRUE(verification_result->rejected_transactions.empty());
  EXPECT_EQ(verified_proposal_event.ledger_state->ledger_peers,
            ordering_event.ledger_state->ledger_peers);

  auto block_event =
      simulator->processVerifiedProposal(verified_proposal_event);
  auto block = getBlockUnsafe(block_event);
  EXPECT_EQ(block->height(), proposal->height());
  EXPECT_EQ(block->transactions(), proposal->transactions());
  EXPECT_EQ(block_event.ledger_state->ledger_peers,
            ordering_event.ledger_state->ledger_peers);
}

/**
 * Checks, that after failing a certain number of transactions in a proposal,
 * returned verified proposal will have only valid transactions
 *
 * @given proposal consisting of several transactions
 * @when failing some of the transactions in that proposal
 * @then verified proposal consists of txs we did not fail, and the failed
 * transactions are provided as well
 */
TEST_F(SimulatorTest, SomeFailingTxs) {
  // create a 3-height proposal, but validator returns only a 2-height
  // verified proposal
  const int kNumTransactions = 3;
  std::vector<shared_model::proto::Transaction> txs;
  uint64_t created_time = iroha::time::now();
  for (int i = 0; i < kNumTransactions; ++i) {
    txs.push_back(makeTx(created_time + i));
  }
  std::shared_ptr<shared_model::interface::Proposal const> proposal =
      std::make_shared<shared_model::proto::Proposal>(
          shared_model::proto::ProposalBuilder()
              .height(3)
              .createdTime(iroha::time::now())
              .transactions(txs)
              .build());
  auto verified_proposal_and_errors =
      std::make_unique<VerifiedProposalAndErrors>();
  const shared_model::interface::types::HeightType verified_proposal_height = 2;
  const std::vector<shared_model::proto::Transaction>
      verified_proposal_transactions{txs[0]};
  verified_proposal_and_errors->verified_proposal =
      std::make_unique<shared_model::proto::Proposal>(
          shared_model::proto::ProposalBuilder()
              .height(verified_proposal_height)
              .createdTime(iroha::time::now())
              .transactions(verified_proposal_transactions)
              .build());
  for (auto rejected_tx = txs.begin() + 1; rejected_tx != txs.end();
       ++rejected_tx) {
    verified_proposal_and_errors->rejected_transactions.emplace_back(
        validation::TransactionError{
            rejected_tx->hash(),
            validation::CommandError{"SomeCommand", 1, "", true}});
  }

  EXPECT_CALL(*factory, createTemporaryWsv(_)).Times(1);

  EXPECT_CALL(*validator, validate(_, _))
      .WillOnce(Invoke([&verified_proposal_and_errors](const auto &p, auto &v) {
        return std::move(verified_proposal_and_errors);
      }));

  auto ledger_state = std::make_shared<LedgerState>(
      ledger_peers,
      ledger_sync_peers,
      proposal->height() - 1,
      shared_model::crypto::Hash{std::string("hash")});
  OrderingEvent ordering_event{
      std::make_optional(proposal), consensus::Round{}, ledger_state};
  auto verification_result =
      simulator->processProposal(ordering_event).verified_proposal_result;
  ASSERT_TRUE(verification_result);
  auto verified_proposal = verification_result.value()->verified_proposal;

  // ensure that txs in verified proposal do not include failed ones
  EXPECT_EQ(verified_proposal->height(), verified_proposal_height);
  EXPECT_EQ(verified_proposal->transactions(), verified_proposal_transactions);
  EXPECT_TRUE(verification_result.value()->rejected_transactions.size()
              == kNumTransactions - 1);
  const auto verified_proposal_rejected_tx_hashes =
      verification_result.value()->rejected_transactions
      | boost::adaptors::transformed(
            [](const auto &tx_error) { return tx_error.tx_hash; });
  for (auto rejected_tx = txs.begin() + 1; rejected_tx != txs.end();
       ++rejected_tx) {
    EXPECT_NE(boost::range::find(verified_proposal_rejected_tx_hashes,
                                 rejected_tx->hash()),
              boost::end(verified_proposal_rejected_tx_hashes))
        << rejected_tx->toString() << " missing in rejected transactions.";
  }
}

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/processor/transaction_processor_impl.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/join.hpp>
#include <boost/variant.hpp>
#include "backend/protobuf/proto_tx_status_factory.hpp"
#include "builders/protobuf/transaction.hpp"
#include "framework/batch_helper.hpp"
#include "framework/crypto_literals.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_sequence_factory.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/network/network_mocks.hpp"
#include "module/irohad/torii/torii_mocks.hpp"
#include "module/shared_model/builders/protobuf/proposal.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_proposal_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace iroha;
using namespace iroha::network;
using namespace iroha::torii;

using ::testing::_;
using ::testing::A;
using ::testing::Return;

using shared_model::interface::TransactionBatch;

class TransactionProcessorTest : public ::testing::Test {
 public:
  void SetUp() override {
    pcs = std::make_shared<MockPeerCommunicationService>();

    status_bus = std::make_shared<MockStatusBus>();
    tp = std::make_shared<TransactionProcessorImpl>(
        pcs,
        status_bus,
        std::make_shared<shared_model::proto::ProtoTxStatusFactory>(),
        getTestLogger("TransactionProcessor"));

    ledger_state = std::make_shared<LedgerState>(
        shared_model::interface::types::PeerList{
            makePeer("127.0.0.1", "111"_hex_pubkey)},
        shared_model::interface::types::PeerList{
            makePeer("127.0.0.2", "222"_hex_pubkey)},
        round.block_round - 1,
        shared_model::crypto::Hash{std::string("hash")});
  }

  auto base_tx() {
    return shared_model::proto::TransactionBuilder()
        .creatorAccountId("user@domain")
        .createdTime(iroha::time::now())
        .setAccountQuorum("user@domain", 2)
        .quorum(1);
  }

  auto baseTestTx(shared_model::interface::types::QuorumType quorum = 1) {
    return TestTransactionBuilder()
        .createdTime(iroha::time::now())
        .creatorAccountId("user@domain")
        .setAccountQuorum("user@domain", 2)
        .quorum(quorum)
        .build();
  }

  inline auto makeKey() {
    return shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  }

  template <typename Transaction, typename... KeyPairs>
  auto addSignaturesFromKeyPairs(Transaction &&tx, KeyPairs... keypairs) {
    auto create_signature = [&](auto &&key_pair) {
      auto &payload = tx.payload();
      auto signedBlob = shared_model::crypto::CryptoSigner::sign(
          shared_model::crypto::Blob(payload), key_pair);
      using namespace shared_model::interface::types;
      tx.addSignature(SignedHexStringView{signedBlob},
                      PublicKeyHexStringView{key_pair.publicKey()});
    };

    int temp[] = {(create_signature(std::forward<KeyPairs>(keypairs)), 0)...};
    (void)temp;

    return std::forward<Transaction>(tx);
  }

 protected:
  using StatusMapType = std::unordered_map<
      shared_model::crypto::Hash,
      std::shared_ptr<shared_model::interface::TransactionResponse>,
      shared_model::crypto::Hash::Hasher>;

  /**
   * Checks if all transactions have corresponding status
   * @param transactions transactions to check status
   * @param status to be checked
   */
  template <typename Status>
  void validateStatuses(
      std::vector<shared_model::proto::Transaction> &transactions) {
    for (const auto &tx : transactions) {
      auto tx_status = status_map.find(tx.hash());
      ASSERT_NE(tx_status, status_map.end());
      ASSERT_NO_THROW(boost::get<const Status &>(tx_status->second->get()));
    }
  }

  std::shared_ptr<MockPeerCommunicationService> pcs;
  std::shared_ptr<MockStatusBus> status_bus;
  std::shared_ptr<TransactionProcessorImpl> tp;

  StatusMapType status_map;
  std::shared_ptr<shared_model::interface::TxStatusFactory> status_factory =
      std::make_shared<shared_model::proto::ProtoTxStatusFactory>();

  consensus::Round round{1, 0};
  std::shared_ptr<LedgerState> ledger_state;

  const size_t proposal_size = 5;
  const size_t block_size = 3;
};
/**
 * @given transaction processor
 * @when transactions passed to processor compose proposal which is sent to peer
 * communication service
 * @then for every transaction in batches propagate_batch called
 */
TEST_F(TransactionProcessorTest, TransactionProcessorOnProposalTest) {
  std::vector<shared_model::proto::Transaction> txs;
  for (size_t i = 0; i < proposal_size; i++) {
    auto &&tx = addSignaturesFromKeyPairs(baseTestTx(), makeKey());
    txs.push_back(tx);
  }

  EXPECT_CALL(*pcs, propagate_batch(_)).Times(txs.size());

  for (const auto &tx : txs) {
    tp->batchHandle(framework::batch::createBatchFromSingleTransaction(
        std::shared_ptr<shared_model::interface::Transaction>(clone(tx))));
  }

  // create proposal and notify about it
  auto proposal = std::make_shared<shared_model::proto::Proposal>(
      TestProposalBuilder().transactions(txs).build());
}

/**
 * @given transactions from the same batch
 * @when transactions sequence is created and propagated
 * AND all transactions were returned by pcs in proposal notifier
 * @then all transactions in batches have ENOUGH_SIGNATURES_COLLECTED status
 */
TEST_F(TransactionProcessorTest, TransactionProcessorOnProposalBatchTest) {
  using namespace shared_model::validation;
  using TxsValidator = DefaultSignedTransactionsValidator;

  auto transactions =
      framework::batch::createValidBatch(proposal_size)->transactions();

  auto transaction_sequence_result = shared_model::interface::
      TransactionSequenceFactory::createTransactionSequence(
          transactions,
          TxsValidator(iroha::test::kTestsValidatorsConfig),
          FieldValidator(iroha::test::kTestsValidatorsConfig));
  auto transaction_sequence =
      framework::expected::val(transaction_sequence_result).value().value;

  EXPECT_CALL(*pcs, propagate_batch(_))
      .Times(transaction_sequence.batches().size());

  for (const auto &batch : transaction_sequence.batches()) {
    tp->batchHandle(batch);
  }

  // create proposal from sequence transactions and notify about it
  std::vector<shared_model::proto::Transaction> proto_transactions;

  std::transform(
      transactions.begin(),
      transactions.end(),
      std::back_inserter(proto_transactions),
      [](const auto tx) {
        return *std::static_pointer_cast<shared_model::proto::Transaction>(tx);
      });

  auto proposal = std::make_shared<shared_model::proto::Proposal>(
      TestProposalBuilder().transactions(proto_transactions).build());
}

/**
 * @given transaction processor
 * @when transactions compose proposal which is sent to peer
 * communication service
 * @then for every transaction in batches STATEFUL_VALID status is returned
 */
TEST_F(TransactionProcessorTest, TransactionProcessorVerifiedProposalTest) {
  std::vector<shared_model::proto::Transaction> txs;
  for (size_t i = 0; i < proposal_size; i++) {
    auto &&tx = addSignaturesFromKeyPairs(baseTestTx(), makeKey());
    txs.push_back(tx);
  }

  EXPECT_CALL(*pcs, propagate_batch(_)).Times(txs.size());

  for (const auto &tx : txs) {
    tp->batchHandle(framework::batch::createBatchFromSingleTransaction(
        std::shared_ptr<shared_model::interface::Transaction>(clone(tx))));
  }

  // 1. Create proposal and notify transaction processor about it
  auto validation_result =
      std::make_shared<iroha::validation::VerifiedProposalAndErrors>();
  validation_result->verified_proposal =
      std::make_unique<shared_model::proto::Proposal>(
          TestProposalBuilder().transactions(txs).build());

  // empty transactions errors - all txs are valid
  tp->processVerifiedProposalCreatorEvent(
      simulator::VerifiedProposalCreatorEvent{
          validation_result, round, ledger_state});
}

/**
 * @given transaction processor
 * @when transactions compose proposal which is sent to peer
 * communication service @and all transactions composed the block @and were
 * committed
 * @then for every transaction COMMIT status is returned
 */
TEST_F(TransactionProcessorTest, TransactionProcessorOnCommitTest) {
  std::vector<shared_model::proto::Transaction> txs;
  for (size_t i = 0; i < proposal_size; i++) {
    auto &&tx = addSignaturesFromKeyPairs(baseTestTx(), makeKey());
    txs.push_back(tx);
  }

  EXPECT_CALL(*pcs, propagate_batch(_)).Times(txs.size());

  for (const auto &tx : txs) {
    tp->batchHandle(framework::batch::createBatchFromSingleTransaction(
        std::shared_ptr<shared_model::interface::Transaction>(clone(tx))));
  }

  // 1. Create proposal and notify transaction processor about it
  auto validation_result =
      std::make_shared<iroha::validation::VerifiedProposalAndErrors>();
  validation_result->verified_proposal =
      std::make_unique<shared_model::proto::Proposal>(
          TestProposalBuilder().transactions(txs).build());

  // empty transactions errors - all txs are valid
  tp->processVerifiedProposalCreatorEvent(
      simulator::VerifiedProposalCreatorEvent{
          validation_result, round, ledger_state});

  auto block = TestBlockBuilder().transactions(txs).build();

  // 2. Create block and notify transaction processor about it
  tp->processCommit(
      std::shared_ptr<shared_model::interface::Block>(clone(block)));
}

/**
 * @given transaction processor
 * @when transactions compose proposal which is sent to peer
 * communication service @and some transactions became part of block, while some
 * were not committed, failing stateful validation
 * @then for every transaction from block COMMIT status is returned @and
 * for every transaction, which failed stateful validation, REJECTED status is
 * returned
 */
TEST_F(TransactionProcessorTest, TransactionProcessorInvalidTxsTest) {
  std::vector<shared_model::proto::Transaction> block_txs;
  for (size_t i = 0; i < block_size; i++) {
    auto &&tx = TestTransactionBuilder().createdTime(i).build();
    block_txs.push_back(tx);
    status_map[tx.hash()] = status_factory->makeNotReceived(tx.hash());
  }

  std::vector<shared_model::proto::Transaction> invalid_txs;

  for (size_t i = block_size; i < proposal_size; i++) {
    auto &&tx = TestTransactionBuilder().createdTime(i).build();
    invalid_txs.push_back(tx);
    status_map[tx.hash()] = status_factory->makeNotReceived(tx.hash());
  }

  // For all transactions from proposal
  // transaction will be published twice
  // (first that they are stateless
  // valid and second that they either
  // passed or not stateful validation)
  // Plus all transactions from block will
  // be committed and corresponding status will be sent
  // Rejected statuses will be published for invalid transactions
  EXPECT_CALL(*status_bus, publish(_))
      .Times(proposal_size + block_size + invalid_txs.size())
      .WillRepeatedly(testing::Invoke([this](auto response) {
        status_map[response->transactionHash()] = response;
      }));

  auto proposal = std::make_shared<shared_model::proto::Proposal>(
      TestProposalBuilder()
          .transactions(boost::join(block_txs, invalid_txs))
          .build());

  // trigger the verified event with txs, which we want to fail, as errors
  auto validation_result =
      std::make_shared<iroha::validation::VerifiedProposalAndErrors>();
  validation_result->verified_proposal =
      std::make_unique<shared_model::proto::Proposal>(
          TestProposalBuilder().transactions(block_txs).build());
  for (size_t i = 0; i < invalid_txs.size(); ++i) {
    validation_result->rejected_transactions.emplace_back(
        validation::TransactionError{invalid_txs[i].hash(),
                                     iroha::validation::CommandError{
                                         "SomeCommandName", 1, "", true, i}});
  }
  tp->processVerifiedProposalCreatorEvent(
      simulator::VerifiedProposalCreatorEvent{
          validation_result, round, ledger_state});

  {
    SCOPED_TRACE("Stateful invalid status verification");
    // check that all invalid transactions will have stateful invalid status
    validateStatuses<shared_model::interface::StatefulFailedTxResponse>(
        invalid_txs);
  }

  auto block = TestBlockBuilder()
                   .transactions(block_txs)
                   .rejectedTransactions(
                       invalid_txs | boost::adaptors::transformed([](auto &tx) {
                         return tx.hash();
                       }))
                   .build();

  tp->processCommit(
      std::shared_ptr<shared_model::interface::Block>(clone(block)));

  {
    SCOPED_TRACE("Rejected status verification");
    // check that all invalid transactions will have rejected status
    validateStatuses<shared_model::interface::RejectedTxResponse>(invalid_txs);
  }
  {
    SCOPED_TRACE("Committed status verification");
    // check that all transactions from block will be committed
    validateStatuses<shared_model::interface::CommittedTxResponse>(block_txs);
  }
}

/**
 * @given batch one transaction with quorum 2
 * AND one signature
 * @when transaction_processor handle the batch
 * @then checks that batch is relayed to MST
 */
TEST_F(TransactionProcessorTest, MultisigTransactionToMst) {
  auto &&tx = addSignaturesFromKeyPairs(baseTestTx(2), makeKey());

  auto &&after_mst = framework::batch::createBatchFromSingleTransaction(
      std::shared_ptr<shared_model::interface::Transaction>(clone(tx)));

  EXPECT_CALL(*pcs, propagate_batch(_)).Times(1);
  tp->batchHandle(std::move(after_mst));
}

/**
 * @given batch one transaction with quorum 2
 * AND one signature
 * @when MST emits the batch
 * @then checks that PCS is invoked.
 * This happens because tx processor is subscribed for MST
 */
TEST_F(TransactionProcessorTest, MultisigTransactionFromMst) {
  auto &&tx = addSignaturesFromKeyPairs(baseTestTx(2), makeKey(), makeKey());

  auto &&after_mst = framework::batch::createBatchFromSingleTransaction(
      std::shared_ptr<shared_model::interface::Transaction>(clone(tx)));

  tp->processPreparedBatch(after_mst);
}

/**
 * @given valid multisig tx
 * @when transaction_processor handle it
 * @then it will has MST_EXPIRED status
 */
TEST_F(TransactionProcessorTest, MultisigExpired) {
  EXPECT_CALL(*pcs, propagate_batch(_)).Times(1);

  std::shared_ptr<shared_model::interface::Transaction> tx =
      clone(base_tx()
                .quorum(2)
                .build()
                .signAndAddSignature(
                    shared_model::crypto::DefaultCryptoAlgorithmType::
                        generateKeypair())
                .finish());
  EXPECT_CALL(*status_bus, publish(_))
      .WillRepeatedly(testing::Invoke([](auto response) {
        ASSERT_NO_THROW(
            boost::get<const shared_model::interface::MstExpiredResponse &>(
                response->get()));
      }));
  tp->batchHandle(framework::batch::createBatchFromSingleTransaction(tx));
  tp->processExpiredBatch(
      framework::batch::createBatchFromSingleTransaction(tx));
}

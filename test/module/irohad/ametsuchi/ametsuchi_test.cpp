/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"

#include <gtest/gtest.h>

#include "ametsuchi/impl/postgres_block_query.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/impl/wsv_restorer_impl.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/temporary_wsv.hpp"
#include "builders/protobuf/transaction.hpp"
#include "framework/result_fixture.hpp"
#include "framework/test_logger.hpp"
#include "framework/test_subscriber.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

using namespace iroha::ametsuchi;
using namespace framework::test_subscriber;
using namespace shared_model::interface::permissions;
using framework::expected::err;
using framework::expected::val;

auto zero_string = std::string(32, '0');
auto fake_hash = shared_model::crypto::Hash(zero_string);
auto fake_pubkey = shared_model::crypto::PublicKey(zero_string);

// Allows to print amount string in case of test failure
namespace shared_model {
  namespace interface {
    void PrintTo(const Amount &amount, std::ostream *os) {
      *os << amount.toString();
    }
  }  // namespace interface
}  // namespace shared_model

/**
 * Validate getAccountAsset with given parameters
 * @tparam W WSV query type
 * @param wsv WSV query object
 * @param account id to query
 * @param asset id to query
 * @param amount to validate
 */
template <typename W>
void validateAccountAsset(W &&wsv,
                          const std::string &account,
                          const std::string &asset,
                          const shared_model::interface::Amount &amount) {
  auto account_asset = wsv->getAccountAsset(account, asset);
  ASSERT_TRUE(account_asset);
  ASSERT_EQ((*account_asset)->accountId(), account);
  ASSERT_EQ((*account_asset)->assetId(), asset);
  ASSERT_EQ((*account_asset)->balance(), amount);
}

/**
 * Validate getAccount with given parameters
 * @tparam W WSV query type
 * @param wsv WSV query object
 * @param id account to query
 * @param domain id to validate
 */
template <typename W>
void validateAccount(W &&wsv,
                     const std::string &id,
                     const std::string &domain) {
  auto account = wsv->getAccount(id);
  ASSERT_TRUE(account);
  ASSERT_EQ((*account)->accountId(), id);
  ASSERT_EQ((*account)->domainId(), domain);
}

TEST_F(AmetsuchiTest, GetBlocksCompletedWhenCalled) {
  // Commit block => get block => observable completed
  ASSERT_TRUE(storage);
  auto blocks = storage->getBlockQuery();

  auto block = createBlock({}, 1, fake_hash);

  apply(storage, block);

  ASSERT_EQ(*boost::get<iroha::expected::Value<
                 std::unique_ptr<shared_model::interface::Block>>>(
                 blocks->getBlock(1))
                 .value,
            *block);
}

TEST_F(AmetsuchiTest, SampleTest) {
  ASSERT_TRUE(storage);
  auto wsv = storage->getWsvQuery();
  auto blocks = storage->getBlockQuery();

  const auto domain = "ru", user1name = "userone", user2name = "usertwo",
             user1id = "userone@ru", user2id = "usertwo@ru", assetname = "rub",
             assetid = "rub#ru";

  // Block 1
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(
      TestTransactionBuilder()
          .creatorAccountId("admin1")
          .createRole("user",
                      {Role::kAddPeer, Role::kCreateAsset, Role::kGetMyAccount})
          .createDomain(domain, "user")
          .createAccount(user1name, domain, fake_pubkey)
          .build());
  auto block1 = createBlock(txs, 1, fake_hash);

  apply(storage, block1);

  validateAccount(sql_query, user1id, domain);

  // Block 2
  txs.clear();
  txs.push_back(
      TestTransactionBuilder()
          .creatorAccountId(user1id)
          .createAccount(user2name, domain, fake_pubkey)
          .createAsset(assetname, domain, 1)
          .addAssetQuantity(assetid, "150.0")
          .transferAsset(user1id, user2id, assetid, "Transfer asset", "100.0")
          .build());
  auto block2 = createBlock(txs, 2, block1->hash());

  apply(storage, block2);
  validateAccountAsset(
      sql_query, user1id, assetid, shared_model::interface::Amount("50.0"));
  validateAccountAsset(
      sql_query, user2id, assetid, shared_model::interface::Amount("100.0"));

  // Block store tests
  auto hashes = {block1->hash(), block2->hash()};

  for (size_t i = 0; i < hashes.size(); i++) {
    EXPECT_EQ(*(hashes.begin() + i),
              boost::get<iroha::expected::Value<
                  std::unique_ptr<shared_model::interface::Block>>>(
                  blocks->getBlock(i + 1))
                  .value->hash());
  }
}

TEST_F(AmetsuchiTest, PeerTest) {
  auto wsv = storage->getWsvQuery();

  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(TestTransactionBuilder()
                    .addPeer("192.168.9.1:50051", fake_pubkey)
                    .build());

  auto block = createBlock(txs, 1, fake_hash);

  apply(storage, block);

  auto peers = wsv->getPeers();
  ASSERT_TRUE(peers);
  ASSERT_EQ(peers->size(), 1);
  ASSERT_EQ(peers->at(0)->address(), "192.168.9.1:50051");

  ASSERT_EQ(peers->at(0)->pubkey(), fake_pubkey.hex());
}

TEST_F(AmetsuchiTest, AddSignatoryTest) {
  ASSERT_TRUE(storage);
  auto wsv = storage->getWsvQuery();

  shared_model::crypto::PublicKey pubkey1(std::string(32, '1'));
  shared_model::crypto::PublicKey pubkey2(std::string(32, '2'));

  auto user1id = "userone@domain";
  auto user2id = "usertwo@domain";

  // 1st tx (create user1 with pubkey1)
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(
      TestTransactionBuilder()
          .creatorAccountId("adminone")
          .createRole("user",
                      {Role::kAddPeer, Role::kCreateAsset, Role::kGetMyAccount})
          .createDomain("domain", "user")
          .createAccount("userone", "domain", pubkey1)
          .build());
  auto block1 = createBlock(txs, 1, fake_hash);

  apply(storage, block1);

  {
    auto account_opt = sql_query->getAccount(user1id);
    ASSERT_TRUE(account_opt);
    auto account = account_opt.value();
    ASSERT_EQ(account->accountId(), user1id);
    ASSERT_EQ(account->domainId(), "domain");

    auto signatories = wsv->getSignatories(user1id);
    ASSERT_TRUE(signatories);
    ASSERT_EQ(signatories->size(), 1);
    ASSERT_EQ(signatories->at(0), pubkey1);
  }

  // 2nd tx (add sig2 to user1)
  txs.clear();
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId(user1id)
                    .addSignatory(user1id, pubkey2)
                    .build());

  auto block2 = createBlock(txs, 2, block1->hash());

  apply(storage, block2);

  {
    auto account = sql_query->getAccount(user1id);
    ASSERT_TRUE(account);

    auto signatories = wsv->getSignatories(user1id);
    ASSERT_TRUE(signatories);
    ASSERT_EQ(signatories->size(), 2);
    ASSERT_EQ(signatories->at(0), pubkey1);
    ASSERT_EQ(signatories->at(1), pubkey2);
  }

  // 3rd tx (create user2 with pubkey1 that is same as user1's key)
  txs.clear();
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId("admintwo")
                    .createAccount("usertwo", "domain", pubkey1)
                    .build());

  auto block3 = createBlock(txs, 3, block2->hash());

  apply(storage, block3);

  {
    auto account1 = sql_query->getAccount(user1id);
    ASSERT_TRUE(account1);

    auto account2 = sql_query->getAccount(user2id);
    ASSERT_TRUE(account2);

    auto signatories1 = wsv->getSignatories(user1id);
    ASSERT_TRUE(signatories1);
    ASSERT_EQ(signatories1->size(), 2);
    ASSERT_EQ(signatories1->at(0), pubkey1);
    ASSERT_EQ(signatories1->at(1), pubkey2);

    auto signatories2 = wsv->getSignatories(user2id);
    ASSERT_TRUE(signatories2);
    ASSERT_EQ(signatories2->size(), 1);
    ASSERT_EQ(signatories2->at(0), pubkey1);
  }

  // 4th tx (remove pubkey1 from user1)
  txs.clear();
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId(user1id)
                    .removeSignatory(user1id, pubkey1)
                    .build());

  auto block4 = createBlock(txs, 4, block3->hash());

  apply(storage, block4);

  {
    auto account = sql_query->getAccount(user1id);
    ASSERT_TRUE(account);

    // user1 has only pubkey2.
    auto signatories1 = wsv->getSignatories(user1id);
    ASSERT_TRUE(signatories1);
    ASSERT_EQ(signatories1->size(), 1);
    ASSERT_EQ(signatories1->at(0), pubkey2);

    // user2 still has pubkey1.
    auto signatories2 = wsv->getSignatories(user2id);
    ASSERT_TRUE(signatories2);
    ASSERT_EQ(signatories2->size(), 1);
    ASSERT_EQ(signatories2->at(0), pubkey1);
  }

  // 5th tx (add sig2 to user2 and set quorum = 1)
  txs.clear();
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId(user1id)
                    .addSignatory(user2id, pubkey2)
                    .setAccountQuorum(user2id, 2)
                    .build());

  auto block5 = createBlock(txs, 5, block4->hash());

  apply(storage, block5);

  {
    auto account_opt = sql_query->getAccount(user2id);
    ASSERT_TRUE(account_opt);
    auto &account = account_opt.value();
    ASSERT_EQ(account->quorum(), 2);

    // user2 has pubkey1 and pubkey2.
    auto signatories = wsv->getSignatories(user2id);
    ASSERT_TRUE(signatories);
    ASSERT_EQ(signatories->size(), 2);
    ASSERT_EQ(signatories->at(0), pubkey1);
    ASSERT_EQ(signatories->at(1), pubkey2);
  }

  // 6th tx (remove sig2 fro user2: This must success)
  txs.clear();
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId(user2id)
                    .removeSignatory(user2id, pubkey2)
                    .setAccountQuorum(user2id, 2)
                    .build());

  auto block6 = createBlock(txs, 6, block5->hash());

  apply(storage, block6);

  {
    // user2 only has pubkey1.
    auto signatories = wsv->getSignatories(user2id);
    ASSERT_TRUE(signatories);
    ASSERT_EQ(signatories->size(), 1);
    ASSERT_EQ(signatories->at(0), pubkey1);
  }
}

std::shared_ptr<const shared_model::interface::Block> getBlock() {
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(TestTransactionBuilder()
                    .creatorAccountId("adminone")
                    .addPeer("192.168.0.0:10001", fake_pubkey)
                    .build());

  auto block = createBlock(txs, 1, fake_hash);
  return block;
}

TEST_F(AmetsuchiTest, TestingStorageWhenInsertBlock) {
  auto log = getTestLogger("TestStorage");
  log->info(
      "Test case: create storage "
      "=> insert block "
      "=> assert that inserted");
  ASSERT_TRUE(storage);
  static auto wrapper =
      make_test_subscriber<CallExact>(storage->on_commit(), 1);
  wrapper.subscribe();
  auto wsv = storage->getWsvQuery();
  ASSERT_EQ(0, wsv->getPeers().value().size());

  log->info("Try insert block");

  auto inserted = storage->insertBlock(getBlock());
  ASSERT_TRUE(inserted);

  log->info("Request ledger information");

  ASSERT_NE(0, wsv->getPeers().value().size());

  ASSERT_TRUE(wrapper.validate());
  wrapper.unsubscribe();
}

/**
 * @given created storage
 * @when commit block
 * @then committed block is emitted to observable
 */
TEST_F(AmetsuchiTest, TestingStorageWhenCommitBlock) {
  ASSERT_TRUE(storage);

  auto expected_block = getBlock();

  // create test subscriber to check if committed block is as expected
  static auto wrapper =
      make_test_subscriber<CallExact>(storage->on_commit(), 1);
  wrapper.subscribe([&expected_block](const auto &block) {
    ASSERT_EQ(block, expected_block);
  });

  auto mutable_storage = createMutableStorage();
  mutable_storage->apply(expected_block);

  ASSERT_TRUE(val(storage->commit(std::move(mutable_storage))));

  ASSERT_TRUE(wrapper.validate());
  wrapper.unsubscribe();
}

/**
 * @given spoiled WSV
 * @when WSV is restored
 * @then WSV is valid
 */
TEST_F(AmetsuchiTest, TestRestoreWSV) {
  // initialize storage with genesis block
  std::string default_domain = "test";
  std::string default_role = "admin";

  std::vector<shared_model::proto::Transaction> genesis_tx;
  genesis_tx.push_back(
      shared_model::proto::TransactionBuilder()
          .creatorAccountId("admin@test")
          .createdTime(iroha::time::now())
          .quorum(1)
          .createRole(default_role,
                      {Role::kCreateDomain,
                       Role::kCreateAccount,
                       Role::kAddAssetQty,
                       Role::kAddPeer,
                       Role::kReceive,
                       Role::kTransfer})
          .createDomain(default_domain, default_role)
          .build()
          .signAndAddSignature(
              shared_model::crypto::DefaultCryptoAlgorithmType::
                  generateKeypair())
          .finish());

  auto genesis_block = createBlock(genesis_tx);

  apply(storage, genesis_block);

  auto res = sql_query->getDomain("test");
  EXPECT_TRUE(res);

  // spoil WSV
  *sql << "DELETE FROM domain";

  // check there is no data in WSV
  res = sql_query->getDomain("test");
  EXPECT_FALSE(res);

  // recover storage and check it is recovered
  WsvRestorerImpl wsvRestorer;
  wsvRestorer.restoreWsv(*storage).match(
      [](const auto &) {},
      [&](const auto &error) { FAIL() << "Failed to recover WSV"; });

  res = sql_query->getDomain("test");
  EXPECT_TRUE(res);
}

/**
 * @given created storage
 *        @and a subscribed observer on on_commit() event
 * @when commit block
 * @then the effect of transactions in the committed block can be verified with
 * queries
 */
TEST_F(AmetsuchiTest, TestingWsvAfterCommitBlock) {
  ASSERT_TRUE(storage);

  shared_model::crypto::Keypair key{
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair()};

  auto genesis_tx = shared_model::proto::TransactionBuilder()
                        .creatorAccountId("admin@test")
                        .createdTime(iroha::time::now())
                        .quorum(1)
                        .createRole("admin",
                                    {Role::kCreateDomain,
                                     Role::kCreateAccount,
                                     Role::kAddAssetQty,
                                     Role::kAddPeer,
                                     Role::kReceive,
                                     Role::kTransfer})
                        .createDomain("test", "admin")
                        .createAccount("admin", "test", key.publicKey())
                        .createAccount("receiver", "test", key.publicKey())
                        .createAsset("coin", "test", 2)
                        .addAssetQuantity("coin#test", "20.00")
                        .build()
                        .signAndAddSignature(key)
                        .finish();

  auto genesis_block = createBlock({genesis_tx});
  apply(storage, genesis_block);

  auto add_ast_tx =
      shared_model::proto::TransactionBuilder()
          .creatorAccountId("admin@test")
          .createdTime(iroha::time::now())
          .quorum(1)
          .transferAsset(
              "admin@test", "receiver@test", "coin#test", "deal", "10.00")
          .build()
          .signAndAddSignature(key)
          .finish();

  auto expected_block = createBlock({add_ast_tx}, 2, genesis_block->hash());

  static auto wrapper =
      make_test_subscriber<CallExact>(storage->on_commit(), 1);
  wrapper.subscribe([&](const auto &block) {
    ASSERT_EQ(*block, *expected_block);
    shared_model::interface::Amount resultingAmount("10.00");
    validateAccountAsset(
        sql_query, "receiver@test", "coin#test", resultingAmount);
  });

  apply(storage, expected_block);

  ASSERT_TRUE(wrapper.validate());
  wrapper.unsubscribe();
}

class PreparedBlockTest : public AmetsuchiTest {
 public:
  PreparedBlockTest()
      : key(shared_model::crypto::DefaultCryptoAlgorithmType::
                generateKeypair()) {}

  shared_model::proto::Transaction createAddAsset(const std::string &amount) {
    return shared_model::proto::TransactionBuilder()
        .creatorAccountId("admin@test")
        .createdTime(iroha::time::now())
        .quorum(1)
        .addAssetQuantity("coin#test", amount)
        .build()
        .signAndAddSignature(key)
        .finish();
  }

  void SetUp() override {
    AmetsuchiTest::SetUp();
    genesis_tx =
        clone(shared_model::proto::TransactionBuilder()
                  .creatorAccountId("admin@test")
                  .createdTime(iroha::time::now())
                  .quorum(1)
                  .createRole(default_role,
                              {Role::kCreateDomain,
                               Role::kCreateAccount,
                               Role::kAddAssetQty,
                               Role::kAddPeer,
                               Role::kReceive,
                               Role::kTransfer})
                  .createDomain(default_domain, default_role)
                  .createAccount("admin", "test", key.publicKey())
                  .createAsset("coin", default_domain, 2)
                  .addAssetQuantity("coin#test", base_balance.toStringRepr())
                  .build()
                  .signAndAddSignature(key)
                  .finish());
    genesis_block = createBlock({*genesis_tx});
    initial_tx = clone(createAddAsset("5.00"));
    apply(storage, genesis_block);
    command_executor = std::move(val(storage->createCommandExecutor())->value);
    temp_wsv = storage->createTemporaryWsv(command_executor);
  }

  shared_model::crypto::Keypair key;
  std::string default_domain{"test"};
  std::string default_role{"admin"};
  std::unique_ptr<shared_model::proto::Transaction> genesis_tx;
  std::unique_ptr<shared_model::proto::Transaction> initial_tx;
  std::shared_ptr<const shared_model::interface::Block> genesis_block;
  std::shared_ptr<iroha::ametsuchi::CommandExecutor> command_executor;
  std::unique_ptr<iroha::ametsuchi::TemporaryWsv> temp_wsv;
  shared_model::interface::Amount base_balance{"5.00"};
};

/**
 * @given TemporaryWSV with several transactions
 * @when block is prepared for two phase commit
 * @then state of the ledger remains unchanged
 */
TEST_F(PreparedBlockTest, PrepareBlockNoStateChanged) {
  validateAccountAsset(sql_query,
                       "admin@test",
                       "coin#test",
                       shared_model::interface::Amount(base_balance));

  auto result = temp_wsv->apply(*initial_tx);
  ASSERT_FALSE(framework::expected::err(result));
  storage->prepareBlock(std::move(temp_wsv));

  // balance remains unchanged
  validateAccountAsset(sql_query, "admin@test", "coin#test", base_balance);
}

/**
 * @given Storage with prepared state
 * @when prepared state is applied
 * @then state of the ledger is changed
 */
TEST_F(PreparedBlockTest, CommitPreparedStateChanged) {
  auto other_tx = createAddAsset("5.00");

  auto block = createBlock({other_tx}, 2);

  auto result = temp_wsv->apply(*initial_tx);
  ASSERT_FALSE(framework::expected::err(result));
  storage->prepareBlock(std::move(temp_wsv));

  auto commited = storage->commitPrepared(block);

  ASSERT_TRUE(val(commited))
      << "Error in commitPrepared: " << err(commited)->error;

  shared_model::interface::Amount resultingAmount("10.00");

  validateAccountAsset(sql_query, "admin@test", "coin#test", resultingAmount);
}

/**
 * @given Storage with prepared state
 * @when another block is applied
 * @then state of the ledger is changed to that of the applied block
 * and not of the prepared state
 */
TEST_F(PreparedBlockTest, PrepareBlockCommitDifferentBlock) {
  // tx which actually gets commited
  auto other_tx = createAddAsset("10.00");

  auto block = createBlock({other_tx}, 2);

  auto result = temp_wsv->apply(*initial_tx);
  ASSERT_TRUE(val(result));
  storage->prepareBlock(std::move(temp_wsv));

  apply(storage, block);

  shared_model::interface::Amount resultingBalance{"15.00"};
  validateAccountAsset(sql_query, "admin@test", "coin#test", resultingBalance);
}

/**
 * @given Storage with prepared state
 * @when another block is applied
 * @then commitPrepared fails @and prepared state is not applied
 */
TEST_F(PreparedBlockTest, CommitPreparedFailsAfterCommit) {
  // tx which we prepare
  auto tx = createAddAsset("5.00");

  // tx which actually gets commited
  auto other_tx = createAddAsset("10.00");

  auto block = createBlock({other_tx}, 2);

  auto result = temp_wsv->apply(*initial_tx);
  ASSERT_FALSE(framework::expected::err(result));
  storage->prepareBlock(std::move(temp_wsv));

  apply(storage, block);

  auto commited = storage->commitPrepared(block);

  EXPECT_TRUE(err(commited));

  shared_model::interface::Amount resultingBalance{"15.00"};
  validateAccountAsset(sql_query, "admin@test", "coin#test", resultingBalance);
}

/**
 * @given Storage with prepared state
 * @when another temporary wsv is created and transaction is applied
 * @then previous state is dropped and new transaction is applied successfully
 */
TEST_F(PreparedBlockTest, TemporaryWsvUnlocks) {
  auto result = temp_wsv->apply(*initial_tx);
  ASSERT_TRUE(val(result));
  storage->prepareBlock(std::move(temp_wsv));

  temp_wsv = storage->createTemporaryWsv(command_executor);

  result = temp_wsv->apply(*initial_tx);
  ASSERT_TRUE(val(result));
  storage->prepareBlock(std::move(temp_wsv));
}

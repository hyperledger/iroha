/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "ametsuchi/impl/flat_file/flat_file.hpp"
#include "ametsuchi/impl/postgres_block_query.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/impl/wsv_restorer_impl.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/temporary_wsv.hpp"
#include "builders/protobuf/transaction.hpp"
#include "common/byteutils.hpp"
#include "framework/common_constants.hpp"
#include "framework/crypto_literals.hpp"
#include "framework/result_fixture.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "validation/chain_validator.hpp"

using namespace common_constants;
using namespace iroha::ametsuchi;
using namespace shared_model::interface::permissions;
using namespace shared_model::interface::types;
using framework::expected::err;
using framework::expected::val;

namespace {
  auto zero_string = std::string(32, '0');
  auto fake_hash = shared_model::crypto::Hash(zero_string);
  const PublicKeyHexStringView fake_pubkey{zero_string};
  const shared_model::interface::Amount base_balance{"5.00"};

  const shared_model::proto::Transaction &getGenesisTx() {
    static auto genesis_tx =
        shared_model::proto::TransactionBuilder()
            .creatorAccountId(kUserId)
            .createdTime(iroha::time::now())
            .quorum(1)
            .createRole(kRole,
                        {Role::kCreateDomain,
                         Role::kCreateAccount,
                         Role::kAddAssetQty,
                         Role::kAddPeer,
                         Role::kReceive,
                         Role::kTransfer})
            .createDomain(kDomain, kRole)
            .createAccount(kUser,
                           kDomain,
                           PublicKeyHexStringView{kUserKeypair.publicKey()})
            .createAccount(
                kSecondUser,
                kDomain,
                PublicKeyHexStringView{kSameDomainUserKeypair.publicKey()})
            .createAsset(kAssetName, kDomain, 2)
            .addAssetQuantity(kAssetId, base_balance.toStringRepr())
            .build()
            .signAndAddSignature(kUserKeypair)
            .finish();
    std::cerr << std::endl << genesis_tx.toString() << std::endl;
    return genesis_tx;
  }

  shared_model::proto::Transaction createAddAsset(const std::string &amount) {
    return shared_model::proto::TransactionBuilder()
        .creatorAccountId(kUserId)
        .createdTime(iroha::time::now())
        .quorum(1)
        .addAssetQuantity(kAssetId, amount)
        .build()
        .signAndAddSignature(kUserKeypair)
        .finish();
  }
}  // namespace

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

  auto peers = wsv->getPeers(false);
  ASSERT_TRUE(peers);
  ASSERT_EQ(peers->size(), 1);
  ASSERT_EQ(peers->at(0)->address(), "192.168.9.1:50051");

  ASSERT_EQ(peers->at(0)->pubkey(), fake_pubkey);
}

TEST_F(AmetsuchiTest, AddSignatoryTest) {
  ASSERT_TRUE(storage);
  auto wsv = storage->getWsvQuery();

  auto pubkey1{"1"_hex_pubkey};
  auto pubkey2{"2"_hex_pubkey};

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
  auto wsv = storage->getWsvQuery();
  ASSERT_EQ(0, wsv->getPeers(false).value().size());

  log->info("Try insert block");

  auto inserted = storage->insertBlock(getBlock());
  IROHA_ASSERT_RESULT_VALUE(inserted);

  log->info("Request ledger information");

  ASSERT_NE(0, wsv->getPeers(false).value().size());

  ASSERT_EQ(1, committed_blocks_.size());
}

/**
 * @given created storage
 * @when commit block
 * @then committed block is emitted to observable
 */
TEST_F(AmetsuchiTest, TestingStorageWhenCommitBlock) {
  ASSERT_TRUE(storage);

  auto expected_block = getBlock();

  auto mutable_storage = createMutableStorage();
  mutable_storage->apply(expected_block);

  ASSERT_TRUE(val(storage->commit(std::move(mutable_storage))));

  ASSERT_EQ(1, committed_blocks_.size());
  ASSERT_EQ(*expected_block, *committed_blocks_.front());
}

class IdentityChainValidator : public iroha::validation::ChainValidator {
 public:
  bool validateAndApply(
      std::shared_ptr<const shared_model::interface::Block> block,
      MutableStorage &storage) const override {
    return storage.apply(block);
  }
};
using MockBlockIValidator =
    shared_model::validation::MockValidator<shared_model::interface::Block>;
using MockBlockPValidator =
    shared_model::validation::MockValidator<iroha::protocol::Block_v1>;

/**
 * @given empty WSV and a genesis block in block storage
 * @when WSV is restored from block storage
 * @then WSV is valid
 */
TEST_F(AmetsuchiTest, TestRestoreWsvFromBlockStorage) {
  // initialize storage with genesis block
  auto genesis_block = createBlock({getGenesisTx()});
  apply(storage, genesis_block);

  auto res = sql_query->getDomain(kDomain);
  EXPECT_TRUE(res);

  const auto height = block_storage_->size();
  const auto top_hash = block_storage_->fetch(height).value()->hash();

  // clear WSV
  truncateWsv();
  destroyWsvStorage();
  initializeStorage();

  // block storage should not be altered
  EXPECT_EQ(storage->getLedgerState(), boost::none);
  EXPECT_EQ(block_storage_->size(), height);
  EXPECT_EQ(block_storage_->fetch(height).value()->hash(), top_hash);

  // check there is no data in WSV
  res = sql_query->getDomain(kDomain);
  EXPECT_FALSE(res);

  // recover WSV from block storage and check it is recovered
  auto chain_validator = std::make_shared<IdentityChainValidator>();
  auto interface_validator = std::make_unique<MockBlockIValidator>();
  auto proto_validator = std::make_unique<MockBlockPValidator>();
  WsvRestorerImpl wsvRestorer(std::move(interface_validator),
                              std::move(proto_validator),
                              chain_validator,
                              getTestLogger("WsvRestorer"));
  wsvRestorer.restoreWsv(*storage, false)
      .match([](const auto &) {},
             [&](const auto &error) {
               FAIL() << "Failed to recover WSV: " << error.error;
             });

  res = sql_query->getDomain(kDomain);
  EXPECT_TRUE(res);
}

class RestoreWsvTest : public AmetsuchiTest {
 public:
  using BlockPtr = decltype(createBlock({}));

  void commitToWsvAndBlockStorage(const std::vector<BlockPtr> &blocks) {
    for (const auto &block : blocks) {
      apply(storage, block);
    }
  }

  void commitToBlockStorageOnly(const std::vector<BlockPtr> &blocks) {
    for (const auto &block : blocks) {
      storeBlock(block);
    }
  }

  void rewriteBlockStorage(const std::vector<BlockPtr> &blocks) {
    destroyWsvStorage();
    block_storage_->clear();
    block_storage_ = InMemoryBlockStorageFactory{}.create().assumeValue();
    for (const auto &block : blocks) {
      EXPECT_TRUE(block_storage_->insert(block));
    }
    EXPECT_EQ(block_storage_->size(), blocks.size());
    initializeStorage(true);
    EXPECT_EQ(block_storage_->size(), blocks.size());
    assert(storage);
    EXPECT_EQ(storage->getBlockQuery()->getTopBlockHeight(), blocks.size())
        << "Failed to rewrite block storage.";
  }

  void restoreWsv() {
    auto chain_validator = std::make_shared<IdentityChainValidator>();
    auto interface_validator = std::make_unique<MockBlockIValidator>();
    auto proto_validator = std::make_unique<MockBlockPValidator>();
    WsvRestorerImpl wsvRestorer(std::move(interface_validator),
                                std::move(proto_validator),
                                chain_validator,
                                getTestLogger("WsvRestorer"));
    wsvRestorer.restoreWsv(*storage, false)
        .match([](const auto &) {},
               [&](const auto &error) {
                 FAIL() << "Failed to recover WSV: " << error.error;
               });
  }

  void checkRestoreWsvError(const std::string error_substr) {
    auto chain_validator = std::make_shared<IdentityChainValidator>();
    auto interface_validator = std::make_unique<MockBlockIValidator>();
    auto proto_validator = std::make_unique<MockBlockPValidator>();
    WsvRestorerImpl wsvRestorer(std::move(interface_validator),
                                std::move(proto_validator),
                                chain_validator,
                                getTestLogger("WsvRestorer"));
    wsvRestorer.restoreWsv(*storage, false)
        .match(
            [](const auto &) {
              FAIL() << "Should have failed to recover WSV.";
            },
            [&](const auto &error) {
              EXPECT_THAT(error.error, ::testing::HasSubstr(error_substr));
            });
  }
};

/**
 * @given valid WSV matching genesis block. block store contains genesis block
 * and one more block.
 * @when WSV is restored from block storage reusing present data
 * @then the missing block is applied to WSV @and WSV is valid
 */
TEST_F(RestoreWsvTest, TestRestoreWsvFromBlockStorageReuseOlderState) {
  // initialize storage with genesis block
  auto genesis_block = createBlock({getGenesisTx()});
  commitToWsvAndBlockStorage({genesis_block});

  // apply second block that adds asset qty to block storage only
  auto block2 = createBlock({createAddAsset("5.00")}, 2, genesis_block->hash());
  commitToBlockStorageOnly({block2});

  // WSV keeps unchanged
  validateAccountAsset(sql_query, kUserId, kAssetId, base_balance);

  // recover WSV from block storage and check it is recovered
  restoreWsv();
  shared_model::interface::Amount updated_qty("10.00");
  validateAccountAsset(sql_query, kUserId, kAssetId, updated_qty);
}

/**
 * @given valid WSV matching block storage
 * @when WSV is restored from block storage reusing present data
 * @then WSV is valid
 */
TEST_F(RestoreWsvTest, TestRestoreWsvFromBlockStorageReuseMatchingState) {
  // initialize storage with genesis block and a block that adds asset qty
  auto genesis_block = createBlock({getGenesisTx()});
  auto block2 = createBlock({createAddAsset("5.00")}, 2, genesis_block->hash());
  commitToWsvAndBlockStorage({genesis_block, block2});

  shared_model::interface::Amount updated_qty("10.00");
  validateAccountAsset(sql_query, kUserId, kAssetId, updated_qty);

  // recover WSV from block storage and check that WSV keeps unchanged
  restoreWsv();
  validateAccountAsset(sql_query, kUserId, kAssetId, updated_qty);
}

/**
 * @given WSV after 2 blocks and block storage with 2 other blocks
 * @when WSV is restored from block storage reusing present data
 * @then restoration fails
 */
TEST_F(RestoreWsvTest, TestRestoreWsvFromBlockStorageReuseMismatchingState) {
  // initialize storage with genesis block and a block that adds asset qty
  auto genesis_block = createBlock({getGenesisTx()});
  auto block2 = createBlock({createAddAsset("5.00")}, 2, genesis_block->hash());
  commitToWsvAndBlockStorage({genesis_block, block2});

  shared_model::interface::Amount updated_qty("10.00");
  validateAccountAsset(sql_query, kUserId, kAssetId, updated_qty);

  // rewrite different blocks and recreate the storage
  auto block2_another =
      createBlock({createAddAsset("50.00")}, 2, genesis_block->hash());
  rewriteBlockStorage({genesis_block, block2_another});

  EXPECT_EQ((*storage->getLedgerState())->top_block_info.top_hash,
            block2->hash());
  EXPECT_EQ(block_storage_->fetch(block2_another->height()).value()->hash(),
            block2_another->hash());

  // try to recover WSV from block storage and check it fails
  checkRestoreWsvError(
      "does not match the hash of the block from block storage");

  // WSV keeps unchanged
  validateAccountAsset(sql_query, kUserId, kAssetId, updated_qty);
}

/**
 * @given valid WSV as after applying 2 blocks. block storage contains only the
 * first of them.
 * @when WSV is restored from block storage reusing present data
 * @then restoration fails
 */
TEST_F(RestoreWsvTest, TestRestoreWsvFromBlockStorageReuseNewerState) {
  // initialize storage with genesis block and a block that adds asset qty
  auto genesis_block = createBlock({getGenesisTx()});
  auto block2 = createBlock({createAddAsset("5.00")}, 2, genesis_block->hash());
  commitToWsvAndBlockStorage({genesis_block, block2});

  shared_model::interface::Amount updated_qty("10.00");
  validateAccountAsset(sql_query, kUserId, kAssetId, updated_qty);

  // leave only the genesis block in block storage
  rewriteBlockStorage({genesis_block});

  ASSERT_EQ((*storage->getLedgerState())->top_block_info.height, 2);

  // try to recover WSV from block storage and check it fails
  checkRestoreWsvError(
      "WSV state (height 2) is more recent than block storage (height 1).");

  // WSV keeps unchanged
  validateAccountAsset(sql_query, kUserId, kAssetId, updated_qty);
}

/**
 * @given valid WSV matching block storage, but incompatible schema version
 * @when WSV is restored from block storage reusing present data
 * @then error occurs
 */
TEST_F(RestoreWsvTest, TestRestoreWsvFromIncompatibleSchema) {
  // initialize storage with genesis block and a block that adds asset qty
  auto genesis_block = createBlock({getGenesisTx()});
  auto block2 = createBlock({createAddAsset("5.00")}, 2, genesis_block->hash());
  commitToWsvAndBlockStorage({genesis_block, block2});

  // alter schema version
  *sql << "update schema_version set iroha_major = iroha_major + 1";

  // try connect to the WSV DB keeping the state
  auto db_pool_result_error = err(PgConnectionInit::prepareWorkingDatabase(
      iroha::StartupWsvDataPolicy::kReuse, *options_));
  ASSERT_TRUE(db_pool_result_error) << "Must have failed reusing WSV.";
  EXPECT_THAT(db_pool_result_error->error,
              ::testing::HasSubstr("The schema is not compatible."));
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

  auto genesis_block = createBlock({getGenesisTx()});
  apply(storage, genesis_block);

  shared_model::interface::Amount transferredAmount("1.00");

  auto add_ast_tx = shared_model::proto::TransactionBuilder()
                        .creatorAccountId(kUserId)
                        .createdTime(iroha::time::now())
                        .quorum(1)
                        .transferAsset(kUserId,
                                       kSameDomainUserId,
                                       kAssetId,
                                       "deal",
                                       transferredAmount.toStringRepr())
                        .build()
                        .signAndAddSignature(kSameDomainUserKeypair)
                        .finish();

  auto expected_block = createBlock({add_ast_tx}, 2, genesis_block->hash());

  apply(storage, expected_block);

  ASSERT_EQ(2, committed_blocks_.size());
  ASSERT_EQ(*expected_block, *committed_blocks_.back());
  validateAccountAsset(
      sql_query, kSameDomainUserId, kAssetId, transferredAmount);
}

class PreparedBlockTest : public AmetsuchiTest {
 public:
  void SetUp() override {
    AmetsuchiTest::SetUp();
    if (not prepared_blocks_enabled) {
      GTEST_SKIP();
    }
    genesis_block = createBlock({getGenesisTx()});
    initial_tx = clone(createAddAsset("5.00"));
    apply(storage, genesis_block);
    temp_wsv = storage->createTemporaryWsv(command_executor);
  }

  std::unique_ptr<shared_model::proto::Transaction> initial_tx;
  std::shared_ptr<const shared_model::interface::Block> genesis_block;
  std::unique_ptr<iroha::ametsuchi::TemporaryWsv> temp_wsv;
};

/**
 * @given TemporaryWSV with several transactions
 * @when block is prepared for two phase commit
 * @then state of the ledger remains unchanged
 */
TEST_F(PreparedBlockTest, PrepareBlockNoStateChanged) {
  validateAccountAsset(sql_query, kUserId, kAssetId, base_balance);

  auto result = temp_wsv->apply(*initial_tx);
  ASSERT_FALSE(framework::expected::err(result));
  storage->prepareBlock(std::move(temp_wsv));

  // balance remains unchanged
  validateAccountAsset(sql_query, kUserId, kAssetId, base_balance);
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

  auto commited_res = storage->commitPrepared(block);
  IROHA_ASSERT_RESULT_VALUE(commited_res);

  shared_model::interface::Amount resultingAmount("10.00");

  validateAccountAsset(sql_query, kUserId, kAssetId, resultingAmount);

  auto ledger_state = std::move(commited_res).assumeValue();
  ASSERT_NE(ledger_state, nullptr);
  PostgresWsvQuery wsv_query{*sql, getTestLogger("WsvQuery")};
  auto top_block_info =
      iroha::expected::resultToOptionalValue(wsv_query.getTopBlockInfo());
  ASSERT_TRUE(top_block_info) << "Failed to get top block info.";
  EXPECT_EQ(top_block_info->height, ledger_state->top_block_info.height);
  EXPECT_EQ(top_block_info->top_hash, ledger_state->top_block_info.top_hash);
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
  validateAccountAsset(sql_query, kUserId, kAssetId, resultingBalance);
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
  validateAccountAsset(sql_query, kUserId, kAssetId, resultingBalance);
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

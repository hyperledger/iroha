/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include "ametsuchi/impl/rocksdb_common.hpp"
#include "ametsuchi/impl/rocksdb_wsv_command.hpp"
#include "ametsuchi/impl/rocksdb_wsv_query.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "cryptography/hash.hpp"
#include "framework/result_fixture.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"
#include "module/shared_model/interface_mocks.hpp"

namespace fs = boost::filesystem;
using namespace std::literals;

namespace iroha {
  namespace ametsuchi {

    using namespace framework::expected;

    class RdbWsvQueryCommandTest : public AmetsuchiTest {
     public:
      void SetUp() override {
        AmetsuchiTest::SetUp();

        db_name_ = (fs::temp_directory_path() / fs::unique_path()).string();
        auto db_port = std::make_shared<RocksDBPort>();
        db_port->initialize(db_name_);

        auto db_context = std::make_shared<RocksDBContext>(db_port);
        command_ = std::make_unique<RocksDBWsvCommand>(db_context);
        query_ = std::make_unique<RocksDBWsvQuery>(db_context,
                                                   getTestLogger("WsvQuery"));
      }

      void TearDown() override {
        command_.reset();
        query_.reset();

        fs::remove_all(db_name_);
        AmetsuchiTest::TearDown();
      }

      std::string db_name_;
      std::unique_ptr<WsvCommand> command_;
      std::unique_ptr<WsvQuery> query_;
    };

    class RoleTest : public RdbWsvQueryCommandTest {};

    TEST_F(RoleTest, InsertDuplicateRole) {
      ASSERT_TRUE(val(command_->insertRole("role")));
      ASSERT_TRUE(err(command_->insertRole("role")));
    }

    /**
     * @given WSV state
     * @when we set top block info with wsv command
     * @then we get same top block info with wsv query
     */
    TEST_F(RdbWsvQueryCommandTest, SetAndGetTopBlockInfo) {
      iroha::TopBlockInfo top_block_info_set{
          1234, shared_model::crypto::Hash{"hash"}};
      framework::expected::expectResultValue(
          command_->setTopBlockInfo(top_block_info_set));

      auto top_block_info_read = query_->getTopBlockInfo();
      IROHA_ASSERT_RESULT_VALUE(top_block_info_read);
      EXPECT_EQ(top_block_info_set.top_hash,
                top_block_info_read.assumeValue().top_hash);
      EXPECT_EQ(top_block_info_set.height,
                top_block_info_read.assumeValue().height);
    }

    class DeletePeerTest : public RdbWsvQueryCommandTest {
     public:
      void SetUp() override {
        RdbWsvQueryCommandTest::SetUp();

        peer = makePeer(address, pk);
      }
      std::shared_ptr<MockPeer> peer;
      shared_model::interface::types::AddressType address{"address"};
      shared_model::interface::types::PublicKeyHexStringView pk{"pk"sv};
    };

    /**
     * @given storage with peer
     * @when trying to delete existing peer
     * @then peer is successfully deleted
     */
    TEST_F(DeletePeerTest, DeletePeerValidWhenPeerExists) {
      ASSERT_TRUE(val(command_->insertPeer(*peer)));

      ASSERT_TRUE(val(command_->deletePeer(*peer)));
    }

  }  // namespace ametsuchi
}  // namespace iroha

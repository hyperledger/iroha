/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include "ametsuchi/impl/postgres_wsv_command.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "cryptography/hash.hpp"
#include "framework/result_fixture.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace std::literals;

namespace iroha {
  namespace ametsuchi {

    using namespace framework::expected;

    class WsvQueryCommandTest : public AmetsuchiTest {
     public:
      void SetUp() override {
        AmetsuchiTest::SetUp();
        sql = std::make_unique<soci::session>(*soci::factory_postgresql(),
                                              pgopt_);

        command = std::make_unique<PostgresWsvCommand>(*sql);
        query =
            std::make_unique<PostgresWsvQuery>(*sql, getTestLogger("WsvQuery"));
      }

      void TearDown() override {
        sql->close();
        AmetsuchiTest::TearDown();
      }

      std::unique_ptr<soci::session> sql;

      std::unique_ptr<WsvCommand> command;
      std::unique_ptr<WsvQuery> query;
    };

    class RoleTest : public WsvQueryCommandTest {};

    TEST_F(RoleTest, InsertTwoRole) {
      ASSERT_TRUE(val(command->insertRole("role")));
      ASSERT_TRUE(err(command->insertRole("role")));
    }

    /**
     * @given WSV state
     * @when we set top block info with wsv command
     * @then we get same top block info with wsv query
     */
    TEST_F(WsvQueryCommandTest, SetAndGetTopBlockInfo) {
      iroha::TopBlockInfo top_block_info_set{
          1234, shared_model::crypto::Hash{std::string("hash")}};
      framework::expected::expectResultValue(
          command->setTopBlockInfo(top_block_info_set));
      auto top_block_info_read = query->getTopBlockInfo();
      IROHA_ASSERT_RESULT_VALUE(top_block_info_read);
      EXPECT_EQ(top_block_info_set.top_hash,
                top_block_info_read.assumeValue().top_hash);
      EXPECT_EQ(top_block_info_set.height,
                top_block_info_read.assumeValue().height);
    }

    class DeletePeerTest : public WsvQueryCommandTest {
     public:
      void SetUp() override {
        WsvQueryCommandTest::SetUp();

        peer = makePeer(address, pk);
      }
      std::shared_ptr<MockPeer> peer;
      shared_model::interface::types::AddressType address{""};
      shared_model::interface::types::PublicKeyHexStringView pk{""sv};
    };

    /**
     * @given storage with peer
     * @when trying to delete existing peer
     * @then peer is successfully deleted
     */
    TEST_F(DeletePeerTest, DeletePeerValidWhenPeerExists) {
      ASSERT_TRUE(val(command->insertPeer(*peer)));

      ASSERT_TRUE(val(command->deletePeer(*peer)));
    }

  }  // namespace ametsuchi
}  // namespace iroha

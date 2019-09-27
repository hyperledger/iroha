/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include <backend/plain/peer.hpp>
#include "ametsuchi/impl/postgres_wsv_command.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"

namespace iroha {
  namespace ametsuchi {

    class WsvQueryTest : public AmetsuchiTest {
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

    /**
     * @given storage with peers
     * @when trying to get existing peers
     * @then peer list successfully received
     */
    TEST_F(WsvQueryTest, GetPeers) {
      shared_model::plain::Peer peer1(
          "some-address", shared_model::crypto::PublicKey("some-public-key"));
      command->insertPeer(peer1);
      shared_model::plain::Peer peer2(
          "another-address",
          shared_model::crypto::PublicKey("another-public-key"));
      command->insertPeer(peer2);

      auto result = query->getPeers();
      ASSERT_TRUE(result);
      auto peers = result.get();
      ASSERT_EQ(peers.size(), 2);
      ASSERT_EQ(*peers[0], peer1);
      ASSERT_EQ(*peers[1], peer2);
    }

  }  // namespace ametsuchi
}  // namespace iroha

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include "ametsuchi/impl/postgres_indexer.hpp"
#include "ametsuchi/impl/postgres_wsv_command.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "backend/plain/account.hpp"
#include "backend/plain/domain.hpp"
#include "backend/plain/peer.hpp"
#include "backend/plain/signature.hpp"
#include "framework/make_peer_pointee_matcher.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"

using namespace std::literals;
using namespace shared_model::interface::types;

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
      ASSERT_EQ(query->countPeers(false).assumeValue(), 0);

      shared_model::plain::Peer peer1{
          "some-address", "0a", std::nullopt, false};
      command->insertPeer(peer1);
      shared_model::plain::Peer peer2{
          "another-address", "0b", std::nullopt, false};
      command->insertPeer(peer2);

      auto result = query->getPeers(false);
      ASSERT_TRUE(result);
      ASSERT_THAT(*result,
                  testing::ElementsAre(testing::Pointee(testing::Eq(peer1)),
                                       testing::Pointee(testing::Eq(peer2))));

      ASSERT_EQ(query->countPeers(false).assumeValue(), 2);
    }

    /**
     * @given storage with sync peers
     * @when trying to get existing peers
     * @then peer list successfully received
     */
    TEST_F(WsvQueryTest, GetSyncPeers) {
      ASSERT_EQ(query->countPeers(true).assumeValue(), 0);

      shared_model::plain::Peer peer1{"some-address", "0a", std::nullopt, true};
      command->insertPeer(peer1);
      shared_model::plain::Peer peer2{
          "another-address", "0b", std::nullopt, true};
      command->insertPeer(peer2);

      auto result = query->getPeers(true);
      ASSERT_TRUE(result);
      ASSERT_THAT(*result,
                  testing::ElementsAre(testing::Pointee(testing::Eq(peer1)),
                                       testing::Pointee(testing::Eq(peer2))));

      ASSERT_EQ(query->countPeers(true).assumeValue(), 2);
    }

    TEST_F(WsvQueryTest, countDomains) {
      using shared_model::plain::Domain;
      using namespace iroha::expected;
      command->insertRole("user");
      ASSERT_EQ(query->countDomains().assumeValue(), 0);
      ASSERT_FALSE(hasError(command->insertDomain(Domain{"aaa", "user"})));
      ASSERT_FALSE(hasError(command->insertDomain(Domain{"ccc", "user"})));
      ASSERT_EQ(query->countDomains().assumeValue(), 2);
    }

    TEST_F(WsvQueryTest, countPeers) {
      ASSERT_EQ(query->countPeers(false).assumeValue(), 0);
      command->insertPeer(
          shared_model::plain::Peer{"127.0.0.1", "111", std::nullopt, false});
      command->insertPeer(
          shared_model::plain::Peer{"127.0.0.2", "222", std::nullopt, false});
      ASSERT_EQ(query->countPeers(false).assumeValue(), 2);
    }

    TEST_F(WsvQueryTest, countTransactions) {
      ASSERT_EQ(query->countTransactions().assumeValue(), 0);
      auto indexer = iroha::ametsuchi::PostgresIndexer(*sql);
      using shared_model::crypto::Hash, iroha::ametsuchi::Indexer;
      indexer.txPositions("account_type",
                          Hash("abdef1"),
                          boost::none,
                          123346,
                          Indexer::TxPosition{1, 2});
      indexer.txPositions("account_type",
                          Hash("abdef2"),
                          boost::none,
                          123347,
                          Indexer::TxPosition{1, 3});
      indexer.flush();
      ASSERT_EQ(query->countTransactions().assumeValue(), 2);
    }

    /**
     * @given storage with signatories
     * @when trying to get signatories of one account
     * @then signature list for one account successfully received
     */
    TEST_F(WsvQueryTest, GetSignatories) {
      command->insertRole("role");
      shared_model::plain::Domain domain("domain", "role");
      command->insertDomain(domain);
      shared_model::plain::Account account("account", "domain", 1, "{}");
      command->insertAccount(account);

      PublicKeyHexStringView pub_key1{"some-public-key"sv};
      command->insertSignatory(pub_key1);
      command->insertAccountSignatory("account", pub_key1);
      PublicKeyHexStringView pub_key2{"another-public-key"sv};
      command->insertSignatory(pub_key2);
      command->insertAccountSignatory("account", pub_key2);

      auto result = query->getSignatories("account");
      ASSERT_TRUE(result);
      auto signatories = result.get();
      ASSERT_THAT(signatories,
                  testing::UnorderedElementsAre(pub_key1, pub_key2));
    }

  }  // namespace ametsuchi
}  // namespace iroha

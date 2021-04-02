/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

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

        command = std::make_unique<PostgresWsvCommand>(sql);
        query =
            std::make_unique<PostgresWsvQuery>(sql, getTestLogger("WsvQuery"));
      }

      void TearDown() override {
        sql->close();
        AmetsuchiTest::TearDown();
      }

      std::shared_ptr<soci::session> sql;

      std::unique_ptr<WsvCommand> command;
      std::unique_ptr<WsvQuery> query;
    };

    /**
     * @given storage with peers
     * @when trying to get existing peers
     * @then peer list successfully received
     */
    TEST_F(WsvQueryTest, GetPeers) {
      shared_model::plain::Peer peer1{"some-address", "0a", std::nullopt};
      command->insertPeer(peer1);
      shared_model::plain::Peer peer2{"another-address", "0b", std::nullopt};
      command->insertPeer(peer2);

      auto result = query->getPeers();
      ASSERT_TRUE(result);
      ASSERT_THAT(*result,
                  testing::ElementsAre(testing::Pointee(testing::Eq(peer1)),
                                       testing::Pointee(testing::Eq(peer2))));
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

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include "ametsuchi/impl/rocksdb_common.hpp"
#include "ametsuchi/impl/rocksdb_wsv_command.hpp"
#include "ametsuchi/impl/rocksdb_wsv_query.hpp"
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
namespace fs = boost::filesystem;

namespace iroha {
  namespace ametsuchi {

    class RdbWsvQueryTest : public AmetsuchiTest {
     public:
      void SetUp() override {
        AmetsuchiTest::SetUp();

        db_name_ = (fs::temp_directory_path() / fs::unique_path()).string();
        auto db_port = std::make_shared<RocksDBPort>();
        db_port->initialize(db_name_);

        command = std::make_unique<RocksDBWsvCommand>(db_port);
        query = std::make_unique<RocksDBWsvQuery>(db_port,
                                                  getTestLogger("WsvQuery"));
      }

      void TearDown() override {
        command.reset();
        query.reset();

        fs::remove_all(db_name_);
        AmetsuchiTest::TearDown();
      }

      std::string db_name_;
      std::unique_ptr<WsvCommand> command;
      std::unique_ptr<WsvQuery> query;
    };

    /**
     * @given storage with peers
     * @when trying to get existing peers
     * @then peer list successfully received
     */
    TEST_F(RdbWsvQueryTest, GetPeers) {
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
    TEST_F(RdbWsvQueryTest, GetSignatories) {
      command->insertRole("role");
      shared_model::plain::Domain domain("domain", "role");
      command->insertDomain(domain);
      shared_model::plain::Account account("account", "domain", 1, "{}");
      command->insertAccount(account);

      PublicKeyHexStringView pub_key1{"some-public-key"sv};
      command->insertAccountSignatory("account@domain", pub_key1);
      PublicKeyHexStringView pub_key2{"another-public-key"sv};
      command->insertAccountSignatory("account@domain", pub_key2);

      auto result = query->getSignatories("account@domain");
      ASSERT_TRUE(result);
      auto signatories = result.get();
      ASSERT_THAT(signatories,
                  testing::UnorderedElementsAre(pub_key1, pub_key2));
    }

  }  // namespace ametsuchi
}  // namespace iroha

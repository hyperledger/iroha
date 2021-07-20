/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "utils/query_error_response_visitor.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace shared_model::interface::types;
using namespace common_constants;

class QueriesAcceptanceTest : public AcceptanceFixture {
 public:
  QueriesAcceptanceTest()
      : invalidPrivateKey(kUserKeypair.privateKey().hex()),
        invalidPublicKey(kUserKeypair.publicKey()) {
    /*
     * It's deliberately break the public and private keys to simulate a
     * non-valid signature and public key and use their combinations in the
     * tests below
     * Both keys are hex values represented as a std::string so
     * characters can be values only in the range 0-9 and a-f
     */
    invalidPrivateKey[0] == '9' or invalidPrivateKey[0] == 'f'
        ? --invalidPrivateKey[0]
        : ++invalidPrivateKey[0];
    invalidPublicKey[0] == '9' or invalidPublicKey[0] == 'f'
        ? --invalidPublicKey[0]
        : ++invalidPublicKey[0];
    invalidPublicKeyView = invalidPublicKey;
  };

  void SetUp(){};

  static void checkRolesResponse(const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const shared_model::interface::RolesResponse &>(
              response.get());
      ASSERT_NE(resp.roles().size(), 0);
    });
  }

  template <typename F>
  void executeForItf(F &&f) {
    for (auto const type :
         {iroha::StorageType::kPostgres, iroha::StorageType::kRocksDb}) {
      IntegrationTestFramework itf(1, type);
      itf.setInitialState(kAdminKeypair)
          .sendTxAwait(
              makeUserWithPerms({interface::permissions::Role::kGetRoles}),
              [](auto &block) {
                ASSERT_EQ(boost::size(block->transactions()), 1);
              });
      std::forward<F>(f)(itf);
    }
  }

  std::string invalidPrivateKey;
  std::string invalidPublicKey;
  PublicKeyHexStringView invalidPublicKeyView;
  const std::string NonExistentUserId = "aaaa@aaaa";
};

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a SFV integration test
 * (possibly including torii query processor)
 *
 * @given query with a non-existent creator_account_id
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateful validation
 */
TEST_F(QueriesAcceptanceTest, NonExistentCreatorId) {
  executeForItf([&](auto &itf) {
    auto query = complete(baseQry(NonExistentUserId).getRoles());

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatefulFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with an 1 hour old UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query returns list of roles
 */
TEST_F(QueriesAcceptanceTest, OneHourOldTime) {
  executeForItf([&](auto &itf) {
    auto query =
        complete(baseQry()
                     .createdTime(iroha::time::now(std::chrono::hours(-1)))
                     .getRoles());

    itf.sendQuery(query, checkRolesResponse);
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with more than 24 hour old UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, More24HourOldTime) {
  executeForItf([&](auto &itf) {
    auto query =
        complete(baseQry()
                     .createdTime(iroha::time::now(std::chrono::hours(-24)
                                                   - std::chrono::seconds(1)))
                     .getRoles());

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with less than 24 hour old UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query returns list of roles
 */
TEST_F(QueriesAcceptanceTest, Less24HourOldTime) {
  executeForItf([&](auto &itf) {
    auto query =
        complete(baseQry()
                     .createdTime(iroha::time::now(std::chrono::hours(-24)
                                                   + std::chrono::seconds(1)))
                     .getRoles());

    itf.sendQuery(query, checkRolesResponse);
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with less than 5 minutes from future UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query returns list of roles
 */
TEST_F(QueriesAcceptanceTest, LessFiveMinutesFromFuture) {
  executeForItf([&](auto &itf) {
    auto query =
        complete(baseQry()
                     .createdTime(iroha::time::now(std::chrono::minutes(5)
                                                   - std::chrono::seconds(1)))
                     .getRoles());

    itf.sendQuery(query, checkRolesResponse);
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with 5 minutes from future UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query returns list of roles
 */
TEST_F(QueriesAcceptanceTest, FiveMinutesFromFuture) {
  executeForItf([&](auto &itf) {
    auto query =
        complete(baseQry()
                     .createdTime(iroha::time::now(std::chrono::minutes(5)))
                     .getRoles());

    itf.sendQuery(query, checkRolesResponse);
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with more than 5 minutes from future UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, MoreFiveMinutesFromFuture) {
  executeForItf([&](auto &itf) {
    auto query =
        complete(baseQry()
                     .createdTime(iroha::time::now(std::chrono::minutes(5)
                                                   + std::chrono::seconds(1)))
                     .getRoles());

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with 10 minutes from future UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, TenMinutesFromFuture) {
  executeForItf([&](auto &itf) {
    auto query =
        complete(baseQry()
                     .createdTime(iroha::time::now(std::chrono::minutes(10)))
                     .getRoles());

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 * Note a similar test: AcceptanceTest.TransactionInvalidPublicKey
 *
 * @given query with Keypair which contains invalid signature but valid public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, InvalidSignValidPubKeypair) {
  executeForItf([&](auto &itf) {
    crypto::Keypair kInvalidSignValidPubKeypair = crypto::Keypair(
        PublicKeyHexStringView{kUserKeypair.publicKey()},
        crypto::PrivateKey(crypto::Blob::fromHexString(invalidPrivateKey)));

    auto query = complete(baseQry().getRoles(), kInvalidSignValidPubKeypair);

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 *
 * @given query with Keypair which contains valid signature but invalid public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, ValidSignInvalidPubKeypair) {
  executeForItf([&](auto &itf) {
    crypto::Keypair kValidSignInvalidPubKeypair =
        crypto::Keypair(invalidPublicKeyView, kUserKeypair.privateKey());

    auto query = complete(baseQry().getRoles(), kValidSignInvalidPubKeypair);

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a SFV integration test
 *
 * @given query with Keypair which contains invalid signature and invalid public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, FullyInvalidKeypair) {
  executeForItf([&](auto &itf) {
    crypto::Keypair kFullyInvalidKeypair = crypto::Keypair(
        invalidPublicKeyView,
        crypto::PrivateKey(crypto::Blob::fromHexString(invalidPrivateKey)));

    auto query = complete(baseQry().getRoles(), kFullyInvalidKeypair);

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 * Note a similar test: AcceptanceTest.EmptySignatures
 *
 * @given query with Keypair which contains empty signature and valid public key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, EmptySignValidPubKeypair) {
  executeForItf([&](auto &itf) {
    auto proto_query = complete(baseQry().getRoles()).getTransport();

    proto_query.clear_signature();
    auto query = proto::Query(proto_query);

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with Keypair which contains valid signature and empty public key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, ValidSignEmptyPubKeypair) {
  executeForItf([&](auto &itf) {
    auto proto_query = complete(baseQry().getRoles()).getTransport();

    proto_query.mutable_signature()->clear_public_key();
    auto query = proto::Query(proto_query);

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 *
 * @given query with Keypair which contains empty signature and empty public key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, FullyEmptyPubKeypair) {
  executeForItf([&](auto &itf) {
    auto proto_query = complete(baseQry().getRoles()).getTransport();

    proto_query.clear_signature();
    proto_query.mutable_signature()->clear_public_key();
    auto query = proto::Query(proto_query);

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 *
 * @given query with Keypair which contains invalid signature and empty public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, InvalidSignEmptyPubKeypair) {
  executeForItf([&](auto &itf) {
    crypto::Keypair kInvalidSignEmptyPubKeypair = crypto::Keypair(
        PublicKeyHexStringView{kUserKeypair.publicKey()},
        crypto::PrivateKey(crypto::Blob::fromHexString(invalidPrivateKey)));

    auto proto_query =
        complete(baseQry().getRoles(), kInvalidSignEmptyPubKeypair)
            .getTransport();

    proto_query.mutable_signature()->clear_public_key();
    auto query = proto::Query(proto_query);

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a SFV integration test
 * including SignableModelValidator or even whole torii::QueryService
 * and the crypto provider, that verifies that a transaction failing the
 * crypto provider check is rejected.
 *
 *
 * @given query with Keypair which contains empty signature and invalid public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, EmptySignInvalidPubKeypair) {
  executeForItf([&](auto &itf) {
    crypto::Keypair kEmptySignInvalidPubKeypair =
        crypto::Keypair(invalidPublicKeyView, kUserKeypair.privateKey());

    auto proto_query =
        complete(baseQry().getRoles(), kEmptySignInvalidPubKeypair)
            .getTransport();

    proto_query.clear_signature();
    auto query = proto::Query(proto_query);

    itf.sendQuery(
        query,
        checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
  });
}

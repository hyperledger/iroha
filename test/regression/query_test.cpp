/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "builders/protobuf/queries.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "interfaces/query_responses/error_responses/stateless_failed_error_response.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using shared_model::interface::types::PublicKeyHexStringView;

template <typename BaseType>
auto makeQuery() {
  return BaseType()
      .createdTime(iroha::time::now())
      .creatorAccountId("admin@test")
      .queryCounter(1)
      .getAccount("admin@test")
      .build();
}

template <typename Query>
auto createInvalidQuery(Query query,
                        const shared_model::crypto::Keypair &keypair) {
  std::string signature{32, 'a'};
  query.addSignature(
      shared_model::interface::types::SignedHexStringView{signature},
      PublicKeyHexStringView{keypair.publicKey()});
  return query;
}

/**
 * @given itf instance
 * @when  pass query with invalid signature
 * @then  assure that query with invalid signature is failed with stateless
 * error
 */
TEST(QueryTest, FailedQueryTest) {
  const auto key_pair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();

  auto query_with_broken_signature =
      createInvalidQuery(makeQuery<TestQueryBuilder>(), key_pair);
  auto stateless_invalid_query_response = [](auto &status) {
    auto &resp =
        boost::get<const shared_model::interface::ErrorQueryResponse &>(
            status.get());
    boost::get<const shared_model::interface::StatelessFailedErrorResponse &>(
        resp.get());
  };

  for (auto const type :
       {iroha::StorageType::kPostgres, iroha::StorageType::kRocksDb}) {
    integration_framework::IntegrationTestFramework itf(1, type);
    itf.setInitialState(key_pair).sendQuery(query_with_broken_signature,
                                            stateless_invalid_query_response);
  }
}

/**
 * @given itf instance
 * @when  pass block query with invalid signature
 * @then  assure that query with invalid signature is failed with stateless
 * error
 */
TEST(QueryTest, FailedBlockQueryTest) {
  // TODO: 01/08/2018 @muratovv Implement test since IR-1569 will be completed
}

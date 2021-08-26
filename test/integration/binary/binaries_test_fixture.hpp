/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BINARIES_TEST_FIXTURE_HPP
#define IROHA_BINARIES_TEST_FIXTURE_HPP

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include <vector>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/binary/launchers.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"

namespace shared_model {

  namespace proto {
    class Query;
  }

  namespace interface {

    class Block;
    class AccountDetailResponse;
    class AccountAssetResponse;
    class AccountResponse;
    class AssetResponse;
    class RolePermissionsResponse;
    class RolesResponse;
    class SignatoriesResponse;
    class TransactionsResponse;

  }  // namespace interface

}  // namespace shared_model

namespace query_validation {

  using QueryIterator = std::vector<shared_model::proto::Query>::iterator;

  namespace internal {

    /**
     * Helper type that is used as a marker of the end of types list in variadic
     * templates.
     * Should not be used outside of query_validation namespace.
     */
    class Void {};

    /**
     * Asserts that actual query response type equals to expected type.
     *
     * @tparam ExpectedResponseType - expected type of QueryResponse object
     * @param response - QueryResponse object to check
     */
    template <typename ExpectedResponseType>
    inline void checkQueryResponseType(
        const shared_model::proto::QueryResponse &response) {
      ASSERT_NO_THROW(boost::get<const ExpectedResponseType &>(response.get()));
    }

    /**
     * Recursively iterates over a list of types and a vector of queries,
     * executes queries and asserts that query responses types equal to expected
     * types.
     *
     * @tparam Head - the type of expected query response for the current query
     * @tparam Tail - the rest of expected query response types
     * @param it - points to query needs to be checked on current step
     * @param end - queries' vector iterator that points to .end()
     * @param itf - already initialized ITF instance that will be used queries
     *    execution.
     */
    template <typename Head, typename... Tail>
    inline void _validateQueries(
        ::query_validation::QueryIterator it,
        ::query_validation::QueryIterator end,
        integration_framework::IntegrationTestFramework &itf) {
      if (it != end) {
        itf.sendQuery(*it, checkQueryResponseType<Head>);
        _validateQueries<Tail...>(++it, end, itf);
      }
    }

    /**
     * Handles terminating scenario for recursion made over variadic templates.
     */
    template <>
    inline void _validateQueries<internal::Void>(
        ::query_validation::QueryIterator it,
        ::query_validation::QueryIterator end,
        integration_framework::IntegrationTestFramework &itf){};

  }  // namespace internal

  /**
   * Sequentially executes queries via ITF and asserts that types of actual
   * query responses equal to expected types.
   *
   * @tparam ExpectedResponsesTypes - A list of types of expected query
   *    responses. The order of types should match the order of queries in a
   *    vector.
   * @param it - queries' vector iterator that points to .begin()
   * @param end - queries' vector iterator that points to .end()
   * @param itf - already initialized ITF instance that will be used queries
   *    execution.
   */
  template <typename... ExpectedResponsesTypes>
  inline void validateQueriesResponseTypes(
      QueryIterator it,
      QueryIterator end,
      integration_framework::IntegrationTestFramework &itf) {
    internal::_validateQueries<ExpectedResponsesTypes..., internal::Void>(
        it, end, itf);
  }

}  // namespace query_validation

/**
 * @tparam Launcher - class that can run scripts on target language for
 * transactions' and queries' binaries generation.
 */
template <typename Launcher>
class BinaryTestFixture
    : public ::testing::Test,
      public ::testing::WithParamInterface<iroha::StorageType> {
  {
   public:
    static constexpr iroha::StorageType storage_types[] = {
        iroha::StorageType::kPostgres, iroha::StorageType::kRocksDb};

    Launcher launcher;

    /**
     * Generates genesis block for ITF initialization using the first
     * transaction and keypair received from launcher.
     *
     * @return - genesis block
     */
    shared_model::proto::Block genesis() {
      return makeGenesis(launcher.transactions[0], *launcher.admin_key);
    }

    /**
     * Callback that asserts that passed block contains one transaction.
     *
     * @param result - Block object
     */
    static void blockWithTransactionValidation(
        const std::shared_ptr<const shared_model::interface::Block> &result) {
      ASSERT_EQ(result->transactions().size(), 1);
    }

    /**
     * Initalizes ITF. Sequentially applies transacttions and then queries
     * provided by launcher. Checks that every transaction was committed.
     * Asserts that query response types match to expected types.
     *
     * @tparam ExpectedQueryResponsesTypes - list of expected query response
     * types. The order should match order of queries that were provided by
     *    launcher.
     * @param transactions_expected - expected amount of transactions
     * @param queries_expected - expected amount of queries
     */
    template <typename... ExpectedQueryResponsesTypes>
    void doTest(const unsigned &transactions_expected = 0,
                const unsigned &queries_expected = 0) {
      if (launcher.initialized(transactions_expected, queries_expected)) {
        integration_framework::IntegrationTestFramework itf(1, GetParam());

        itf.setInitialState(launcher.admin_key.value(), genesis());

        std::for_each(
            std::next(  // first transaction was used as genesis transaction
                launcher.transactions.begin()),
            launcher.transactions.end(),
            [&itf](const auto &tx) {
              itf.sendTx(tx).checkBlock(
                  BinaryTestFixture::blockWithTransactionValidation);
            });

        query_validation::validateQueriesResponseTypes<
            ExpectedQueryResponsesTypes...>(
            launcher.queries.begin(), launcher.queries.end(), itf);

        itf.done();
    }
  }

 protected:
  virtual void SetUp() {
    launcher(::testing::UnitTest::GetInstance()->current_test_info()->name());
  }

  shared_model::proto::Block makeGenesis(
      const shared_model::proto::Transaction &genesis_tx,
      const shared_model::crypto::Keypair &keypair) {
    return shared_model::proto::BlockBuilder()
        .transactions(std::vector<shared_model::proto::Transaction>{genesis_tx})
        .height(1)
        .prevHash(shared_model::crypto::DefaultHashProvider::makeHash(
            shared_model::crypto::Blob("")))
        .createdTime(iroha::time::now())
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }
  };

#endif  // IROHA_BINARIES_TEST_FIXTURE_HPP

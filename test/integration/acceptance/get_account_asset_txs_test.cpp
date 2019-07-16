/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "query_permission_fixture.hpp"
#include "query_permission_test_ast_txs.hpp"

using namespace common_constants;
using AccountAssetTxsFixture = QueryPermissionFixture<QueryPermissionAssetTxs>;

static constexpr shared_model::interface::types::TransactionsNumberType
    kTxPageSize(10);

/**
 * TODO mboldyrev 18.01.2019 IR-209 remove, covered by field validator test
 *
 * C346 Pass an empty asset id
 * @given a user with kGetAllAccAstTxs permission
 * @when the user tries to retrieve a list of own asset transactions specifying
 * empty asset id
 * @then the query recognized as stateless invalid
 */
TEST_F(AccountAssetTxsFixture, ReadEmptyAssetHavingAllTxsPermission) {
  const interface::types::AssetIdType empty = "";
  impl_.prepareState(*this, {Role::kGetAllAccAstTxs})
      .sendQuery(complete(baseQry().getAccountAssetTransactions(
                     kUserId, empty, kTxPageSize)),
                 getQueryStatelesslyInvalidChecker());
}

/**
 * TODO mboldyrev 18.01.2019 IR-209 convert to a SFV integration test
 * (no such test in postgres_query_executor_test)
 *
 * C347 Pass a non existing asset id
 * @given a user with kGetAllAccAstTxs permission
 * @when the user tries tor retrieve a list of own asset transactions specifying
 * a non-existing asset id
 * @then the query recognized as stateful invalid
 *
 * TODO igor-egorov, 2018-08-21, IR-1631, wrong response (it returns
 * TransactionsResponse instead of ErrorQueryResponse)
 */
TEST_F(AccountAssetTxsFixture,
       DISABLED_ReadNonExistingAssetHavingAllTxsPermission) {
  const interface::types::AssetIdType non_existing = "nonexisting#" + kDomain;
  impl_.prepareState(*this, {Role::kGetAllAccAstTxs})
      .sendQuery(complete(baseQry().getAccountAssetTransactions(
                     kUserId, non_existing, kTxPageSize)),
                 getQueryStatefullyInvalidChecker());
}

/**
 * TODO mboldyrev 18.01.2019 IR-209 convert to a SFV integration test
 * (no such test in postgres_query_executor_test)
 *
 * @given a user with kGetAllAccAstTxs permission
 * @when the user tries to retrieve a list of own asset transactions, which
 * contain a transaction with addAssetQuantity command
 * @then all transactions are shown
 *
 * TODO igor-egorov, 2018-08-21, IR-1632, wrong response (response does not
 * contain transaction with addAssetQuantity command)
 */
TEST_F(AccountAssetTxsFixture, DISABLED_OwnTxsIncludingAddAssetQuantity) {
  auto tx = complete(baseTx().addAssetQuantity(kAssetId, "200.0"));
  impl_.tx_hashes_.push_back(tx.hash());
  impl_.prepareState(*this, {Role::kGetAllAccAstTxs})
      .sendTxAwait(
          tx, [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendQuery(complete(baseQry().getAccountAssetTransactions(
                     kUserId, kAssetId, kTxPageSize)),
                 impl_.getGeneralResponseChecker());
}

/**
 * TODO mboldyrev 18.01.2019 IR-209 convert to a SFV integration test
 * (no such test in postgres_query_executor_test)
 *
 * @given a user with kGetAllAccAstTxs permission
 * @when the user tries to retrieve a list of own asset transactions, which
 * contain a transaction with subtractAssetQuantity command
 * @then all transactions are shown
 *
 * TODO igor-egorov, 2018-08-21, IR-1632, wrong response (response does not
 * contain transaction with subtractAssetQuantity command)
 */
TEST_F(AccountAssetTxsFixture, DISABLED_OwnTxsIncludingSubtractAssetQuantity) {
  auto tx = complete(baseTx()
                         .addAssetQuantity(kAssetId, "200.0")
                         .subtractAssetQuantity(kAssetId, "100.0"));
  impl_.tx_hashes_.push_back(tx.hash());
  impl_.prepareState(*this, {Role::kGetAllAccAstTxs})
      .sendTxAwait(
          tx, [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendQuery(complete(baseQry().getAccountAssetTransactions(
                     kUserId, kAssetId, kTxPageSize)),
                 impl_.getGeneralResponseChecker());
}

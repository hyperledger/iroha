/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "query_permission_fixture.hpp"
#include "query_permission_test_ast_txs.hpp"
#include "query_permission_test_txs.hpp"

using namespace common_constants;
using QueryPermissionTestingTypes =
    ::testing::Types<QueryPermissionAssetTxs, QueryPermissionTxs>;
TYPED_TEST_SUITE(QueryPermissionFixture, QueryPermissionTestingTypes, );

/**
 * TODO mboldyrev 18.01.2019 IR-219 remove, covered by field validator test
 *
 * Get data from a non-existing account
 * @given a user with permission to read all accounts
 * @when tries to retrieve data from a non-existing
 * account id
 * @then no data are shown. Query should be recognized as stateful
 * invalid
 *
 * TODO igor-egorov, 2018-08-21, IR-1631, wrong response (it returns
 * TransactionsResponse instead of ErrorQueryResponse)
 */
TYPED_TEST(QueryPermissionFixture,
           DISABLED_ReadNonExistingAccountHavingPermissionForAll) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryEveryone})
      .sendQuery(this->impl_.makeQuery(
                     *this, "nonexisting@" + kDomain, kUserId, kUserKeypair),
                 getQueryStatefullyInvalidChecker());
}

/**
 * TODO mboldyrev 18.01.2019 IR-219 remove, covered by field validator test
 *
 * Pass an empty account id
 * @given a user with permission to read all accounts
 * @when the user tries to retrieve data from an account with empty id
 * @then the query recognized as stateless invalid
 */
TYPED_TEST(QueryPermissionFixture, ReadEmptyAccountHavingPermissionForAll) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryEveryone})
      .sendQuery(this->impl_.makeQuery(*this, "", kUserId, kUserKeypair),
                 getQueryStatelesslyInvalidChecker());
}

/*
 * TODO mboldyrev 18.01.2019 IR-219 convert to a SFV integration test
 *
 * Below are test cases that check different combinations of permission modes
 * (1 - no permissions,   2 - can_get_my_*,
 *  3 - can_get_domain_*, 4 - can_get_all_*)
 * combined with different accounts as query source
 * (1 - target user's own account,
 *  2 - an account from the same domain as target account,
 *  3 - an account from domain that different to domain of target account).
 */

/**
 * Get my data without any permission
 * @given a user without any query permission
 * @when the user tries to retrieve data from own account
 * @then no data are shown. Query should be recognized as stateful invalid
 */
TYPED_TEST(QueryPermissionFixture, OwnWithoutAnyPermission) {
  this->impl_.prepareState(*this, {}).sendQuery(
      this->impl_.makeQuery(*this, kUserId, kUserId, kUserKeypair),
      getQueryStatefullyInvalidChecker());
}

/**
 * Get my data with a permission for my account
 * @given a user with permission to read own account
 * @when the user tries to retrieve data from own account
 * @then data are shown to the user
 */
TYPED_TEST(QueryPermissionFixture, OwnWithPermissionForMy) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryMyself})
      .sendQuery(this->impl_.makeQuery(*this, kUserId, kUserId, kUserKeypair),
                 this->impl_.getGeneralResponseChecker());
}

/**
 * Get my data with only CanGetDomainAccountAssetTransactions
 * permission
 * @given a user with permission to read same domain accounts
 * @when the user tries to retrieve data from own account
 * @then data are shown
 */
TYPED_TEST(QueryPermissionFixture, OwnWithPermissionForDomain) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryMyDomain})
      .sendQuery(this->impl_.makeQuery(*this, kUserId, kUserId, kUserKeypair),
                 this->impl_.getGeneralResponseChecker());
}

/**
 * Get my data with only CanGetAllAccountAssetTransactions
 * permission
 * @given a user with permission to read all accounts
 * @when the user tries to retrieve data from own account
 * @then data are shown
 */
TYPED_TEST(QueryPermissionFixture, OwnWithPermissionForAll) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryEveryone})
      .sendQuery(this->impl_.makeQuery(*this, kUserId, kUserId, kUserKeypair),
                 this->impl_.getGeneralResponseChecker());
}

/**
 * @given a user without any query permission
 * @when the user tries to retrieve data from a user from the same domain
 * @then no data are shown. Query should be recognized as stateful invalid
 */
TYPED_TEST(QueryPermissionFixture, AnothersFromSameDomainWithoutAnyPermission) {
  this->impl_.prepareState(*this, {}).sendQuery(
      this->impl_.makeQuery(
          *this, kUserId, kSameDomainUserId, kSameDomainUserKeypair),
      getQueryStatefullyInvalidChecker());
}

/**
 * @given a user with permission to read own account
 * @when the user tries to retrieve data from a user from the same domain
 * @then no data are shown. Query should be recognized as stateful
 * invalid
 */
TYPED_TEST(QueryPermissionFixture, AnothersFromSameDomainWithPermissionForMy) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryMyself})
      .sendQuery(this->impl_.makeQuery(
                     *this, kUserId, kSameDomainUserId, kSameDomainUserKeypair),
                 getQueryStatefullyInvalidChecker());
}

/**
 * Get account data from the domain having
 * CanGetDomainAccountAssetTransactions permission
 * @given a user with permission to read same domain accounts
 * @when the user tries to retrieve data from a user from the same domain
 * @then data are shown
 */
TYPED_TEST(QueryPermissionFixture,
           AnothersFromSameDomainWithPermissionForDomain) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryMyDomain})
      .sendQuery(this->impl_.makeQuery(
                     *this, kUserId, kSameDomainUserId, kSameDomainUserKeypair),
                 this->impl_.getGeneralResponseChecker());
}

/**
 * @given a user with permission to read all accounts
 * @when the user tries to retrieve data from a user from the same domain
 * @then data are shown
 */
TYPED_TEST(QueryPermissionFixture, AnothersFromSameDomainWithPermissionForAll) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryEveryone})
      .sendQuery(this->impl_.makeQuery(
                     *this, kUserId, kSameDomainUserId, kSameDomainUserKeypair),
                 this->impl_.getGeneralResponseChecker());
}

/**
 * @given a user without any query permission
 * @when the user tries to retrieve data of a user from another domain
 * @then no data are shown. Query should be recognized as stateful invalid
 */
TYPED_TEST(QueryPermissionFixture,
           AnothersFromDifferentDomainWithoutAnyPermission) {
  this->impl_.prepareState(*this, {}).sendQuery(
      this->impl_.makeQuery(
          *this, kUserId, kSecondDomainUserId, kSecondDomainUserKeypair),
      getQueryStatefullyInvalidChecker());
}

/**
 * Get another's data from a different domain with permission for my
 * account
 * @given a user with permission to read own account
 * @when the user tries to retrieve data of a user from another domain
 * @then no data are shown. Query should be recognized as stateful invalid
 */
TYPED_TEST(QueryPermissionFixture,
           AnothersFromDifferentDomainWithPermissionForMy) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryMyself})
      .sendQuery(
          this->impl_.makeQuery(
              *this, kUserId, kSecondDomainUserId, kSecondDomainUserKeypair),
          getQueryStatefullyInvalidChecker());
}

/**
 * Get another's data from a different domain with permission for same
 * domain
 * @given a user with permission to read same domain accounts
 * @when the user tries to retrieve data of a user from another domain
 * @then no data are shown. Query should be recognized as stateful
 * invalid
 */
TYPED_TEST(QueryPermissionFixture,
           AnothersFromDifferentDomainWithPermissionForDomain) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryMyDomain})
      .sendQuery(
          this->impl_.makeQuery(
              *this, kUserId, kSecondDomainUserId, kSecondDomainUserKeypair),
          getQueryStatefullyInvalidChecker());
}

/**
 * Get account data from another domain having
 * CanGetAllAccountAssetTransactions permission
 * @given a user with permission to read all accounts
 * @when the user tries to retrieve data of a user from another domain
 * @then data are shown
 */
TYPED_TEST(QueryPermissionFixture,
           AnothersFromDifferentDomainWithPermissionForAll) {
  this->impl_.prepareState(*this, {this->impl_.kPermissionToQueryEveryone})
      .sendQuery(
          this->impl_.makeQuery(
              *this, kUserId, kSecondDomainUserId, kSecondDomainUserKeypair),
          this->impl_.getGeneralResponseChecker());
}

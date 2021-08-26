/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ACCEPTANCE_FIXTURE_HPP
#define IROHA_ACCEPTANCE_FIXTURE_HPP

#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <vector>

#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"
#include "cryptography/keypair.hpp"
#include "framework/common_constants.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/query_responses/query_response.hpp"
#include "interfaces/transaction_responses/tx_response.hpp"
#include "main/startup_params.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

namespace {
  template <typename Type, typename T>
  void checkTransactionResponse(const T &resp) {
    ASSERT_NO_THROW(boost::get<const Type &>(resp.get())) << resp.toString();
  }

#define BASE_CHECK_RESPONSE(type)                                  \
  [](const auto &resp) {                                           \
    SCOPED_TRACE(#type);                                           \
    checkTransactionResponse<shared_model::interface::type>(resp); \
  }

#define CHECK_ENOUGH_SIGNATURES \
  BASE_CHECK_RESPONSE(EnoughSignaturesCollectedResponse)

#define CHECK_STATELESS_INVALID BASE_CHECK_RESPONSE(StatelessFailedTxResponse)

#define CHECK_STATELESS_VALID BASE_CHECK_RESPONSE(StatelessValidTxResponse)

#define CHECK_STATEFUL_INVALID BASE_CHECK_RESPONSE(StatefulFailedTxResponse)

#define CHECK_STATEFUL_VALID BASE_CHECK_RESPONSE(StatefulValidTxResponse)

#define CHECK_COMMITTED BASE_CHECK_RESPONSE(CommittedTxResponse)

#define CHECK_REJECTED BASE_CHECK_RESPONSE(RejectedTxResponse)

#define CHECK_MST_PENDING BASE_CHECK_RESPONSE(MstPendingResponse)

#define CHECK_TXS_QUANTITY(i) \
  [](const auto &resp) { ASSERT_EQ(resp->transactions().size(), i); }
}  // namespace

/**
 * Common values (user, domain, asset)
 * and methods (create user, base transaction) for acceptance tests
 */
class AcceptanceFixture : public ::testing::Test {
 public:
  AcceptanceFixture();

  virtual ~AcceptanceFixture() = default;

  /**
   * Creates a set of transactions for user creation
   * @param user is username of new user
   * @param key is a public key of new user
   * @return pre-built transaction
   */
  TestUnsignedTransactionBuilder createUser(
      const shared_model::interface::types::AccountNameType &user,
      shared_model::interface::types::PublicKeyHexStringView key);

  /**
   * Creates a set of transactions for user creation with specified permissions
   * @param user is username of new user
   * @param key is a public key of new user
   * @param role_id is new role of the user
   * @param perms is a collections of permissions of the user
   * @return pre-build transaction
   */
  TestUnsignedTransactionBuilder createUserWithPerms(
      const shared_model::interface::types::AccountNameType &user,
      shared_model::interface::types::PublicKeyHexStringView key,
      const shared_model::interface::types::RoleIdType &role_id,
      const shared_model::interface::RolePermissionSet &perms);

  /**
   * Creates the transaction with the user creation commands
   * @param role_name is a name of the role
   * @param perms are the permissions of the user
   * @return built tx and a hash of its payload
   */
  shared_model::proto::Transaction makeUserWithPerms(
      const shared_model::interface::types::RoleIdType &role_name,
      const shared_model::interface::RolePermissionSet &perms);

  /**
   * Creates the transaction with the user creation commands
   * @param perms are the permissions of the user
   * @return built tx and a hash of its payload
   */
  shared_model::proto::Transaction makeUserWithPerms(
      const shared_model::interface::RolePermissionSet &perms);

  /**
   * Add default user creator account id and current created time to builder
   * @tparam Builder type (transaction, query)
   * @param builder object to modify
   * @param account_id - account of transaction creator
   * @return builder containing creator account id and created time
   */
  template <typename Builder>
  auto base(Builder builder,
            const shared_model::interface::types::AccountIdType &account_id)
      -> decltype(builder
                      .creatorAccountId(
                          shared_model::interface::types::AccountIdType())
                      .createdTime(uint64_t()));

  /**
   * Create valid base pre-built transaction with specified creator
   * @param account_id - account of transaction creator
   * @return pre-built tx
   */
  auto baseTx(const shared_model::interface::types::AccountIdType &account_id)
      -> decltype(base(TestUnsignedTransactionBuilder(),
                       shared_model::interface::types::AccountIdType()));

  /**
   * Create valid base pre-built transaction with kUserId as transaction creator
   * @return pre-built tx
   */
  auto baseTx()
      -> decltype(baseTx(shared_model::interface::types::AccountIdType()));

  /**
   * Create valid base pre-built query with specified query creator
   * @param account_id - account of query creator
   * @return pre-built query
   */
  auto baseQry(const shared_model::interface::types::AccountIdType &account_id)
      -> decltype(base(TestUnsignedQueryBuilder(), std::string()));

  /**
   * Create valid base pre-built query with kUserId as query creator
   * @return pre-built query
   */
  auto baseQry() -> decltype(baseQry(std::string()));

  /**
   * Completes pre-built object with specified keypair for signing
   * @tparam Builder - is a type of a pre-built object
   * @param builder - is a pre-built object
   * @param keypair - keypair used for signing
   * @return built object
   */
  template <typename Builder>
  auto complete(Builder builder, const shared_model::crypto::Keypair &keypair)
      -> decltype(builder.build()
                      .signAndAddSignature(
                          std::declval<shared_model::crypto::Keypair>())
                      .finish());

  /**
   * Completes pre-built object with kUserKeypair used for signing
   * @param builder is a pre-built object
   * @return built object
   */
  template <typename Builder>
  auto complete(Builder builder) -> decltype(builder.build().finish());

  /**
   * Checks whether a response contains particular error
   * @tparam ErrorResponse is type of error to check against
   * @param response to check for
   */
  template <typename ErrorResponse>
  std::function<void(const shared_model::interface::QueryResponse &)>
  checkQueryErrorResponse();

  /**
   * @return unique time for this fixture
   */
  iroha::time::time_t getUniqueTime();

 private:
  iroha::time::time_t initial_time;
  /// number of created transactions, used to provide unique time
  std::atomic_int nonce_counter;
};

#endif  // IROHA_ACCEPTANCE_FIXTURE_HPP

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/acceptance_fixture.hpp"

#include <utility>

#include "datetime/time.hpp"
#include "utils/query_error_response_visitor.hpp"

using namespace common_constants;

AcceptanceFixture::AcceptanceFixture()
    : initial_time(iroha::time::now()), nonce_counter(1) {}

TestUnsignedTransactionBuilder AcceptanceFixture::createUser(
    const shared_model::interface::types::AccountNameType &user,
    shared_model::interface::types::PublicKeyHexStringView key) {
  return TestUnsignedTransactionBuilder()
      .createAccount(user, kDomain, key)
      .creatorAccountId(kAdminId)
      .createdTime(getUniqueTime())
      .quorum(1);
}

TestUnsignedTransactionBuilder AcceptanceFixture::createUserWithPerms(
    const shared_model::interface::types::AccountNameType &user,
    shared_model::interface::types::PublicKeyHexStringView key,
    const shared_model::interface::types::RoleIdType &role_id,
    const shared_model::interface::RolePermissionSet &perms) {
  const auto user_id = user + "@" + kDomain;
  return createUser(user, key)
      .detachRole(user_id, kDefaultRole)
      .createRole(role_id, perms)
      .appendRole(user_id, role_id);
}

shared_model::proto::Transaction AcceptanceFixture::makeUserWithPerms(
    const shared_model::interface::types::RoleIdType &role_name,
    const shared_model::interface::RolePermissionSet &perms) {
  using shared_model::interface::types::PublicKeyHexStringView;
  return createUserWithPerms(kUser,
                             PublicKeyHexStringView{kUserKeypair.publicKey()},
                             role_name,
                             perms)
      .build()
      .signAndAddSignature(kAdminKeypair)
      .finish();
}

shared_model::proto::Transaction AcceptanceFixture::makeUserWithPerms(
    const shared_model::interface::RolePermissionSet &perms) {
  return makeUserWithPerms(kRole, perms);
}

template <typename Builder>
auto AcceptanceFixture::base(
    Builder builder,
    const shared_model::interface::types::AccountIdType &account_id)
    -> decltype(
        builder
            .creatorAccountId(shared_model::interface::types::AccountIdType())
            .createdTime(uint64_t())) {
  return builder.creatorAccountId(account_id).createdTime(getUniqueTime());
}

template auto AcceptanceFixture::base<TestUnsignedTransactionBuilder>(
    TestUnsignedTransactionBuilder builder,
    const shared_model::interface::types::AccountIdType &account_id)
    -> decltype(
        builder
            .creatorAccountId(shared_model::interface::types::AccountIdType())
            .createdTime(uint64_t()));
template auto AcceptanceFixture::base<TestUnsignedQueryBuilder>(
    TestUnsignedQueryBuilder builder,
    const shared_model::interface::types::AccountIdType &account_id)
    -> decltype(
        builder
            .creatorAccountId(shared_model::interface::types::AccountIdType())
            .createdTime(uint64_t()));

auto AcceptanceFixture::baseTx(
    const shared_model::interface::types::AccountIdType &account_id)
    -> decltype(base(TestUnsignedTransactionBuilder(), std::string())) {
  return base(TestUnsignedTransactionBuilder(), account_id).quorum(1);
}

auto AcceptanceFixture::baseTx()
    -> decltype(baseTx(shared_model::interface::types::AccountIdType())) {
  return baseTx(kUserId);
}

auto AcceptanceFixture::baseQry(
    const shared_model::interface::types::AccountIdType &account_id)
    -> decltype(base(TestUnsignedQueryBuilder(), std::string())) {
  return base(TestUnsignedQueryBuilder(), account_id)
      .queryCounter(nonce_counter);
}

auto AcceptanceFixture::baseQry()
    -> decltype(baseQry(shared_model::interface::types::AccountIdType())) {
  return baseQry(kUserId);
}

template <typename Builder>
auto AcceptanceFixture::complete(Builder builder,
                                 const shared_model::crypto::Keypair &keypair)
    -> decltype(
        builder.build()
            .signAndAddSignature(std::declval<shared_model::crypto::Keypair>())
            .finish()) {
  return builder.build().signAndAddSignature(keypair).finish();
}

template auto AcceptanceFixture::complete<TestUnsignedTransactionBuilder>(
    TestUnsignedTransactionBuilder builder,
    const shared_model::crypto::Keypair &keypair)
    -> decltype(
        builder.build()
            .signAndAddSignature(std::declval<shared_model::crypto::Keypair>())
            .finish());
template auto AcceptanceFixture::complete<TestUnsignedQueryBuilder>(
    TestUnsignedQueryBuilder builder,
    const shared_model::crypto::Keypair &keypair)
    -> decltype(
        builder.build()
            .signAndAddSignature(std::declval<shared_model::crypto::Keypair>())
            .finish());

template <typename Builder>
auto AcceptanceFixture::complete(Builder builder)
    -> decltype(builder.build().finish()) {
  return complete(builder, kUserKeypair);
}

template <typename ErrorResponse>
std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse() {
  return [](auto &response) {
    ASSERT_TRUE(boost::apply_visitor(
        shared_model::interface::QueryErrorResponseChecker<ErrorResponse>(),
        response.get()));
  };
}

template auto AcceptanceFixture::complete<TestUnsignedTransactionBuilder>(
    TestUnsignedTransactionBuilder builder)
    -> decltype(builder.build().finish());
template auto AcceptanceFixture::complete<TestUnsignedQueryBuilder>(
    TestUnsignedQueryBuilder builder) -> decltype(builder.build().finish());

template std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse<
    shared_model::interface::StatelessFailedErrorResponse>();
template std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse<
    shared_model::interface::StatefulFailedErrorResponse>();
template std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse<
    shared_model::interface::NoAccountErrorResponse>();
template std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse<
    shared_model::interface::NoAccountAssetsErrorResponse>();
template std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse<
    shared_model::interface::NoAccountDetailErrorResponse>();
template std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse<
    shared_model::interface::NoSignatoriesErrorResponse>();
template std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse<
    shared_model::interface::NotSupportedErrorResponse>();
template std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse<
    shared_model::interface::NoAssetErrorResponse>();
template std::function<void(const shared_model::interface::QueryResponse &)>
AcceptanceFixture::checkQueryErrorResponse<
    shared_model::interface::NoRolesErrorResponse>();

iroha::time::time_t AcceptanceFixture::getUniqueTime() {
  return initial_time + nonce_counter++;
}

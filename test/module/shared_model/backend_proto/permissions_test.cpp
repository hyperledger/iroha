/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/permissions.hpp"
#include <gtest/gtest.h>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>

using namespace shared_model::proto::permissions;

template <typename PermType>
static PermType getRole(int i) {
  return static_cast<PermType>(i);
}

class RolePermType {
 public:
  using Proto = iroha::protocol::RolePermission;
  using Model = shared_model::interface::permissions::Role;

  static auto descriptor() {
    return iroha::protocol::RolePermission_descriptor();
  }

  static auto size() {
    return iroha::protocol::RolePermission_ARRAYSIZE;
  }

  static void parse(const std::string &name, Proto *t) {
    iroha::protocol::RolePermission_Parse(name, t);
  }
};

class GrantablePermType {
 public:
  using Proto = iroha::protocol::GrantablePermission;
  using Model = shared_model::interface::permissions::Grantable;

  static auto descriptor() {
    return iroha::protocol::GrantablePermission_descriptor();
  }

  static auto size() {
    return iroha::protocol::GrantablePermission_ARRAYSIZE;
  }

  static void parse(const std::string &name, Proto *t) {
    iroha::protocol::GrantablePermission_Parse(name, t);
  }
};

template <typename T>
class ProtoPermission : public ::testing::Test {
 public:
  typename T::Proto perm;
};

typedef ::testing::Types<RolePermType, GrantablePermType> PermTypes;
TYPED_TEST_SUITE(ProtoPermission, PermTypes, );

/**
 * For each protobuf RolePermission
 * @given protobuf RolePermission
 * @when fromTransport is called
 * @then related sm type produced
 */
TYPED_TEST(ProtoPermission, IsValid) {
  boost::for_each(boost::irange(0, TypeParam::size()), [&](auto i) {
    ASSERT_TRUE(isValid(getRole<typename TypeParam::Model>(i)));
  });
}

/**
 * For each protobuf RolePermission
 * @given protobuf RolePermission
 * @when fromTransport is called
 * @then related sm type produced
 */
TYPED_TEST(ProtoPermission, FromTransport) {
  boost::for_each(boost::irange(0, TypeParam::size()), [&](auto i) {
    this->perm = getRole<decltype(this->perm)>(i);
    auto converted = fromTransport(this->perm);
    ASSERT_EQ(getRole<typename TypeParam::Model>(i), converted);
  });
}

/**
 * For each protobuf RolePermission
 * @given protobuf RolePermission
 * @when composition of fromTransport and toTransport is called
 * @then previous protobuf object produced
 */
TYPED_TEST(ProtoPermission, FromToTransport) {
  auto desc = TypeParam::descriptor();
  boost::for_each(boost::irange(0, TypeParam::size()), [&](auto i) {
    TypeParam::parse(desc->value(i)->name(), &this->perm);
    auto converted = fromTransport(this->perm);
    ASSERT_EQ(this->perm, toTransport(converted));
  });
}

/**
 * For each sm role permission type
 * @given protobuf RolePermission
 * @when toTransport is called
 * @then related protobuf object permission produced
 */
TYPED_TEST(ProtoPermission, ToTransport) {
  boost::for_each(boost::irange(0, TypeParam::size()), [&](auto i) {
    this->perm = getRole<decltype(this->perm)>(i);
    ASSERT_EQ(this->perm, toTransport(getRole<typename TypeParam::Model>(i)));
  });
}

/**
 * @given sizes of protobuf and sm permissions
 * @when -
 * @then they are equal
 */
TYPED_TEST(ProtoPermission, SizesMatch) {
  ASSERT_EQ(static_cast<decltype(TypeParam::size())>(TypeParam::Model::COUNT),
            TypeParam::size());
}

TEST(ProtoPermission, PermissionSet) {
  using Role = shared_model::interface::permissions::Role;
  using PermSet = shared_model::interface::PermissionSet<Role>;
  PermSet set({Role::kAppendRole, Role::kAddAssetQty, Role::kAddPeer});
  ASSERT_TRUE(set.isSet(Role::kAppendRole));
  ASSERT_TRUE(set.isSet(Role::kAddAssetQty));
  ASSERT_TRUE(set.isSet(Role::kAddPeer));
  ASSERT_FALSE(set.isSet(Role::kTransfer));
  set.set(Role::kTransfer);
  ASSERT_TRUE(set.isSet(Role::kTransfer));
  set.unset(Role::kAddAssetQty);
  ASSERT_FALSE(set.isSet(Role::kAddAssetQty));
}

TEST(ProtoPermission, PermissionSubset) {
  using Role = shared_model::interface::permissions::Role;
  using PermSet = shared_model::interface::PermissionSet<Role>;
  PermSet big({Role::kAppendRole,
               Role::kCreateRole,
               Role::kDetachRole,
               Role::kAddAssetQty,
               Role::kSubtractAssetQty,
               Role::kAddPeer,
               Role::kAddSignatory,
               Role::kRemoveSignatory,
               Role::kSetQuorum,
               Role::kCreateAccount,
               Role::kSetDetail,
               Role::kCreateAsset,
               Role::kTransfer,
               Role::kReceive});
  PermSet sub({Role::kAppendRole,
               Role::kCreateRole,
               Role::kDetachRole,
               Role::kSubtractAssetQty,
               Role::kAddSignatory,
               Role::kSetDetail,
               Role::kCreateAsset});
  auto nonsub = sub;
  ASSERT_FALSE(big.isSet(Role::kGetDomainAccounts));
  nonsub.set(Role::kGetDomainAccounts);

  ASSERT_TRUE(sub.isSubsetOf(big));
  ASSERT_TRUE(sub.isSubsetOf(sub));
  ASSERT_FALSE(nonsub.isSubsetOf(sub));
  ASSERT_FALSE(nonsub.isSubsetOf(big));
}

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/command_permission_test.hpp"

#include "framework/common_constants.hpp"

using namespace common_constants;
using namespace executor_testing;

using shared_model::interface::GrantablePermissionSet;
using shared_model::interface::RolePermissionSet;
using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;

enum class ActorRolePermissions : int {
  kNone = 0,
  kMe,
  kSameDomain,
  kEveryone,
  kRoot,

  LAST,
  FIRST = kNone
};

enum class Actor : int {
  kMe = 1,
  kSameDomain,
  kSecondDomain,

  LAST,
  FIRST = kMe
};

template <typename T>
struct EnumHasher {
  std::size_t operator()(T t) const {
    return static_cast<std::size_t>(t);
  }
};

template <typename Key, typename Value>
using EnumMap = std::unordered_map<Key, Value, EnumHasher<Key>>;

static constexpr bool enoughRolePermissions(
    Actor actor, ActorRolePermissions actor_role_permissions) {
  return static_cast<int>(actor_role_permissions) >= static_cast<int>(actor);
}

static bool enoughPermissions(Actor actor,
                              ActorRolePermissions actor_role_permissions,
                              bool has_granted_permission,
                              bool always_allowed_for_myself) {
  return has_granted_permission
      or (always_allowed_for_myself and actor == Actor::kMe)
      or enoughRolePermissions(actor, actor_role_permissions);
}

std::string makeDescription(ActorRolePermissions actor_role_permissions,
                            Actor actor,
                            bool has_granted_permission = false,
                            bool validation_enabled = true) {
  static const EnumMap<ActorRolePermissions, std::string>
      kActorRolePermissionNames{
          {ActorRolePermissions::kNone, "no_role_permissions"},
          {ActorRolePermissions::kMe, "role_permission_for_himself"},
          {ActorRolePermissions::kSameDomain,
           "role_permission_for_same_domain"},
          {ActorRolePermissions::kEveryone, "role_permission_for_everyone"},
          {ActorRolePermissions::kRoot, "root_permission"}};
  static const EnumMap<Actor, std::string> kActorNames{
      {Actor::kMe, "same_account"},
      {Actor::kSameDomain, "an_account_from_same_domain"},
      {Actor::kSecondDomain, "an_account_from_another_domain"}};
  std::stringstream ss;
  ss << kActorNames.at(actor) << "_having_"
     << kActorRolePermissionNames.at(actor_role_permissions);
  if (has_granted_permission) {
    ss << "_and_grantable_permission";
  }
  if (not validation_enabled) {
    ss << "_with_validation_disabled";
  }
  return ss.str();
}

template <typename TEnum, typename Callable>
static void iterateEnum(Callable callback) {
  using IterType = std::underlying_type_t<TEnum>;
  for (IterType it = static_cast<IterType>(TEnum::FIRST);
       it < static_cast<IterType>(TEnum::LAST);
       ++it) {
    callback(static_cast<TEnum>(it));
  }
}

decltype(::testing::Combine(
    executor_testing::getExecutorTestParams(),
    ::testing::ValuesIn(
        {command_permission_test::SpecificCommandPermissionTestData{}})))
command_permission_test::getParams(
    boost::optional<Role> permission_for_myself,
    boost::optional<Role> permission_for_my_domain,
    boost::optional<Role> permission_for_everyone,
    boost::optional<Grantable> grantable_permission,
    bool always_allowed_for_myself) {
  std::vector<SpecificCommandPermissionTestData> perm_params;
  const EnumMap<Actor, std::string> actors_map{
      {Actor::kMe, kUserId},
      {Actor::kSameDomain, kSameDomainUserId},
      {Actor::kSecondDomain, kSecondDomainUserId}};
  const RolePermissionSet kNoRolePerms;
  const boost::optional<Grantable> kNoGrantablePerm;

  auto add_case = [&](ActorRolePermissions role_perm_type,
                      RolePermissionSet role_permissions,
                      boost::optional<Grantable> granted_permission,
                      Actor actor,
                      bool validation_enabled = true) {
    const bool has_granted_permission{granted_permission};
    perm_params.emplace_back(SpecificCommandPermissionTestData{
        role_permissions,
        granted_permission,
        validation_enabled,
        actors_map.at(actor),
        (not validation_enabled)
            or enoughPermissions(actor,
                                 role_perm_type,
                                 has_granted_permission,
                                 always_allowed_for_myself),
        makeDescription(role_perm_type,
                        actor,
                        has_granted_permission,
                        validation_enabled)});
  };

  auto add_role_cases = [&](ActorRolePermissions role_perm_type,
                            RolePermissionSet role_permissions) {
    iterateEnum<Actor>([&](Actor actor) {
      add_case(role_perm_type, role_permissions, kNoGrantablePerm, actor);
    });
  };

  auto add_role_cases_if_permission_provided =
      [&](ActorRolePermissions role_perm_type,
          boost::optional<Role> permission) {
        if (permission) {
          add_role_cases(role_perm_type, RolePermissionSet{permission.value()});
        }
      };

  // case for genesis block: no permissions and validation disabled
  add_case(ActorRolePermissions::kNone,
           kNoRolePerms,
           kNoGrantablePerm,
           Actor::kSecondDomain,
           false);
  if (grantable_permission) {
    // only granted permission, inter-domain (when applicable)
    add_case(ActorRolePermissions::kNone,
             kNoRolePerms,
             grantable_permission,
             Actor::kSecondDomain);
  }
  // all actors with no permissions
  add_role_cases(ActorRolePermissions::kNone, kNoRolePerms);
  // all actors with permission for myself, if provided
  add_role_cases_if_permission_provided(ActorRolePermissions::kMe,
                                        permission_for_myself);
  // all actors with permission for my domain, if provided
  add_role_cases_if_permission_provided(ActorRolePermissions::kSameDomain,
                                        permission_for_my_domain);
  // all actors with universal permission, if provided
  add_role_cases_if_permission_provided(ActorRolePermissions::kEveryone,
                                        permission_for_everyone);
  // all actors with root permission
  add_role_cases_if_permission_provided(ActorRolePermissions::kRoot,
                                        Role::kRoot);

  return ::testing::Combine(getExecutorTestParams(),
                            ::testing::ValuesIn(std::move(perm_params)));
}

std::string command_permission_test::paramToString(
    testing::TestParamInfo<std::tuple<ExecutorTestParamProvider,
                                      SpecificCommandPermissionTestData>>
        param) {
  return std::get<0>(param.param)().get().toString() + "___"
      + std::get<1>(param.param).description;
}

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/query_permission_test.hpp"

#include "framework/common_constants.hpp"

using namespace common_constants;
using namespace executor_testing;

using shared_model::interface::RolePermissionSet;

enum class SpectatorPermissions : int {
  kNone = 0,
  kMyself,
  kSameDomain,
  kEveryone,
  kRoot,

  LAST,
  FIRST = kNone
};

enum class Spectator : int {
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

static constexpr bool enoughPermissions(
    SpectatorPermissions spectator_permissions, Spectator spectator) {
  return static_cast<int>(spectator_permissions) >= static_cast<int>(spectator);
}

std::string makeDescription(SpectatorPermissions spectator_permissions,
                            Spectator spectator) {
  static const EnumMap<SpectatorPermissions, std::string>
      kSpectatorPermissionNames{
          {SpectatorPermissions::kNone, "NoPermissions"},
          {SpectatorPermissions::kMyself, "PermissionToQueryMyself"},
          {SpectatorPermissions::kSameDomain, "PermissionToQueryMyDomain"},
          {SpectatorPermissions::kEveryone, "PermissionToQueryEveryone"},
          {SpectatorPermissions::kRoot, "RootPermission"}};
  static const EnumMap<Spectator, std::string> kSpectatorNames{
      {Spectator::kMe, "Myself"},
      {Spectator::kSameDomain, "AnAccountFromMyDomain"},
      {Spectator::kSecondDomain, "AnAccountFromAnotherDomain"}};
  std::stringstream ss;
  ss << "Query" << kSpectatorNames.at(spectator) << "Having"
     << kSpectatorPermissionNames.at(spectator_permissions);
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
        {query_permission_test::SpecificQueryPermissionTestData{}})))
query_permission_test::getParams(
    RolePermissionSet permission_to_query_myself,
    RolePermissionSet permission_to_query_my_domain,
    RolePermissionSet permission_to_query_everyone) {
  std::vector<SpecificQueryPermissionTestData> perm_params;
  shared_model::interface::RolePermissionSet no_permissions;
  static const RolePermissionSet kRootPermission(
      {shared_model::interface::permissions::Role::kRoot});
  const EnumMap<SpectatorPermissions, const RolePermissionSet &>
      spectator_permissions_map{
          {SpectatorPermissions::kNone, no_permissions},
          {SpectatorPermissions::kMyself, permission_to_query_myself},
          {SpectatorPermissions::kSameDomain, permission_to_query_my_domain},
          {SpectatorPermissions::kEveryone, permission_to_query_everyone},
          {SpectatorPermissions::kRoot, kRootPermission}};
  const EnumMap<Spectator, std::string> spectators_map{
      {Spectator::kMe, kUserId},
      {Spectator::kSameDomain, kSameDomainUserId},
      {Spectator::kSecondDomain, kSecondDomainUserId}};
  iterateEnum<SpectatorPermissions>(
      [&](SpectatorPermissions spectator_permissions) {
        iterateEnum<Spectator>([&](Spectator spectator) {
          perm_params.emplace_back(SpecificQueryPermissionTestData{
              spectator_permissions_map.at(spectator_permissions),
              spectators_map.at(spectator),
              enoughPermissions(spectator_permissions, spectator),
              makeDescription(spectator_permissions, spectator)});
        });
      });
  return ::testing::Combine(getExecutorTestParams(),
                            ::testing::ValuesIn(std::move(perm_params)));
}

std::string query_permission_test::paramToString(
    testing::TestParamInfo<std::tuple<std::shared_ptr<ExecutorTestParam>,
                                      SpecificQueryPermissionTestData>> param) {
  return std::get<0>(param.param)->toString()
      + std::get<1>(param.param).description;
}

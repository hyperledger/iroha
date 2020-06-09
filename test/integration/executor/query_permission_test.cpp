/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/query_permission_test.hpp"

#include "framework/common_constants.hpp"

using namespace common_constants;
using namespace executor_testing;

using shared_model::interface::RolePermissionSet;
using shared_model::interface::permissions::Role;

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
          {SpectatorPermissions::kNone, "no_permissions"},
          {SpectatorPermissions::kMyself, "permission_to_query_myself"},
          {SpectatorPermissions::kSameDomain, "permission_to_query_my_domain"},
          {SpectatorPermissions::kEveryone, "permission_to_query_everyone"},
          {SpectatorPermissions::kRoot, "root_permission"}};
  static const EnumMap<Spectator, std::string> kSpectatorNames{
      {Spectator::kMe, "myself"},
      {Spectator::kSameDomain, "an_account_from_my_domain"},
      {Spectator::kSecondDomain, "an_account_from_another_domain"}};
  std::stringstream ss;
  ss << "query_" << kSpectatorNames.at(spectator) << "_having_"
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
    boost::optional<Role> permission_to_query_myself,
    boost::optional<Role> permission_to_query_my_domain,
    boost::optional<Role> permission_to_query_everyone) {
  std::vector<SpecificQueryPermissionTestData> perm_params;
  const EnumMap<Spectator, std::string> spectators_map{
      {Spectator::kMe, kUserId},
      {Spectator::kSameDomain, kSameDomainUserId},
      {Spectator::kSecondDomain, kSecondDomainUserId}};

  auto add_perm_case = [&](SpectatorPermissions perm_type,
                           RolePermissionSet permissions) {
    iterateEnum<Spectator>([&](Spectator spectator) {
      perm_params.emplace_back(SpecificQueryPermissionTestData{
          permissions,
          spectators_map.at(spectator),
          enoughPermissions(perm_type, spectator),
          makeDescription(perm_type, spectator)});
    });
  };

  auto add_perm_case_if_provided = [&](SpectatorPermissions perm_type,
                                       boost::optional<Role> permission) {
    if (permission) {
      add_perm_case(perm_type, RolePermissionSet{permission.value()});
    }
  };

  add_perm_case(SpectatorPermissions::kNone, {});
  add_perm_case_if_provided(SpectatorPermissions::kMyself,
                            permission_to_query_myself);
  add_perm_case_if_provided(SpectatorPermissions::kSameDomain,
                            permission_to_query_my_domain);
  add_perm_case_if_provided(SpectatorPermissions::kEveryone,
                            permission_to_query_everyone);
  add_perm_case_if_provided(SpectatorPermissions::kRoot, Role::kRoot);

  return ::testing::Combine(getExecutorTestParams(),
                            ::testing::ValuesIn(std::move(perm_params)));
}

std::string query_permission_test::paramToString(
    testing::TestParamInfo<std::tuple<ExecutorTestParamProvider,
                                      SpecificQueryPermissionTestData>> param) {
  return std::get<0>(param.param)().get().toString() + "___"
      + std::get<1>(param.param).description;
}

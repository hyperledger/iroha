/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/permissions.hpp"

using namespace shared_model::interface;

namespace shared_model {
  namespace interface {
    namespace permissions {

      Role permissionFor(Grantable g) {
        switch (g) {
          case Grantable::kAddMySignatory:
            return Role::kAddMySignatory;
          case Grantable::kRemoveMySignatory:
            return Role::kRemoveMySignatory;
          case Grantable::kSetMyQuorum:
            return Role::kSetMyQuorum;
          case Grantable::kSetMyAccountDetail:
            return Role::kSetMyAccountDetail;
          case Grantable::kTransferMyAssets:
            return Role::kTransferMyAssets;
          case Grantable::kCallEngineOnMyBehalf:
            return Role::kGrantCallEngineOnMyBehalf;
          default:;
        }
        return Role::COUNT;
      }

      bool isValid(Role perm) noexcept {
        auto p = static_cast<size_t>(perm);
        return p < static_cast<size_t>(Role::COUNT);
      }

      bool isValid(Grantable perm) noexcept {
        auto p = static_cast<size_t>(perm);
        return p < static_cast<size_t>(Grantable::COUNT);
      }
    }  // namespace permissions
  }    // namespace interface
}  // namespace shared_model

template <typename Perm>
constexpr auto bit(Perm p) {
  return static_cast<size_t>(p);
}
template <typename Perm>
PermissionSet<Perm>::PermissionSet() = default;

template <typename Perm>
PermissionSet<Perm>::PermissionSet(std::initializer_list<Perm> list) {
  for (auto l : list) {
    perms_bitset_.set(bit(l));
  }
}

template <typename Perm>
PermissionSet<Perm>::PermissionSet(std::string_view bitstring)
    : perms_bitset_(bitstring.data(), bitstring.size()) {}

template <typename Perm>
std::string PermissionSet<Perm>::toBitstring() const {
  return perms_bitset_.to_string();
}

template <typename Perm>
PermissionSet<Perm> &PermissionSet<Perm>::unsetAll() {
  perms_bitset_.reset();
  return *this;
}

template <typename Perm>
PermissionSet<Perm> &PermissionSet<Perm>::setAll() {
  perms_bitset_.set();
  return *this;
}

template <typename Perm>
PermissionSet<Perm> &PermissionSet<Perm>::set(Perm p) {
  perms_bitset_.set(bit(p), true);
  return *this;
}

template <typename Perm>
PermissionSet<Perm> &PermissionSet<Perm>::unset(Perm p) {
  perms_bitset_.set(bit(p), false);
  return *this;
}

template <typename Perm>
bool PermissionSet<Perm>::isSet(Perm p) const {
  return PermissionSet<Perm>::perms_bitset_.test(bit(p));
}

template <typename Perm>
bool PermissionSet<Perm>::isEmpty() const {
  return perms_bitset_.none();
}

template <typename Perm>
bool PermissionSet<Perm>::isSubsetOf(const PermissionSet<Perm> &r) const {
  return (perms_bitset_ & r.perms_bitset_) == perms_bitset_;
}

template <typename Perm>
bool PermissionSet<Perm>::operator==(const PermissionSet<Perm> &r) const {
  return perms_bitset_.operator==(r.perms_bitset_);
}

template <typename Perm>
bool PermissionSet<Perm>::operator!=(const PermissionSet<Perm> &r) const {
  return perms_bitset_.operator!=(r.perms_bitset_);
}

template <typename Perm>
PermissionSet<Perm> &PermissionSet<Perm>::operator&=(
    const PermissionSet<Perm> &r) {
  perms_bitset_.operator&=(r.perms_bitset_);
  return *this;
}

template <typename Perm>
PermissionSet<Perm> &PermissionSet<Perm>::operator|=(
    const PermissionSet<Perm> &r) {
  perms_bitset_.operator|=(r.perms_bitset_);
  return *this;
}

template <typename Perm>
PermissionSet<Perm> &PermissionSet<Perm>::operator^=(
    const PermissionSet<Perm> &r) {
  perms_bitset_.operator^=(r.perms_bitset_);
  return *this;
}

template <typename Perm>
void PermissionSet<Perm>::iterate(std::function<void(Perm)> f) const {
  for (size_t i = 0; i < size(); ++i) {
    auto perm = static_cast<Perm>(i);
    if (isSet(perm)) {
      f(perm);
    }
  }
}

template class shared_model::interface::PermissionSet<permissions::Role>;
template class shared_model::interface::PermissionSet<permissions::Grantable>;

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_wsv_command.hpp"

#include <numeric>

#include <fmt/core.h>
#include <boost/format.hpp>
#include "ametsuchi/impl/executor_common.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "backend/protobuf/permissions.hpp"
#include "interfaces/common_objects/account.hpp"
#include "interfaces/common_objects/account_asset.hpp"
#include "interfaces/common_objects/asset.hpp"
#include "interfaces/common_objects/domain.hpp"
#include "interfaces/common_objects/peer.hpp"

namespace iroha::ametsuchi {

  template <typename Func, typename Error>
  WsvCommandResult execute(std::shared_ptr<RocksDBContext> &context,
                           Func &&func,
                           Error &&error) {
    RocksDbCommon common(context);
    if (auto result = std::forward<Func>(func)(common);
        expected::hasError(result))
      return expected::makeError(
          fmt::format("Command: {}, DB error: {} with description {}",
                      std::forward<Error>(error)(),
                      result.assumeError().code,
                      result.assumeError().description));

    common.commit();
    return {};
  }

  RocksDBWsvCommand::RocksDBWsvCommand(std::shared_ptr<RocksDBPort> db_port)
      : db_port_{std::move(db_port)},
        db_context_(std::make_shared<RocksDBContext>(db_port_)) {
    assert(db_port_);
    assert(db_context_);
  }

  WsvCommandResult RocksDBWsvCommand::insertRole(
      const shared_model::interface::types::RoleIdType &role_name) {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          RDB_ERROR_CHECK(forRole<kDbOperation::kGet, kDbEntry::kMustNotExist>(
              common, role_name));

          shared_model::interface::RolePermissionSet role_permissions;
          common.valueBuffer().assign(role_permissions.toBitstring());
          RDB_ERROR_CHECK(forRole<kDbOperation::kPut>(common, role_name));

          return {};
        },
        [&]() { return fmt::format("Insert role {}", role_name); });
  }

  WsvCommandResult RocksDBWsvCommand::insertAccountRole(
      const shared_model::interface::types::AccountIdType &account_id,
      const shared_model::interface::types::RoleIdType &role_name) {
    return execute(db_context_,
                   [&](auto &common) -> expected::Result<void, DbError> {
                     auto const names = staticSplitId<2ull>(account_id);
                     auto const &account_name = names.at(0);
                     auto const &domain_id = names.at(1);

                     common.valueBuffer() = "";
                     RDB_ERROR_CHECK(forAccountRole<kDbOperation::kPut>(
                         common, account_name, domain_id, role_name));

                     return {};
                   },
                   [&]() {
                     return fmt::format(
                         "Insert account {} role {}", account_id, role_name);
                   });
  }

  WsvCommandResult RocksDBWsvCommand::deleteAccountRole(
      const shared_model::interface::types::AccountIdType &account_id,
      const shared_model::interface::types::RoleIdType &role_name) {
    return execute(db_context_,
                   [&](auto &common) -> expected::Result<void, DbError> {
                     auto const names = staticSplitId<2ull>(account_id);
                     auto const &account_name = names.at(0);
                     auto const &domain_id = names.at(1);

                     RDB_ERROR_CHECK(forAccountRole<kDbOperation::kDel>(
                         common, account_name, domain_id, role_name));

                     return {};
                   },
                   [&]() {
                     return fmt::format(
                         "Delete account {} role {}", account_id, role_name);
                   });
  }

  WsvCommandResult RocksDBWsvCommand::insertRolePermissions(
      const shared_model::interface::types::RoleIdType &role_id,
      const shared_model::interface::RolePermissionSet &permissions) {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          common.valueBuffer().assign(permissions.toBitstring());
          RDB_ERROR_CHECK(forRole<kDbOperation::kPut>(common, role_id));

          return {};
        },
        [&]() { return fmt::format("Insert role {}", role_id); });
  }

  WsvCommandResult RocksDBWsvCommand::insertAccountGrantablePermission(
      const shared_model::interface::types::AccountIdType &permittee_account_id,
      const shared_model::interface::types::AccountIdType &account_id,
      shared_model::interface::permissions::Grantable permission) {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          auto grantee_names = staticSplitId<2ull>(permittee_account_id);
          auto &grantee_account_name = grantee_names.at(0);
          auto &grantee_domain_id = grantee_names.at(1);

          auto names = staticSplitId<2ull>(account_id);
          auto &account_name = names.at(0);
          auto &domain_id = names.at(1);

          shared_model::interface::GrantablePermissionSet
              granted_account_permissions;
          {
            RDB_TRY_GET_VALUE(perm,
                              forGrantablePermissions<kDbOperation::kGet,
                                                      kDbEntry::kCanExist>(
                                  common,
                                  account_name,
                                  domain_id,
                                  grantee_account_name,
                                  grantee_domain_id));
            if (perm)
              granted_account_permissions = std::move(*perm);
          }

          granted_account_permissions.set(permission);
          common.valueBuffer().assign(
              granted_account_permissions.toBitstring());
          RDB_ERROR_CHECK(
              forGrantablePermissions<kDbOperation::kPut, kDbEntry::kMustExist>(
                  common,
                  account_name,
                  domain_id,
                  grantee_account_name,
                  grantee_domain_id));

          return {};
        },
        [&]() {
          return fmt::format("Insert account {} grantable permission {} for {}",
                             account_id,
                             permission,
                             permittee_account_id);
        });
  }

  WsvCommandResult RocksDBWsvCommand::deleteAccountGrantablePermission(
      const shared_model::interface::types::AccountIdType &permittee_account_id,
      const shared_model::interface::types::AccountIdType &account_id,
      shared_model::interface::permissions::Grantable permission) {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          auto const grantee_names = staticSplitId<2ull>(permittee_account_id);
          auto const &grantee_account_name = grantee_names.at(0);
          auto const &grantee_domain_id = grantee_names.at(1);

          auto const names = staticSplitId<2ull>(account_id);
          auto const &account_name = names.at(0);
          auto const &domain_id = names.at(1);

          shared_model::interface::GrantablePermissionSet
              granted_account_permissions;
          {
            RDB_TRY_GET_VALUE(perm,
                              forGrantablePermissions<kDbOperation::kGet,
                                                      kDbEntry::kCanExist>(
                                  common,
                                  account_name,
                                  domain_id,
                                  grantee_account_name,
                                  grantee_domain_id));
            if (perm)
              granted_account_permissions = std::move(*perm);
          }

          granted_account_permissions.unset(permission);
          common.valueBuffer().assign(
              granted_account_permissions.toBitstring());
          RDB_ERROR_CHECK(
              forGrantablePermissions<kDbOperation::kPut, kDbEntry::kMustExist>(
                  common,
                  account_name,
                  domain_id,
                  grantee_account_name,
                  grantee_domain_id));

          return {};
        },
        [&]() {
          return fmt::format("Delete account {} grantable permission {} for {}",
                             account_id,
                             permission,
                             permittee_account_id);
        });
  }

  WsvCommandResult RocksDBWsvCommand::insertAccount(
      const shared_model::interface::Account &account) {
    return execute(db_context_,
                   [&](auto &common) -> expected::Result<void, DbError> {
                     common.encode(account.quorum());
                     RDB_ERROR_CHECK(forQuorum<kDbOperation::kPut>(
                         common, account.accountId(), account.domainId()));

                     assert(account.jsonData() == "{}");
                     return {};
                   },
                   [&]() {
                     return fmt::format("Insert account {}#{} details",
                                        account.accountId(),
                                        account.domainId());
                   });
  }

  WsvCommandResult RocksDBWsvCommand::insertAsset(
      const shared_model::interface::Asset &asset) {
    return execute(db_context_,
                   [&](auto &common) -> expected::Result<void, DbError> {
                     common.encode(asset.precision());
                     RDB_ERROR_CHECK(forAsset<kDbOperation::kPut>(
                         common, asset.assetId(), asset.domainId()));
                     return {};
                   },
                   [&]() {
                     return fmt::format("Insert asset {}#{} with precision {}",
                                        asset.assetId(),
                                        asset.domainId(),
                                        asset.precision());
                   });
  }

  WsvCommandResult RocksDBWsvCommand::upsertAccountAsset(
      const shared_model::interface::AccountAsset &asset) {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          auto const names = staticSplitId<2ull>(asset.accountId());
          auto const &account_name = names.at(0);
          auto const &domain_id = names.at(1);

          common.valueBuffer().assign(asset.balance().toStringRepr());
          RDB_ERROR_CHECK(forAccountAssets<kDbOperation::kPut>(
              common, account_name, domain_id, asset.assetId()));
          return {};
        },
        [&]() {
          return fmt::format("Account {} asset {} balance {}",
                             asset.accountId(),
                             asset.assetId(),
                             asset.balance().toStringRepr());
        });
  }

  WsvCommandResult RocksDBWsvCommand::insertSignatory(
      shared_model::interface::types::PublicKeyHexStringView signatory) {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          return makeError<void>(1000u, "Not used");
        },
        [&]() { return fmt::format("Insert signatory {}", signatory); });
  }

  WsvCommandResult RocksDBWsvCommand::insertAccountSignatory(
      const shared_model::interface::types::AccountIdType &account_id,
      shared_model::interface::types::PublicKeyHexStringView signatory) {
    return execute(db_context_,
                   [&](auto &common) -> expected::Result<void, DbError> {
                     auto const names = staticSplitId<2ull>(account_id);
                     auto const &account_name = names.at(0);
                     auto const &domain_id = names.at(1);

                     std::string result;
                     std::transform(((std::string_view)signatory).begin(),
                                    ((std::string_view)signatory).end(),
                                    std::back_inserter(result),
                                    [](auto c) { return std::tolower(c); });

                     common.valueBuffer() = "";
                     RDB_ERROR_CHECK(forSignatory<kDbOperation::kPut>(
                         common, account_name, domain_id, result));
                     return {};
                   },
                   [&]() {
                     return fmt::format("Account {} insert signatory {}",
                                        account_id,
                                        signatory);
                   });
  }

  WsvCommandResult RocksDBWsvCommand::deleteAccountSignatory(
      const shared_model::interface::types::AccountIdType &account_id,
      shared_model::interface::types::PublicKeyHexStringView signatory) {
    return execute(db_context_,
                   [&](auto &common) -> expected::Result<void, DbError> {
                     auto const names = staticSplitId<2ull>(account_id);
                     auto const &account_name = names.at(0);
                     auto const &domain_id = names.at(1);

                     std::string result;
                     std::transform(((std::string_view)signatory).begin(),
                                    ((std::string_view)signatory).end(),
                                    std::back_inserter(result),
                                    [](auto c) { return std::tolower(c); });

                     RDB_ERROR_CHECK(forSignatory<kDbOperation::kDel>(
                         common, account_name, domain_id, result));
                     return {};
                   },
                   [&]() {
                     return fmt::format("Account {} delete signatory {}",
                                        account_id,
                                        signatory);
                   });
  }

  WsvCommandResult RocksDBWsvCommand::deleteSignatory(
      shared_model::interface::types::PublicKeyHexStringView signatory) {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          return makeError<void>(1000u, "Not used");
        },
        [&]() { return fmt::format("Insert signatory {}", signatory); });
  }

  WsvCommandResult RocksDBWsvCommand::insertPeer(
      const shared_model::interface::Peer &peer) {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          std::string result;
          std::transform(peer.pubkey().begin(),
                         peer.pubkey().end(),
                         std::back_inserter(result),
                         [](auto c) { return std::tolower(c); });

          common.valueBuffer().assign(peer.address());
          RDB_ERROR_CHECK(forPeerAddress<kDbOperation::kPut>(common, result));

          if (peer.tlsCertificate()) {
            common.valueBuffer().assign(peer.tlsCertificate().value());
            RDB_ERROR_CHECK(forPeerTLS<kDbOperation::kPut>(common, result));
          }
          return {};
        },
        [&]() {
          return fmt::format(
              "Insert peer {} with address {}", peer.pubkey(), peer.address());
        });
  }

  WsvCommandResult RocksDBWsvCommand::deletePeer(
      const shared_model::interface::Peer &peer) {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          std::string result;
          std::transform(peer.pubkey().begin(),
                         peer.pubkey().end(),
                         std::back_inserter(result),
                         [](auto c) { return std::tolower(c); });

          RDB_ERROR_CHECK(forPeerAddress<kDbOperation::kDel>(common, result));
          RDB_ERROR_CHECK(forPeerTLS<kDbOperation::kDel>(common, result));
          return {};
        },
        [&]() {
          return fmt::format(
              "Delete peer {} with address {}", peer.pubkey(), peer.address());
        });
  }

  WsvCommandResult RocksDBWsvCommand::insertDomain(
      const shared_model::interface::Domain &domain) {
    return execute(db_context_,
                   [&](auto &common) -> expected::Result<void, DbError> {
                     common.valueBuffer().assign(domain.defaultRole());
                     RDB_ERROR_CHECK(forDomain<kDbOperation::kPut>(
                         common, domain.domainId()));
                     return {};
                   },
                   [&]() {
                     return fmt::format("Domain {} with default role {}",
                                        domain.domainId(),
                                        domain.defaultRole());
                   });
  }

  WsvCommandResult RocksDBWsvCommand::updateAccount(
      const shared_model::interface::Account &account) {
    return execute(db_context_,
                   [&](auto &common) -> expected::Result<void, DbError> {
                     auto const names =
                         staticSplitId<2ull>(account.accountId());
                     auto const &account_name = names.at(0);
                     auto const &domain_id = names.at(1);

                     common.encode(account.quorum());
                     RDB_ERROR_CHECK(forQuorum<kDbOperation::kPut>(
                         common, account_name, domain_id));
                     return {};
                   },
                   [&]() {
                     return fmt::format("Account {} with quorum {}",
                                        account.accountId(),
                                        account.quorum());
                   });
  }

  WsvCommandResult RocksDBWsvCommand::setAccountKV(
      const shared_model::interface::types::AccountIdType &account_id,
      const shared_model::interface::types::AccountIdType &creator_account_id,
      const std::string &key,
      const std::string &val) {
    return execute(db_context_,
                   [&](auto &common) -> expected::Result<void, DbError> {
                     return makeError<void>(1000u, "Not used");
                   },
                   [&]() {
                     return fmt::format(
                         "Set account {} kv with creator {} and key {}",
                         account_id,
                         creator_account_id,
                         key);
                   });
  }

  WsvCommandResult RocksDBWsvCommand::setTopBlockInfo(
      const TopBlockInfo &top_block_info) const {
    return execute(
        db_context_,
        [&](auto &common) -> expected::Result<void, DbError> {
          common.valueBuffer() = std::to_string(top_block_info.height);
          common.valueBuffer() += "#";
          common.valueBuffer() += top_block_info.top_hash.hex();

          RDB_ERROR_CHECK(forTopBlockInfo<kDbOperation::kPut>(common));
          return {};
        },
        [&]() {
          return fmt::format("Top block height {} and hash {}",
                             top_block_info.height,
                             top_block_info.top_hash.hex());
        });
  }
}  // namespace iroha::ametsuchi

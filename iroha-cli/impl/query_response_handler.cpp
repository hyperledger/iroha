/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "query_response_handler.hpp"
#include "backend/protobuf/commands/proto_command.hpp"
#include "backend/protobuf/permissions.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/query_responses/proto_transaction_response.hpp"
#include "interfaces/permissions.hpp"
#include "logger/logger.hpp"
#include "model/converters/pb_common.hpp"

using namespace iroha::protocol;
namespace iroha_cli {

  QueryResponseHandler::QueryResponseHandler(logger::LoggerPtr log)
      : log_(std::move(log)) {
    handler_map_[QueryResponse::ResponseCase::kErrorResponse] =
        &QueryResponseHandler::handleErrorResponse;
    handler_map_[QueryResponse::ResponseCase::kAccountResponse] =
        &QueryResponseHandler::handleAccountResponse;
    handler_map_[QueryResponse::ResponseCase::kAccountAssetsResponse] =
        &QueryResponseHandler::handleAccountAssetsResponse;
    handler_map_[QueryResponse::ResponseCase::kSignatoriesResponse] =
        &QueryResponseHandler::handleSignatoriesResponse;
    handler_map_[QueryResponse::ResponseCase::kTransactionsResponse] =
        &QueryResponseHandler::handleTransactionsResponse;
    handler_map_[QueryResponse::ResponseCase::kRolesResponse] =
        &QueryResponseHandler::handleRolesResponse;
    handler_map_[QueryResponse::ResponseCase::kRolePermissionsResponse] =
        &QueryResponseHandler::handleRolePermissionsResponse;
    handler_map_[QueryResponse::ResponseCase::kAssetResponse] =
        &QueryResponseHandler::handleAssetResponse;

    // Error responses:
    error_handler_map_[ErrorResponse::STATEFUL_INVALID] =
        "Query is stateful invalid";
    error_handler_map_[ErrorResponse::STATELESS_INVALID] =
        "Query is stateless invalid";
    error_handler_map_[ErrorResponse::NO_ACCOUNT] = "Account not found";
    error_handler_map_[ErrorResponse::NO_ACCOUNT_ASSETS] =
        "Account assets not found";
    error_handler_map_[ErrorResponse::NO_SIGNATORIES] = "No signatories found";
    error_handler_map_[ErrorResponse::NOT_SUPPORTED] = "Query not supported";
    error_handler_map_[ErrorResponse::NO_ROLES] = "No roles in the system";
    error_handler_map_[ErrorResponse::NO_ASSET] = "No asset found";
  }

  void QueryResponseHandler::handle(
      const iroha::protocol::QueryResponse &response) {
    auto it = handler_map_.find(response.response_case());
    if (it != handler_map_.end()) {
      (this->*it->second)(response);
    } else {
      log_->error("Response Handle {} not Implemented",
                  response.response_case());
    }
  }

  enum PrefixId {
    kAccountId,
    kAssetId,
    kAmount,
    kDomainId,
    kSignatories,
    kPrecision,
    kRoles,
    kJsonData,
    kCreatorId,
    kCreatedTime,
    kHash,
    kCommands,
    kDefault,
  };

  const std::map<PrefixId, const char *> prefix{
      {kAccountId, "-Account Id:- {}"},
      {kAssetId, "-Asset Id- {}"},
      {kAmount, "-Balance- {}"},
      {kDomainId, "-Domain- {}"},
      {kSignatories, "-Signatory- {}"},
      {kPrecision, "-Precision- {}"},
      {kRoles, "-Roles-: "},
      {kJsonData, "-Data-: {}"},
      {kCreatorId, "-Creator Id- {}"},
      {kCreatedTime, "-Created Time- {}"},
      {kHash, "-Hash- {}"},
      {kCommands, "-Commands- {}"},
      {kDefault, " {} "}};

  void QueryResponseHandler::handleErrorResponse(
      const iroha::protocol::QueryResponse &response) {
    auto it = error_handler_map_.find((response.error_response().reason()));
    if (it != error_handler_map_.end()) {
      log_->error(it->second);
    } else {
      // Response of some other type received
      log_->error("Error Response Handle of type {} not Implemented",
                  response.error_response().reason());
    }
  }

  void QueryResponseHandler::handleAccountResponse(
      const iroha::protocol::QueryResponse &response) {
    auto account = response.account_response().account();
    log_->info("[Account]:");
    log_->info(prefix.at(kAccountId), account.account_id());
    log_->info(prefix.at(kDomainId), account.domain_id());

    log_->info(prefix.at(kRoles));
    auto roles = response.account_response().account_roles();
    std::for_each(roles.begin(), roles.end(), [this](auto role) {
      log_->info(prefix.at(kDefault), role);
    });
    log_->info(prefix.at(kJsonData), account.json_data());
  }

  void QueryResponseHandler::handleRolesResponse(
      const iroha::protocol::QueryResponse &response) {
    auto roles = response.roles_response().roles();
    std::for_each(roles.begin(), roles.end(), [this](auto role) {
      log_->info(prefix.at(kDefault), role);
    });
  }

  void QueryResponseHandler::handleRolePermissionsResponse(
      const iroha::protocol::QueryResponse &response) {
    auto perms = response.role_permissions_response().permissions();
    std::for_each(perms.begin(), perms.end(), [this](auto perm) {
      log_->info(
          prefix.at(kDefault),
          shared_model::proto::permissions::toString(
              static_cast<shared_model::interface::permissions::Role>(perm)));
    });
  }

  void QueryResponseHandler::handleAccountAssetsResponse(
      const iroha::protocol::QueryResponse &response) {
    auto acc_assets = response.account_assets_response().account_assets();
    log_->info("[Account Assets]");
    for (auto &acc_asset : acc_assets) {
      log_->info(prefix.at(kAccountId), acc_asset.account_id());
      log_->info(prefix.at(kAssetId), acc_asset.asset_id());
      log_->info(prefix.at(kAmount), acc_asset.balance());
    }
  }

  void QueryResponseHandler::handleSignatoriesResponse(
      const iroha::protocol::QueryResponse &response) {
    auto signatories = response.signatories_response().keys();
    log_->info("[Signatories]");
    std::for_each(
        signatories.begin(), signatories.end(), [this](auto signatory) {
          log_->info(prefix.at(kSignatories), signatory);
        });
  }

  void QueryResponseHandler::handleAssetResponse(
      const iroha::protocol::QueryResponse &response) {
    auto asset = response.asset_response().asset();
    log_->info("[Asset]");
    log_->info(prefix.at(kAssetId), asset.asset_id());
    log_->info(prefix.at(kDomainId), asset.domain_id());
    log_->info(prefix.at(kPrecision), asset.precision());
  }

  void QueryResponseHandler::handleTransactionsResponse(
      const iroha::protocol::QueryResponse &response) {
    iroha::protocol::QueryResponse response_copy{response};
    shared_model::proto::TransactionsResponse resp{response_copy};
    auto txs = resp.transactions();
    std::for_each(txs.begin(), txs.end(), [this](auto &tx) {
      log_->info("[Transaction]");
      log_->info(prefix.at(kHash), tx.hash().hex());
      log_->info(prefix.at(kCreatorId), tx.creatorAccountId());
      log_->info(prefix.at(kCreatedTime), tx.createdTime());
      log_->info(prefix.at(kCommands), tx.commands().size());

      auto cmds = tx.commands();
      std::for_each(cmds.begin(), cmds.end(), [this](auto &cmd) {
        log_->info(prefix.at(kDefault), cmd);
      });
    });
  }

}  // namespace iroha_cli

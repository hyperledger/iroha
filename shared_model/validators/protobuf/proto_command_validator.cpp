/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_command_validator.hpp"

#include <ciso646>

#include <fmt/core.h>
#include <boost/range/adaptor/indexed.hpp>
#include "commands.pb.h"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

using namespace shared_model::validation;

namespace {
  std::optional<ValidationError> validatePublicKey(
      const std::string &public_key) {
    if (not validateHexString(public_key)) {
      return ValidationError{"Public key", {"Not in hex format"}};
    }
    return std::nullopt;
  }
}  // namespace

namespace shared_model {
  namespace validation {

    std::optional<ValidationError> ProtoCommandValidator::validate(
        const iroha::protocol::Command &command) const {
      switch (command.command_case()) {
        case iroha::protocol::Command::COMMAND_NOT_SET: {
          return ValidationError{"Undefined command.", {"Not allowed."}};
        }
        case iroha::protocol::Command::kAddSignatory: {
          const auto &as = command.add_signatory();
          return aggregateErrors(
              "AddSignatory", {}, {validatePublicKey(as.public_key())});
        }
        case iroha::protocol::Command::kCallEngine: {
          const auto &cmd = command.call_engine();
          using EngineType = iroha::protocol::CallEngine::EngineType;
          switch (cmd.type()) {
            case EngineType::CallEngine_EngineType_kSolidity:
              break;
            default:
              return ValidationError{"CallEngine", {"Unknown engine type."}};
          }
          return std::nullopt;
        }
        case iroha::protocol::Command::kCreateAccount: {
          const auto &ca = command.create_account();
          return aggregateErrors(
              "CreateAccount", {}, {validatePublicKey(ca.public_key())});
        }
        case iroha::protocol::Command::kCreateAsset: {
          const auto &ca = command.create_asset();
          return aggregateErrors(
              "CreateAsset",
              {},
              {[](auto precision) -> std::optional<ValidationError> {
                if (precision < 0 or precision > 255) {
                  return ValidationError(
                      "Precision",
                      {"Precision should be within range [0, 255]"});
                }
                return std::nullopt;
              }(ca.precision())});
        }
        case iroha::protocol::Command::kRemoveSignatory: {
          const auto &rs = command.remove_signatory();
          return aggregateErrors(
              "RemoveSignatory", {}, {validatePublicKey(rs.public_key())});
        }
        case iroha::protocol::Command::kAddPeer: {
          const auto &ap = command.add_peer();
          return aggregateErrors(
              "AddPeer", {}, {validatePublicKey(ap.peer().peer_key())});
        }
        case iroha::protocol::Command::kCreateRole: {
          const auto &cr = command.create_role();
          ValidationErrorCreator error_creator;
          for (auto perm : cr.permissions() | boost::adaptors::indexed(1)) {
            if (not iroha::protocol::RolePermission_IsValid(perm.value())) {
              error_creator.addReason(
                  fmt::format("Permission #{} is invalid.", perm.index()));
            }
          }
          return std::move(error_creator).getValidationError("CreateRole");
        }
        case iroha::protocol::Command::kGrantPermission: {
          if (not iroha::protocol::GrantablePermission_IsValid(
                  command.grant_permission().permission())) {
            return ValidationError{"GrantPermission",
                                   {"Invalid grantable permission."}};
          }
          return std::nullopt;
        }
        case iroha::protocol::Command::kRevokePermission: {
          if (not iroha::protocol::GrantablePermission_IsValid(
                  command.revoke_permission().permission())) {
            return ValidationError{"RevokePermission",
                                   {"Invalid grantable permission."}};
          }
          return std::nullopt;
        }
        default:
          return std::nullopt;
      }
    }
  }  // namespace validation
}  // namespace shared_model

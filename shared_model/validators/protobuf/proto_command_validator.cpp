/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_command_validator.hpp"

#include <fmt/core.h>
#include <boost/range/adaptor/indexed.hpp>
#include "commands.pb.h"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

using namespace shared_model::validation;

namespace {
  boost::optional<ValidationError> validatePublicKey(
      const std::string &public_key) {
    if (not validateHexString(public_key)) {
      return ValidationError{"Public key", {"Not in hex format"}};
    }
    return boost::none;
  }
}  // namespace

namespace shared_model {
  namespace validation {

    boost::optional<ValidationError> ProtoCommandValidator::validate(
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
        case iroha::protocol::Command::kCreateAccount: {
          const auto &ca = command.create_account();
          return aggregateErrors(
              "CreateAccount", {}, {validatePublicKey(ca.public_key())});
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
          for (const auto &perm :
               cr.permissions() | boost::adaptors::indexed(1)) {
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
          return boost::none;
        }
        case iroha::protocol::Command::kRevokePermission: {
          if (not iroha::protocol::GrantablePermission_IsValid(
                  command.revoke_permission().permission())) {
            return ValidationError{"RevokePermission",
                                   {"Invalid grantable permission."}};
          }
          return boost::none;
        }
        default:
          return boost::none;
      }
    }
  }  // namespace validation
}  // namespace shared_model

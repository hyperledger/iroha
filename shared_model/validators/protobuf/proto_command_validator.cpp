/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_command_validator.hpp"

#include "commands.pb.h"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    void validatePublicKey(const std::string &public_key,
                           ReasonsGroupType &reason) {
      if (not validateHexString(public_key)) {
        reason.second.emplace_back("Public key is not in hex format");
      }
    }

    Answer ProtoCommandValidator::validate(
        const iroha::protocol::Command &command) const {
      Answer answer;
      std::string tx_reason_name = "Protobuf Command";
      ReasonsGroupType reason(tx_reason_name, GroupedReasons());
      switch (command.command_case()) {
        case iroha::protocol::Command::COMMAND_NOT_SET: {
          reason.second.emplace_back("Undefined command is found");
          answer.addReason(std::move(reason));
          return answer;
        }
        case iroha::protocol::Command::kAddSignatory: {
          const auto &as = command.add_signatory();
          validatePublicKey(as.public_key(), reason);
          break;
        }
        case iroha::protocol::Command::kCreateAccount: {
          const auto &ca = command.create_account();
          validatePublicKey(ca.public_key(), reason);
          break;
        }
        case iroha::protocol::Command::kRemoveSignatory: {
          const auto &rs = command.remove_signatory();
          validatePublicKey(rs.public_key(), reason);
          break;
        }
        case iroha::protocol::Command::kAddPeer: {
          const auto &ap = command.add_peer();
          validatePublicKey(ap.peer().peer_key(), reason);
          break;
        }
        case iroha::protocol::Command::kCreateRole: {
          const auto &cr = command.create_role();
          bool all_permissions_valid = std::all_of(
              cr.permissions().begin(),
              cr.permissions().end(),
              [](const auto &perm) {
                return iroha::protocol::RolePermission_IsValid(perm);
              });
          if (not all_permissions_valid) {
            reason.second.emplace_back("Invalid role permission");
          }
          break;
        }
        case iroha::protocol::Command::kGrantPermission: {
          if (not iroha::protocol::GrantablePermission_IsValid(
                  command.grant_permission().permission())) {
            reason.second.emplace_back("Invalid grantable permission");
          }
          break;
        }
        case iroha::protocol::Command::kRevokePermission: {
          if (not iroha::protocol::GrantablePermission_IsValid(
                  command.revoke_permission().permission())) {
            reason.second.emplace_back("Invalid grantable permission");
          }
          break;
        }
        default:
          break;
      }
      if (not reason.second.empty()) {
        answer.addReason(std::move(reason));
      }
      return answer;
    }
  }  // namespace validation
}  // namespace shared_model

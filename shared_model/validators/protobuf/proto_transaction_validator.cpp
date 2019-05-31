/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_transaction_validator.hpp"

#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    void validatePublicKey(const std::string &public_key,
                           ReasonsGroupType &reason) {
      if (not validateHexString(public_key)) {
        reason.second.emplace_back("Public key is not in hex format");
      }
    }

    Answer validateProtoTx(const iroha::protocol::Transaction &transaction) {
      Answer answer;
      std::string tx_reason_name = "Protobuf Transaction";
      ReasonsGroupType reason(tx_reason_name, GroupedReasons());
      for (const auto &command :
           transaction.payload().reduced_payload().commands()) {
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
      }
      if (transaction.payload().has_batch()) {
        if (not iroha::protocol::Transaction_Payload_BatchMeta::
                BatchType_IsValid(transaction.payload().batch().type())) {
          reason.second.emplace_back("Invalid batch type");
        }
      }
      if (not reason.second.empty()) {
        answer.addReason(std::move(reason));
      }
      return answer;
    }

    Answer ProtoTransactionValidator::validate(
        const iroha::protocol::Transaction &tx) const {
      return validateProtoTx(tx);
    }
  }  // namespace validation
}  // namespace shared_model

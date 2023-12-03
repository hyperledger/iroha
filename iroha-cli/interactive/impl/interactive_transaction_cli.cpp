/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interactive/interactive_transaction_cli.hpp"

#include <fstream>
#include <utility>

#include "backend/protobuf/transaction.hpp"
#include "client.hpp"
#include "grpc_response_handler.hpp"
#include "logger/logger.hpp"
#include "model/commands/append_role.hpp"
#include "model/commands/create_role.hpp"
#include "model/commands/detach_role.hpp"
#include "model/commands/grant_permission.hpp"
#include "model/commands/revoke_permission.hpp"
#include "model/commands/set_account_detail.hpp"
#include "model/converters/json_common.hpp"
#include "model/converters/json_transaction_factory.hpp"
#include "model/converters/pb_common.hpp"
#include "model/converters/pb_transaction_factory.hpp"
#include "model/model_crypto_provider.hpp"  // for ModelCryptoProvider
#include "model/permissions.hpp"
#include "model/sha3_hash.hpp"
#include "parser/parser.hpp"  // for parser::ParseValue

using namespace iroha::model;
using namespace shared_model::permissions;

namespace iroha_cli {
  namespace interactive {

    void InteractiveTransactionCli::createCommandMenu() {
      commands_description_map_ = {
          {ADD_ASSET_QTY, "Add Asset Quantity"},
          {ADD_PEER, "Add Peer to Iroha Network"},
          {ADD_SIGN, "Add Signatory to Account"},
          {CREATE_ACC, "Create Account"},
          {CREATE_DOMAIN, "Create Domain"},
          {CREATE_ASSET, "Create Asset"},
          {REMOVE_SIGN, "Remove Signatory"},
          {SET_QUO, "Set Account Quorum"},
          {SUB_ASSET_QTY, "Subtract Assets Quantity"},
          {TRAN_ASSET, "Transfer Assets"},
          {CREATE_ROLE, "Create new role"},
          {APPEND_ROLE, "Add new role to account"},
          {DETACH_ROLE, "Detach role from account"},
          {GRANT_PERM, "Grant permission over your account"},
          {REVOKE_PERM, "Revoke permission from account"},
          {SET_ACC_KV, "Set account key/value detail"}
          // commands_description_map_
      };

      const auto acc_id = "Account Id";
      const auto ast_id = "Asset Id";
      const auto dom_id = "Domain Id";
      const auto add_amount_str = "Amount to add, e.g 123.456";
      const auto sub_amount_str = "Amount to subtract, e.g 123.456";
      const auto transfer_amount_str = "Amount to transfer, e.g 123.456";
      const auto peer_id = "Full address of a peer";
      const auto pub_key = "Public Key";
      const auto acc_name = "Account Name";
      const auto ast_name = "Asset name";
      const auto ast_precision = "Asset precision";
      const auto quorum = "Quorum";
      const auto role = "Role name";
      const auto perm = "Permission name";

      const auto can_read_self = "Can read all information about their account";
      const auto can_edit_self = "Can change their quorum/signatory";
      const auto can_read_all = "Can read all other accounts";
      const auto can_transfer_receive = "Can receive/transfer assets";
      const auto can_asset_creator = "Can create/add new assets";
      const auto can_roles = "Can create/append roles";

      command_params_map_ = {
          {ADD_ASSET_QTY, makeParamsDescription({ast_id, add_amount_str})},
          {ADD_PEER, makeParamsDescription({peer_id, pub_key})},
          {ADD_SIGN, makeParamsDescription({acc_id, pub_key})},
          {CREATE_ACC, makeParamsDescription({acc_name, dom_id, pub_key})},
          {CREATE_DOMAIN,
           makeParamsDescription({dom_id, std::string("Default ") + role})},
          {CREATE_ASSET,
           makeParamsDescription({ast_name, dom_id, ast_precision})},
          {REMOVE_SIGN, makeParamsDescription({acc_id, pub_key})},
          {SET_QUO, makeParamsDescription({acc_id, quorum})},
          {SUB_ASSET_QTY, makeParamsDescription({ast_id, sub_amount_str})},
          {TRAN_ASSET,
           makeParamsDescription({std::string("Src") + acc_id,
                                  std::string("Dest") + acc_id,
                                  ast_id,
                                  transfer_amount_str})},
          {CREATE_ROLE,
           makeParamsDescription({role,
                                  can_read_self,
                                  can_edit_self,
                                  can_read_all,
                                  can_transfer_receive,
                                  can_asset_creator,
                                  can_create_domain,
                                  can_roles,
                                  can_create_account})},
          {APPEND_ROLE, makeParamsDescription({acc_id, role})},
          {DETACH_ROLE, makeParamsDescription({acc_id, role})},
          {GRANT_PERM, makeParamsDescription({acc_id, perm})},
          {REVOKE_PERM, makeParamsDescription({acc_id, perm})},
          {SET_ACC_KV, makeParamsDescription({acc_id, "key", "value"})}
          // command parameters descriptions
      };

      command_handlers_ = {
          {ADD_ASSET_QTY, &InteractiveTransactionCli::parseAddAssetQuantity},
          {ADD_PEER, &InteractiveTransactionCli::parseAddPeer},
          {ADD_SIGN, &InteractiveTransactionCli::parseAddSignatory},
          {CREATE_ACC, &InteractiveTransactionCli::parseCreateAccount},
          {CREATE_DOMAIN, &InteractiveTransactionCli::parseCreateDomain},
          {CREATE_ASSET, &InteractiveTransactionCli::parseCreateAsset},
          {REMOVE_SIGN, &InteractiveTransactionCli::parseRemoveSignatory},
          {SET_QUO, &InteractiveTransactionCli::parseSetQuorum},
          {SUB_ASSET_QTY,
           &InteractiveTransactionCli::parseSubtractAssetQuantity},
          {TRAN_ASSET, &InteractiveTransactionCli::parseTransferAsset},
          {CREATE_ROLE, &InteractiveTransactionCli::parseCreateRole},
          {APPEND_ROLE, &InteractiveTransactionCli::parseAppendRole},
          {DETACH_ROLE, &InteractiveTransactionCli::parseDetachRole},
          {GRANT_PERM, &InteractiveTransactionCli::parseGrantPermission},
          {REVOKE_PERM, &InteractiveTransactionCli::parseGrantPermission},
          {SET_ACC_KV, &InteractiveTransactionCli::parseSetAccountDetail}
          // Command parsers
      };

      commands_menu_ = formMenu(
          command_handlers_, command_params_map_, commands_description_map_);
      // Add "go back" option
      addBackOption(commands_menu_);
    }

    void InteractiveTransactionCli::createResultMenu() {
      // --- Add result menu points ---

      auto result_desciption = getCommonDescriptionMap();
      const auto ADD_CMD = "add";

      result_desciption.insert(
          {ADD_CMD, "Add one more command to the transaction"});
      result_desciption.insert(
          {BACK_CODE, "Go back and start a new transaction"});

      result_params_map = getCommonParamsMap(default_peer_ip_, default_port_);

      result_params_map.insert({ADD_CMD, {}});
      result_params_map.insert({BACK_CODE, {}});

      result_handlers_ = {
          {SAVE_CODE, &InteractiveTransactionCli::parseSaveFile},
          {SEND_CODE, &InteractiveTransactionCli::parseSendToIroha},
          {ADD_CMD, &InteractiveTransactionCli::parseAddCommand},
          {BACK_CODE, &InteractiveTransactionCli::parseGoBack}
          // Parsers for result
      };

      result_menu_ =
          formMenu(result_handlers_, result_params_map, result_desciption);
    }

    InteractiveTransactionCli::InteractiveTransactionCli(
        const std::string &creator_account,
        const std::string &default_peer_ip,
        int default_port,
        const std::shared_ptr<iroha::model::ModelCryptoProvider> &provider,
        logger::LoggerManagerTreePtr response_handler_log_manager,
        logger::LoggerPtr pb_qry_factory_log,
        logger::LoggerPtr log)
        : current_context_(MAIN),
          creator_(creator_account),
          default_peer_ip_(default_peer_ip),
          default_port_(default_port),
          provider_(provider),
          response_handler_log_manager_(
              std::move(response_handler_log_manager)),
          pb_qry_factory_log_(std::move(pb_qry_factory_log)),
          log_(std::move(log)) {
      createCommandMenu();
      createResultMenu();
    }

    void InteractiveTransactionCli::run() {
      bool is_parsing = true;
      current_context_ = MAIN;
      printMenu("Forming a new transactions, choose command to add: ",
                commands_menu_);
      // Creating a new transaction
      while (is_parsing) {
        auto line = promptString("> ");
        if (not line) {
          // The promtSting returns error, terminating symbol
          is_parsing = false;
          break;
        }
        switch (current_context_) {
          case MAIN:
            is_parsing = parseCommand(line.value());
            break;
          case RESULT:
            is_parsing = parseResult(line.value());
            break;
          default:
            // shouldn't get here
            BOOST_ASSERT_MSG(false, "not implemented");
            break;
        }
      }
    }

    bool InteractiveTransactionCli::parseCommand(std::string line) {
      if (isBackOption(line)) {
        // Switch current context
        return false;
      }

      auto res = handleParse<std::shared_ptr<iroha::model::Command>>(
          this, line, command_handlers_, command_params_map_);

      if (not res) {
        // Continue parsing
        return true;
      }

      commands_.push_back(res.value());
      current_context_ = RESULT;
      printMenu("Command is formed. Choose what to do:", result_menu_);
      return true;
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseCreateRole(
        std::vector<std::string> params) {
      auto role = params[0];
      auto read_self = parser::parseValue<bool>(params[1]);
      auto edit_self = parser::parseValue<bool>(params[2]);
      auto read_all = parser::parseValue<bool>(params[3]);
      auto transfer_receive = parser::parseValue<bool>(params[4]);
      auto asset_create = parser::parseValue<bool>(params[5]);
      auto create_domain = parser::parseValue<bool>(params[6]);
      auto roles = parser::parseValue<bool>(params[7]);
      auto create_account = parser::parseValue<bool>(params[8]);

      if (not(read_self and edit_self and read_all and transfer_receive
              and asset_create and create_domain and roles
              and create_account)) {
        std::cout << "Wrong format for permission" << std::endl;
        return nullptr;
      }

      std::set<std::string> perms;
      if (read_self.value()) {
        perms.insert(read_self_group.begin(), read_self_group.end());
      }
      if (edit_self.value()) {
        perms.insert(edit_self_group.begin(), edit_self_group.end());
        perms.insert(grant_group.begin(), grant_group.end());
      }

      if (read_all.value()) {
        perms.insert(read_all_group.begin(), read_all_group.end());
      }
      if (transfer_receive.value()) {
        perms.insert(can_transfer);
        perms.insert(can_receive);
      }
      if (asset_create.value()) {
        perms.insert(asset_creator_group.begin(), asset_creator_group.end());
      }
      if (create_domain.value()) {
        perms.insert(can_create_domain);
      }
      if (roles.value()) {
        perms.insert(can_create_role);
        perms.insert(can_append_role);
      }
      if (create_account.value()) {
        perms.insert(can_create_account);
      }

      return std::make_shared<CreateRole>(role, perms);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseAppendRole(
        std::vector<std::string> params) {
      auto acc_id = params[0];
      auto role = params[1];
      return std::make_shared<AppendRole>(acc_id, role);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseDetachRole(
        std::vector<std::string> params) {
      auto acc_id = params[0];
      auto role = params[1];
      return std::make_shared<DetachRole>(acc_id, role);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseGrantPermission(
        std::vector<std::string> params) {
      auto acc_id = params[0];
      auto permission = params[1];
      return std::make_shared<GrantPermission>(acc_id, permission);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseRevokePermission(
        std::vector<std::string> params) {
      auto acc_id = params[0];
      auto permission = params[1];
      return std::make_shared<RevokePermission>(acc_id, permission);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseAddAssetQuantity(
        std::vector<std::string> params) {
      auto asset_id = params[0];
      auto amount = params[1];
      auto description = params[2];
      return generator_.generateAddAssetQuantity(asset_id, amount, description);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseAddPeer(std::vector<std::string> params) {
      auto address = params[0];
      auto key = params[1];
      iroha::pubkey_t pubkey;
      pubkey = iroha::hexstringToArray<iroha::pubkey_t::size()>(key).value();
      return generator_.generateAddPeer(Peer(address, pubkey));
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseAddSignatory(
        std::vector<std::string> params) {
      auto account_id = params[0];
      auto key = params[1];
      iroha::pubkey_t pubkey;
      pubkey = iroha::hexstringToArray<iroha::pubkey_t::size()>(key).value();
      return generator_.generateAddSignatory(account_id, pubkey);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseCreateAccount(
        std::vector<std::string> params) {
      auto account_id = params[0];
      auto domain_id = params[1];
      auto key = params[2];
      iroha::pubkey_t pubkey;
      pubkey = iroha::hexstringToArray<iroha::pubkey_t::size()>(key).value();
      return generator_.generateCreateAccount(account_id, domain_id, pubkey);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseCreateDomain(
        std::vector<std::string> params) {
      auto domain_id = params[0];
      auto user_default_role = params[1];
      return generator_.generateCreateDomain(domain_id, user_default_role);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseCreateAsset(
        std::vector<std::string> params) {
      auto asset_name = params[0];
      auto domain_id = params[1];
      auto val = parser::parseValue<uint32_t>(params[2]);
      if (not val) {
        std::cout << "Wrong format for precision" << std::endl;
        return nullptr;
      }
      return generator_.generateCreateAsset(asset_name, domain_id, val.value());
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseRemoveSignatory(
        std::vector<std::string> params) {
      auto account_id = params[0];
      auto key = params[1];
      iroha::pubkey_t pubkey;
      pubkey = iroha::hexstringToArray<iroha::pubkey_t::size()>(key).value();
      return generator_.generateRemoveSignatory(account_id, pubkey);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseSetQuorum(std::vector<std::string> params) {
      auto account_id = params[0];
      auto quorum = parser::parseValue<uint64_t>(params[1]);
      if (not quorum) {
        std::cout << "Wrong format for quorum" << std::endl;
        return nullptr;
      }
      return generator_.generateSetQuorum(account_id, quorum.value());
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseSubtractAssetQuantity(
        std::vector<std::string> params) {
      auto asset_id = params[0];
      auto amount = params[1];
      auto description = params[2];
      return generator_.generateSubtractAssetQuantity(asset_id, amount, description);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseTransferAsset(
        std::vector<std::string> params) {
      auto src_account_id = params[0];
      auto dest_account_id = params[1];
      auto asset_id = params[2];
      auto amount = params[3];
      return generator_.generateTransferAsset(
          src_account_id, dest_account_id, asset_id, amount);
    }

    std::shared_ptr<iroha::model::Command>
    InteractiveTransactionCli::parseSetAccountDetail(
        std::vector<std::string> params) {
      auto account_id = params[0];
      auto key = params[1];
      auto value = params[2];
      return std::make_shared<SetAccountDetail>(account_id, key, value);
    }

    // --------- Result parsers -------------

    bool InteractiveTransactionCli::parseResult(std::string line) {
      // Find in result handler map
      auto res =
          handleParse<bool>(this, line, result_handlers_, result_params_map);
      return res.get_value_or(true);
    }

    bool InteractiveTransactionCli::parseSendToIroha(
        std::vector<std::string> params) {
      auto address = parseIrohaPeerParams(
          std::move(params), default_peer_ip_, default_port_);
      if (not address) {
        return true;
      }

      // Forming a transaction

      auto tx = tx_generator_.generateTransaction(creator_, commands_);
      // clear commands so that we can start creating new tx
      commands_.clear();

      provider_->sign(tx);

      GrpcResponseHandler response_handler(response_handler_log_manager_);
      auto shared_tx = shared_model::proto::Transaction(
          iroha::model::converters::PbTransactionFactory().serialize(tx));
      response_handler.handle(CliClient(address.value().first,
                                        address.value().second,
                                        pb_qry_factory_log_)
                                  .sendTx(shared_tx));

      printTxHash(tx);
      printEnd();
      // Stop parsing
      return false;
    }

    bool InteractiveTransactionCli::parseSaveFile(
        std::vector<std::string> params) {
      auto path = params[0];
      std::ofstream output_file(path);
      if (not output_file) {
        std::cout << "Wrong path" << std::endl;
        // Continue parsing
        return true;
      }

      // Forming a transaction
      auto tx = tx_generator_.generateTransaction(creator_, commands_);

      // clear commands so that we can start creating new tx
      commands_.clear();

      provider_->sign(tx);

      iroha::model::converters::JsonTransactionFactory json_factory;
      auto json_doc = json_factory.serialize(tx);
      auto json_string = iroha::model::converters::jsonToString(json_doc);
      output_file << json_string;
      std::cout << "Successfully saved!" << std::endl;
      printEnd();
      // Stop parsing
      return false;
    }

    bool InteractiveTransactionCli::parseGoBack(
        std::vector<std::string> params) {
      current_context_ = MAIN;
      // Remove all old commands
      commands_.clear();
      printEnd();
      printMenu("Forming a new transaction. Choose command to add: ",
                commands_menu_);
      // Continue parsing
      return true;
    }

    bool InteractiveTransactionCli::parseAddCommand(
        std::vector<std::string> params) {
      current_context_ = MAIN;
      printEnd();
      printMenu("Choose command to add: ", commands_menu_);
      // Continue parsing
      return true;
    }

    void InteractiveTransactionCli::printTxHash(iroha::model::Transaction &tx) {
      std::cout
          << "Congratulation, your transaction was accepted for processing."
          << std::endl;
      std::cout << "Its hash is " << iroha::hash(tx).to_hexstring()
                << std::endl;
    }

  }  // namespace interactive
}  // namespace iroha_cli

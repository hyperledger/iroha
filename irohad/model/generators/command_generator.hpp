/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMAND_GENERATOR_HPP
#define IROHA_COMMAND_GENERATOR_HPP

#include <memory>
#include "crypto/keypair.hpp"
#include "generator/generator.hpp"

namespace iroha {
  namespace model {

    struct Peer;
    struct Command;
    struct Account;

    namespace generators {

      class CommandGenerator {
       public:
        std::shared_ptr<Command> generateAddPeer(const Peer &peer);

        std::shared_ptr<Command> generateAddSignatory(
            const std::string &account_id, const pubkey_t &key);

        std::shared_ptr<Command> generateRemoveSignatory(
            const std::string &account_id, const pubkey_t &key);

        std::shared_ptr<Command> generateCreateAccount(
            const std::string &account_name,
            const std::string &domain_id,
            const pubkey_t &key);

        std::shared_ptr<Command> generateCreateDomain(
            const std::string &domain_id, const std::string &default_role);

        std::shared_ptr<Command> generateCreateAsset(
            const std::string &asset_name,
            const std::string &domain_name,
            uint8_t precision);

        template <typename Type, typename... ParamTypes>
        std::shared_ptr<Command> generateCommand(ParamTypes... args) {
          return std::make_shared<Type>(args...);
        }

        std::shared_ptr<Command> generateCreateAdminRole(std::string role_name);

        std::shared_ptr<Command> generateCreateUserRole(std::string role_name);

        std::shared_ptr<Command> generateCreateAssetCreatorRole(
            std::string role_name);

        std::shared_ptr<Command> generateSetQuorum(
            const std::string &account_id, uint32_t quorum);

        std::shared_ptr<Command> generateAddAssetQuantity(
            const std::string &asset_id, const std::string &amount, const std::string &title);

        std::shared_ptr<Command> generateSubtractAssetQuantity(
            const std::string &asset_id, const std::string &amount, const std::string &title);
        /**
         * Generate transfer assets from source account_id to target account_id
         * @param src_account_id - source account identifier
         * @param target_account_id - target account identifier
         * @param asset_id - asset identifier to transfer
         * @param amount - amount of assets to transfer
         * @return
         */
        std::shared_ptr<Command> generateTransferAsset(
            const std::string &src_account_id,
            const std::string &target_account_id,
            const std::string &asset_id,
            const std::string &amount);

        std::shared_ptr<Command> generateAppendRole(
            const std::string &account_id, const std::string &role_name);
      };
    }  // namespace generators
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_COMMAND_GENERATOR_HPP

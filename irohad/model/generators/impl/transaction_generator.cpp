/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/generators/transaction_generator.hpp"

#include "common/result.hpp"
#include "crypto/keys_manager_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"
#include "datetime/time.hpp"
#include "model/commands/append_role.hpp"
#include "model/peer.hpp"

namespace iroha {
  namespace model {
    namespace generators {

      iroha::keypair_t *makeOldModel(
          const shared_model::crypto::Keypair &keypair) {
        return new iroha::keypair_t{
            iroha::pubkey_t::from_hexstring(keypair.publicKey()).assumeValue(),
            iroha::privkey_t::from_string(toBinaryString(keypair.privateKey()))
                .assumeValue()};
      }

      Transaction TransactionGenerator::generateGenesisTransaction(
          ts64_t timestamp,
          std::vector<std::string> peers_address,
          logger::LoggerPtr keys_manager_logger) {
        Transaction tx;
        tx.created_ts = timestamp;
        tx.creator_account_id = "";
        CommandGenerator command_generator;
        // Add peers
        for (size_t i = 0; i < peers_address.size(); ++i) {
          KeysManagerImpl manager("node" + std::to_string(i),
                                  keys_manager_logger);
          manager.createKeys(boost::none);
          auto keypair = *std::unique_ptr<iroha::keypair_t>(
              makeOldModel(manager.loadKeys(boost::none).assumeValue()));
          tx.commands.push_back(command_generator.generateAddPeer(
              Peer(peers_address[i], keypair.pubkey)));
        }
        // Create admin role
        tx.commands.push_back(
            command_generator.generateCreateAdminRole("admin"));
        // Create user role
        tx.commands.push_back(command_generator.generateCreateUserRole("user"));
        tx.commands.push_back(
            command_generator.generateCreateAssetCreatorRole("money_creator"));
        // Add domain
        tx.commands.push_back(
            command_generator.generateCreateDomain("test", "user"));
        // Create asset
        auto precision = 2;
        tx.commands.push_back(
            command_generator.generateCreateAsset("coin", "test", precision));
        // Create accounts
        KeysManagerImpl manager("admin@test", keys_manager_logger);
        manager.createKeys(boost::none);
        auto keypair = *std::unique_ptr<iroha::keypair_t>(
            makeOldModel(manager.loadKeys(boost::none).assumeValue()));
        tx.commands.push_back(command_generator.generateCreateAccount(
            "admin", "test", keypair.pubkey));
        manager = KeysManagerImpl("test@test", std::move(keys_manager_logger));
        manager.createKeys(boost::none);
        keypair = *std::unique_ptr<iroha::keypair_t>(
            makeOldModel(manager.loadKeys(boost::none).assumeValue()));
        tx.commands.push_back(command_generator.generateCreateAccount(
            "test", "test", keypair.pubkey));

        tx.commands.push_back(
            std::make_shared<AppendRole>("admin@test", "admin"));
        tx.commands.push_back(
            std::make_shared<AppendRole>("admin@test", "money_creator"));
        return tx;
      }

      Transaction TransactionGenerator::generateTransaction(
          ts64_t timestamp,
          std::string creator_account_id,
          std::vector<std::shared_ptr<Command>> commands) {
        Transaction tx;
        tx.created_ts = timestamp;
        tx.creator_account_id = creator_account_id;
        tx.commands = commands;
        return tx;
      }

      Transaction TransactionGenerator::generateTransaction(
          std::string creator_account_id,
          std::vector<std::shared_ptr<Command>> commands) {
        return generateTransaction(
            iroha::time::now(), creator_account_id, commands);
      }

    }  // namespace generators
  }    // namespace model
}  // namespace iroha

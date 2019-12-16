/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/pb_transaction_factory.hpp"

#include "model/commands/add_asset_quantity.hpp"
#include "model/converters/pb_command_factory.hpp"

namespace iroha {
  namespace model {
    namespace converters {

      protocol::Transaction PbTransactionFactory::serialize(
          const model::Transaction &tx) {
        model::converters::PbCommandFactory factory;
        protocol::Transaction pbtx;

        auto pl = pbtx.mutable_payload()->mutable_reduced_payload();
        pl->set_created_time(tx.created_ts);
        pl->set_creator_account_id(tx.creator_account_id);
        pl->set_quorum(tx.quorum);

        for (const auto &command : tx.commands) {
          auto cmd = pl->add_commands();
          new (cmd)
              protocol::Command(factory.serializeAbstractCommand(*command));
        }

        for (const auto &sig_obj : tx.signatures) {
          auto proto_signature = pbtx.add_signatures();
          proto_signature->set_public_key(sig_obj.pubkey.to_hexstring());
          proto_signature->set_signature(sig_obj.signature.to_hexstring());
        }
        return pbtx;
      }

      std::shared_ptr<model::Transaction> PbTransactionFactory::deserialize(
          const protocol::Transaction &pb_tx) {
        model::converters::PbCommandFactory commandFactory;
        model::Transaction tx;

        const auto &pl = pb_tx.payload().reduced_payload();
        tx.creator_account_id = pl.creator_account_id();
        tx.created_ts = pl.created_time();
        tx.quorum = static_cast<uint8_t>(pl.quorum());

        for (const auto &pb_sig : pb_tx.signatures()) {
          model::Signature sig{};
          sig.pubkey =
              pubkey_t::from_hexstring(pb_sig.public_key()).assumeValue();
          sig.signature =
              sig_t::from_hexstring(pb_sig.signature()).assumeValue();
          tx.signatures.push_back(sig);
        }

        for (const auto &pb_command : pl.commands()) {
          tx.commands.push_back(
              commandFactory.deserializeAbstractCommand(pb_command));
        }
        return std::make_shared<model::Transaction>(tx);
      }

    }  // namespace converters
  }    // namespace model
}  // namespace iroha

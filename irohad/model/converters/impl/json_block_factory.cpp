/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/json_block_factory.hpp"

using namespace rapidjson;

namespace iroha {
  namespace model {
    namespace converters {

      JsonBlockFactory::JsonBlockFactory(logger::LoggerPtr log)
          : log_{std::move(log)} {}

      Document JsonBlockFactory::serialize(const Block &block) {
        Document document;
        auto &allocator = document.GetAllocator();
        document.SetObject();

        Value signatures;
        signatures.SetArray();
        for (const auto &signature : block.sigs) {
          signatures.PushBack(serializeSignature(signature, allocator),
                              allocator);
        }
        document.AddMember("signatures", signatures, allocator);

        document.AddMember("created_ts", block.created_ts, allocator);
        document.AddMember("hash", block.hash.to_hexstring(), allocator);
        document.AddMember(
            "prev_hash", block.prev_hash.to_hexstring(), allocator);
        document.AddMember("height", block.height, allocator);
        document.AddMember("txs_number", block.txs_number, allocator);

        Value commands;
        commands.SetArray();
        for (auto &&transaction : block.transactions) {
          commands.PushBack(
              Document(&allocator)
                  .CopyFrom(factory_.serialize(transaction), allocator),
              allocator);
        }
        document.AddMember("transactions", commands, allocator);

        Value rejected_transactions;
        rejected_transactions.SetArray();
        for (auto &&hash : block.rejected_transactions_hashes) {
          Value serialized_hash;
          serialized_hash.SetString(hash.to_hexstring().c_str(), allocator);
          rejected_transactions.PushBack(serialized_hash, allocator);
        }
        document.AddMember(
            "rejected_transactions", rejected_transactions, allocator);

        return document;
      }

      boost::optional<Block> JsonBlockFactory::deserialize(
          const Document &document) {
        auto des = makeFieldDeserializer(document);
        auto des_transactions = [this](auto array) {
          auto acc_transactions = [this](auto init, auto &x) {
            return init | [this, &x](auto transactions) {
              return factory_.deserialize(x) |
                  [&transactions](auto transaction) {
                    transactions.push_back(transaction);
                    return boost::make_optional(std::move(transactions));
                  };
            };
          };
          return std::accumulate(
              array.begin(),
              array.end(),
              boost::make_optional(Block::TransactionsType()),
              acc_transactions);
        };
        return boost::make_optional(model::Block())
            | des.Uint64(&Block::created_ts, "created_ts")
            | des.Uint64(&Block::height, "height")
            | des.Uint(&Block::txs_number, "txs_number")
            | des.String(&Block::hash, "hash")
            | des.String(&Block::prev_hash, "prev_hash")
            | des.Array(&Block::sigs, "signatures")
            | des.Array(&Block::transactions, "transactions", des_transactions)
            | des.Array(&Block::rejected_transactions_hashes,
                        "rejected_transactions");
      }

    }  // namespace converters
  }    // namespace model
}  // namespace iroha

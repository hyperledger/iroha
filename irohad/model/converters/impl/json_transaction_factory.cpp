/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/json_transaction_factory.hpp"

#include <algorithm>
#include "model/converters/json_common.hpp"

using namespace rapidjson;

namespace iroha {
  namespace model {
    namespace converters {

      Document JsonTransactionFactory::serialize(
          const Transaction &transaction) {
        Document document;
        auto &allocator = document.GetAllocator();
        document.SetObject();

        Value signatures;
        signatures.SetArray();
        for (const auto &signature : transaction.signatures) {
          signatures.PushBack(serializeSignature(signature, allocator),
                              allocator);
        }
        document.AddMember("signatures", signatures, allocator);

        document.AddMember("created_ts", transaction.created_ts, allocator);
        document.AddMember(
            "creator_account_id", transaction.creator_account_id, allocator);
        document.AddMember("quorum", transaction.quorum, allocator);

        Value commands;
        commands.SetArray();
        for (auto &&command : transaction.commands) {
          commands.PushBack(
              Document(&allocator)
                  .CopyFrom(factory_.serializeAbstractCommand(command),
                            allocator),
              allocator);
        }

        document.AddMember("commands", commands, allocator);

        return document;
      }

      boost::optional<Transaction> JsonTransactionFactory::deserialize(
          const Value &document) {
        auto des = makeFieldDeserializer(document);
        auto des_commands = [this](auto array) {
          auto acc_commands = [this](auto init, auto &x) {
            return init | [this, &x](auto commands) {
              return factory_.deserializeAbstractCommand(x) |
                  [&commands](auto command) {
                    commands.push_back(command);
                    return boost::make_optional(std::move(commands));
                  };
            };
          };
          return std::accumulate(
              array.begin(),
              array.end(),
              boost::make_optional(Transaction::CommandsType()),
              acc_commands);
        };
        return boost::make_optional(Transaction())
            | des.Uint64(&Transaction::created_ts, "created_ts")
            | des.String(&Transaction::creator_account_id, "creator_account_id")
            | des.Array(&Transaction::signatures, "signatures")
            | des.Uint(&Transaction::quorum, "quorum")
            | des.Array(&Transaction::commands, "commands", des_commands);
      }

    }  // namespace converters
  }    // namespace model
}  // namespace iroha

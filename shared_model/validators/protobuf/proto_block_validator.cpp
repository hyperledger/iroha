/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_block_validator.hpp"

#include <boost/format.hpp>
#include <boost/range/adaptors.hpp>
#include <boost/range/algorithm/for_each.hpp>

#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {
    Answer ProtoBlockValidator::validate(
        const iroha::protocol::Block &block) const {
      Answer answer;
      std::string tx_reason_name = "Protobuf Block";
      ReasonsGroupType reason{tx_reason_name, GroupedReasons()};

      // make sure version one_of field of the Block is set
      if (block.block_version_case()
          == iroha::protocol::Block::BLOCK_VERSION_NOT_SET) {
        reason.second.emplace_back("Block version is not set");
        answer.addReason(std::move(reason));
        return answer;
      }

      const auto &rejected_hashes =
          block.block_v1().payload().rejected_transactions_hashes();

      boost::for_each(rejected_hashes | boost::adaptors::indexed(0),
                      [&reason](const auto &hash) {
                        if (not validateHexString(hash.value())) {
                          reason.second.emplace_back(
                              (boost::format("Rejected hash '%s' with index "
                                             "'%d' is not in hash format")
                               % hash.value() % hash.index())
                                  .str());
                        }
                      });
      if (not validateHexString(block.block_v1().payload().prev_block_hash())) {
        reason.second.emplace_back("Prev block hash has incorrect format");
      }
      if (not reason.second.empty()) {
        answer.addReason(std::move(reason));
      }

      return answer;
    }
  }  // namespace validation
}  // namespace shared_model

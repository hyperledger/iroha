/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/pb_block_factory.hpp"

#include <boost/assert.hpp>

#include "model/converters/pb_common.hpp"
#include "model/converters/pb_transaction_factory.hpp"

namespace iroha {
  namespace model {
    namespace converters {

      protocol::Block PbBlockFactory::serialize(
          const model::Block &block) const {
        protocol::Block pb_block{};
        auto *pb_block_v1 = pb_block.mutable_block_v1();

        auto *pl = pb_block_v1->mutable_payload();
        pl->set_tx_number(block.txs_number);
        pl->set_height(block.height);
        pl->set_prev_block_hash(block.prev_hash.to_string());
        pl->set_created_time(block.created_ts);

        for (const auto &sig_obj : block.sigs) {
          auto sig = pb_block_v1->add_signatures();
          sig->set_public_key(sig_obj.pubkey.to_string());
          sig->set_signature(sig_obj.signature.to_string());
        }

        for (const auto &tx : block.transactions) {
          auto pb_tx = pl->add_transactions();
          pb_tx->CopyFrom(PbTransactionFactory::serialize(tx));
        }

        for (const auto &hash : block.rejected_transactions_hashes) {
          auto pb_hash = pl->add_rejected_transactions_hashes();
          *pb_hash = hash.to_string();
        }

        return pb_block;
      }

      model::Block PbBlockFactory::deserialize(
          protocol::Block const &pb_block) const {
        model::Block block{};
        BOOST_ASSERT_MSG(pb_block.has_block_v1(),
                         "Incompatible version of the block is used");
        const auto &pl = pb_block.block_v1().payload();

        // in proto we use uint32, but txs_number is uint16
        auto txn_max = std::numeric_limits<decltype(block.txs_number)>::max();
        if (pl.tx_number() > txn_max) {
          throw BadFormatException("too many transactions in block");
        }

        block.txs_number = static_cast<uint16_t>(pl.tx_number());
        block.height = pl.height();
        block.prev_hash =
            hash256_t::from_string(pl.prev_block_hash()).assumeValue();
        block.created_ts = pl.created_time();

        for (const auto &pb_sig : pb_block.block_v1().signatures()) {
          model::Signature sig;
          sig.signature = sig_t::from_string(pb_sig.signature()).assumeValue();
          sig.pubkey = pubkey_t::from_string(pb_sig.public_key()).assumeValue();
          block.sigs.push_back(std::move(sig));
        }

        for (const auto &pb_tx : pl.transactions()) {
          block.transactions.push_back(
              *PbTransactionFactory::deserialize(pb_tx));
        }

        for (const auto &pb_hash : pl.rejected_transactions_hashes()) {
          BOOST_VERIFY_MSG(
              pb_hash.size() == model::Block::HashType::size(),
              ("Wrong rejected transaction hash: " + pb_hash).c_str());
          block.rejected_transactions_hashes.emplace_back();
          std::copy(pb_hash.begin(),
                    pb_hash.end(),
                    block.rejected_transactions_hashes.back().begin());
        }

        block.hash = iroha::hash(pb_block.block_v1());

        return block;
      }
    }  // namespace converters
  }    // namespace model
}  // namespace iroha

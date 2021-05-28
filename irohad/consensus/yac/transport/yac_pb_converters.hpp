/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_PB_CONVERTERS_HPP
#define IROHA_YAC_PB_CONVERTERS_HPP

#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "common/byteutils.hpp"
#include "consensus/yac/outcome_messages.hpp"
#include "interfaces/common_objects/signature.hpp"
#include "logger/logger.hpp"
#include "validators/field_validator.hpp"
#include "yac.pb.h"

namespace iroha::consensus::yac {
  class PbConverters {
   private:
    static inline proto::Vote serializeRoundAndHashes(const VoteMessage &vote) {
      proto::Vote pb_vote;

      auto hash = pb_vote.mutable_hash();
      auto hash_round = hash->mutable_vote_round();
      hash_round->set_block_round(vote.hash.vote_round.block_round);
      hash_round->set_reject_round(vote.hash.vote_round.reject_round);
      auto hash_vote_hashes = hash->mutable_vote_hashes();
      hash_vote_hashes->set_proposal(vote.hash.vote_hashes.proposal_hash);
      hash_vote_hashes->set_block(vote.hash.vote_hashes.block_hash);

      return pb_vote;
    }

    static inline VoteMessage deserealizeRoundAndHashes(
        const proto::Vote &pb_vote) {
      VoteMessage vote;

      vote.hash.vote_round = Round{pb_vote.hash().vote_round().block_round(),
                                   pb_vote.hash().vote_round().reject_round()};
      vote.hash.vote_hashes =
          YacHash::VoteHashes{pb_vote.hash().vote_hashes().proposal(),
                              pb_vote.hash().vote_hashes().block()};

      return vote;
    }

   public:
    static proto::Vote serializeVotePayload(const VoteMessage &vote) {
      auto pb_vote = serializeRoundAndHashes(vote);

      if (vote.hash.block_signature) {
        auto block_signature =
            pb_vote.mutable_hash()->mutable_block_signature();
        auto signature = hexstringToBytestringResult(
            vote.hash.block_signature->signedData());
        auto public_key =
            hexstringToBytestringResult(vote.hash.block_signature->publicKey());
        block_signature->set_signature(std::move(signature).assumeValue());
        block_signature->set_pubkey(std::move(public_key).assumeValue());
      }

      return pb_vote;
    }

    static proto::Vote serializeVote(const VoteMessage &vote) {
      auto pb_vote = serializeRoundAndHashes(vote);

      if (vote.hash.block_signature) {
        auto block_signature =
            pb_vote.mutable_hash()->mutable_block_signature();
        auto signature = hexstringToBytestringResult(
            vote.hash.block_signature->signedData());
        auto public_key =
            hexstringToBytestringResult(vote.hash.block_signature->publicKey());
        block_signature->set_signature(std::move(signature).assumeValue());
        block_signature->set_pubkey(std::move(public_key).assumeValue());
      }

      auto vote_signature = pb_vote.mutable_signature();
      auto signature =
          hexstringToBytestringResult(vote.signature->signedData());
      auto public_key =
          hexstringToBytestringResult(vote.signature->publicKey());
      vote_signature->set_signature(std::move(signature).assumeValue());
      vote_signature->set_pubkey(std::move(public_key).assumeValue());

      return pb_vote;
    }

    static boost::optional<VoteMessage> deserializeVote(
        const proto::Vote &pb_vote, logger::LoggerPtr log) {
      // TODO IR-428 igor-egorov refactor PbConverters - do the class
      // instantiable
      static const uint64_t kMaxBatchSize{0};
      // This is a workaround for the following ProtoCommonObjectsFactory.
      // We able to do this, because we don't have batches in consensus.
      static shared_model::proto::ProtoCommonObjectsFactory<
          shared_model::validation::FieldValidator>
          factory{std::make_shared<shared_model::validation::ValidatorsConfig>(
              kMaxBatchSize)};

      auto vote = deserealizeRoundAndHashes(pb_vote);

      auto deserialize = [&](auto &pubkey, auto &signature, const auto &msg) {
        auto pubkey_hex = bytestringToHexstring(pubkey);
        auto signature_hex = bytestringToHexstring(signature);
        using shared_model::interface::types::PublicKeyHexStringView;
        using shared_model::interface::types::SignedHexStringView;
        return factory
            .createSignature(PublicKeyHexStringView{pubkey_hex},
                             SignedHexStringView{signature_hex})
            .match(
                [&](auto &&sig)
                    -> boost::optional<
                        std::unique_ptr<shared_model::interface::Signature>> {
                  return std::move(sig).value;
                },
                [&](const auto &reason)
                    -> boost::optional<
                        std::unique_ptr<shared_model::interface::Signature>> {
                  log->error(msg, reason.error);
                  return boost::none;
                });
      };

      if (pb_vote.hash().has_block_signature()) {
        if (auto block_signature =
                deserialize(pb_vote.hash().block_signature().pubkey(),
                            pb_vote.hash().block_signature().signature(),
                            "Cannot build vote hash block signature: {}")) {
          vote.hash.block_signature = *std::move(block_signature);
        } else {
          return boost::none;
        }
      }

      if (auto vote_signature =
              deserialize(pb_vote.signature().pubkey(),
                          pb_vote.signature().signature(),
                          "Cannot build vote signature: {}")) {
        vote.signature = *std::move(vote_signature);
      } else {
        return boost::none;
      }

      return vote;
    }
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_PB_CONVERTERS_HPP

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROPOSAL_CACHE_HPP
#define IROHA_PROPOSAL_CACHE_HPP

#include <map>
#include <memory>

#include "interfaces/iroha_internal/proposal.hpp"
#include "consensus/round.hpp"
#include "common/common.hpp"

namespace iroha::ordering {

  class ProposalCache final {
    using ProposalCacheDataType =
        std::vector<std::shared_ptr<shared_model::interface::Proposal const>>;
    utils::ReadWriteObject<ProposalCacheDataType, std::mutex> cached_data_;

   public:
    ProposalCache(ProposalCache const &) = delete;
    ProposalCache &operator=(ProposalCache const &) = delete;

    ProposalCache(ProposalCache &&) = default;
    ProposalCache &operator=(ProposalCache &&) = default;

    ProposalCache() = default;

   public:
    void push(
        std::vector<std::shared_ptr<shared_model::interface::Proposal const>>
            &&proposal_pack) {
      cached_data_.exclusiveAccess([proposal_pack{std::move(proposal_pack)}](
                                       auto &cache) mutable {
        assert(cache.empty());
        cache = std::move(proposal_pack);
        std::sort(cache.begin(), cache.end(), [](auto const &l, auto const &r) {
          return l->height() >= r->height();
        });
      });
    }

    std::shared_ptr<shared_model::interface::Proposal const> pop(consensus::Round const &round) {
      return cached_data_.exclusiveAccess(
          [&](auto &cache)
              -> std::shared_ptr<shared_model::interface::Proposal const> {
            if (cache.empty())
              return nullptr;

            auto it = std::lower_bound(cache.begin(), cache.end(), [](auto const &l, auto const &r) {
              return l->height() >= r->height();
            });
            1

            auto back = cache.back();
            cache.pop_back();
            return back;
          });
    }
  };

}

#endif//IROHA_PROPOSAL_CACHE_HPP

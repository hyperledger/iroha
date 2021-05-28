/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONSENSUS_SUPERMAJORITY_CHECKER_HPP
#define IROHA_CONSENSUS_SUPERMAJORITY_CHECKER_HPP

#include <memory>
#include <vector>

#include <boost/range/any_range.hpp>
#include "consensus/yac/consistency_model.hpp"
#include "consensus/yac/yac_types.hpp"
#include "interfaces/common_objects/range_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model::interface {
  class Peer;
}  // namespace shared_model::interface

namespace iroha::consensus::yac {
  /**
   * Interface is responsible for checking if supermajority is achieved
   */
  class SupermajorityChecker {
   public:
    using VoteGroups = boost::any_range<PeersNumberType,
                                        boost::forward_traversal_tag,
                                        // reference type must be const for
                                        // transform_iterator to be able to
                                        // assign to any_iterator safely
                                        const PeersNumberType,
                                        std::ptrdiff_t>;

    virtual ~SupermajorityChecker() = default;

    /**
     * Check if supermajority is achieved
     * @param current actual number of signatures
     * @param all number of peers
     * @return true if supermajority is possible or false otherwise
     */
    virtual bool hasSupermajority(PeersNumberType current,
                                  PeersNumberType all) const = 0;

    /**
     * Check tolerance condition
     * @param number - voted peers
     * @param all - number of all peers in network
     * @return true if the given number of peers is tolerated by the network
     */
    virtual bool isTolerated(PeersNumberType number,
                             PeersNumberType all) const = 0;

    /**
     * Check if supermajority is possible
     * @param voted - numbers of peers voted for each option
     * @param all - number of peers in round
     * @return true, if reject
     */
    virtual bool canHaveSupermajority(const VoteGroups &votes,
                                      PeersNumberType all) const = 0;
  };

  /// Get a SupermajorityChecker for the given consistency model.
  std::unique_ptr<SupermajorityChecker> getSupermajorityChecker(
      ConsistencyModel c);
}  // namespace iroha::consensus::yac

#endif  // IROHA_CONSENSUS_SUPERMAJORITY_CHECKER_HPP

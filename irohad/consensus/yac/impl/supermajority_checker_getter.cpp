/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/supermajority_checker.hpp"

#include "consensus/yac/impl/supermajority_checker_bft.hpp"
#include "consensus/yac/impl/supermajority_checker_cft.hpp"

namespace yac = iroha::consensus::yac;

std::unique_ptr<iroha::consensus::yac::SupermajorityChecker>
yac::getSupermajorityChecker(ConsistencyModel c) {
  switch (c) {
    case ConsistencyModel::kCft:
      return std::make_unique<SupermajorityCheckerCft>();
    case ConsistencyModel::kBft:
      return std::make_unique<SupermajorityCheckerBft>();
    default:
      throw(std::runtime_error("Unknown consistency model requested!"));
  }
}

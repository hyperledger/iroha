/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "simulator/verified_proposal_creator_common.hpp"

#include "cryptography/hash.hpp"

namespace iroha {
  namespace simulator {

    std::shared_ptr<validation::VerifiedProposalAndErrors>
    getVerifiedProposalUnsafe(const VerifiedProposalCreatorEvent &event) {
      return *event.verified_proposal_result;
    }

  }  // namespace simulator
}  // namespace iroha

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ENOUGH_SIGNATURES_COLLECTED_RESPONSE_HPP
#define IROHA_ENOUGH_SIGNATURES_COLLECTED_RESPONSE_HPP

namespace shared_model {
  namespace interface {
    /**
     * Transaction successfully collected signatures enough to pass the quorum
     * and is ready for stateful validation
     */
    class EnoughSignaturesCollectedResponse
        : public AbstractTxResponse<EnoughSignaturesCollectedResponse> {
     private:
      std::string className() const override {
        return "EnoughSignaturesCollectedResponse";
      }
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_ENOUGH_SIGNATURES_COLLECTED_RESPONSE_HPP

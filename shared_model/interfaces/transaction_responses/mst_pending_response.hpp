/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_PENDING_RESPONSE_HPP
#define IROHA_MST_PENDING_RESPONSE_HPP

namespace shared_model {
  namespace interface {
    /**
     * Transaction was sent to MST processing and not yet signed by all required
     * signatories
     */
    class MstPendingResponse : public AbstractTxResponse<MstPendingResponse> {
     private:
      // TODO: [IR-1666] Akvinikym 29.08.18: Make interface methods public
      std::string className() const override {
        return "MstPendingResponse";
      }
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_MST_PENDING_RESPONSE_HPP

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_STATUS_BUILDER_HPP
#define IROHA_TRANSACTION_STATUS_BUILDER_HPP

#include "interfaces/common_objects/account_asset.hpp"

namespace shared_model {
  namespace builder {

    // TODO: kamilsa 09.02.2018 IR-1087 Improve transaction status builder, so
    // that it is not allowed to set more than one status and transaction hash
    // is set before build method is invoked
    /**
     * Builder to construct transaction status object
     * @tparam BuilderImpl
     */
    template <typename BuilderImpl>
    class [[deprecated]] TransactionStatusBuilder {
     public:
      std::shared_ptr<shared_model::interface::TransactionResponse> build() {
        return clone(builder_.build());
      }

      TransactionStatusBuilder statelessValidationSuccess() {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.statelessValidationSuccess();
        return copy;
      }

      TransactionStatusBuilder statelessValidationFailed() {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.statelessValidationFailed();
        return copy;
      }

      TransactionStatusBuilder mstPending() {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.mstPending();
        return copy;
      }

      TransactionStatusBuilder enoughSignaturesCollected() {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.enoughSignaturesCollected();
        return copy;
      }

      TransactionStatusBuilder statefulValidationSuccess() {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.statefulValidationSuccess();
        return copy;
      }

      TransactionStatusBuilder statefulValidationFailed() {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.statefulValidationFailed();
        return copy;
      }

      TransactionStatusBuilder committed() {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.committed();
        return copy;
      }

      TransactionStatusBuilder notReceived() {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.notReceived();
        return copy;
      }

      TransactionStatusBuilder mstExpired() {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.mstExpired();
        return copy;
      }

      TransactionStatusBuilder txHash(const crypto::Hash &hash) {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.txHash(hash);
        return copy;
      }

      TransactionStatusBuilder statelessErrorOrCmdName(
          const std::string &name) {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.statelessErrorOrCmdName(name);
        return copy;
      }

      TransactionStatusBuilder failedCmdIndex(size_t index) {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.failedCmdIndex(index);
        return copy;
      }

      TransactionStatusBuilder errorCode(uint32_t code) {
        TransactionStatusBuilder copy(*this);
        copy.builder_ = this->builder_.errorCode(code);
        return copy;
      }

     private:
      BuilderImpl builder_;
    };

  }  // namespace builder
}  // namespace shared_model

#endif  // IROHA_TRANSACTION_STATUS_BUILDER_HPP

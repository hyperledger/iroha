/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_WSVRESTORERIMPL_HPP
#define IROHA_WSVRESTORERIMPL_HPP

#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/wsv_restorer.hpp"
#include "common/result.hpp"
#include "logger/logger_fwd.hpp"

namespace shared_model {
  namespace interface {
    class Block;
  }
  namespace validation {
    template <typename Model>
    class AbstractValidator;
  }
}  // namespace shared_model

namespace iroha {
  namespace protocol {
    class Block_v1;
  }
  namespace validation {
    class ChainValidator;
  }
  namespace ametsuchi {

    /**
     * Recover WSV (World State View).
     * @return true on success, otherwise false
     */
    class WsvRestorerImpl : public WsvRestorer {
     public:
      WsvRestorerImpl(
          std::unique_ptr<shared_model::validation::AbstractValidator<
              shared_model::interface::Block>> interface_validator,
          std::unique_ptr<shared_model::validation::AbstractValidator<
              iroha::protocol::Block_v1>> proto_validator,
          std::shared_ptr<validation::ChainValidator> validator,
          logger::LoggerPtr log);

      virtual ~WsvRestorerImpl() = default;
      /**
       * Recover WSV (World State View).
       * Drop storage and apply blocks one by one.
       * @param storage of blocks in ledger
       * @param wait_for_new_blocks - flag for wait for new blocks mode.
       * Method waits for new blocks in block storage.
       * @return ledger state after restoration on success, otherwise error
       * string
       */
      CommitResult restoreWsv(
          Storage &storagem,
          bool wait_for_new_blocks,
          std::shared_ptr<BlockQuery> = nullptr,
          std::shared_ptr<BlockStorageFactory> = nullptr) override;

     private:
      std::unique_ptr<shared_model::validation::AbstractValidator<
          shared_model::interface::Block>>
          interface_validator_;
      std::unique_ptr<shared_model::validation::AbstractValidator<
          iroha::protocol::Block_v1>>
          proto_validator_;
      std::shared_ptr<validation::ChainValidator> validator_;
      logger::LoggerPtr log_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_WSVRESTORERIMPL_HPP

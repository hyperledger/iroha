/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEMPORARY_FACTORY_HPP
#define IROHA_TEMPORARY_FACTORY_HPP

#include <memory>
#include "common/result.hpp"

namespace iroha {
  namespace ametsuchi {

    class TemporaryWsv;

    class TemporaryFactory {
     public:
      /**
       * Creates a temporary world state view from the current state.
       * Temporary state will be not committed and will be erased on destructor
       * call.
       * Temporary state might be used for transaction validation.
       * @return Created Result with temporary wsv or string error
       */
      virtual expected::Result<std::unique_ptr<TemporaryWsv>, std::string>
      createTemporaryWsv() = 0;

      /**
       * Prepare state which was accumulated in temporary WSV.
       * After preparation, this state is not visible until it isn't committed.
       *
       * @param wsv - state which will be prepared.
       */
      virtual void prepareBlock(std::unique_ptr<TemporaryWsv> wsv) = 0;

      virtual ~TemporaryFactory() = default;
    };

  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_TEMPORARY_FACTORY_HPP

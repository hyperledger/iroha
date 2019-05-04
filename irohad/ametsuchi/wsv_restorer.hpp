/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_WSVRESTORER_HPP
#define IROHA_WSVRESTORER_HPP

#include "common/result.hpp"

namespace iroha {
  namespace ametsuchi {

    class Storage;

    /**
     * Interface for World State View restoring from the storage
     */
    class WsvRestorer {
     public:
      virtual ~WsvRestorer() = default;

      /**
       * Recover WSV (World State View).
       * @param storage storage of blocks in ledger
       * @return ledger state after restoration on success, otherwise error
       * string
       */
      virtual iroha::expected::
          Result<boost::optional<std::unique_ptr<LedgerState>>, std::string>
          restoreWsv(Storage &storage) = 0;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_WSVRESTORER_HPP

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_temporary_wsv_impl.hpp"

#include "ametsuchi/impl/rocksdb_command_executor.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "common/to_lower.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/permission_to_string.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace iroha::ametsuchi {

  RocksDbTemporaryWsvImpl::RocksDbTemporaryWsvImpl(
      std::shared_ptr<RocksDbCommandExecutor> command_executor,
      logger::LoggerManagerTreePtr log_manager)
      : TemporaryWsvImpl(command_executor, log_manager),
        tx_context_(command_executor->getSession()) {}

  expected::Result<void, validation::CommandError>
  RocksDbTemporaryWsvImpl::validateSignatures(
      const shared_model::interface::Transaction &transaction) {
    auto const &[account, domain] =
        staticSplitId<2>(transaction.creatorAccountId());
    RocksDbCommon common(tx_context_);

    uint64_t quorum;
    if (auto result = forQuorum<kDbOperation::kGet, kDbEntry::kMustExist>(
            common, account, domain);
        expected::hasError(result))
      return expected::makeError(
          validation::CommandError{"signatures validation",
                                   result.assumeError().code,
                                   result.assumeError().description,
                                   false});
    else
      quorum = *result.assumeValue();

    std::string pk;
    for (auto &signatory : transaction.signatures()) {
      pk.clear();
      toLowerAppend(signatory.publicKey(), pk);
      if (auto result =
              forSignatory<kDbOperation::kCheck, kDbEntry::kMustExist>(
                  common, account, domain, pk);
          expected::hasError(result))
        return expected::makeError(
            validation::CommandError{"signatures validation",
                                     1,
                                     result.assumeError().description,
                                     false});
    }

    if (boost::size(transaction.signatures()) < quorum) {
      auto error_str = "Transaction " + transaction.toString()
          + " failed signatures validation";
      return expected::makeError(validation::CommandError{
          "signatures validation", 2, error_str, false});
    }

    return {};
  }

}  // namespace iroha::ametsuchi

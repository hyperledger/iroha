/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LOGGER_LOGGER_FWD_HPP
#define IROHA_LOGGER_LOGGER_FWD_HPP

#include <memory>

/* It is preferable to include this header in files that do not contain
 * dereferencing of LoggerPtr and do not use the Logger class functions, because
 * the actual Logger class definition contains template member functions that
 * use template library functions, thus making the preprocessed source file much
 * bigger.
 */

namespace logger {

  class Logger;

  using LoggerPtr = std::shared_ptr<Logger>;

}  // namespace logger

#endif  // IROHA_LOGGER_LOGGER_FWD_HPP

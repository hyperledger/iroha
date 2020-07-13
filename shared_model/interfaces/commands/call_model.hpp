/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_CALL_MODEL_HPP
#define IROHA_SHARED_MODEL_CALL_MODEL_HPP

#include <string>

namespace shared_model::interface {

  class CallModel {
   public:
    virtual ~CallModel();

    virtual const std::string &name() const = 0;

    virtual const std::string &version() const = 0;

    std::string toString() const;

    bool operator==(const CallModel &rhs) const;
  };
}  // namespace shared_model::interface

#endif

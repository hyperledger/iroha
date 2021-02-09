/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_DISPATCHER_HPP
#define IROHA_SUBSCRIPTION_DISPATCHER_HPP

#include "subscription/common.hpp"

namespace iroha::subscription {

  template<size_t kCount>
  class Dispatcher final : utils::NoCopy, utils::NoMove {
   public:
    static constexpr size_t kHandlersCount = kCount;

   private:
    threadHandler handlers[kHandlersCount];

   public:

  };

}

#endif//IROHA_SUBSCRIPTION_DISPATCHER_HPP

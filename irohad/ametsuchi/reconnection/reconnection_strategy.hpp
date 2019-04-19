/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RECONNECTION_STRATEGY_HPP
#define IROHA_RECONNECTION_STRATEGY_HPP

#include <string>

namespace iroha {
  namespace ametsuchi {
    /**
     * The interface provides a strategy for reconnection to data base.
     */
    class ReconnectionStorageStrategy {
     public:
      /// Identifier type of unique invocation
      using Tag = std::string;

      /**
       * check that invocation by tag will be appropriate
       */
      virtual bool canInvoke(const Tag &) = 0;

      /**
       * Reset invocations by tag
       */
      virtual void reset(const Tag &) = 0;

      /**
       * Create a tag based on passed
       * @param passed - initial tag
       */
      virtual Tag makeTag(const Tag &passed) = 0;

      virtual ~ReconnectionStorageStrategy() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  //IROHA_RECONNECTION_STRATEGY_HPP

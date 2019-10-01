/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FAKE_PEER_OS_NETWORK_NOTIFIER_HPP_
#define FAKE_PEER_OS_NETWORK_NOTIFIER_HPP_

#include "network/ordering_service_transport.hpp"

#include <mutex>

#include <rxcpp/rx-lite.hpp>
#include "framework/integration_framework/fake_peer/types.hpp"

namespace integration_framework {
  namespace fake_peer {

    class OsNetworkNotifier final
        : public iroha::network::OrderingServiceNotification {
     public:
      void onBatch(std::unique_ptr<shared_model::interface::TransactionBatch>
                       batch) override;

      rxcpp::observable<
          std::shared_ptr<shared_model::interface::TransactionBatch>>
      getObservable();

     private:
      rxcpp::subjects::subject<
          std::shared_ptr<shared_model::interface::TransactionBatch>>
          batches_subject_;
      std::mutex batches_subject_mutex_;
    };

  }  // namespace fake_peer
}  // namespace integration_framework

#endif /* FAKE_PEER_OS_NETWORK_NOTIFIER_HPP_ */

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MAINTENANCE_METRICS_HPP
#define IROHA_MAINTENANCE_METRICS_HPP

#include <string>
#include <memory>
#include <prometheus/registry.h>

std::shared_ptr<prometheus::Registry>
    maintenance_metrics_init(std::string const& listen_addr);

#endif //IROHA_MAINTENANCE_METRICS_HPP

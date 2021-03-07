/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>
#include <memory>
#include <prometheus/registry.h>

auto maintenance_metrics_init(std::string const& listen_addr)
->std::optional<std::shared_ptr<prometheus::Registry>>;

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "util/status_notifier.hpp"

using namespace iroha::utility_service;

StatusNotifier::~StatusNotifier() = default;

void StatusNotifier::notify(Status status) {}

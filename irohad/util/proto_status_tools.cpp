/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "util/proto_status_tools.hpp"

#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/tuple/elem.hpp>
#include <optional>
#include "common/bind.hpp"
#include "util/status.hpp"

using iroha::operator|;

// clang-format off
#define EL0 (Status::kUnknown,        proto::Status_StatusEnum_unknown)
#define EL1 (Status::kInitialization, proto::Status_StatusEnum_initialization)
#define EL2 (Status::kRunning,        proto::Status_StatusEnum_running)
#define EL3 (Status::kTermination,    proto::Status_StatusEnum_termination)
#define EL4 (Status::kStopped,        proto::Status_StatusEnum_stopped)
#define EL5 (Status::kFailed,         proto::Status_StatusEnum_failed)
// clang-format on

#define NUM_ELEMS 6

#define SWL(z, i, ...)                   \
  case BOOST_PP_TUPLE_ELEM(2, 0, EL##i): \
    return BOOST_PP_TUPLE_ELEM(2, 1, EL##i);
#define SWR(z, i, ...)                   \
  case BOOST_PP_TUPLE_ELEM(2, 1, EL##i): \
    return BOOST_PP_TUPLE_ELEM(2, 0, EL##i);

#define SW_ALL_LEFT(v) \
  switch (v) { BOOST_PP_REPEAT(NUM_ELEMS, SWL, ) }

#define SW_ALL_RIGHT(v) \
  switch (v) { BOOST_PP_REPEAT(NUM_ELEMS, SWR, ) default : break; }

namespace iroha {
  namespace utility_service {
    proto::Status_StatusEnum makeProtoStatus(Status status) {
      SW_ALL_LEFT(status)
      return proto::Status_StatusEnum_unknown;
    }

    Status makeStatus(const proto::Status_StatusEnum &status) {
      SW_ALL_RIGHT(status)
      return Status::kUnknown;
    }
  }  // namespace utility_service
}  // namespace iroha

namespace iroha {
  namespace to_string {
    std::string toString(const ::iroha::utility_service::Status &val) {
      return ::iroha::to_string::toString(makeProtoStatus(val));
    }
  }  // namespace to_string
}  // namespace iroha

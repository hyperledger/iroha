/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef VENDOR_GRPC_MOCKS_HPP
#define VENDOR_GRPC_MOCKS_HPP

#include <gmock/gmock.h>
#include <grpc++/grpc++.h>

namespace iroha {
  template <typename T>
  class MockServerWriter : public grpc::ServerWriterInterface<T> {
   public:
    MOCK_METHOD1_T(Write, void(T));
    MOCK_METHOD2_T(Write, bool(const T &, grpc::WriteOptions));
    MOCK_METHOD0(SendInitialMetadata, void());
    MOCK_METHOD1(NextMessageSize, bool(uint32_t *));
  };
}  // namespace iroha

#endif  // VENDOR_GRPC_MOCKS_HPP

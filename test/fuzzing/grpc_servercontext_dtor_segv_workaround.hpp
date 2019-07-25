/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GRPC_SERVERCONTEXT_DTOR_SEGV_WORKAROUND_HPP
#define IROHA_GRPC_SERVERCONTEXT_DTOR_SEGV_WORKAROUND_HPP

#include <grpcpp/impl/grpc_library.h>

// segfaults happen inside ~ServerContext() sometimes
// check https://github.com/grpc/grpc/issues/14633 for details
static grpc::internal::GrpcLibraryInitializer g_gli_initializer;

#endif  // IROHA_GRPC_SERVERCONTEXT_DTOR_SEGV_WORKAROUND_HPP

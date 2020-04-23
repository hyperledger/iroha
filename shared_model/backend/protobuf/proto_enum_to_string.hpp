/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_ENUM_TO_STRING_HPP
#define IROHA_PROTO_ENUM_TO_STRING_HPP

#include <string>

#include <google/protobuf/generated_enum_reflection.h>

#define IROHA_DEFINE_PROTO_ENUM_TO_STRING(EnumType)                       \
  namespace iroha {                                                       \
    namespace to_string {                                                 \
      inline std::string toString(const EnumType &val) {                  \
        const ::google::protobuf::EnumDescriptor *const descriptor =      \
            ::google::protobuf::GetEnumDescriptor<EnumType>();            \
        return ::google::protobuf::internal::NameOfEnum(descriptor, val); \
      }                                                                   \
    }                                                                     \
  }

#endif

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_FUNCTION_STACK_INFO_HPP
#define IROHA_FUNCTION_STACK_INFO_HPP

#include <assert.h>

#include "common/memory_utils.hpp"

namespace iroha { namespace performance_tools {

using FunctionStackKey = uint64_t;
using StackPosition = uint16_t;

union FunctionStackInfo {
private:
    struct {
        StackPosition stack_depth;
        uint16_t checkpoint;
        Hash f_id;
    } f_stack_description;
    FunctionStackKey f_key;
    static_assert(sizeof(f_key) == sizeof(f_stack_description), "Recalculate packed data size. It can be not optimized.");

public:
    FunctionStackInfo() : f_key(0ull) {
        iroha::memory::memzero(f_stack_description);
    }

    FunctionStackInfo(FunctionStackInfo const& c) : f_key(c.f_key)
    { }

    FunctionStackInfo(StackPosition stack_position, Hash f_id) {
        f_stack_description.stack_depth = stack_position;
        f_stack_description.f_id = f_id;
        f_stack_description.checkpoint = static_cast<decltype(f_stack_description.checkpoint)>(f_id);
    }

    FunctionStackInfo& operator=(FunctionStackInfo const& c) {
        f_key = c.f_key;
        return *this;
    }

    FunctionStackInfo& operator=(FunctionStackKey const& c) {
        f_key = c;
        return *this;
    }

    FunctionStackInfo& reset(StackPosition stack_position, Hash f_id) {
        f_stack_description.stack_depth = stack_position;
        f_stack_description.f_id = f_id;
        f_stack_description.checkpoint = static_cast<decltype(f_stack_description.checkpoint)>(f_id);
        return *this;
    }

    FunctionStackInfo& swallow(FunctionStackInfo const& other) {
        assert(0ull != other.f_key);
        f_stack_description.f_id ^= other.f_stack_description.f_id;
        f_stack_description.checkpoint += other.f_stack_description.checkpoint;
        ++f_stack_description.stack_depth;

        //std::cout << "STACK POINTER: " << f_key << std::endl;
        return *this;
    }

    FunctionStackInfo& emit(FunctionStackInfo const& other) {
        assert(0ull != other.f_key);
        f_stack_description.f_id ^= other.f_stack_description.f_id;
        f_stack_description.checkpoint -= other.f_stack_description.checkpoint;
        --f_stack_description.stack_depth;
        return *this;
    }

    operator bool() const {
        return (f_key != 0ull);
    }

    void clear() {
        f_key = 0ull;
    }

    Hash getFunctionId() const {
        return f_stack_description.f_id;
    }

    FunctionStackKey getKey() const {
        return f_key;
    }
};
static_assert(sizeof(FunctionStackInfo) == sizeof(FunctionStackKey), "Recalculate packed data size. It can be not optimized.");

} }

#endif//IROHA_FUNCTION_STACK_INFO_HPP

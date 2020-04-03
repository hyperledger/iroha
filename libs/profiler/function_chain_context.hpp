/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_FUNCTION_CHAIN_CONTEXT_HPP
#define IROHA_FUNCTION_CHAIN_CONTEXT_HPP

#include <assert.h>

#include "common/memory_utils.hpp"
#include "profiler/function_stack_info.hpp"

namespace iroha { namespace performance_tools {

class  FunctionChainContext final {
    FunctionStackInfo const f_stack_info_;
    struct {
        uint64_t entries;
        uint64_t ts_counter;
    } counters_;

    FunctionChainContext(FunctionChainContext&&) = delete;
    FunctionChainContext& operator=(FunctionChainContext const&) = delete;
    FunctionChainContext& operator=(FunctionChainContext&&) = delete;

public:
    FunctionChainContext(FunctionChainContext const& c) : f_stack_info_(c.f_stack_info_) {
        memory::memcpy(counters_, c.counters_);
    }

    FunctionChainContext(FunctionStackInfo stack_info) : f_stack_info_(stack_info) {
        memory::memzero(counters_);
    }

public:
    void entriesInc() {
        ++counters_.entries;
    }

    uint64_t getEntries() const {
        return counters_.entries;
    }

    void tsCounterAdd(uint64_t value) {
        counters_.ts_counter += value;
    }

    uint64_t tsCounterGet() const {
        return counters_.ts_counter;
    }

    FunctionStackInfo const& getStackInfo() const {
        return f_stack_info_;
    }

    void merge(FunctionChainContext const& other) {
        assert(f_stack_info_.getKey() == other.f_stack_info_.getKey());
        counters_.entries += other.counters_.entries;
        counters_.ts_counter += other.counters_.ts_counter;
    }
};

} }

#endif//IROHA_FUNCTION_CHAIN_CONTEXT_HPP

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_FUNCTION_CONTEXT_HPP
#define IROHA_FUNCTION_CONTEXT_HPP

#include <assert.h>

#include "common/memory_utils.hpp"

namespace iroha { namespace performance_tools {

class FunctionContext final {
    char const* const f_name_;
    struct {
        uint64_t entries;
        uint64_t ns_counter;
        uint64_t ref_pt_counters[ReferencePointers::kRefPointsCount];
    } counters_;

    FunctionContext() = delete;
    FunctionContext(FunctionContext&&) = delete;
    FunctionContext& operator=(FunctionContext&&) = delete;
    FunctionContext& operator=(FunctionContext const&) = delete;

public:
    FunctionContext(FunctionContext const& c) : f_name_(c.f_name_) {
        memory::memcpy(counters_, c.counters_);
    }

    FunctionContext(char const *n) : f_name_(n) {
        memory::memzero(counters_);
    }

public:
    char const* getFunctionName() const {
        return f_name_;
    }

    void entriesInc() {
        ++counters_.entries;
    }

    uint64_t getEntries() const {
        return counters_.entries;
    }

    void nsCounterAdd(uint64_t value) {
        counters_.ns_counter += value;
    }

    uint64_t nsCounterGet() const {
        return counters_.ns_counter;
    }

    void refPtCounterAdd(ReferencePointers pt, uint64_t value) {
        assert(pt < ReferencePointers::kRefPointsCount);
        counters_.ref_pt_counters[pt] += value;
    }

    uint64_t refCounterGet(ReferencePointers pt) const {
        assert(pt < ReferencePointers::kRefPointsCount);
        return counters_.ref_pt_counters[pt];
    }

    void merge(FunctionContext const& other) {
        assert(0 == strcmp(f_name_, other.f_name_));
        counters_.entries += other.counters_.entries;
        counters_.ns_counter += other.counters_.ns_counter;
        for (size_t ix = 0; ix < ReferencePointers::kRefPointsCount; ++ix) {
            counters_.ref_pt_counters[ix] += other.counters_.ref_pt_counters[ix];
        }
    }
};

} }

#endif//IROHA_FUNCTION_CONTEXT_HPP

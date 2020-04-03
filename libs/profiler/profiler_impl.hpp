/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_PROFILER_IMPL_HPP
#define IROHA_PROFILER_IMPL_HPP

#include "profiler/profiler.hpp"

#include <memory>
#include <unordered_map>
#include <type_traits>
#include <cstring>
#include <assert.h>
#include <thread>

#include "common/memory_utils.hpp"
#include "common/stack.hpp"
#include "common/spin_lock.hpp"
#include "profiler/function_context.hpp"
#include "profiler/function_chain_context.hpp"

namespace iroha { namespace performance_tools {

static const size_t stack_depth = 1024;

class Profiler final {
public:
    struct StackFrame final {
        Hash const f_id;
        uint16_t entry_count;

        StackFrame(StackFrame const&) = delete;
        StackFrame& operator=(StackFrame const&) = delete;
        StackFrame(StackFrame&&) = delete;
        StackFrame& operator=(StackFrame&&) = delete;

        StackFrame(Hash id) : f_id(id), entry_count(0)
        { }
    };
    containers::Stack<StackFrame, stack_depth, alignof(StackFrame)> f_stack_;

    using FunctionProfilerData = std::unordered_map<Hash, FunctionContext>;
    using StackProfilerData = std::unordered_map<FunctionStackKey, FunctionChainContext>;

private:
    FunctionProfilerData f_description_;
    StackProfilerData f_chains_;

    FunctionStackInfo current_stack_pt_;
    FunctionStackInfo current_frame_info_;

public:
    Profiler(Profiler const&) = delete;
    Profiler& operator=(Profiler const&) = delete;

    Profiler(Profiler&&) = delete;
    Profiler& operator=(Profiler&&) = delete;

    Profiler() = default;
    ~Profiler() = default;

public:
    void push(Hash hash) {
        if (f_stack_.empty() || f_stack_.get().f_id != hash) {
            f_stack_.push(hash);
            current_frame_info_.reset(f_stack_.size(), hash);
            current_stack_pt_.swallow(current_frame_info_);
            assert(0ull != current_stack_pt_);
        }
        ++f_stack_.get().entry_count;
    }
    void pop(PerformanceCounter counter, char const* tag) {
        assert(nullptr != tag);
        auto &frame = f_stack_.get();
        if (0 == --frame.entry_count) {
            { // per-method counting
                auto &f_desc = (*f_description_.emplace(frame.f_id, tag).first).second;
                f_desc.nsCounterAdd(counter);
                f_desc.entriesInc();
            }
            { // per-stack position counting
                auto &f_stack = (*f_chains_.emplace(current_stack_pt_.getKey(), current_frame_info_).first).second;
                f_stack.tsCounterAdd(counter);
                f_stack.entriesInc();
            }

            // unwind stack
            f_stack_.pop();
            current_stack_pt_.emit(current_frame_info_);

            if (!f_stack_.empty()) {
                auto &_ = f_stack_.get();
                current_frame_info_.reset(f_stack_.size(), _.f_id);
            }
        }
    }

    void addPoint(ReferencePointers point, PerformanceCounter counter, char const* tag) {
        assert(nullptr != tag);
        auto &frame = f_stack_.get();
        if (1 == frame.entry_count) {
            auto &f_desc = (*f_description_.emplace(frame.f_id, tag).first).second;
            f_desc.refPtCounterAdd(point, counter);
        }
    }

    FunctionProfilerData const& getFuncDescriptions() const {
        return f_description_;
    }

    StackProfilerData const& getStackDescriptions() const {
        return f_chains_;
    }
};

} }

#endif//IROHA_PROFILER_IMPL_HPP

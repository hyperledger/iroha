/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_PROFILER_REPORT_HPP
#define IROHA_PROFILER_REPORT_HPP

#include <assert.h>

#include "common/memory_utils.hpp"

namespace iroha { namespace performance_tools {

struct ReportData {
    Profiler::FunctionProfilerData profiler_functions;
    Profiler::StackProfilerData profiler_stack;

    ReportData(ReportData const&) = delete;
    ReportData& operator=(ReportData const&) = delete;
    ReportData(Profiler const&) = delete;
    ReportData() = default;

    ReportData(ReportData&& c) 
        : profiler_functions(std::move(c.profiler_functions))
        , profiler_stack(std::move(c.profiler_stack))
    { }
    
    ReportData& operator=(ReportData&& c) {
        profiler_functions = std::move(c.profiler_functions);
        profiler_stack = std::move(c.profiler_stack);
        return *this;
    }

    ReportData& operator=(Profiler const &report) {
        profiler_functions = report.getFuncDescriptions();
        profiler_stack = report.getStackDescriptions();
        return *this;
    }

    void swap(ReportData &value) {
        profiler_functions.swap(value.profiler_functions);
        profiler_stack.swap(value.profiler_stack);
    }
};

} }

#endif//IROHA_PROFILER_REPORT_HPP

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "profiler/profiler.hpp"

#include <memory>
#include <unordered_map>
#include <type_traits>
#include <cstring>
#include <assert.h>
#include <thread>

#include "profiler/profiler_impl.hpp"
#include "profiler/viewer/report.hpp"
#include "profiler/viewer/report_viewer_impl.hpp"

namespace iroha { namespace performance_tools {

class ProfilerThreadData final {
    Profiler profiler_;
    ReportData thread_report_;

public:
    void prepareReport() {
        thread_report_ = profiler_;
    }

    Profiler& getProfiler() {
        return profiler_;
    }

    ReportData& getReport() {
        return thread_report_;
    }
};
thread_local std::unique_ptr<ProfilerThreadData> profiler_instance;

thread_concurrency::SpinLock thread_reports_cs;
std::unordered_map<std::thread::id, ReportData> thread_reports;

void pushFunctionEntry(Hash f_hash) {
    if (!profiler_instance)
        profiler_instance = std::make_unique<ProfilerThreadData>();

    assert(!!profiler_instance);
    profiler_instance->getProfiler().push(f_hash);
}

void popFunctionEntry(PerformanceCounter value, char const* tag) {
    assert(!!profiler_instance);
    profiler_instance->getProfiler().pop(value, tag);
}

void setPointValue(ReferencePointers point, PerformanceCounter value, char const* tag) {
    assert(!!profiler_instance);
    profiler_instance->getProfiler().addPoint(point, value, tag);
}

void prepareThreadReport() {
    assert(!!profiler_instance);
    profiler_instance->prepareReport();

    thread_concurrency::SpinLockInfinite guard(thread_reports_cs);
    thread_reports[std::this_thread::get_id()].swap(profiler_instance->getReport());
}

void getThreadReport(std::unique_ptr<IReportViewer>& report) {
    if (!report) {
        report = std::make_unique<ReportViewer>();
    }
    ReportViewer *rw = (ReportViewer*)report.get();
    thread_concurrency::SpinLockInfinite guard(thread_reports_cs);
    rw->swap(thread_reports);
}

} }

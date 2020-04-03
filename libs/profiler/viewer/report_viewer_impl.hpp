/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_PROFILER_REPORT_VIEWER_HPP
#define IROHA_PROFILER_REPORT_VIEWER_HPP

#include "profiler/profiler.hpp"

#include <optional>
#include <vector>
#include <algorithm>
#include <sstream>

#include "profiler/viewer/report.hpp"
#include "profiler/viewer/report_iterator_reader.hpp"

namespace iroha { namespace performance_tools {

class ReportViewer final
: public IReportViewer
, public IReportMethodIterator
, public IReportStackIterator
, public IReportThreadIterator
{
    using ThreadReports = std::unordered_map<std::thread::id, ReportData>;

    class EntriesViewer final {
        ReportIteratorReader<Profiler::FunctionProfilerData> f_profiler_data;
        ReportIteratorReader<Profiler::StackProfilerData>    s_profiler_data;

        ReportData *report_read_ptr;
        FunctionStackInfo s_position;
        std::string report_name_;

    public:
        EntriesViewer() : report_read_ptr(nullptr)
        { }

        bool bindStackPosition() {
            FunctionStackKey key;
            if (s_profiler_data.key(key)) {
                s_position = key;
                return true;
            }
            s_position.clear();
            return false;
        }

        bool unwindStack() {
            if (!s_position) { return false; }
            if (nullptr == report_read_ptr) { return false; }

            ReportIteratorReader<Profiler::StackProfilerData> it_stack(&report_read_ptr->profiler_stack);
            auto const _ = it_stack.find(s_position.getKey());
            assert(!!_);

            FunctionStackInfo si;
            using T = decltype(it_stack)::Value;

            auto const __ = it_stack.get(&T::getStackInfo, si);
            assert(!!__);

            s_position.emit(si);
            return !!s_position;
        }

        void fixupViewer(ReportData *report, std::string&& report_name = std::string()) {
            report_read_ptr = report;
            report_name_ = std::move(report_name);
            f_profiler_data = (nullptr != report_read_ptr ? &report_read_ptr->profiler_functions : nullptr);
            s_profiler_data = (nullptr != report_read_ptr ? &report_read_ptr->profiler_stack : nullptr);
            bindStackPosition();
        }

        inline bool methodItFirst() {
            return f_profiler_data.first();
        }

        inline bool methodItNext() {
            return f_profiler_data.next();
        }

        inline bool stackItFirst() {
            auto const result = s_profiler_data.first();
            bindStackPosition();
            return result;
        }

        inline bool stackItNext() {
            auto const result = s_profiler_data.next();
            bindStackPosition();
            return result;
        }

        std::string const& getReportName() const{
            return report_name_;
        }

        bool getMethodId(Hash &id) const {
            return f_profiler_data.key(id);
        }

        bool getMethodName(char const *&name) const {
            using T = decltype(f_profiler_data)::Value;
            auto const res = f_profiler_data.get(&T::getFunctionName, name);

            assert(nullptr != name);
            return res;
        }

        bool getMethodEntries(uint64_t &entries) const {
            using T = decltype(f_profiler_data)::Value;
            return f_profiler_data.get(&T::getEntries, entries);
        }

        bool getMethodCounter(uint64_t &counter) const {
            using T = decltype(f_profiler_data)::Value;
            return f_profiler_data.get(&T::nsCounterGet, counter);
        }

        bool getMethodPointCounter(ReferencePointers pt, uint64_t &counter) const {
            using T = decltype(f_profiler_data)::Value;
            return f_profiler_data.get(&T::refCounterGet, counter, pt);
        }

        bool getStackFrameName(char const *&name, Hash &id) const {
            if (!s_position) {
                return false;
            }

            ReportIteratorReader<Profiler::StackProfilerData> it_stack(&report_read_ptr->profiler_stack);
            if (!it_stack.find(s_position.getKey())) {
                assert(!"Find key failed.");
                return false;
            }

            FunctionStackInfo si;
            if (!it_stack.get(&decltype(it_stack)::Value::getStackInfo, si)) {
                assert(!"Get stack info failed.");
                return false;
            }

            ReportIteratorReader<Profiler::FunctionProfilerData> it_function(&report_read_ptr->profiler_functions);
            if (!it_function.find(si.getFunctionId())) {
                assert(!"Find method failed.");
                return false;
            }

            if (!it_function.get(&decltype(it_function)::Value::getFunctionName, name)) {
                assert(!"Unexpected method.");
                return false;
            }

            if (!it_function.key(id)) {
                assert(!"Get function id failed.");
                return false;
            }

            assert(nullptr != name);
            return true;
        }

        bool getStackFrameEntries(uint64_t &entries) const {
            using T = decltype(s_profiler_data)::Value;
            return s_profiler_data.get(&T::getEntries, entries);
        }

        bool getStackFrameCounter(uint64_t &counter) const {
            using T = decltype(s_profiler_data)::Value;
            return s_profiler_data.get(&T::tsCounterGet, counter);
        }

        void sortMethods(SortType type, bool asc) {
            f_profiler_data.sort([type, asc](auto const &l, auto const &r) {
                auto f = [asc](auto const &l, auto const &r) {
                    if (asc) return l < r;
                    return r < l;
                };

                switch(type) {
                    case SortType::kSortByEntries: return f(l.getEntries(), r.getEntries());

                    default: assert(!"Unexpected sort type.");
                    case SortType::kSortByCounter: return f(l.nsCounterGet(), r.nsCounterGet());
                };
            });
        }

        void sortStacks(SortType type, bool asc) {
            s_profiler_data.sort([type, asc](auto const &l, auto const &r) {
                auto f = [asc](auto const &l, auto const &r) {
                    if (asc) return l < r;
                    return r < l;
                };

                switch(type) {
                    case SortType::kSortByEntries: return f(l.getEntries(), r.getEntries());

                    default: assert(!"Unexpected sort type.");
                    case SortType::kSortByCounter: return f(l.tsCounterGet(), r.tsCounterGet());
                };
            });
        }
    };

    ThreadReports thread_reports_;
    std::optional<ReportData> merged_threads_data_;

    ThreadReports::iterator it_thread_;
    EntriesViewer entries_viewer_;

    template<typename TDst, typename TSrc, typename Func>
    inline void merge(TDst &dst, TSrc const &src, Func&& context_key_getter) {
        for (auto const &it : src) {
            auto const &key = it.first;
            auto const &val = it.second;

            auto &target = (*dst.emplace(key, context_key_getter(val)).first).second;
            target.merge(val);
        }
    }

    static inline std::string threadIdToString(std::thread::id const &id) {
        /// TODO: optimize if. there will be a way to do this.
        std::stringstream ss;
        ss << id;
        return ss.str();
    }

public:
    ReportViewer()
    : it_thread_(thread_reports_.end())
    { }

    void swap(ThreadReports& c) {
        thread_reports_.swap(c);
        it_thread_ = thread_reports_.begin();

        if (it_thread_ == thread_reports_.end()) {
            entries_viewer_.fixupViewer(nullptr);
        } else {
            entries_viewer_.fixupViewer(&it_thread_->second, threadIdToString(it_thread_->first));
        }
        
    }

    void mergeThreadData() {
        if (!!merged_threads_data_) {
            return;
        }

        ReportData _;
        for (auto const &it_thread : thread_reports_) {
            merge(_.profiler_functions, it_thread.second.profiler_functions, [](FunctionContext const &val) {
                return val.getFunctionName();
            });

            merge(_.profiler_stack, it_thread.second.profiler_stack, [](FunctionChainContext const &val) {
                return val.getStackInfo();
            });
        }

        merged_threads_data_.emplace(std::move(_));
        entries_viewer_.fixupViewer(&merged_threads_data_.value(), "{merged_report}");
    }

    bool threadAtMergedThreadData() override {
        if (!merged_threads_data_) {
            return false;
        }
        entries_viewer_.fixupViewer(&merged_threads_data_.value(), "{merged_report}");
        return true;
    }

    bool threadFirst() override {
        if ((it_thread_ = thread_reports_.begin()) == thread_reports_.end()) {
            entries_viewer_.fixupViewer(nullptr);
            return false;
        }
        entries_viewer_.fixupViewer(&it_thread_->second, threadIdToString(it_thread_->first));
        return true;
    }

    bool threadNext() override {
        if (thread_reports_.end() == it_thread_) {
            return false;
        }
        if (++it_thread_ == thread_reports_.end()) {
            entries_viewer_.fixupViewer(nullptr);
            return false;
        }
        entries_viewer_.fixupViewer(&it_thread_->second, threadIdToString(it_thread_->first));
        return true;
    }

    bool stackFirst() override {
        return entries_viewer_.stackItFirst();
    }

    bool stackNext() override {
        return entries_viewer_.stackItNext();
    }

    bool methodFirst() override {
        return entries_viewer_.methodItFirst();
    }

    bool methodNext() override {
        return entries_viewer_.methodItNext();
    }

    bool unwindStackFirst() override {
        return entries_viewer_.bindStackPosition();
    }

    bool unwindStackNext() override {
        return entries_viewer_.unwindStack();
    }

    bool getMethodName(char const *&name) const override {
        return entries_viewer_.getMethodName(name);
    }

    bool getMethodEntries(uint64_t &entries) const override {
        return entries_viewer_.getMethodEntries(entries);
    }

    bool getMethodCounter(uint64_t &counter) const override {
        return entries_viewer_.getMethodCounter(counter);
    }

    bool getMethodPointCounter(ReferencePointers pt, uint64_t &counter) const override {
        return entries_viewer_.getMethodPointCounter(pt, counter);
    }

    bool getStackFrameName(char const *&name, Hash &id) const override {
        return entries_viewer_.getStackFrameName(name, id);
    }

    bool getStackFrameEntries(uint64_t &entries) const override {
        return entries_viewer_.getStackFrameEntries(entries);
    }

    bool getStackFrameCounter(uint64_t &counter) const override {
        return entries_viewer_.getStackFrameCounter(counter);
    }

    void sortMethods(SortType type, bool asc) override {
        return entries_viewer_.sortMethods(type, asc);
    }

    bool getMethodId(Hash &id) const override {
        return entries_viewer_.getMethodId(id);
    }

    void sortStacks(SortType type, bool asc) override {
        return entries_viewer_.sortStacks(type, asc);
    }

    std::string& printMethods(std::string& dst) override {
        if (entries_viewer_.methodItFirst()) {
            dst.append("[REPORT:");
            dst.append(entries_viewer_.getReportName());
            dst.append("]\r\n");
            do {
                char const *name;
                uint64_t entries;
                uint64_t counter;
                Hash id;

                entries_viewer_.getMethodName(name);
                entries_viewer_.getMethodEntries(entries);
                entries_viewer_.getMethodCounter(counter);
                entries_viewer_.getMethodId(id);

                dst.append("\r\n\t[entries:");
                dst.append(std::to_string(entries));
                dst.append(", counters:");
                dst.append(std::to_string(counter));
                dst.append("  {");

                for (uint32_t pt = ReferencePointers::kRefPoint_0; pt < ReferencePointers::kRefPointsCount; ++pt) {
                    entries_viewer_.getMethodPointCounter(static_cast<ReferencePointers>(pt), counter);
                    dst.append(std::to_string(counter));
                    dst.append((pt == ReferencePointers::kRefPointsCount - 1) ? "" : ", ");
                }

                dst.append("} ]   [id:");
                dst.append(std::to_string(id));
                dst.append("]   ");
                dst.append(name);
            } while(entries_viewer_.methodItNext());
            dst.append("\r\n");
        }
        return dst;
    }

    std::string& printStacks(std::string& dst) override {
        if (entries_viewer_.stackItFirst()) {
            uint64_t entries;
            PerformanceCounter counter;
            char const *name;
            Hash id;

            dst.append("[REPORT:");
            dst.append(entries_viewer_.getReportName());
            dst.append("]\r\n");
            do {
                entries_viewer_.getStackFrameEntries(entries);
                entries_viewer_.getStackFrameCounter(counter);

                dst.append("\r\n\t[entries:");
                dst.append(std::to_string(entries));
                dst.append(", counter:");
                dst.append(std::to_string(counter));
                dst.append("]\r\n");

                size_t ix = 0;
                if (entries_viewer_.bindStackPosition()) {
                    do {
                        entries_viewer_.getStackFrameName(name, id);
                        dst.append("\t|");
                        dst.append(ix * 2, '-');
                        dst.append("[id:");
                        dst.append(std::to_string(id));
                        dst.append("] ");
                        dst.append(name);
                        dst.append("\r\n");
                        ++ix;
                    } while (entries_viewer_.unwindStack());
                }
            } while(entries_viewer_.stackItNext());
            dst.append("\r\n");
        }
        return dst;
    }

    IReportMethodIterator& getMethodIterator() override {
        return *this;
    }

    IReportStackIterator& getStackIterator()  override {
        return *this;
    }

    IReportThreadIterator& getThreadIterator()  override {
        return *this;
    }
};

} }

#endif//IROHA_PROFILER_REPORT_VIEWER_HPP

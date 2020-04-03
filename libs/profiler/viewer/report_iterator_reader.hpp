/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_PROFILER_REPORT_ITERATOR_READER_HPP
#define IROHA_PROFILER_REPORT_ITERATOR_READER_HPP

#include <optional>
#include <vector>
#include <algorithm>

namespace iroha { namespace performance_tools {

template<typename Container>
class ReportIteratorReader {
public:
    using Key = typename Container::key_type;
    using Value = typename Container::mapped_type;

public:
    using InternalContainer = std::vector<typename Container::value_type const*>;
    using Iterator = typename InternalContainer::const_iterator;

    std::optional<InternalContainer> data_;
    Iterator current_;
    Iterator end_;
    Iterator begin_;

    inline void fixupIterators() {
        if (!!data_) {
            end_ = data_->end();
            begin_ = data_->begin();
            current_ = begin_;
        }
    }

    inline void loadData(Container const *data) {
        if (nullptr != data) {
            InternalContainer _;
            for (auto const &value : *data) {
                _.emplace_back(&value);
            }
            data_.emplace(std::move(_));
        } else {
            data_.reset();
        }
        fixupIterators();
    }

public:
    ReportIteratorReader(ReportIteratorReader const&) = delete;
    ReportIteratorReader& operator=(ReportIteratorReader const&) = delete;

    ReportIteratorReader(Container const *data) {
        loadData(data);
    }

    ReportIteratorReader() {
        fixupIterators();
    }

    ReportIteratorReader& operator=(Container const *data) {
        loadData(data);
        return *this;
    }

    bool first() {
        if (!data_) { return false; }
        return ((current_ = begin_) != end_);
    }

    bool next() {
        if (!data_) { return false; }
        if (end_ != current_) {
            ++current_;
        }
        return (current_ != end_);
    }

    bool find(Key const& key) {
        if (!data_) { return false; }
        // TODO: fix complexity O(N)
        current_ = std::find_if(data_->begin(), data_->end(), [&key](auto const& value) {
            return value->first == key;
        });
        return (current_ != data_->end());
    }

    template<typename FuncPredicate>
    void sort(FuncPredicate&& f) {
        std::sort(data_->begin(), data_->end(), [f{std::move(f)}](auto const &l, auto const &r) {
            return f(l->second, r->second);
        });
    }

    bool key(Key& key) const {
        if (!data_ || end_ == current_) {
            return false;
        }
        key = (*current_)->first;
        return true;
    }

    template<typename FuncProp, typename Ret, typename...Args>
    bool get(FuncProp prop, Ret &value, Args&&...args) const {
        if (!data_ || end_ == current_) {
            return false;
        }
        value = (((*current_)->second).*prop)(std::forward<Args>(args)...);
        return true;
    }
};

} }

#endif//IROHA_PROFILER_REPORT_ITERATOR_READER_HPP

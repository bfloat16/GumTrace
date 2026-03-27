#ifndef TAINT_TAINTENGINE_H
#define TAINT_TAINTENGINE_H

#include "TraceParser.h"

#include <string>
#include <unordered_set>
#include <vector>

enum class TrackMode {
    FORWARD,
    BACKWARD
};

enum class StopReason {
    ALL_TAINT_CLEARED,
    END_OF_TRACE,
    SCAN_LIMIT_REACHED
};

struct TaintSource {
    RegId reg = REG_INVALID;
    uint64_t mem_addr = 0;
    bool is_mem = false;
};

class TaintEngine {
public:
    void set_mode(TrackMode mode) { mode_ = mode; }
    void set_source(const TaintSource &source);
    void set_max_scan_distance(int n) { max_scan_distance_ = n; }
    void run(const std::vector<TraceLine> &lines, int start_index);
    bool write_result(const std::string &output_path, const TraceParser &parser) const;
    StopReason stop_reason() const { return stop_reason_; }

private:
    TrackMode mode_ = TrackMode::FORWARD;
    TaintSource source_;
    StopReason stop_reason_ = StopReason::END_OF_TRACE;
    int max_scan_distance_ = 1000000;
    bool reg_taint_[256] = {};
    int tainted_reg_count_ = 0;
    std::unordered_set<uint64_t> tainted_mem_;

    struct ResultEntry {
        int index = 0;
        bool reg_snapshot[256] = {};
        std::unordered_set<uint64_t> mem_snapshot;
    };
    std::vector<ResultEntry> results_;

    inline void taint_reg(RegId id) {
        if (id == REG_INVALID) return;
        auto idx = static_cast<uint16_t>(TraceParser::normalize(id));
        if (!reg_taint_[idx]) {
            reg_taint_[idx] = true;
            tainted_reg_count_++;
        }
    }

    inline void untaint_reg(RegId id) {
        if (id == REG_INVALID) return;
        auto idx = static_cast<uint16_t>(TraceParser::normalize(id));
        if (reg_taint_[idx]) {
            reg_taint_[idx] = false;
            tainted_reg_count_--;
        }
    }

    inline bool is_reg_tainted(RegId id) const {
        if (id == REG_INVALID) return false;
        return reg_taint_[static_cast<uint16_t>(TraceParser::normalize(id))];
    }

    bool any_src_tainted(const TraceLine &line) const;
    bool any_dst_tainted(const TraceLine &line) const;
    void propagate_forward(const TraceLine &line);
    void propagate_backward(const TraceLine &line);
    void record(int index);
    int count_tainted_regs() const;
};

#endif // TAINT_TAINTENGINE_H

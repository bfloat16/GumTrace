#include "TaintEngine.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

bool TaintEngine::any_src_tainted(const TraceLine &line) const {
    for (int i = 0; i < line.num_src; i++) {
        if (is_reg_tainted(line.src_regs[i])) {
            return true;
        }
    }
    return line.has_mem_read && tainted_mem_.count(line.mem_read_addr) > 0;
}

bool TaintEngine::any_dst_tainted(const TraceLine &line) const {
    for (int i = 0; i < line.num_dst; i++) {
        if (is_reg_tainted(line.dst_regs[i])) {
            return true;
        }
    }
    return line.has_mem_write && tainted_mem_.count(line.mem_write_addr) > 0;
}

void TaintEngine::set_source(const TaintSource &source) {
    source_ = source;
    std::memset(reg_taint_, 0, sizeof(reg_taint_));
    tainted_reg_count_ = 0;
    tainted_mem_.clear();
    results_.clear();
    stop_reason_ = StopReason::END_OF_TRACE;

    if (source.is_mem) {
        tainted_mem_.insert(source.mem_addr);
    } else {
        taint_reg(source.reg);
    }
}

void TaintEngine::record(int index) {
    ResultEntry entry;
    entry.index = index;
    std::memcpy(entry.reg_snapshot, reg_taint_, sizeof(reg_taint_));
    entry.mem_snapshot = tainted_mem_;
    results_.push_back(std::move(entry));
}

int TaintEngine::count_tainted_regs() const {
    return tainted_reg_count_;
}

void TaintEngine::propagate_forward(const TraceLine &line) {
    bool src_tainted = any_src_tainted(line);
    bool has_source = line.num_src > 0 || line.has_mem_read;

    for (int i = 0; i < line.num_dst; i++) {
        if (src_tainted) taint_reg(line.dst_regs[i]);
        else untaint_reg(line.dst_regs[i]);
    }

    if (line.has_mem_write) {
        if (src_tainted) tainted_mem_.insert(line.mem_write_addr);
        else if (!has_source || !src_tainted) tainted_mem_.erase(line.mem_write_addr);
    }
}

void TaintEngine::propagate_backward(const TraceLine &line) {
    bool dst_tainted = any_dst_tainted(line);
    bool has_source = line.num_src > 0 || line.has_mem_read;
    if (!dst_tainted) {
        return;
    }

    for (int i = 0; i < line.num_dst; i++) {
        untaint_reg(line.dst_regs[i]);
    }
    if (line.has_mem_write) {
        tainted_mem_.erase(line.mem_write_addr);
    }

    if (!has_source) {
        return;
    }

    for (int i = 0; i < line.num_src; i++) {
        taint_reg(line.src_regs[i]);
    }
    if (line.has_mem_read) {
        tainted_mem_.insert(line.mem_read_addr);
    }
}

void TaintEngine::run(const std::vector<TraceLine> &lines, int start_index) {
    results_.clear();
    stop_reason_ = StopReason::END_OF_TRACE;

    if (mode_ == TrackMode::FORWARD) {
        record(start_index);
        int lines_since_last = 0;
        for (int i = start_index + 1; i < static_cast<int>(lines.size()); i++) {
            const auto &line = lines[i];
            bool involved = any_src_tainted(line) ||
                (line.has_mem_write && tainted_mem_.count(line.mem_write_addr) > 0);

            propagate_forward(line);

            if (involved) {
                record(i);
                lines_since_last = 0;
            } else if (++lines_since_last >= max_scan_distance_) {
                stop_reason_ = StopReason::SCAN_LIMIT_REACHED;
                break;
            }

            if (count_tainted_regs() == 0 && tainted_mem_.empty()) {
                stop_reason_ = StopReason::ALL_TAINT_CLEARED;
                break;
            }
        }
    } else {
        propagate_backward(lines[start_index]);
        record(start_index);

        int lines_since_last = 0;
        for (int i = start_index - 1; i >= 0; i--) {
            const auto &line = lines[i];
            bool involved = any_dst_tainted(line);
            if (involved) {
                propagate_backward(line);
                record(i);
                lines_since_last = 0;
            } else if (++lines_since_last >= max_scan_distance_) {
                stop_reason_ = StopReason::SCAN_LIMIT_REACHED;
                break;
            }

            if (count_tainted_regs() == 0 && tainted_mem_.empty()) {
                stop_reason_ = StopReason::ALL_TAINT_CLEARED;
                break;
            }
        }

        std::reverse(results_.begin(), results_.end());
    }
}

bool TaintEngine::write_result(const std::string &output_path, const TraceParser &parser) const {
    FILE *out = std::fopen(output_path.c_str(), "w");
    if (out == nullptr) {
        std::fprintf(stderr, "Error: cannot open output file: %s\n", output_path.c_str());
        return false;
    }

    FILE *src = std::fopen(parser.get_filepath().c_str(), "r");
    const auto &lines = parser.get_lines();

    std::fprintf(out, "=== Taint %s Tracking ===\n",
        mode_ == TrackMode::FORWARD ? "Forward" : "Backward");
    std::fprintf(out, "Source: ");
    if (source_.is_mem) std::fprintf(out, "mem:0x%llx", static_cast<unsigned long long>(source_.mem_addr));
    else std::fprintf(out, "%s", TraceParser::reg_name(source_.reg));
    std::fprintf(out, "\nTotal matched: %zu instructions\n", results_.size());

    switch (stop_reason_) {
        case StopReason::ALL_TAINT_CLEARED:
            std::fprintf(out, "Stop reason: all taint cleared\n");
            break;
        case StopReason::SCAN_LIMIT_REACHED:
            std::fprintf(out, "Stop reason: scan limit reached (%d lines without propagation)\n", max_scan_distance_);
            break;
        case StopReason::END_OF_TRACE:
            std::fprintf(out, "Stop reason: end of trace\n");
            break;
    }

    std::fprintf(out, "============================================================\n\n");

    char line_buf[4096];
    for (const auto &entry : results_) {
        const auto &tl = lines[entry.index];
        if (src != nullptr && tl.line_len > 0 && tl.line_len < static_cast<int>(sizeof(line_buf))) {
            std::fseek(src, tl.file_offset, SEEK_SET);
            int n = static_cast<int>(std::fread(line_buf, 1, tl.line_len, src));
            line_buf[n] = '\0';
            std::fprintf(out, "[%d] %s\n", tl.line_number, line_buf);
        } else {
            std::fprintf(out, "[%d] (line too long or read error)\n", tl.line_number);
        }

        std::fprintf(out, "      tainted: {");
        bool first = true;
        for (int i = 0; i < 256; i++) {
            if (entry.reg_snapshot[i]) {
                if (!first) std::fprintf(out, ", ");
                std::fprintf(out, "%s", TraceParser::reg_name(static_cast<RegId>(i)));
                first = false;
            }
        }
        for (const auto &m : entry.mem_snapshot) {
            if (!first) std::fprintf(out, ", ");
            std::fprintf(out, "mem:0x%llx", static_cast<unsigned long long>(m));
            first = false;
        }
        std::fprintf(out, "}\n\n");
    }

    if (src != nullptr) std::fclose(src);
    std::fclose(out);

    std::fprintf(stderr, "Result written to: %s (%zu instructions)\n", output_path.c_str(), results_.size());
    return true;
}

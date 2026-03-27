#include "TraceParser.h"

#include <algorithm>
#include <cctype>
#include <cstring>

uint64_t TraceParser::parse_hex_safe(const char *s, int len) {
    uint64_t val = 0;
    int start = (len > 16) ? (len - 16) : 0;
    for (int i = start; i < len; i++) {
        char c = s[i];
        uint64_t digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else break;
        val = (val << 4) | digit;
    }
    return val;
}

static bool parse_vector_reg(const char *s, int len, const char *prefix, RegId base, RegId &out) {
    int prefix_len = static_cast<int>(std::strlen(prefix));
    if (len <= prefix_len || std::memcmp(s, prefix, prefix_len) != 0) {
        return false;
    }

    int index = 0;
    for (int i = prefix_len; i < len; i++) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
            return false;
        }
        index = index * 10 + (s[i] - '0');
    }
    if (index < 0 || index > 31) {
        return false;
    }

    out = static_cast<RegId>(base + index);
    return true;
}

RegId TraceParser::parse_reg_name(const char *s, int len) {
    if (len <= 0) {
        return REG_INVALID;
    }

    if (len == 3) {
        if (std::memcmp(s, "rax", 3) == 0) return REG_RAX;
        if (std::memcmp(s, "rbx", 3) == 0) return REG_RBX;
        if (std::memcmp(s, "rcx", 3) == 0) return REG_RCX;
        if (std::memcmp(s, "rdx", 3) == 0) return REG_RDX;
        if (std::memcmp(s, "rsi", 3) == 0) return REG_RSI;
        if (std::memcmp(s, "rdi", 3) == 0) return REG_RDI;
        if (std::memcmp(s, "rbp", 3) == 0) return REG_RBP;
        if (std::memcmp(s, "rsp", 3) == 0) return REG_RSP;
        if (std::memcmp(s, "rip", 3) == 0) return REG_RIP;
    }

    if (len == 2 && s[0] == 'r' && s[1] >= '8' && s[1] <= '9') {
        return static_cast<RegId>(REG_R8 + (s[1] - '8'));
    }

    if (len == 3 && s[0] == 'r' && s[1] == '1' && s[2] >= '0' && s[2] <= '5') {
        return static_cast<RegId>(REG_R10 + (s[2] - '0'));
    }

    RegId out = REG_INVALID;
    if (parse_vector_reg(s, len, "xmm", REG_XMM0, out) ||
        parse_vector_reg(s, len, "ymm", REG_YMM0, out) ||
        parse_vector_reg(s, len, "zmm", REG_ZMM0, out)) {
        return out;
    }

    return REG_INVALID;
}

static const char *reg_names[] = {
    "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
    "r8","r9","r10","r11","r12","r13","r14","r15","rip",
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15",
    "xmm16","xmm17","xmm18","xmm19","xmm20","xmm21","xmm22","xmm23",
    "xmm24","xmm25","xmm26","xmm27","xmm28","xmm29","xmm30","xmm31",
    "ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7",
    "ymm8","ymm9","ymm10","ymm11","ymm12","ymm13","ymm14","ymm15",
    "ymm16","ymm17","ymm18","ymm19","ymm20","ymm21","ymm22","ymm23",
    "ymm24","ymm25","ymm26","ymm27","ymm28","ymm29","ymm30","ymm31",
    "zmm0","zmm1","zmm2","zmm3","zmm4","zmm5","zmm6","zmm7",
    "zmm8","zmm9","zmm10","zmm11","zmm12","zmm13","zmm14","zmm15",
    "zmm16","zmm17","zmm18","zmm19","zmm20","zmm21","zmm22","zmm23",
    "zmm24","zmm25","zmm26","zmm27","zmm28","zmm29","zmm30","zmm31"
};

const char *TraceParser::reg_name(RegId id) {
    if (id == REG_INVALID) {
        return "?";
    }
    size_t index = static_cast<size_t>(id);
    return index < (sizeof(reg_names) / sizeof(reg_names[0])) ? reg_names[index] : "?";
}

bool TraceParser::is_instruction_line(const char *buf, int len) {
    return len > 0 && buf[0] == '[';
}

static void append_reg(RegId *regs, uint8_t &count, size_t capacity, RegId reg) {
    if (reg == REG_INVALID) {
        return;
    }
    for (uint8_t i = 0; i < count; i++) {
        if (regs[i] == reg) {
            return;
        }
    }
    if (count < capacity) {
        regs[count++] = reg;
    }
}

static void parse_info_section(const char *section, int len, RegId *regs, uint8_t &count, size_t capacity,
    bool parse_mem, TraceLine &out) {
    auto parse_inline_hex = [] (const char *s, int n) -> uint64_t {
        uint64_t value = 0;
        int start = (n > 16) ? (n - 16) : 0;
        for (int idx = start; idx < n; idx++) {
            char c = s[idx];
            uint64_t digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else break;
            value = (value << 4) | digit;
        }
        return value;
    };

    for (int i = 0; i < len; i++) {
        if (i + 7 < len && std::memcmp(section + i, "mem_r=0x", 8) == 0) {
            i += 8;
            int start = i;
            while (i < len && std::isxdigit(static_cast<unsigned char>(section[i]))) i++;
            if (parse_mem) {
                out.has_mem_read = true;
                out.mem_read_addr = parse_inline_hex(section + start, i - start);
            }
            i--;
            continue;
        }

        if (i + 7 < len && std::memcmp(section + i, "mem_w=0x", 8) == 0) {
            i += 8;
            int start = i;
            while (i < len && std::isxdigit(static_cast<unsigned char>(section[i]))) i++;
            if (parse_mem) {
                out.has_mem_write = true;
                out.mem_write_addr = parse_inline_hex(section + start, i - start);
            }
            i--;
            continue;
        }

        if (!std::isalpha(static_cast<unsigned char>(section[i]))) {
            continue;
        }

        int start = i;
        while (i < len && (std::isalnum(static_cast<unsigned char>(section[i])) || section[i] == '_')) i++;
        int token_len = i - start;
        if (i < len && section[i] == '=' && i + 2 < len && section[i + 1] == '0' && section[i + 2] == 'x') {
            RegId reg = TraceParser::parse_reg_name(section + start, token_len);
            append_reg(regs, count, capacity, reg);
        }
    }
}

bool TraceParser::parse_line(const char *buf, int len, int line_number, long offset, TraceLine &out) {
    if (!is_instruction_line(buf, len)) {
        return false;
    }

    out.line_number = line_number;
    out.file_offset = offset;
    out.line_len = len;

    int i = 1;
    while (i < len && buf[i] != ']') i++;
    if (i >= len) return false;
    i++;
    while (i < len && buf[i] == ' ') i++;

    if (i + 2 >= len || buf[i] != '0' || buf[i + 1] != 'x') return false;
    i += 2;
    while (i < len && buf[i] != '!') i++;
    if (i >= len) return false;
    i++;
    if (i + 2 >= len || buf[i] != '0' || buf[i + 1] != 'x') return false;
    i += 2;
    int rel_start = i;
    while (i < len && buf[i] != ' ') i++;
    out.rel_addr = parse_hex_safe(buf + rel_start, i - rel_start);

    int semi_pos = -1;
    for (int j = i; j < len - 1; j++) {
        if (buf[j] == ';' && buf[j + 1] == ' ') {
            semi_pos = j;
            break;
        }
    }
    if (semi_pos < 0) {
        return true;
    }

    const char *info = buf + semi_pos + 2;
    int info_len = len - semi_pos - 2;
    const char *arrow = nullptr;
    for (int j = 0; j < info_len - 1; j++) {
        if (info[j] == '-' && info[j + 1] == '>') {
            arrow = info + j;
            break;
        }
    }

    if (arrow != nullptr) {
        int left_len = static_cast<int>(arrow - info);
        int right_len = info_len - left_len - 2;
        parse_info_section(info, left_len, out.src_regs, out.num_src, 16, true, out);
        parse_info_section(arrow + 2, right_len, out.dst_regs, out.num_dst, 8, false, out);
    } else {
        parse_info_section(info, info_len, out.src_regs, out.num_src, 16, true, out);
    }

    return true;
}

bool TraceParser::load(const std::string &filepath) {
    return load_range(filepath, INT32_MAX);
}

bool TraceParser::load_range_by_offset(const std::string &filepath, long max_offset) {
    filepath_ = filepath;
    lines_.clear();

    FILE *fp = std::fopen(filepath.c_str(), "r");
    if (fp == nullptr) {
        std::fprintf(stderr, "Error: cannot open file: %s\n", filepath.c_str());
        return false;
    }

    char buf[4096];
    int line_number = 0;
    long cur_offset = 0;
    while (cur_offset <= max_offset) {
        long line_start = cur_offset;
        if (std::fgets(buf, sizeof(buf), fp) == nullptr) break;
        line_number++;
        int len = static_cast<int>(std::strlen(buf));
        cur_offset += len;
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) len--;
        if (len == 0) continue;

        TraceLine tl = {};
        if (parse_line(buf, len, line_number, line_start, tl)) {
            lines_.push_back(tl);
        }
    }

    std::fclose(fp);
    std::fprintf(stderr, "Loaded %zu instruction lines from %d file lines (up to offset %ld).\n",
        lines_.size(), line_number, max_offset);
    return true;
}

bool TraceParser::load_range(const std::string &filepath, int max_line) {
    filepath_ = filepath;
    lines_.clear();

    FILE *fp = std::fopen(filepath.c_str(), "r");
    if (fp == nullptr) {
        std::fprintf(stderr, "Error: cannot open file: %s\n", filepath.c_str());
        return false;
    }

    char buf[4096];
    int line_number = 0;
    long cur_offset = 0;
    while (line_number < max_line) {
        long line_start = cur_offset;
        if (std::fgets(buf, sizeof(buf), fp) == nullptr) break;
        line_number++;
        int len = static_cast<int>(std::strlen(buf));
        cur_offset += len;
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) len--;
        if (len == 0) continue;

        TraceLine tl = {};
        if (parse_line(buf, len, line_number, line_start, tl)) {
            lines_.push_back(tl);
        }
    }

    std::fclose(fp);
    std::fprintf(stderr, "Loaded %zu instruction lines from %d file lines.\n", lines_.size(), line_number);
    return true;
}

int TraceParser::find_by_rel_addr(uint64_t rel_addr) const {
    for (size_t i = 0; i < lines_.size(); i++) {
        if (lines_[i].rel_addr == rel_addr) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int TraceParser::find_by_offset(long byte_offset) const {
    int lo = 0;
    int hi = static_cast<int>(lines_.size()) - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (lines_[mid].file_offset < byte_offset) lo = mid + 1;
        else if (lines_[mid].file_offset > byte_offset) hi = mid - 1;
        else return mid;
    }
    return lo < static_cast<int>(lines_.size()) ? lo : -1;
}

int TraceParser::find_by_line(int line_number) const {
    int lo = 0;
    int hi = static_cast<int>(lines_.size()) - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (lines_[mid].line_number < line_number) lo = mid + 1;
        else if (lines_[mid].line_number > line_number) hi = mid - 1;
        else return mid;
    }
    return lo < static_cast<int>(lines_.size()) ? lo : -1;
}

std::string TraceParser::read_raw_line(const TraceLine &tl) const {
    if (tl.file_offset < 0 || tl.line_len <= 0) {
        return "";
    }
    FILE *fp = std::fopen(filepath_.c_str(), "r");
    if (fp == nullptr) {
        return "";
    }
    std::fseek(fp, tl.file_offset, SEEK_SET);
    std::string result(tl.line_len, '\0');
    size_t read = std::fread(&result[0], 1, tl.line_len, fp);
    result.resize(read);
    std::fclose(fp);
    return result;
}

#ifndef TAINT_TRACEPARSER_H
#define TAINT_TRACEPARSER_H

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

enum RegId : uint16_t {
    REG_RAX = 0, REG_RBX, REG_RCX, REG_RDX,
    REG_RSI, REG_RDI, REG_RBP, REG_RSP,
    REG_R8, REG_R9, REG_R10, REG_R11,
    REG_R12, REG_R13, REG_R14, REG_R15,
    REG_RIP,
    REG_XMM0, REG_XMM1, REG_XMM2, REG_XMM3, REG_XMM4, REG_XMM5, REG_XMM6, REG_XMM7,
    REG_XMM8, REG_XMM9, REG_XMM10, REG_XMM11, REG_XMM12, REG_XMM13, REG_XMM14, REG_XMM15,
    REG_XMM16, REG_XMM17, REG_XMM18, REG_XMM19, REG_XMM20, REG_XMM21, REG_XMM22, REG_XMM23,
    REG_XMM24, REG_XMM25, REG_XMM26, REG_XMM27, REG_XMM28, REG_XMM29, REG_XMM30, REG_XMM31,
    REG_YMM0, REG_YMM1, REG_YMM2, REG_YMM3, REG_YMM4, REG_YMM5, REG_YMM6, REG_YMM7,
    REG_YMM8, REG_YMM9, REG_YMM10, REG_YMM11, REG_YMM12, REG_YMM13, REG_YMM14, REG_YMM15,
    REG_YMM16, REG_YMM17, REG_YMM18, REG_YMM19, REG_YMM20, REG_YMM21, REG_YMM22, REG_YMM23,
    REG_YMM24, REG_YMM25, REG_YMM26, REG_YMM27, REG_YMM28, REG_YMM29, REG_YMM30, REG_YMM31,
    REG_ZMM0, REG_ZMM1, REG_ZMM2, REG_ZMM3, REG_ZMM4, REG_ZMM5, REG_ZMM6, REG_ZMM7,
    REG_ZMM8, REG_ZMM9, REG_ZMM10, REG_ZMM11, REG_ZMM12, REG_ZMM13, REG_ZMM14, REG_ZMM15,
    REG_ZMM16, REG_ZMM17, REG_ZMM18, REG_ZMM19, REG_ZMM20, REG_ZMM21, REG_ZMM22, REG_ZMM23,
    REG_ZMM24, REG_ZMM25, REG_ZMM26, REG_ZMM27, REG_ZMM28, REG_ZMM29, REG_ZMM30, REG_ZMM31,
    REG_INVALID = 0xffff
};

struct TraceLine {
    int line_number = 0;
    uint8_t num_dst = 0;
    uint8_t num_src = 0;
    RegId dst_regs[8] = {};
    RegId src_regs[16] = {};
    uint64_t mem_read_addr = 0;
    uint64_t mem_write_addr = 0;
    uint64_t rel_addr = 0;
    bool has_mem_read = false;
    bool has_mem_write = false;
    long file_offset = 0;
    int line_len = 0;
};

class TraceParser {
public:
    bool load(const std::string &filepath);
    bool load_range(const std::string &filepath, int max_line);
    bool load_range_by_offset(const std::string &filepath, long max_offset);

    const std::vector<TraceLine> &get_lines() const { return lines_; }
    size_t size() const { return lines_.size(); }
    const std::string &get_filepath() const { return filepath_; }

    int find_by_rel_addr(uint64_t rel_addr) const;
    int find_by_line(int line_number) const;
    int find_by_offset(long byte_offset) const;
    std::string read_raw_line(const TraceLine &tl) const;

    static const char *reg_name(RegId id);
    static RegId parse_reg_name(const char *s, int len);
    static RegId normalize(RegId id) { return id; }

private:
    std::vector<TraceLine> lines_;
    std::string filepath_;

    bool parse_line(const char *buf, int len, int line_number, long offset, TraceLine &out);
    static uint64_t parse_hex_safe(const char *s, int len);
    static bool is_instruction_line(const char *buf, int len);
};

#endif // TAINT_TRACEPARSER_H

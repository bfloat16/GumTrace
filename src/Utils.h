//
// Created by lidongyooo on 2026/2/6.
//

#ifndef GUMTRACE_UTILS_H
#define GUMTRACE_UTILS_H

#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/stat.h>

#include "platform.h"
#include <frida-gum.h>

#define LOG_TAG "gumtrace"
#define LOGE(fmt, ...)                                                                                                                                                                                 \
    do {                                                                                                                                                                                               \
        std::fprintf(stderr, "[" LOG_TAG "] " fmt "\n", ##__VA_ARGS__);                                                                                                                                \
        std::fflush(stderr);                                                                                                                                                                           \
    } while (0)

#define PAGE_SIZE 4096
#define GUMTRACE_BUFFER_SIZE (1024 * 1024 * 50)

extern const std::vector<std::string> windows_module_allowlist;

class Utils {
  public:
    static std::vector<std::string> str_split(const std::string &s, char symbol);
    static bool is_atomic_instruction(const cs_insn *insn);
    static bool get_register_value(x86_reg reg, const GumX64CpuContext *ctx, uint64_t &value);
    static bool get_memory_operand_address(const cs_insn *insn, const cs_x86_op &op, const GumX64CpuContext *ctx, uint64_t &address);
    static const char *normalize_register_name(x86_reg reg);
    static void append_uint64_hex(char *buff, int &counter, uint64_t val);
    static void auto_snprintf(int &counter, char *buff, const char *__restrict format, ...);
    static bool file_stat(const char *path, uint64_t &size_bytes);

    static inline void append_string(char *buff, int &counter, const char *str) {
        if (str == nullptr) {
            return;
        }
        while (*str != '\0') {
            buff[counter++] = *str++;
        }
    }

    static inline void append_char(char *buff, int &counter, char c) { buff[counter++] = c; }
};

#endif // GUMTRACE_UTILS_H

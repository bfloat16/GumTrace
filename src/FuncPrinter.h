//
// Created by lidongyooo on 2026/2/6.
//

#ifndef GUMTRACE_FUNCPRINTER_H
#define GUMTRACE_FUNCPRINTER_H

#include <functional>
#include <unordered_set>

#include "GumTrace.h"
#include "Utils.h"

class FuncPrinter {
  public:
    static void before(FUNC_CONTEXT *func_context);
    static void after(FUNC_CONTEXT *func_context, GumCpuContext *curr_cpu_context);
    static void params_join(FUNC_CONTEXT *func_context, uint32_t count);
    static void read_string(int &buff_n, char *buff, const char *str, size_t max_len = 1024);
    static void hexdump(int &buff_n, char *buff, uint64_t address, size_t count);
};

typedef enum {
    STR_INDEX_ZERO = 0,
    STR_INDEX_ONE = 1,
    STR_INDEX_TWO = 2,
    STR_INDEX_THREE = 3,
    STR_INDEX_FOUR = 4,
    STR_INDEX_FIVE = 5,
    STR_INDEX_SIX = 6,
    STR_INDEX_SEVEN = 7,
} StrEnum;

typedef enum {
    HEX_INDEX_ZERO = 0,
    HEX_INDEX_ONE = 1,
    HEX_INDEX_TWO = 2,
    HEX_INDEX_THREE = 3,
    HEX_INDEX_FOUR = 4,
    HEX_INDEX_FIVE = 5,
    HEX_INDEX_SIX = 6,
    HEX_INDEX_SEVEN = 7,
    HEX_INDEX_SPECIAL_32 = 32,
} HexEnum;

typedef enum {
    PARAMS_NUMBER_ZERO = 0,
    PARAMS_NUMBER_ONE = 1,
    PARAMS_NUMBER_TWO = 2,
    PARAMS_NUMBER_THREE = 3,
    PARAMS_NUMBER_FOUR = 4,
    PARAMS_NUMBER_FIVE = 5,
    PARAMS_NUMBER_SIX = 6,
    PARAMS_NUMBER_SEVEN = 7,
} ParamsNumberEnum;

using HexRegisterPair = std::array<HexEnum, 2>;
struct BeforeFuncConfig {
    int params_number;
    std::vector<int> string_indices;
    std::vector<std::array<int, 2>> hexdump_indices;
    std::function<void(FUNC_CONTEXT *)> special_handler;

    BeforeFuncConfig(ParamsNumberEnum params = PARAMS_NUMBER_ZERO, std::initializer_list<StrEnum> str_idx = {}, std::initializer_list<HexRegisterPair> hex_idx = {},
                     std::function<void(FUNC_CONTEXT *)> handler = nullptr)
        : params_number(static_cast<int>(params)), special_handler(std::move(handler)) {
        for (auto idx : str_idx) {
            string_indices.push_back(static_cast<int>(idx));
        }
        for (const auto &pair : hex_idx) {
            hexdump_indices.push_back({static_cast<int>(pair[0]), static_cast<int>(pair[1])});
        }
    }
};

extern const std::unordered_map<std::string, BeforeFuncConfig> func_configs;

#endif // GUMTRACE_FUNCPRINTER_H

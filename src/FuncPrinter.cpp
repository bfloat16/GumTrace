//
// Created by lidongyooo on 2026/2/6.
//

#include "FuncPrinter.h"

#include <cctype>

static uint64_t get_arg(const GumCpuContext *cpu_context, uint32_t index) {
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(gum_cpu_context_get_nth_argument(const_cast<GumCpuContext *>(cpu_context), index)));
}

static uint64_t get_return_value(const GumCpuContext *cpu_context) {
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(gum_cpu_context_get_return_value(const_cast<GumCpuContext *>(cpu_context))));
}

const std::unordered_map<std::string, BeforeFuncConfig> func_configs = {
    {"strstr",           {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                     },
    {"strlen",           {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}                                                    },
    {"strcmp",           {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                     },
    {"strncmp",          {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                   },
    {"strcpy",           {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                     },
    {"strncpy",          {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                   },
    {"strcat",           {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                     },
    {"strncat",          {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                   },
    {"strdup",           {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}                                                    },
    {"strchr",           {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}                                                    },
    {"strrchr",          {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}                                                    },
    {"memcpy",           {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}                                  },
    {"memmove",          {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}                                  },
    {"memset",           {PARAMS_NUMBER_THREE, {}, {}}                                                                },
    {"memmem",           {PARAMS_NUMBER_FOUR, {}, {{HEX_INDEX_ZERO, HEX_INDEX_ONE}, {HEX_INDEX_TWO, HEX_INDEX_THREE}}}},
    {"memcmp",           {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ZERO, HEX_INDEX_TWO}, {HEX_INDEX_ONE, HEX_INDEX_TWO}}} },
    {"memchr",           {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ZERO, HEX_INDEX_TWO}}}                                 },
    {"fopen",            {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                     },
    {"read",             {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}                                  },
    {"open",             {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}                                                    },
    {"close",            {PARAMS_NUMBER_ONE, {}, {}}                                                                  },
    {"write",            {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}                                  },
    {"stat",             {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}                                                    },
    {"CreateFileA",      {PARAMS_NUMBER_FIVE, {STR_INDEX_ZERO}, {}}                                                   },
    {"CreateFileW",      {PARAMS_NUMBER_FIVE, {}, {}}                                                                 },
    {"LoadLibraryA",     {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}                                                    },
    {"LoadLibraryW",     {PARAMS_NUMBER_ONE, {}, {}}                                                                  },
    {"GetProcAddress",   {PARAMS_NUMBER_TWO, {STR_INDEX_ONE}, {}}                                                     },
    {"sprintf",          {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                     },
    {"snprintf",         {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO, STR_INDEX_TWO}, {}}                                   },
    {"vsprintf",         {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}                                                    },
    {"vsnprintf",        {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}                                                  },
    {"fgets",            {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}                                                  },
    {"sscanf",           {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}                                     },
    {"calloc",           {PARAMS_NUMBER_TWO, {}, {}}                                                                  },
    {"malloc",           {PARAMS_NUMBER_ONE, {}, {}}                                                                  },
    {"realloc",          {PARAMS_NUMBER_TWO, {}, {{HEX_INDEX_ZERO, HEX_INDEX_SPECIAL_32}}}                            },
    {"free",             {PARAMS_NUMBER_ONE, {}, {{HEX_INDEX_ZERO, HEX_INDEX_SPECIAL_32}}}                            },
    {"VirtualAlloc",     {PARAMS_NUMBER_FOUR, {}, {}}                                                                 },
    {"VirtualProtect",   {PARAMS_NUMBER_FOUR, {}, {}}                                                                 },
    {"GetModuleHandleA", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}                                                    },
    {"GetModuleHandleW", {PARAMS_NUMBER_ONE, {}, {}}                                                                  }
};

void FuncPrinter::params_join(FUNC_CONTEXT *func_context, uint32_t count) {
    func_context->info[func_context->info_n++] = '(';
    for (uint32_t i = 0; i < count; i++) {
        Utils::auto_snprintf(func_context->info_n, func_context->info, "0x%llx", static_cast<unsigned long long>(get_arg(&func_context->cpu_context, i)));
        if (i + 1 != count) {
            func_context->info[func_context->info_n++] = ',';
            func_context->info[func_context->info_n++] = ' ';
        }
    }
    func_context->info[func_context->info_n++] = ')';
}

void FuncPrinter::read_string(int &buff_n, char *buff, const char *str, size_t max_len) {
    if (str == nullptr || reinterpret_cast<uintptr_t>(str) <= 0x1000) {
        return;
    }

    auto *instance = GumTrace::get_instance();
    if (instance->options.mode == GUM_OPTIONS_MODE_STABLE && instance->find_range_by_address(reinterpret_cast<uintptr_t>(str)) == nullptr) {
        return;
    }

    size_t i = 0;
    while (i < max_len && buff_n < GUMTRACE_BUFFER_SIZE - 1 && str[i] != '\0') {
        char c = str[i++];
        buff[buff_n++] = std::isprint(static_cast<unsigned char>(c)) ? c : '.';
    }
}

void FuncPrinter::hexdump(int &buff_n, char *buff, uint64_t address, size_t count) {
    Utils::auto_snprintf(buff_n, buff, "\nhexdump at address 0x%llx with length 0x%llx:\n", static_cast<unsigned long long>(address), static_cast<unsigned long long>(count));

    if (address < 0x10000) {
        return;
    }

    auto *instance = GumTrace::get_instance();
    if (instance->options.mode == GUM_OPTIONS_MODE_STABLE && instance->find_range_by_address(static_cast<uintptr_t>(address)) == nullptr) {
        return;
    }

    auto *byte_ptr = reinterpret_cast<const unsigned char *>(address);
    if (count == 0) {
        while (count < 4096 && byte_ptr[count] != '\0') {
            count++;
        }
    }

    size_t offset = 0;
    while (offset < count) {
        Utils::auto_snprintf(buff_n, buff, "%llx: ", static_cast<unsigned long long>(address + offset));

        char ascii[20];
        int ascii_n = 0;
        ascii[ascii_n++] = '|';
        for (size_t i = 0; i < 16; i++) {
            if (offset + i < count) {
                unsigned char byte = byte_ptr[offset + i];
                Utils::auto_snprintf(buff_n, buff, "%02x ", byte);
                ascii[ascii_n++] = std::isprint(byte) ? static_cast<char>(byte) : '.';
            } else {
                Utils::append_string(buff, buff_n, "   ");
                ascii[ascii_n++] = ' ';
            }
        }
        ascii[ascii_n++] = '|';
        ascii[ascii_n] = '\0';
        Utils::auto_snprintf(buff_n, buff, "%s", ascii);

        offset += 16;
        if (offset < count) {
            Utils::append_char(buff, buff_n, '\n');
        }
    }
}

void FuncPrinter::before(FUNC_CONTEXT *func_context) {
    Utils::auto_snprintf(func_context->info_n, func_context->info, "call func: %s", func_context->name);

    auto *instance = GumTrace::get_instance();
    if (instance->options.mode == GUM_OPTIONS_MODE_DEBUG) {
        LOGE("call func: %s", func_context->name);
    }

    auto it = func_configs.find(func_context->name);
    if (it == func_configs.end()) {
        params_join(func_context, 4);
        func_context->info[func_context->info_n++] = '\n';
        return;
    }

    const auto &config = it->second;
    params_join(func_context, config.params_number);

    if (config.special_handler) {
        config.special_handler(func_context);
        return;
    }

    for (int idx : config.string_indices) {
        Utils::auto_snprintf(func_context->info_n, func_context->info, "\nargs%d: ", idx);
        read_string(func_context->info_n, func_context->info, reinterpret_cast<const char *>(get_arg(&func_context->cpu_context, static_cast<uint32_t>(idx))));
    }

    for (const auto &reg_pair : config.hexdump_indices) {
        uint64_t address = get_arg(&func_context->cpu_context, static_cast<uint32_t>(reg_pair[0]));
        size_t size = reg_pair[1] == HEX_INDEX_SPECIAL_32 ? 0 : static_cast<size_t>(get_arg(&func_context->cpu_context, static_cast<uint32_t>(reg_pair[1])));
        hexdump(func_context->info_n, func_context->info, address, size);
    }

    func_context->info[func_context->info_n++] = '\n';
}

void FuncPrinter::after(FUNC_CONTEXT *func_context, GumCpuContext *curr_cpu_context) {
    Utils::append_string(func_context->info, func_context->info_n, "ret: 0x");
    Utils::append_uint64_hex(func_context->info, func_context->info_n, get_return_value(curr_cpu_context));
    func_context->info[func_context->info_n++] = '\n';
}

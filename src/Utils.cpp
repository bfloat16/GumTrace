//
// Created by lidongyooo on 2026/2/6.
//

#include "Utils.h"

#include <frida-gum.h>

#include <algorithm>

const std::vector<std::string> windows_module_allowlist = {"kernel32.dll", "kernelbase.dll", "ntdll.dll", "ucrtbase.dll", "msvcrt.dll"};

std::vector<std::string> Utils::str_split(const std::string &s, char symbol) {
    std::vector<std::string> result;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t next = s.find(symbol, pos);
        if (next == std::string::npos) {
            next = s.size();
        }
        if (next > pos) {
            result.push_back(s.substr(pos, next - pos));
        }
        pos = next + 1;
    }
    return result;
}

bool Utils::is_atomic_instruction(const cs_insn *insn) {
    if (insn == nullptr || insn->detail == nullptr) {
        return false;
    }

    const cs_x86 &x86 = insn->detail->x86;
    for (uint8_t prefix : x86.prefix) {
        if (prefix == X86_PREFIX_LOCK) {
            return true;
        }
    }
    return false;
}

static bool get_register_family_value(const GumX64CpuContext *ctx, x86_reg reg, uint64_t &value) {
    switch (reg) {
    case X86_REG_RAX:
    case X86_REG_EAX:
    case X86_REG_AX:
    case X86_REG_AH:
    case X86_REG_AL:
        value = ctx->rax;
        return true;
    case X86_REG_RBX:
    case X86_REG_EBX:
    case X86_REG_BX:
    case X86_REG_BH:
    case X86_REG_BL:
        value = ctx->rbx;
        return true;
    case X86_REG_RCX:
    case X86_REG_ECX:
    case X86_REG_CX:
    case X86_REG_CH:
    case X86_REG_CL:
        value = ctx->rcx;
        return true;
    case X86_REG_RDX:
    case X86_REG_EDX:
    case X86_REG_DX:
    case X86_REG_DH:
    case X86_REG_DL:
        value = ctx->rdx;
        return true;
    case X86_REG_RSI:
    case X86_REG_ESI:
    case X86_REG_SI:
    case X86_REG_SIL:
        value = ctx->rsi;
        return true;
    case X86_REG_RDI:
    case X86_REG_EDI:
    case X86_REG_DI:
    case X86_REG_DIL:
        value = ctx->rdi;
        return true;
    case X86_REG_RBP:
    case X86_REG_EBP:
    case X86_REG_BP:
    case X86_REG_BPL:
        value = ctx->rbp;
        return true;
    case X86_REG_RSP:
    case X86_REG_ESP:
    case X86_REG_SP:
    case X86_REG_SPL:
        value = ctx->rsp;
        return true;
    case X86_REG_R8:
    case X86_REG_R8D:
    case X86_REG_R8W:
    case X86_REG_R8B:
        value = ctx->r8;
        return true;
    case X86_REG_R9:
    case X86_REG_R9D:
    case X86_REG_R9W:
    case X86_REG_R9B:
        value = ctx->r9;
        return true;
    case X86_REG_R10:
    case X86_REG_R10D:
    case X86_REG_R10W:
    case X86_REG_R10B:
        value = ctx->r10;
        return true;
    case X86_REG_R11:
    case X86_REG_R11D:
    case X86_REG_R11W:
    case X86_REG_R11B:
        value = ctx->r11;
        return true;
    case X86_REG_R12:
    case X86_REG_R12D:
    case X86_REG_R12W:
    case X86_REG_R12B:
        value = ctx->r12;
        return true;
    case X86_REG_R13:
    case X86_REG_R13D:
    case X86_REG_R13W:
    case X86_REG_R13B:
        value = ctx->r13;
        return true;
    case X86_REG_R14:
    case X86_REG_R14D:
    case X86_REG_R14W:
    case X86_REG_R14B:
        value = ctx->r14;
        return true;
    case X86_REG_R15:
    case X86_REG_R15D:
    case X86_REG_R15W:
    case X86_REG_R15B:
        value = ctx->r15;
        return true;
    case X86_REG_RIP:
    case X86_REG_EIP:
    case X86_REG_IP:
        value = ctx->rip;
        return true;
    default:
        return false;
    }
}

bool Utils::get_register_value(x86_reg reg, const GumX64CpuContext *ctx, uint64_t &value) {
    if (ctx == nullptr) {
        return false;
    }

    uint64_t raw = 0;
    if (!get_register_family_value(ctx, reg, raw)) {
        return false;
    }

    switch (reg) {
    case X86_REG_EAX:
    case X86_REG_EBX:
    case X86_REG_ECX:
    case X86_REG_EDX:
    case X86_REG_ESI:
    case X86_REG_EDI:
    case X86_REG_EBP:
    case X86_REG_ESP:
    case X86_REG_R8D:
    case X86_REG_R9D:
    case X86_REG_R10D:
    case X86_REG_R11D:
    case X86_REG_R12D:
    case X86_REG_R13D:
    case X86_REG_R14D:
    case X86_REG_R15D:
    case X86_REG_EIP:
        value = raw & 0xffffffffULL;
        return true;
    case X86_REG_AX:
    case X86_REG_BX:
    case X86_REG_CX:
    case X86_REG_DX:
    case X86_REG_SI:
    case X86_REG_DI:
    case X86_REG_BP:
    case X86_REG_SP:
    case X86_REG_R8W:
    case X86_REG_R9W:
    case X86_REG_R10W:
    case X86_REG_R11W:
    case X86_REG_R12W:
    case X86_REG_R13W:
    case X86_REG_R14W:
    case X86_REG_R15W:
    case X86_REG_IP:
        value = raw & 0xffffULL;
        return true;
    case X86_REG_AL:
    case X86_REG_BL:
    case X86_REG_CL:
    case X86_REG_DL:
    case X86_REG_SIL:
    case X86_REG_DIL:
    case X86_REG_BPL:
    case X86_REG_SPL:
    case X86_REG_R8B:
    case X86_REG_R9B:
    case X86_REG_R10B:
    case X86_REG_R11B:
    case X86_REG_R12B:
    case X86_REG_R13B:
    case X86_REG_R14B:
    case X86_REG_R15B:
        value = raw & 0xffULL;
        return true;
    case X86_REG_AH:
    case X86_REG_BH:
    case X86_REG_CH:
    case X86_REG_DH:
        value = (raw >> 8) & 0xffULL;
        return true;
    default:
        value = raw;
        return true;
    }
}

bool Utils::get_memory_operand_address(const cs_insn *insn, const cs_x86_op &op, const GumX64CpuContext *ctx, uint64_t &address) {
    if (insn == nullptr || ctx == nullptr || op.type != X86_OP_MEM) {
        return false;
    }

    int64_t effective = op.mem.disp;
    uint64_t base_value = 0;
    uint64_t index_value = 0;

    if (op.mem.base != X86_REG_INVALID) {
        if (op.mem.base == X86_REG_RIP) {
            effective += static_cast<int64_t>(insn->address + insn->size);
        } else if (get_register_value(static_cast<x86_reg>(op.mem.base), ctx, base_value)) {
            effective += static_cast<int64_t>(base_value);
        }
    }

    if (op.mem.index != X86_REG_INVALID && get_register_value(static_cast<x86_reg>(op.mem.index), ctx, index_value)) {
        effective += static_cast<int64_t>(index_value * op.mem.scale);
    }

    address = static_cast<uint64_t>(effective);
    return true;
}

const char *Utils::normalize_register_name(x86_reg reg) {
    switch (reg) {
    case X86_REG_RAX:
    case X86_REG_EAX:
    case X86_REG_AX:
    case X86_REG_AH:
    case X86_REG_AL:
        return "rax";
    case X86_REG_RBX:
    case X86_REG_EBX:
    case X86_REG_BX:
    case X86_REG_BH:
    case X86_REG_BL:
        return "rbx";
    case X86_REG_RCX:
    case X86_REG_ECX:
    case X86_REG_CX:
    case X86_REG_CH:
    case X86_REG_CL:
        return "rcx";
    case X86_REG_RDX:
    case X86_REG_EDX:
    case X86_REG_DX:
    case X86_REG_DH:
    case X86_REG_DL:
        return "rdx";
    case X86_REG_RSI:
    case X86_REG_ESI:
    case X86_REG_SI:
    case X86_REG_SIL:
        return "rsi";
    case X86_REG_RDI:
    case X86_REG_EDI:
    case X86_REG_DI:
    case X86_REG_DIL:
        return "rdi";
    case X86_REG_RBP:
    case X86_REG_EBP:
    case X86_REG_BP:
    case X86_REG_BPL:
        return "rbp";
    case X86_REG_RSP:
    case X86_REG_ESP:
    case X86_REG_SP:
    case X86_REG_SPL:
        return "rsp";
    case X86_REG_R8:
    case X86_REG_R8D:
    case X86_REG_R8W:
    case X86_REG_R8B:
        return "r8";
    case X86_REG_R9:
    case X86_REG_R9D:
    case X86_REG_R9W:
    case X86_REG_R9B:
        return "r9";
    case X86_REG_R10:
    case X86_REG_R10D:
    case X86_REG_R10W:
    case X86_REG_R10B:
        return "r10";
    case X86_REG_R11:
    case X86_REG_R11D:
    case X86_REG_R11W:
    case X86_REG_R11B:
        return "r11";
    case X86_REG_R12:
    case X86_REG_R12D:
    case X86_REG_R12W:
    case X86_REG_R12B:
        return "r12";
    case X86_REG_R13:
    case X86_REG_R13D:
    case X86_REG_R13W:
    case X86_REG_R13B:
        return "r13";
    case X86_REG_R14:
    case X86_REG_R14D:
    case X86_REG_R14W:
    case X86_REG_R14B:
        return "r14";
    case X86_REG_R15:
    case X86_REG_R15D:
    case X86_REG_R15W:
    case X86_REG_R15B:
        return "r15";
    case X86_REG_RIP:
    case X86_REG_EIP:
    case X86_REG_IP:
        return "rip";
    default:
        return nullptr;
    }
}

static const char hex_chars[] = "0123456789abcdef";

void Utils::append_uint64_hex(char *buff, int &counter, uint64_t val) {
    if (val == 0) {
        buff[counter++] = '0';
        return;
    }

    char temp[16];
    int index = 0;
    while (val != 0) {
        temp[index++] = hex_chars[val & 0xf];
        val >>= 4;
    }
    while (index > 0) {
        buff[counter++] = temp[--index];
    }
}

void Utils::auto_snprintf(int &counter, char *buff, const char *__restrict format, ...) {
    if (buff == nullptr || format == nullptr) {
        return;
    }

    int remaining = GUMTRACE_BUFFER_SIZE - counter;
    if (remaining <= 0) {
        return;
    }

    va_list args;
    va_start(args, format);
    int written = std::vsnprintf(buff + counter, remaining, format, args);
    va_end(args);
    if (written > 0) {
        counter += (written < remaining) ? written : remaining - 1;
    }
}

bool Utils::file_stat(const char *path, uint64_t &size_bytes) {
    if (path == nullptr) {
        return false;
    }

    struct _stat64 st = {};
    if (_stat64(path, &st) != 0) {
        return false;
    }

    size_bytes = static_cast<uint64_t>(st.st_size);
    return true;
}

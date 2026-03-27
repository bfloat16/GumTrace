//
// Created by lidongyooo on 2026/2/6.
//

#include "GumTrace.h"

#include "FuncPrinter.h"

#include <algorithm>
#include <cctype>
#include <chrono>

static std::string to_lower_copy(const std::string &value) {
    std::string result = value;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

GumTrace *GumTrace::get_instance() {
    static GumTrace instance;
    return &instance;
}

GumTrace::GumTrace() {
    _transformer = gum_stalker_transformer_make_from_callback(transform_callback, nullptr, nullptr);
    callback_context_instance = CallbackContext::get_instance();
}

GumTrace::~GumTrace() {
    stop_flush_thread();
    if (_stalker != nullptr) {
        g_object_unref(_stalker);
    }
    if (_transformer != nullptr) {
        g_object_unref(_transformer);
    }
}

static bool append_logged_register(char *buff, int &buff_n, const GumCpuContext *cpu_context, csh handle, x86_reg reg) {
    const char *reg_name = Utils::normalize_register_name(reg);
    if (reg_name == nullptr) {
        reg_name = cs_reg_name(handle, reg);
    }

    uint64_t reg_value = 0;
    if (reg_name == nullptr || !Utils::get_register_value(reg, reinterpret_cast<const GumX64CpuContext *>(cpu_context), reg_value)) {
        return false;
    }

    Utils::append_string(buff, buff_n, reg_name);
    Utils::append_string(buff, buff_n, "=0x");
    Utils::append_uint64_hex(buff, buff_n, reg_value);
    Utils::append_char(buff, buff_n, ' ');
    return true;
}

static bool resolve_indirect_call_target(const cs_insn *insn, const cs_x86_op &op, const GumCpuContext *cpu_context, uint64_t &jump_addr) {
    if (op.type == X86_OP_REG) {
        return Utils::get_register_value(static_cast<x86_reg>(op.reg), reinterpret_cast<const GumX64CpuContext *>(cpu_context), jump_addr);
    }

    if (op.type != X86_OP_MEM) {
        return false;
    }

    uint64_t slot_address = 0;
    if (!Utils::get_memory_operand_address(insn, op, reinterpret_cast<const GumX64CpuContext *>(cpu_context), slot_address)) {
        return false;
    }

    if (!gum_memory_is_readable(reinterpret_cast<gconstpointer>(slot_address), sizeof(gpointer))) {
        return false;
    }

    gsize bytes_read = 0;
    guint8 *data = gum_memory_read(reinterpret_cast<gconstpointer>(slot_address), sizeof(gpointer), &bytes_read);
    if (data == nullptr || bytes_read < sizeof(gpointer)) {
        if (data != nullptr) {
            g_free(data);
        }
        return false;
    }

    std::memcpy(&jump_addr, data, sizeof(gpointer));
    g_free(data);
    return jump_addr != 0;
}

void GumTrace::callout_callback(GumCpuContext *cpu_context, gpointer user_data) {
    auto *self = get_instance();
    auto *callback_ctx = static_cast<CALLBACK_CTX *>(user_data);
    char *buff = self->buffer;
    int &buff_n = self->buffer_offset;

    if (buff_n > GUMTRACE_BUFFER_SIZE - 1024) {
        self->trace_file.write(buff, buff_n);
        buff_n = 0;
    }

    if (self->write_reg_list.num > 0) {
        Utils::append_string(buff, buff_n, "-> ");
        for (int i = 0; i < self->write_reg_list.num; i++) {
            append_logged_register(buff, buff_n, cpu_context, callback_ctx->handle, self->write_reg_list.regs[i]);
        }
        Utils::append_char(buff, buff_n, '\n');
        self->write_reg_list.num = 0;
    }

    if (self->last_func_context.call) {
        if (buff_n > 0) {
            self->trace_file.write(buff, buff_n);
            buff_n = 0;
        }

        self->last_func_context.call = false;
        FuncPrinter::after(&self->last_func_context, cpu_context);
        self->trace_file.write(self->last_func_context.info, self->last_func_context.info_n);
    }

    const auto *native_ctx = reinterpret_cast<const GumX64CpuContext *>(cpu_context);

    Utils::append_char(buff, buff_n, '[');
    Utils::append_string(buff, buff_n, callback_ctx->module_name);
    Utils::append_string(buff, buff_n, "] 0x");
    Utils::append_uint64_hex(buff, buff_n, native_ctx->rip);
    Utils::append_string(buff, buff_n, "!0x");
    Utils::append_uint64_hex(buff, buff_n, native_ctx->rip - callback_ctx->module_base);
    Utils::append_char(buff, buff_n, ' ');
    Utils::append_string(buff, buff_n, callback_ctx->instruction.mnemonic);
    Utils::append_char(buff, buff_n, ' ');
    Utils::append_string(buff, buff_n, callback_ctx->instruction.op_str);
    Utils::append_string(buff, buff_n, "; ");

    bool has_pending_writes = false;
    const cs_x86 &x86 = callback_ctx->instruction_detail.x86;
    for (uint8_t i = 0; i < x86.op_count; i++) {
        const cs_x86_op &op = x86.operands[i];
        if (op.type == X86_OP_REG) {
            if ((op.access & CS_AC_READ) != 0) {
                append_logged_register(buff, buff_n, cpu_context, callback_ctx->handle, static_cast<x86_reg>(op.reg));
            }
            if ((op.access & CS_AC_WRITE) != 0 && self->write_reg_list.num < static_cast<int>(sizeof(self->write_reg_list.regs) / sizeof(self->write_reg_list.regs[0]))) {
                self->write_reg_list.regs[self->write_reg_list.num++] = static_cast<x86_reg>(op.reg);
                has_pending_writes = true;
            }
            continue;
        }

        if (op.type != X86_OP_MEM) {
            continue;
        }

        if (op.mem.base != X86_REG_INVALID) {
            append_logged_register(buff, buff_n, cpu_context, callback_ctx->handle, static_cast<x86_reg>(op.mem.base));
        }
        if (op.mem.index != X86_REG_INVALID) {
            append_logged_register(buff, buff_n, cpu_context, callback_ctx->handle, static_cast<x86_reg>(op.mem.index));
        }

        uint64_t mem_address = 0;
        if (!Utils::get_memory_operand_address(&callback_ctx->instruction, op, native_ctx, mem_address)) {
            continue;
        }

        if ((op.access & CS_AC_READ) != 0) {
            Utils::append_string(buff, buff_n, "mem_r=0x");
            Utils::append_uint64_hex(buff, buff_n, mem_address);
            Utils::append_char(buff, buff_n, ' ');
        }

        if ((op.access & CS_AC_WRITE) != 0) {
            Utils::append_string(buff, buff_n, "mem_w=0x");
            Utils::append_uint64_hex(buff, buff_n, mem_address);
            Utils::append_char(buff, buff_n, ' ');
        }
    }

    if (!has_pending_writes) {
        Utils::append_char(buff, buff_n, '\n');
    }

    if (callback_ctx->instruction.id == X86_INS_CALL && x86.op_count > 0) {
        uint64_t jump_addr = 0;
        const cs_x86_op &target_op = x86.operands[0];
        if (target_op.type == X86_OP_IMM) {
            jump_addr = static_cast<uint64_t>(target_op.imm);
        } else {
            resolve_indirect_call_target(&callback_ctx->instruction, target_op, cpu_context, jump_addr);
        }

        if (jump_addr != 0) {
            auto it = self->func_maps.find(jump_addr);
            if (it != self->func_maps.end()) {
                self->last_func_context.info_n = 0;
                self->last_func_context.address = jump_addr;
                self->last_func_context.name = it->second.c_str();
                std::memcpy(&self->last_func_context.cpu_context, cpu_context, sizeof(GumCpuContext));
                self->last_func_context.call = true;
                FuncPrinter::before(&self->last_func_context);
            }
        }
    }

    self->trace_flush++;
    if (self->options.mode == GUM_OPTIONS_MODE_DEBUG && self->trace_flush > 20) {
        if (buff_n > 0) {
            self->trace_file.write(buff, buff_n);
            buff_n = 0;
        }
        self->trace_file.flush();
        self->trace_flush = 0;
    }
}

void GumTrace::transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data) {
    auto *self = get_instance();
    cs_insn *insn = nullptr;

    while (gum_stalker_iterator_next(iterator, const_cast<const cs_insn **>(&insn))) {
        const std::string *module_name = self->in_range_module(insn->address);
        if (module_name == nullptr || Utils::is_atomic_instruction(insn)) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        const auto &module = self->get_module_by_name(*module_name);
        auto *callback_ctx = self->callback_context_instance->pull(insn, gum_stalker_iterator_get_capstone(iterator), module_name->c_str(), static_cast<uint64_t>(module.at("base")));

        gum_stalker_iterator_put_callout(iterator, callout_callback, callback_ctx, nullptr);
        gum_stalker_iterator_keep(iterator);
    }
}

const std::string *GumTrace::in_range_module(size_t address) {
    if (last_module_cache.name != nullptr && address >= last_module_cache.base && address < last_module_cache.end) {
        return last_module_cache.name;
    }

    for (const auto &pair : modules) {
        const auto &module_map = pair.second;
        size_t base = module_map.at("base");
        size_t end = base + module_map.at("size");
        if (address >= base && address < end) {
            last_module_cache.name = &pair.first;
            last_module_cache.base = base;
            last_module_cache.end = end;
            return &pair.first;
        }
    }

    return nullptr;
}

const RangeInfo *GumTrace::find_range_by_address(uintptr_t addr) const {
    if (safe_ranges.empty()) {
        return nullptr;
    }

    int left = 0;
    int right = static_cast<int>(safe_ranges.size()) - 1;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        const auto &info = safe_ranges[mid];
        if (addr >= info.base && addr < info.end) {
            return &info;
        }
        if (addr < info.base) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    return nullptr;
}

const std::map<std::string, std::size_t> &GumTrace::get_module_by_name(const std::string &module_name) const { return modules.at(module_name); }

bool GumTrace::is_target_module(const std::string &module_name) const {
    std::string lower_name = to_lower_copy(module_name);
    return std::find(target_modules.begin(), target_modules.end(), lower_name) != target_modules.end();
}

void GumTrace::start_flush_thread() {
    stop_flush_thread();
    flush_thread_running_.store(true);
    flush_thread_ = std::thread([this] { flush_loop(); });
}

void GumTrace::stop_flush_thread() {
    flush_thread_running_.store(false);
    if (flush_thread_.joinable()) {
        flush_thread_.join();
    }
}

void GumTrace::flush_loop() {
    uint64_t last_size = 0;

    while (flush_thread_running_.load()) {
        if (!trace_file.is_open()) {
            break;
        }

        if (options.mode != GUM_OPTIONS_MODE_DEBUG) {
            uint64_t current_size = 0;
            if (Utils::file_stat(trace_file_path, current_size)) {
                uint64_t growth_mb = (current_size - last_size) / (1024 * 1024);
                uint64_t size_gb = current_size / (1024 * 1024 * 1024);
                LOGE("trace growth in last interval: %llu MB current size: %llu GB", static_cast<unsigned long long>(growth_mb), static_cast<unsigned long long>(size_gb));
                last_size = current_size;
            }
        }

        trace_file.flush();

        if (options.mode == GUM_OPTIONS_MODE_DEBUG) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } else {
            std::this_thread::sleep_for(std::chrono::seconds(20));
        }
    }
}

void GumTrace::follow() {
    start_flush_thread();
    if (trace_thread_id > 0) {
        gum_stalker_follow(_stalker, trace_thread_id, _transformer, nullptr);
    } else {
        gum_stalker_follow_me(_stalker, _transformer, nullptr);
    }
}

void GumTrace::unfollow() {
    if (trace_thread_id > 0) {
        gum_stalker_unfollow(_stalker, trace_thread_id);
    } else {
        gum_stalker_unfollow_me(_stalker);
    }

    stop_flush_thread();

    if (trace_file.is_open()) {
        if (buffer_offset > 0) {
            trace_file.write(buffer, buffer_offset);
            buffer_offset = 0;
        }
        trace_file.flush();
        trace_file.close();
    }
}

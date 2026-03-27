//
// Created by lidongyooo on 2026/2/6.
//

#include "GumTrace.h"

#include <algorithm>
#include <cctype>
#include <cstring>

static std::string to_lower_copy(const char *value) {
    std::string result = value == nullptr ? "" : value;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

static gboolean module_symbols_cb(const GumSymbolDetails *details, gpointer user_data) {
    auto *instance = GumTrace::get_instance();
    if (details != nullptr && details->name != nullptr && details->address != 0) {
        instance->func_maps[details->address] = details->name;
    }
    return TRUE;
}

static gboolean module_dependency_cb(const GumDependencyDetails *details, gpointer user_data) {
    if (details == nullptr || details->name == nullptr) {
        return TRUE;
    }

    auto *dependency = gum_process_find_module_by_name(details->name);
    if (dependency != nullptr) {
        gum_module_enumerate_symbols(dependency, module_symbols_cb, nullptr);
    }
    return TRUE;
}

static gboolean on_range_found(const GumRangeDetails *details, gpointer user_data) {
    auto *instance = GumTrace::get_instance();

    RangeInfo info;
    info.base = static_cast<uintptr_t>(details->range->base_address);
    info.size = details->range->size;
    info.end = info.base + info.size;
    info.file_path = details->file != nullptr ? details->file->path : "anonymous";

    instance->safe_ranges.push_back(std::move(info));
    return TRUE;
}

static gboolean module_enumerate(GumModule *module, gpointer user_data) {
    auto *instance = GumTrace::get_instance();
    const char *module_name_raw = gum_module_get_name(module);
    const std::string module_name = to_lower_copy(module_name_raw);
    const auto *range = gum_module_get_range(module);

    if (!instance->is_target_module(module_name)) {
        gum_stalker_exclude(instance->_stalker, range);
        return TRUE;
    }

    auto &module_map = instance->modules[module_name];
    module_map["base"] = static_cast<size_t>(range->base_address);
    module_map["size"] = range->size;
    return TRUE;
}

GUMTRACE_EXPORT void init(const char *module_names, char *trace_file_path, int thread_id, GUM_OPTIONS *options) {
    gum_init();

    GumTrace *instance = GumTrace::get_instance();
    instance->modules.clear();
    instance->func_maps.clear();
    instance->target_modules.clear();
    instance->safe_ranges.clear();
    instance->last_module_cache = {};
    instance->buffer_offset = 0;
    instance->write_reg_list.num = 0;
    instance->trace_flush = 0;

    std::memcpy(&instance->options, options, sizeof(GUM_OPTIONS));
    instance->trace_thread_id = thread_id;

    instance->_stalker = gum_stalker_new();
    gum_stalker_set_trust_threshold(instance->_stalker, 0);
    if (instance->options.mode == GUM_OPTIONS_MODE_STABLE) {
        gum_process_enumerate_ranges(GUM_PAGE_READ, on_range_found, nullptr);
        std::sort(instance->safe_ranges.begin(), instance->safe_ranges.end(), [](const RangeInfo &a, const RangeInfo &b) { return a.base < b.base; });
        gum_stalker_set_trust_threshold(instance->_stalker, 2);
    }

    for (const auto &name : Utils::str_split(module_names == nullptr ? "" : module_names, ',')) {
        if (!name.empty()) {
            instance->target_modules.push_back(to_lower_copy(name.c_str()));
        }
    }

    for (const auto &module_name : instance->target_modules) {
        GumModule *module = gum_process_find_module_by_name(module_name.c_str());
        if (module == nullptr) {
            LOGE("module not found: %s", module_name.c_str());
            continue;
        }

        gum_module_enumerate_symbols(module, module_symbols_cb, nullptr);
        gum_module_enumerate_dependencies(module, module_dependency_cb, nullptr);

        const GumMemoryRange *range = gum_module_get_range(module);
        auto &module_map = instance->modules[module_name];
        module_map["base"] = static_cast<size_t>(range->base_address);
        module_map["size"] = range->size;
    }

    gum_process_enumerate_modules(module_enumerate, nullptr);

    size_t path_len = std::strlen(trace_file_path);
    if (path_len >= sizeof(instance->trace_file_path)) {
        path_len = sizeof(instance->trace_file_path) - 1;
    }
    std::memcpy(instance->trace_file_path, trace_file_path, path_len);
    instance->trace_file_path[path_len] = '\0';
    instance->trace_file = std::ofstream(instance->trace_file_path, std::ios::out | std::ios::trunc);
}

GUMTRACE_EXPORT void run() { GumTrace::get_instance()->follow(); }

GUMTRACE_EXPORT void unrun() { GumTrace::get_instance()->unfollow(); }

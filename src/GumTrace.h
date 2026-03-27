//
// Created by lidongyooo on 2026/2/6.
//

#ifndef GUMTRACE_GUMTRACE_H
#define GUMTRACE_GUMTRACE_H

#include <atomic>
#include <thread>

#include "CallbackContext.h"
#include "Utils.h"

struct REG_LIST {
    int num = 0;
    x86_reg regs[32] = {};
};

typedef enum {
    GUM_OPTIONS_MODE_Stand = 0,
    GUM_OPTIONS_MODE_DEBUG,
    GUM_OPTIONS_MODE_STABLE,
} GUM_OPTIONS_MODE;

struct GUM_OPTIONS {
    uint64_t mode;
};

struct FUNC_CONTEXT {
    uint64_t address = 0;
    const char *name = nullptr;
    char info[GUMTRACE_BUFFER_SIZE] = {};
    int info_n = 0;
    bool call = false;
    GumCpuContext cpu_context = {};
};

struct RangeInfo {
    uintptr_t base = 0;
    uintptr_t size = 0;
    uintptr_t end = 0;
    std::string file_path;
};

class GumTrace {
  public:
    static GumTrace *get_instance();

    std::map<std::string, std::map<std::string, std::size_t>> modules;
    std::vector<std::string> target_modules;
    char trace_file_path[260] = {};
    std::ofstream trace_file;
    int trace_thread_id = 0;
    int trace_flush = 0;
    std::unordered_map<size_t, std::string> func_maps;
    FUNC_CONTEXT last_func_context = {};

    GumStalker *_stalker = nullptr;
    GumStalkerTransformer *_transformer = nullptr;
    CallbackContext *callback_context_instance = nullptr;

    static void transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data);
    const std::string *in_range_module(size_t address);
    const RangeInfo *find_range_by_address(uintptr_t addr) const;
    const std::map<std::string, std::size_t> &get_module_by_name(const std::string &module_name) const;
    bool is_target_module(const std::string &module_name) const;
    void follow();
    void unfollow();

    static void callout_callback(GumCpuContext *cpu_context, gpointer user_data);

    char buffer[GUMTRACE_BUFFER_SIZE] = {};
    int buffer_offset = 0;
    REG_LIST write_reg_list;

    struct CachedModule {
        const std::string *name = nullptr;
        size_t base = 0;
        size_t end = 0;
    } last_module_cache;

    GUM_OPTIONS options = {};
    std::vector<RangeInfo> safe_ranges;

  private:
    GumTrace();
    ~GumTrace();

    GumTrace(const GumTrace &) = delete;
    GumTrace &operator=(const GumTrace &) = delete;

    void start_flush_thread();
    void stop_flush_thread();
    void flush_loop();

    std::atomic<bool> flush_thread_running_ = {false};
    std::thread flush_thread_;
};

#endif // GUMTRACE_GUMTRACE_H

#include "TraceParser.h"
#include "TaintEngine.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void print_usage(const char *prog) {
    std::fprintf(stderr, "Usage: %s [options]\n\n", prog);
    std::fprintf(stderr, "Options:\n");
    std::fprintf(stderr, "  -i <file>       Input trace log file\n");
    std::fprintf(stderr, "  -o <file>       Output result log file\n");
    std::fprintf(stderr, "  -f <target>     Forward tracking (from source)\n");
    std::fprintf(stderr, "  -b <target>     Backward tracking (to target)\n");
    std::fprintf(stderr, "  -l <line>       Start line number in trace file\n");
    std::fprintf(stderr, "  -p <offset>     Start by byte offset in trace file\n");
    std::fprintf(stderr, "  -a <addr>       Start by relative address (hex)\n");
    std::fprintf(stderr, "  -h              Show this help\n\n");
    std::fprintf(stderr, "Target format:\n");
    std::fprintf(stderr, "  rax, rcx, r8, xmm0 ...  Register name\n");
    std::fprintf(stderr, "  mem:0x1000              Memory address\n\n");
    std::fprintf(stderr, "Examples:\n");
    std::fprintf(stderr, "  %s -i trace.log -o result.log -f rcx -l 100\n", prog);
    std::fprintf(stderr, "  %s -i trace.log -o result.log -b rax -l 500\n", prog);
    std::fprintf(stderr, "  %s -i trace.log -o result.log -f mem:0x1000 -l 100\n", prog);
}

static TaintSource parse_target(const char *target) {
    TaintSource src;
    if (std::strncmp(target, "mem:", 4) == 0) {
        src.is_mem = true;
        const char *addr = target + 4;
        if (addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X')) {
            addr += 2;
        }
        src.mem_addr = std::strtoull(addr, nullptr, 16);
    } else {
        src.reg = TraceParser::parse_reg_name(target, static_cast<int>(std::strlen(target)));
        if (src.reg == REG_INVALID) {
            std::fprintf(stderr, "Error: unknown register '%s'\n", target);
        }
    }
    return src;
}

int main(int argc, char *argv[]) {
    const char *input_file = nullptr;
    const char *output_file = nullptr;
    const char *target = nullptr;
    TrackMode mode = TrackMode::FORWARD;
    int start_line = -1;
    long start_offset = -1;
    uint64_t start_addr = 0;
    bool use_addr = false;
    bool use_offset = false;
    bool has_mode = false;

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            input_file = argv[++i];
        } else if (std::strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (std::strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            target = argv[++i];
            mode = TrackMode::FORWARD;
            has_mode = true;
        } else if (std::strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            target = argv[++i];
            mode = TrackMode::BACKWARD;
            has_mode = true;
        } else if (std::strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            start_line = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            start_offset = std::atol(argv[++i]);
            use_offset = true;
        } else if (std::strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            const char *addr = argv[++i];
            if (addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X')) {
                addr += 2;
            }
            start_addr = std::strtoull(addr, nullptr, 16);
            use_addr = true;
        } else if (std::strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (input_file == nullptr || output_file == nullptr || !has_mode || target == nullptr) {
        std::fprintf(stderr, "Error: -i, -o, -f/-b and a start location are required\n");
        print_usage(argv[0]);
        return 1;
    }

    if (start_line < 0 && !use_addr && !use_offset) {
        std::fprintf(stderr, "Error: -l, -p, or -a is required\n");
        print_usage(argv[0]);
        return 1;
    }

    TaintSource source = parse_target(target);
    if (!source.is_mem && source.reg == REG_INVALID) {
        return 1;
    }

    if (use_offset && start_line < 0) {
        FILE *fp = std::fopen(input_file, "rb");
        if (fp == nullptr) {
            std::fprintf(stderr, "Error: cannot open file: %s\n", input_file);
            return 1;
        }

        int line_num = 1;
        const int scan_buf_size = 262144;
        char *scan_buf = new char[scan_buf_size];
        long scanned = 0;
        while (scanned < start_offset) {
            long remaining = start_offset - scanned;
            int to_read = remaining < scan_buf_size ? static_cast<int>(remaining) : scan_buf_size;
            int n = static_cast<int>(std::fread(scan_buf, 1, to_read, fp));
            if (n <= 0) {
                break;
            }
            for (int j = 0; j < n; j++) {
                if (scan_buf[j] == '\n') {
                    line_num++;
                }
            }
            scanned += n;
        }
        delete[] scan_buf;
        std::fclose(fp);
        start_line = line_num;
        std::fprintf(stderr, "Converted byte offset %ld -> line %d\n", start_offset, start_line);
    }

    auto t0 = std::chrono::steady_clock::now();

    TraceParser parser;
    if (mode == TrackMode::BACKWARD && start_line > 0) {
        std::fprintf(stderr, "Loading trace (up to line %d)...\n", start_line);
        if (!parser.load_range(input_file, start_line)) {
            return 1;
        }
    } else {
        std::fprintf(stderr, "Loading trace...\n");
        if (!parser.load(input_file)) {
            return 1;
        }
    }

    if (parser.size() == 0) {
        std::fprintf(stderr, "Error: no instruction lines found\n");
        return 1;
    }

    auto t1 = std::chrono::steady_clock::now();
    double load_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::fprintf(stderr, "Load time: %.1f ms\n", load_ms);

    const auto &lines = parser.get_lines();
    int start_index = -1;

    if (use_addr) {
        start_index = parser.find_by_rel_addr(start_addr);
        if (start_index < 0) {
            std::fprintf(stderr, "Error: relative address 0x%llx not found\n",
                static_cast<unsigned long long>(start_addr));
            return 1;
        }
        std::fprintf(stderr, "Found address 0x%llx at index %d (line %d)\n",
            static_cast<unsigned long long>(start_addr),
            start_index,
            lines[start_index].line_number);
    } else {
        start_index = parser.find_by_line(start_line);
        if (start_index < 0) {
            std::fprintf(stderr, "Error: line %d not found\n", start_line);
            return 1;
        }
    }

    TaintEngine engine;
    engine.set_mode(mode);
    engine.set_source(source);

    std::fprintf(stderr, "Running %s tracking from index %d (line %d) target: %s\n",
        mode == TrackMode::FORWARD ? "forward" : "backward",
        start_index,
        lines[start_index].line_number,
        target);

    auto t2 = std::chrono::steady_clock::now();
    engine.run(lines, start_index);
    auto t3 = std::chrono::steady_clock::now();
    double track_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();
    std::fprintf(stderr, "Tracking time: %.1f ms\n", track_ms);

    engine.write_result(output_file, parser);

    auto t4 = std::chrono::steady_clock::now();
    double total_ms = std::chrono::duration<double, std::milli>(t4 - t0).count();
    std::fprintf(stderr, "Total time: %.1f ms\n", total_ms);

    return 0;
}

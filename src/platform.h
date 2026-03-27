//
// Created by lidongyooo on 2026/2/6.
//

#ifndef GUMTRACE_PLATFORM_H
#define GUMTRACE_PLATFORM_H

#if !defined(_WIN32)
#error "GumTrace now targets Windows x86_64 only."
#endif

#if !defined(_M_X64) && !defined(__x86_64__)
#error "GumTrace requires an x86_64 toolchain."
#endif

#define PLATFORM_WINDOWS 1
#define PLATFORM_NAME "Windows"

#if defined(_MSC_VER)
#define GUMTRACE_EXPORT extern "C" __declspec(dllexport)
#else
#define GUMTRACE_EXPORT extern "C" __attribute__((visibility("default")))
#endif

#endif // GUMTRACE_PLATFORM_H
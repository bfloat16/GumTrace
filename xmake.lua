set_project("GumTrace")
set_version("1.0.0")
set_languages("cxx17")
set_encodings("utf-8")

set_runtimes("MT")
set_policy("build.warning", true)
set_policy("check.auto_ignore_flags", false)

local frida_header = path.join(os.projectdir(), "libs", "frida-gum.h")
local frida_library = path.join(os.projectdir(), "libs", "frida-gum.lib")

target("GumTrace")
    set_kind("shared")
    set_arch("x64")
    set_targetdir("$(builddir)/$(mode)")
    add_files(
        "src/main.cpp",
        "src/GumTrace.cpp",
        "src/Utils.cpp",
        "src/CallbackContext.cpp",
        "src/FuncPrinter.cpp"
    )
    add_includedirs(".", "src", "libs")
    add_linkdirs("libs")
    add_links("frida-gum")
    add_syslinks("advapi32", "ole32", "shell32", "user32")
    add_defines("WIN32_LEAN_AND_MEAN", "NOMINMAX", "_CRT_SECURE_NO_WARNINGS")
    add_cxflags("/utf-8", {force = true})

target("taint_tracker")
    set_kind("binary")
    set_arch("x64")
    set_targetdir("$(builddir)/$(mode)")
    add_files(
        "src/taint/main.cpp",
        "src/taint/TraceParser.cpp",
        "src/taint/TaintEngine.cpp"
    )
    add_includedirs("src/taint")
    add_defines("_CRT_SECURE_NO_WARNINGS")
    add_cxflags("/utf-8", {force = true})

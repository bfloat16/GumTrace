param(
    [string]$BuildDir = "build",
    [ValidateSet("debug", "release")]
    [string]$Mode = "release"
)

$ErrorActionPreference = "Stop"

xmake f -p windows -a x64 -m $Mode --builddir="$BuildDir"
if ($LASTEXITCODE -ne 0) {
    throw "xmake configure failed."
}

xmake
if ($LASTEXITCODE -ne 0) {
    throw "xmake build failed."
}

xmake project -k compile_commands "$BuildDir"
if ($LASTEXITCODE -ne 0) {
    throw "compile_commands.json generation failed."
}

Write-Host "Build complete: $BuildDir\$Mode\GumTrace.dll"
Write-Host "Compilation database: $BuildDir\compile_commands.json"

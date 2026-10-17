# Builds the HookMap SKSE plugin (plugin\) and runs its self-test.
#   .\build.ps1                 -> plugin\build\Release\HookMap.dll (+ self-test)
#   .\build.ps1 -Dest "D:\mods\HookMap"   -> also copies the DLL to <Dest>\SKSE\Plugins\HookMap.dll
param([string]$Dest, [switch]$NoTest)

$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot
$build = Join-Path $PSScriptRoot "plugin\build"

cmake -S plugin -B $build -G "Visual Studio 18 2026" -A x64 | Out-Host
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
cmake --build $build --config Release | Out-Host
if ($LASTEXITCODE -ne 0) { throw "build failed" }

$rel = Join-Path $build "Release"
if (-not $NoTest) {
    Write-Host "`nSelf-test:" -ForegroundColor Cyan
    & (Join-Path $rel "hookmap_selftest.exe") | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "self-test failed" }
}

if ($Dest) {
    $plug = Join-Path $Dest "SKSE\Plugins"
    New-Item -ItemType Directory -Force $plug | Out-Null
    Copy-Item (Join-Path $rel "HookMap.dll") $plug -Force
    Write-Host "Copied HookMap.dll to $plug" -ForegroundColor Green
}

# Builds the two downloads into .\release:
#   HookMap-<version>.zip          the program (window + command line); unzip anywhere and run HookMap.App.exe
#   HookMap Plugin-<version>.zip   the in-game plugin as a mod: install it with Mod Organizer like any SKSE mod
#
#   .\package.ps1             build and package
#   .\package.ps1 -SkipBuild  package what is already built
param([switch]$SkipBuild)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$version = (Get-Content (Join-Path $PSScriptRoot "VERSION") -Raw).Trim()
Write-Host "HookMap $version" -ForegroundColor Cyan

$dll = Join-Path $PSScriptRoot "plugin\build\Release\HookMap.dll"
$app = Join-Path $PSScriptRoot "dist\app"
if (-not $SkipBuild) {
    & "$PSScriptRoot\build.ps1"
    if (-not (Test-Path $dll)) { throw "The plugin was not built." }
    if (Test-Path $app) { Remove-Item -Recurse -Force $app }
    dotnet test "$PSScriptRoot\offline\tests\HookMap.Core.Tests" -c Release | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Tests failed." }
    dotnet publish "$PSScriptRoot\offline\src\HookMap.App\HookMap.App.csproj" -c Release -r win-x64 --self-contained false -o $app | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "App build failed." }
    dotnet publish "$PSScriptRoot\offline\src\HookMap.Cli\HookMap.Cli.csproj" -c Release -r win-x64 --self-contained false -o $app | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "CLI build failed." }
}

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
function New-Zip([string]$folder, [string]$zipPath) {
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $root = (Resolve-Path $folder).Path.TrimEnd('\') + '\'
        Get-ChildItem $folder -Recurse -File | ForEach-Object {
            $name = $_.FullName.Substring($root.Length).Replace('\', '/')
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $name, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    } finally { $zip.Dispose() }
}

$release = Join-Path $PSScriptRoot "release"
New-Item -ItemType Directory -Force -Path $release | Out-Null

# The plugin as a mod folder (also carried inside the program zip, so the program's "Add HookMap plugin to MO2" button has it).
$stage = Join-Path $env:TEMP "HookMap-plugin-$version"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path "$stage\SKSE\Plugins" | Out-Null
Copy-Item $dll "$stage\SKSE\Plugins\"
Copy-Item "$PSScriptRoot\README.md" $stage
$pluginZip = Join-Path $release "HookMap Plugin-$version.zip"
New-Zip $stage $pluginZip
Write-Host "Plugin: $pluginZip" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "$app\Plugin\SKSE\Plugins" | Out-Null
Copy-Item $dll "$app\Plugin\SKSE\Plugins\" -Force
Copy-Item "$PSScriptRoot\README.md" $app -Force
Get-ChildItem $app -Filter "*.pdb" -File | Remove-Item -Force
$toolZip = Join-Path $release "HookMap-$version.zip"
New-Zip $app $toolZip
Write-Host "Tool:   $toolZip" -ForegroundColor Green
Remove-Item -Recurse -Force $stage

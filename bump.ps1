# Raises the last number of the HookMap version (VERSION file, used by the plugin and the program):
#   .\bump.ps1            0.1.0 -> 0.1.1
#   .\bump.ps1 -Minor     0.1.5 -> 0.2.0
param([switch]$Minor)
$file = Join-Path $PSScriptRoot "VERSION"
$parts = (Get-Content $file -Raw).Trim().Split('.') | ForEach-Object { [int]$_ }
if ($Minor) { $parts[1]++; $parts[2] = 0 } else { $parts[2]++ }
$new = "$($parts[0]).$($parts[1]).$($parts[2])"
Set-Content -Path $file -Value $new -NoNewline
Write-Host "HookMap version: $new" -ForegroundColor Cyan

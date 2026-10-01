#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$InstallRoot
)

$ErrorActionPreference = 'Stop'
$agent = Join-Path $InstallRoot 'cyclothone-agent.exe'
if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { throw "Agent binary missing: $agent" }

$script = Join-Path $InstallRoot 'install-service.ps1'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw "Service installer missing: $script" }

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -BinaryPath $agent
if ($LASTEXITCODE -ne 0) { throw "Cyclothone Agent service installation failed." }

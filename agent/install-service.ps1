#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$BinaryPath = "$env:ProgramFiles\Cyclothone\cyclothone-agent.exe"
)

$ErrorActionPreference = 'Stop'
$serviceName = 'CyclothoneAgent'
$displayName = 'Cyclothone Agent'
$description = 'Cyclothone endpoint telemetry and local detection agent'

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Cyclothone agent binary not found: $BinaryPath"
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
    }
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to remove existing $serviceName service"
    }
    Start-Sleep -Milliseconds 500
}

& sc.exe create $serviceName binPath= "`"$BinaryPath`" --service" start= auto type= own DisplayName= $displayName | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Failed to create $serviceName service"
}

& sc.exe description $serviceName $description | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to set service description"
}

& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to configure service recovery"
}

Start-Service -Name $serviceName
Write-Host "$serviceName installed and started."

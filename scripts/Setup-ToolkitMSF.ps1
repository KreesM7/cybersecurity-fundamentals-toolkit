[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Rootfs,
    [Parameter(Mandatory=$true)][string]$InstallDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$Sha256
)
$ErrorActionPreference = 'Stop'
$archive = (Resolve-Path -LiteralPath $Rootfs).Path
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $Sha256) {
    throw 'Ubuntu rootfs checksum mismatch. Obtain the hash from the official signed Ubuntu manifest.'
}
$destination = [IO.Path]::GetFullPath($InstallDirectory)
$distributions = @(& wsl.exe --list --quiet) | ForEach-Object { ($_ -replace "`0", '').Trim() }
if ($LASTEXITCODE -ne 0) { throw 'Install and enable WSL2 before provisioning.' }
if ($distributions -notcontains 'Toolkit-MSF') {
    if (Test-Path -LiteralPath $destination) {
        if (@(Get-ChildItem -LiteralPath $destination -Force).Count -ne 0) {
            throw 'Choose an empty installation directory.'
        }
    } else {
        New-Item -ItemType Directory -Path $destination | Out-Null
    }
    & wsl.exe --import Toolkit-MSF $destination $archive --version 2
    if ($LASTEXITCODE -ne 0) { throw 'Toolkit-MSF import failed. Existing distributions were not modified.' }
}
$linuxScripts = (& wsl.exe --distribution Toolkit-MSF --exec /usr/bin/wslpath -a -u $PSScriptRoot).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Unable to resolve the provisioning directory in Toolkit-MSF.' }
& wsl.exe --distribution Toolkit-MSF --user root --exec /bin/bash "$linuxScripts/provision-linux.sh"
if ($LASTEXITCODE -ne 0) { throw 'Provisioning failed. Fix the reported prerequisite and rerun this script.' }
Write-Host 'Toolkit-MSF is ready. Other distributions, including OpenClawGateway, were not modified.'

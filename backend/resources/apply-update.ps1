param([Parameter(Mandatory=$true)][string]$Plan)
$ErrorActionPreference = 'Stop'
$handles = @()
$relaunch = $true
$installed = $false
$manifest = Get-Content -LiteralPath $Plan -Encoding UTF8 -Raw | ConvertFrom-Json
function Hash-File([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}
function Verify-Blob([string]$Artifact, [string]$Bundle) {
    $arguments = @('verify-blob', '--bundle', ('"' + $Bundle + '"'),
        '--certificate-identity-regexp', ('"' + $manifest.identity + '"'),
        '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com', ('"' + $Artifact + '"'))
    $process = Start-Process -FilePath $manifest.verifier -ArgumentList $arguments -WindowStyle Hidden -PassThru
    if (!$process.WaitForExit(60000)) { $process.Kill(); $process.WaitForExit(); throw 'Signature verification timed out.' }
    if ($process.ExitCode -ne 0) { throw 'Signature verification failed.' }
}
try {
    # The backend has already stopped. Wait until Qt/PyInstaller release installed files too.
    $parent = Get-Process -Id $manifest.parent -ErrorAction SilentlyContinue
    if ($parent -and !$parent.WaitForExit(120000)) { $relaunch = $false; throw 'Application did not exit.' }
    # Deny writes/deletes across hash, signature verification and CreateProcess (TOCTOU).
    foreach ($file in @($manifest.installer, $manifest.verifier, $manifest.checksums,
                        $manifest.signature, $manifest.checksums_signature)) {
        $handles += [IO.File]::Open($file, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    }
    if ((Hash-File $manifest.verifier) -ne $manifest.verifier_hash) { throw 'Verifier checksum mismatch.' }
    if ((Hash-File $manifest.installer) -ne $manifest.installer_hash) { throw 'Installer checksum mismatch.' }
    if ((Hash-File $manifest.checksums) -ne $manifest.manifest_hash) { throw 'Manifest checksum mismatch.' }
    Verify-Blob $manifest.checksums $manifest.checksums_signature
    Verify-Blob $manifest.installer $manifest.signature
    $arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', ('/DIR="' + $manifest.directory + '"'))
    $installer = Start-Process -FilePath $manifest.installer -ArgumentList $arguments -WindowStyle Hidden -PassThru
    if (!$installer.WaitForExit(900000)) { $relaunch = $false; throw 'Installer is still running; check it before restarting.' }
    if ($installer.ExitCode -ne 0) { throw 'Installer failed. Restart the application and retry.' }
    $installed = $true
    @{ version = $manifest.version; complete = $true } | ConvertTo-Json | Set-Content -LiteralPath $manifest.flag -Encoding UTF8
} catch {
    # Fixed local text only. Never persist verifier stdout, signed URLs or arbitrary exceptions.
    @{ version = $manifest.version; complete = $false } | ConvertTo-Json | Set-Content -LiteralPath $manifest.flag -Encoding UTF8
} finally {
    foreach ($handle in $handles) { $handle.Dispose() }
    if (!$installed -and $relaunch) {
        foreach ($file in @($manifest.installer, $manifest.signature, $manifest.checksums, $manifest.checksums_signature)) {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $Plan -Force -ErrorAction SilentlyContinue
}

if ($relaunch -and (Test-Path -LiteralPath $manifest.application)) {
    Start-Process -FilePath $manifest.application -ArgumentList @('--profile', ('"' + $manifest.profile + '"'))
}

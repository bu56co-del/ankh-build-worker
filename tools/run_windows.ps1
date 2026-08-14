param(
    [Parameter(Mandatory = $true)][string]$RequestPath,
    [Parameter(Mandatory = $true)][string]$CipherPath,
    [Parameter(Mandatory = $true)][string]$CryptoPath,
    [Parameter(Mandatory = $true)][string]$WorkRoot,
    [Parameter(Mandatory = $true)][string]$ArtifactRoot
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-CapsuleCrypt(
    [string]$Mode,
    [string]$InputPath,
    [string]$OutputPath,
    [string]$Aad,
    [string]$Key
) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $CryptoPath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    [void]$psi.ArgumentList.Add($Mode)
    [void]$psi.ArgumentList.Add($InputPath)
    [void]$psi.ArgumentList.Add($OutputPath)
    [void]$psi.ArgumentList.Add($Aad)
    $psi.Environment['ANKH_CAPSULE_KEY_B64'] = $Key
    $process = [System.Diagnostics.Process]::Start($psi)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "capsule crypt failed"
    }
}

function Invoke-PrivateCargo([string]$Directory, [string[]]$Arguments, [string]$LogPath) {
    Push-Location $Directory
    try {
        & cargo @Arguments *>> $LogPath
        return ($LASTEXITCODE -eq 0)
    }
    finally {
        Pop-Location
    }
}

function Write-Status(
    [string]$Path,
    [string]$BuildId,
    [bool]$Success,
    [string]$OutputCipher,
    [string]$LogCipher
) {
    $status = [ordered]@{
        schema = 1
        build_id = $BuildId
        platform = 'windows'
        success = $Success
        output_cipher_sha256 = Get-Sha256 $OutputCipher
        output_cipher_bytes = (Get-Item -LiteralPath $OutputCipher).Length
        log_cipher_sha256 = Get-Sha256 $LogCipher
        log_cipher_bytes = (Get-Item -LiteralPath $LogCipher).Length
    }
    [System.IO.File]::WriteAllText(
        $Path,
        (($status | ConvertTo-Json -Compress) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
}

New-Item -ItemType Directory -Force -Path $WorkRoot, $ArtifactRoot | Out-Null
$request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
$buildId = [string]$request.build_id
$workerFingerprint = [string]$request.worker_fingerprint
if ($buildId -notmatch '^[0-9a-f]{64}$' -or $workerFingerprint -notmatch '^[0-9a-f]{64}$') {
    throw 'invalid build request identity'
}

$key = [string]$env:ANKH_CAPSULE_KEY_B64
if ([string]::IsNullOrWhiteSpace($key)) {
    throw 'worker capsule key is not configured'
}
Remove-Item Env:ANKH_CAPSULE_KEY_B64 -ErrorAction SilentlyContinue
[Environment]::SetEnvironmentVariable('ANKH_CAPSULE_KEY_B64', $null, 'Process')

$sourceZip = Join-Path $WorkRoot 'source.zip'
$sourceRoot = Join-Path $WorkRoot 'source'
$sourceManifest = Join-Path $sourceRoot 'SOURCE_MANIFEST.json'
$privateLog = Join-Path $WorkRoot 'private-build.log'
$bundle = Join-Path $WorkRoot 'windows-output.zip'
$failurePayload = Join-Path $WorkRoot 'windows-failure.json'
$outputCipher = Join-Path $ArtifactRoot 'windows-output.enc'
$logCipher = Join-Path $ArtifactRoot 'windows-log.enc'
$statusPath = Join-Path $ArtifactRoot 'windows-status.json'
$success = $false

try {
    Invoke-CapsuleCrypt 'decrypt' $CipherPath $sourceZip ("ankh-source-v1:" + $buildId) $key
    & python (Join-Path $PSScriptRoot 'extract_source.py') --archive $sourceZip --output $sourceRoot --expected-build-id $buildId --expected-worker-fingerprint $workerFingerprint *> $null
    if ($LASTEXITCODE -ne 0) { throw 'source capsule verification failed' }

    [System.IO.File]::WriteAllText($privateLog, "private Windows build log`n", [System.Text.UTF8Encoding]::new($false))
    $steps = @(
        @{ dir = (Join-Path $sourceRoot 'daemon'); args = @('test', '--locked', '--quiet') },
        @{ dir = (Join-Path $sourceRoot 'daemon'); args = @('build', '--release', '--locked', '--quiet') },
        @{ dir = (Join-Path $sourceRoot 'pet'); args = @('test', '--lib', '--locked', '--quiet') },
        @{ dir = (Join-Path $sourceRoot 'pet'); args = @('build', '--release', '--locked', '--quiet') }
    )
    foreach ($step in $steps) {
        if (-not (Invoke-PrivateCargo $step.dir $step.args $privateLog)) {
            throw 'private build or test failed'
        }
    }

    & python (Join-Path $PSScriptRoot 'package_output.py') `
        --platform windows `
        --source-manifest $sourceManifest `
        --daemon (Join-Path $sourceRoot 'daemon/target/release/ankh-opener-daemon.exe') `
        --pet (Join-Path $sourceRoot 'pet/target/release/ankh-pet.exe') `
        --output $bundle *>> $privateLog
    if ($LASTEXITCODE -ne 0) { throw 'output packaging failed' }
    $success = $true
}
catch {
    [System.IO.File]::AppendAllText($privateLog, "build failed`n", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        $failurePayload,
        ('{"schema":1,"build_id":"' + $buildId + '","platform":"windows","success":false}' + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $bundle = $failurePayload
}
finally {
    if (-not (Test-Path -LiteralPath $privateLog)) {
        [System.IO.File]::WriteAllText($privateLog, "build did not start`n", [System.Text.UTF8Encoding]::new($false))
    }
    Invoke-CapsuleCrypt 'encrypt' $bundle $outputCipher ("ankh-output-v1:" + $buildId + ':windows') $key
    Invoke-CapsuleCrypt 'encrypt' $privateLog $logCipher ("ankh-log-v1:" + $buildId + ':windows') $key
    Write-Status $statusPath $buildId $success $outputCipher $logCipher
    $key = $null
    [GC]::Collect()
}

if ($success) {
    Write-Host '[OK] encrypted Windows build completed'
} else {
    Write-Host '[ERROR] encrypted Windows build failed; diagnostics remain encrypted'
}

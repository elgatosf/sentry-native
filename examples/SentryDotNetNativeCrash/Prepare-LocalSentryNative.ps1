param(
    [string]$BuildDir = "",
    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"

$sampleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $sampleRoot "..\.."))

if (-not $BuildDir) {
    $BuildDir = Join-Path $repoRoot "build-dotnet-wer"
}

Write-Host "Configuring sentry-native WER build in $BuildDir"
cmake -B $BuildDir `
    -DSENTRY_BACKEND=wer `
    -DSENTRY_BUILD_SHARED_LIBS=ON `
    -DSENTRY_BUILD_TESTS=OFF `
    -DSENTRY_BUILD_EXAMPLES=OFF `
    -DSENTRY_BUILD_BENCHMARKS=OFF `
    -DSENTRY_BUILD_FUZZERS=OFF `
    $repoRoot

Write-Host "Building sentry and sentry_wer_module ($Configuration)"
cmake --build $BuildDir --config $Configuration --target sentry sentry_wer_module

$candidateDirs = @(
    (Join-Path $BuildDir $Configuration),
    $BuildDir
)

$runtimeDir = $candidateDirs | Where-Object {
    (Test-Path (Join-Path $_ "sentry.dll")) -and (Test-Path (Join-Path $_ "sentry_wer_module.dll"))
} | Select-Object -First 1

if (-not $runtimeDir) {
    throw "Could not find sentry.dll and sentry_wer_module.dll under '$BuildDir'."
}

Write-Host "Native runtime ready in $runtimeDir"
Write-Host "Build the WinUI app next, or override the location with:`n  `$env:SENTRY_NATIVE_RUNTIME_DIR = '$runtimeDir'"
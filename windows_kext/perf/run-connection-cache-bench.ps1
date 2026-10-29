param(
    [ValidateRange(3, 101)]
    [int]$Rounds = 9,
    [ValidateRange(0, 63)]
    [int]$Cpu = 2,
    [string]$Filter = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$package = Join-Path $PSScriptRoot "connection_cache_bench"
$manifest = Join-Path $package "Cargo.toml"
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $PSScriptRoot ("results\connection-cache-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path $OutputDirectory) { throw "Output directory must be new: $OutputDirectory" }
[void][IO.Directory]::CreateDirectory($OutputDirectory)

$names = @("RUSTFLAGS", "CC_BENCH_OUT", "CC_BENCH_ROUNDS", "CC_BENCH_CPU", "CC_BENCH_FILTER")
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, "Process") }
try {
    # Match the driver's ISA; the user-mode test harness uses unwind rather than
    # the kernel's panic=abort, and its allocator/clock are test doubles.
    $env:RUSTFLAGS = "-C target-feature=+sse4.2"
    $env:CC_BENCH_OUT = $OutputDirectory
    $env:CC_BENCH_ROUNDS = "$Rounds"
    $env:CC_BENCH_CPU = "$Cpu"
    $env:CC_BENCH_FILTER = $Filter

    # Windows PowerShell 5.1 wraps redirected native stderr in ErrorRecords,
    # including Cargo's successful progress messages. Use the exit code instead.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $build = @(& cargo test --release --locked --manifest-path $manifest --no-run --message-format=json 2> (Join-Path $OutputDirectory "build.log"))
        $buildExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($buildExitCode -ne 0) { throw "Release benchmark build failed: $buildExitCode" }
    $artifacts = @($build | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object {
        $_.reason -eq "compiler-artifact" -and $_.executable -and $_.profile.test
    })
    if ($artifacts.Count -ne 1) { throw "Expected exactly one test executable" }
    $executable = $artifacts[0].executable

    $metadata = Join-Path $OutputDirectory "environment.txt"
    @(
        "Timestamp: $([DateTimeOffset]::Now.ToString('o'))"
        "Git HEAD: $(& git -C (Join-Path $PSScriptRoot '..\..') rev-parse HEAD)"
        "Production variant: directory-fx; btree-btree is a generated reference"
        "Connections per scenario: 50000"
        "Requests per timed pass: 1000000; exact hits: 700000; misses: 300000"
        "Miss classes: unseen remote endpoint / wrong local IP / absent local port, equal shares"
        "Timed rounds per candidate: $Rounds; fixed seed: 0x2026102970475000"
        "Filter: $Filter"
        "RUSTFLAGS: $env:RUSTFLAGS"
        "Release profile: opt-level=3; codegen-units=1; fat LTO"
        "Benchmark pins only its own process to logical CPU $Cpu. Power plan and priority are unchanged."
        "OS: $([Environment]::OSVersion.VersionString)"
        "User-mode container/metadata benchmark, not WFP callback or kernel spin-lock latency."
    ) | Set-Content -Encoding UTF8 $metadata
    & rustc -Vv | Add-Content -Encoding UTF8 $metadata
    & cargo -V | Add-Content -Encoding UTF8 $metadata
    # Keep reports free of processor and host hardware identifiers. Capture only
    # the stable power-plan GUID, without a locale-dependent display name.
    $powerScheme = & powercfg /getactivescheme
    if ($LASTEXITCODE -ne 0) { throw "Cannot read active power scheme: $LASTEXITCODE" }
    $powerSchemeGuid = [regex]::Match(($powerScheme -join "`n"), '[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}')
    if (-not $powerSchemeGuid.Success) { throw "Active power scheme GUID was not found" }
    "Power scheme GUID: $($powerSchemeGuid.Value)" | Add-Content -Encoding UTF8 $metadata
    @($executable, $manifest, (Join-Path $package "Cargo.lock"), (Join-Path $package "build.rs")) +
        @(Get-ChildItem (Join-Path $package "src") -File -Recurse | Select-Object -ExpandProperty FullName) +
        @((Join-Path $PSScriptRoot "..\driver\src\connection.rs"), (Join-Path $PSScriptRoot "..\driver\src\connection_map.rs"), (Join-Path $PSScriptRoot "..\driver\src\port_table.rs")) |
        ForEach-Object { Get-FileHash -Algorithm SHA256 -LiteralPath $_ } |
        Format-Table -AutoSize | Out-String -Width 260 |
        Add-Content -Encoding UTF8 $metadata

    & $executable --test-threads=1 2>&1 | Tee-Object -FilePath (Join-Path $OutputDirectory "tests.log")
    if ($LASTEXITCODE -ne 0) { throw "Cache regression tests failed: $LASTEXITCODE" }
    & $executable benchmark_connection_lookup --ignored --nocapture --test-threads=1 2>&1 |
        Tee-Object -FilePath (Join-Path $OutputDirectory "benchmark.log")
    if ($LASTEXITCODE -ne 0) { throw "Benchmark failed: $LASTEXITCODE" }
    Write-Output "RESULT_DIRECTORY=$OutputDirectory"
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], "Process") }
}

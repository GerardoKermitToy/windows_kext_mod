param(
    [ValidateRange(1, 101)]
    [int]$Runs = 7,
    [ValidateRange(1, 16000000)]
    [int]$Events = 1000000,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$manifest = Join-Path $PSScriptRoot "traffic_stats_bench\Cargo.toml"
$package = Split-Path $manifest
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $PSScriptRoot ("results\traffic-stats-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path $OutputDirectory) {
    throw "Output directory must be new: $OutputDirectory"
}
[void][IO.Directory]::CreateDirectory($OutputDirectory)

$oldRustFlags = $env:RUSTFLAGS
try {
    $env:RUSTFLAGS = "-C target-feature=+sse4.2"
    & cargo test --release --locked --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) { throw "Benchmark tests failed: $LASTEXITCODE" }

    # Match the driver's instruction-set and panic configuration, without
    # building, loading, signing, or installing the driver itself.
    $env:RUSTFLAGS = "-C panic=abort -C target-feature=+sse4.2"
    & cargo build --release --locked --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) { throw "Benchmark build failed: $LASTEXITCODE" }

    $executable = Join-Path $package "target\release\traffic-stats-bench.exe"
    if (-not (Test-Path $executable)) { throw "Missing benchmark executable: $executable" }
    $metadata = Join-Path $OutputDirectory "environment.txt"
    @(
        "Timestamp: $([DateTimeOffset]::Now.ToString('o'))"
        "Events per profile: $Events"
        "Timed runs per candidate: $Runs"
        "RUSTFLAGS: $env:RUSTFLAGS"
        "Process affinity: $((Get-Process -Id $PID).ProcessorAffinity)"
        "Priority: $((Get-Process -Id $PID).PriorityClass)"
        "OS: $([Environment]::OSVersion.VersionString)"
        "Power settings, process affinity and priority are not modified."
        "These are user-mode synthetic container measurements, not kernel callback latency."
    ) | Set-Content -Encoding UTF8 $metadata
    & rustc -Vv | Add-Content -Encoding UTF8 $metadata
    & cargo -V | Add-Content -Encoding UTF8 $metadata
    Get-CimInstance Win32_Processor |
        Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed |
        Format-List | Out-String | Add-Content -Encoding UTF8 $metadata
    & powercfg /getactivescheme | Add-Content -Encoding UTF8 $metadata
    Get-FileHash -Algorithm SHA256 $executable |
        Format-List | Out-String | Add-Content -Encoding UTF8 $metadata
    Get-ChildItem (Join-Path $package "src") -File -Recurse |
        Get-FileHash -Algorithm SHA256 |
        Format-Table -AutoSize | Out-String -Width 240 | Add-Content -Encoding UTF8 $metadata
    Get-FileHash -Algorithm SHA256 $manifest, (Join-Path $package "Cargo.lock") |
        Format-Table -AutoSize | Out-String -Width 240 | Add-Content -Encoding UTF8 $metadata

    $profiles = @(
        @{ Name = "connections-8192"; Unique = [Math]::Min(8192, $Events) },
        @{ Name = "connections-100000"; Unique = [Math]::Min(100000, $Events) },
        @{ Name = "connections-700000"; Unique = [Math]::Min(700000, $Events) },
        @{ Name = "unique-only"; Unique = $Events }
    )
    foreach ($profile in $profiles) {
        $arguments = @("--events", "$Events", "--unique", "$($profile.Unique)", "--runs", "$Runs")
        "COMMAND: traffic-stats-bench $($arguments -join ' ')" |
            Set-Content -Encoding UTF8 (Join-Path $OutputDirectory ($profile.Name + ".txt"))
        & $executable @arguments 2>&1 | ForEach-Object {
            $line = "$_"
            Write-Output $line
            Add-Content -Encoding UTF8 -LiteralPath (Join-Path $OutputDirectory ($profile.Name + ".txt")) -Value $line
        }
        if ($LASTEXITCODE -ne 0) { throw "Profile $($profile.Name) failed: $LASTEXITCODE" }
    }
    Write-Output "RESULT_DIRECTORY=$OutputDirectory"
} finally {
    $env:RUSTFLAGS = $oldRustFlags
}

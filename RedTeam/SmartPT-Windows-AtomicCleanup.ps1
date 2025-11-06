# Smart Atomic Red Team Cleanup Runner (No Module Required)
# Reads C:\baseline.csv and runs cleanup scripts for Tested = Yes entries

$BaselinePath = "C:\baseline.csv"
$RepoPath     = "C:\atomic-red-team"

function Info($m){ Write-Host "[INFO] $m" }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Err($m){ Write-Host "[ERROR] $m" -ForegroundColor Red }

Info "Starting SmartPT Atomic cleanup process..."

# ---- Validate baseline ----
if (-not (Test-Path $BaselinePath)) {
    Err "Baseline file not found at $BaselinePath"
    exit 1
}

try {
    $baseline = Import-Csv -Path $BaselinePath -ErrorAction Stop
    if (-not $baseline -or -not ($baseline | Get-Member -Name 'Technique' -ErrorAction SilentlyContinue)) {
        throw "Baseline invalid or missing expected columns."
    }
} catch {
    Err "Failed to read baseline: $($_.Exception.Message)"
    exit 1
}

# ---- Filter tested entries ----
$testedRows = $baseline | Where-Object { $_.Tested -and $_.Tested.Trim().ToLower() -eq "yes" }

if ($testedRows.Count -eq 0) {
    Info "No tests marked as Tested = Yes. Nothing to clean."
    exit 0
}

Info "Found $($testedRows.Count) tested entries. Starting cleanup..."

# ---- Iterate over tested entries ----
foreach ($t in $testedRows) {
    $tech = $t.Technique
    $num  = $t.TestNumber

    if ([string]::IsNullOrWhiteSpace($tech)) { continue }

    Info "Cleaning Technique=$tech  Test=$num"

    try {
        $techPath = Join-Path $RepoPath ("atomics\" + $tech)
        if (-not (Test-Path $techPath)) {
            Warn "Technique folder not found: $techPath"
            $t.Result = "Cleanup skipped (missing folder)"
            continue
        }

        # Find a PowerShell cleanup script
        $cleanupScript = Get-ChildItem -Path $techPath -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "cleanup" -and $_.Extension -eq ".ps1" } |
            Select-Object -First 1

        if ($cleanupScript) {
            Info "Running cleanup script: $($cleanupScript.FullName)"
            try {
                $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$($cleanupScript.FullName)`""
                $output = Invoke-Expression $cmd 2>&1 | Out-String
                Write-Host $output
                $t.Result = "Cleanup OK"
            } catch {
                Warn "Cleanup failed for $tech Test $num : $($_.Exception.Message)"
                $t.Result = "Cleanup failed: $($_.Exception.Message)"
            }
        } else {
            # If no cleanup script found, check for YAML
            $yamlPath = Join-Path $techPath "atomic_tests.yaml"
            if (Test-Path $yamlPath) {
                Info "No cleanup.ps1 found — YAML present (manual cleanup may be required)."
                $t.Result = "YAML only (manual cleanup)"
            } else {
                Warn "No cleanup content found for $tech"
                $t.Result = "No cleanup found"
            }
        }

        # Update cleanup timestamp
        $t.LastRun = (Get-Date).ToString("s")

    } catch {
        $err = $_.Exception.Message
        Err "Unexpected cleanup error for $tech Test $num : $err"
        $t.Result = "Cleanup error: $err"
    }

    # ---- Save progress after each cleanup ----
    try {
        $baseline | Sort-Object Tactic,Technique,TestNumber | Export-Csv -Path $BaselinePath -NoTypeInformation -Encoding UTF8
    } catch {
        Warn "Failed to persist baseline during cleanup: $($_.Exception.Message)"
    }
}

Info "✅ Cleanup complete. Baseline updated with results."

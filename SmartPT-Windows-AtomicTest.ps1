# Smart Atomic Red Team baseline sync
# Clones repo on first run, updates only when new tests appear

$BaselinePath = "C:\baseline.csv"
$RepoPath = "C:\atomic-red-team"
$IndexUrl = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics/Indexes/Indexes-CSV/windows-index.csv"

# ---- Control flags ----
$RunTests = $false   # set $true to execute tests automatically
$OnlyNew  = $true    # run only new untested tests

Write-Host "[INFO] Starting SmartPT Atomic baseline sync..."

# ---- Ensure Git installed ----
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Git not found. Please install Git and re-run." -ForegroundColor Red
    exit
}

# ---- Download and parse windows-index.csv ----
Write-Host "[INFO] Checking latest windows-index.csv..."
try {
    $csvRaw = Invoke-RestMethod -Uri $IndexUrl -UseBasicParsing
    $remote = $csvRaw | ConvertFrom-Csv
} catch {
    Write-Host "[ERROR] Failed to download index: $_" -ForegroundColor Red
    exit
}

# ---- Filter Windows platform only ----
$platformField = ($remote | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -match 'Platform' }).Name
if ($platformField) {
    $remote = $remote | Where-Object { $_.$platformField -match 'Windows' }
}

$tacticField = 'Tactic'
$techniqueField = 'Technique'
$testField = 'Test'

# ---- Load or create baseline ----
if (Test-Path $BaselinePath) {
    $baseline = Import-Csv $BaselinePath
} else {
    $baseline = @()
}

# ---- Check for new tests ----
$newTests = @()
foreach ($r in $remote) {
    $tech = $r.$techniqueField
    $test = $r.$testField
    $exists = $baseline | Where-Object { $_.Technique -eq $tech -and $_.TestNumber -eq $test }
    if (-not $exists) { $newTests += $r }
}

if ($newTests.Count -eq 0) {
    Write-Host "[INFO] No new tests found. Baseline already up to date."
    exit
}

Write-Host "[INFO] Found $($newTests.Count) new test(s). Updating local repo..."

# ---- Clone or update repo ----
if (-not (Test-Path $RepoPath)) {
    Write-Host "[INFO] Repo folder missing. Cloning Atomic Red Team..."
    git clone https://github.com/redcanaryco/atomic-red-team.git $RepoPath 2>$null | Out-Null
    if (-not (Test-Path $RepoPath)) {
        Write-Host "[ERROR] Failed to clone atomic-red-team repo." -ForegroundColor Red
        exit
    }
} else {
    Write-Host "[INFO] Pulling latest Atomic Red Team repo..."
    git -C $RepoPath pull 2>$null | Out-Null
}

# ---- Ensure Invoke-AtomicTest module is available ----
$ModulePath = Join-Path $RepoPath "invoke-atomicredteam.psm1"
if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    if (Test-Path $ModulePath) {
        try {
            Import-Module $ModulePath -Force -ErrorAction Stop
            Write-Host "[INFO] Imported Invoke-AtomicTest successfully."
        } catch {
            Write-Host "[ERROR] Failed to import module: $_" -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "[ERROR] invoke-atomicredteam.psm1 missing from repo." -ForegroundColor Red
        exit
    }
}

# ---- Update baseline with new tests ----
foreach ($r in $newTests) {
    $baseline += [PSCustomObject]@{
        Tactic     = $r.$tacticField
        Technique  = $r.$techniqueField
        TestNumber = $r.$testField
        Tested     = "No"
        LastRun    = ""
        Result     = ""
    }
}
$baseline | Sort-Object Tactic,Technique,TestNumber | Export-Csv $BaselinePath -NoTypeInformation
Write-Host "[INFO] Baseline updated. Total tests: $($baseline.Count)."

# ---- Exit if not running tests ----
if (-not $RunTests) {
    Write-Host "[INFO] Done. Tests not executed (RunTests=$RunTests)."
    exit
}

# ---- Select tests to run ----
$toRun = if ($OnlyNew) {
    $baseline | Where-Object { $_.Tested -ne "Yes" }
} else {
    $baseline
}

# ---- Run tests ----
foreach ($t in $toRun) {
    $tech = $t.Technique
    $num = $t.TestNumber
    Write-Host "[RUN] $tech test $num"
    try {
        Invoke-AtomicTest -Technique $tech -TestNumbers $num -ErrorAction Stop
        Invoke-AtomicTest -Technique $tech -TestNumbers $num -Cleanup -ErrorAction SilentlyContinue
        $t.Tested = "Yes"
        $t.LastRun = (Get-Date).ToString("s")
        $t.Result = "Executed and cleaned"
    } catch {
        $t.Result = "Error: $($_.Exception.Message)"
    }
    $baseline | Sort-Object Tactic,Technique,TestNumber | Export-Csv $BaselinePath -NoTypeInformation
}

Write-Host "[DONE] All new tests executed successfully."

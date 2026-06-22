#Requires -Version 5.1
<#
.SYNOPSIS
    Roblox Fair-Play Scanner
    Scans your PC for known injectors, illegal FastFlags, and banned network flags.

.DESCRIPTION
    Checks:
    1. Known injector / executor .exe and .dll files in common locations
    2. Running processes matching known injector names
    3. FastFlags config files for illegal flags (animation, physics, hitbox, network)
    4. Startup entries pointing to known cheats
    5. Common install directories

    RULES APPLIED:
      - FPS flags          => ALLOWED
      - Animation flags    => BANNED
      - Physics flags      => BANNED
      - Network flags      => BANNED
      - Injectors          => BANNED

.NOTES
    Run as your normal user (not Administrator) to access your own AppData.
    Running as Administrator gives broader scan coverage.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ─────────────────────────────────────────────────────────────────────────────
# COLORS / OUTPUT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
function Write-Header($text) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}
function Write-Section($text) {
    Write-Host "`n  ── $text ──" -ForegroundColor Yellow
}
function Write-Hit($label, $detail, $severity) {
    $color = switch ($severity) { "DANGER" { "Red" } "WARN" { "Yellow" } default { "Green" } }
    Write-Host "  [!] $label" -ForegroundColor $color
    if ($detail) { Write-Host "      $detail" -ForegroundColor DarkGray }
}
function Write-Clean($text) {
    Write-Host "  [OK] $text" -ForegroundColor Green
}
function Write-Info($text) {
    Write-Host "  [i] $text" -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────────────────────────────────
# DATABASES
# ─────────────────────────────────────────────────────────────────────────────

# Known injector executables
$KnownInjectors = @(
    @{ Name="Synapse X";          Files=@("synapse.exe","synapseui.exe","sxlib.dll");                   Severity="DANGER" },
    @{ Name="KRNL";               Files=@("krnl.exe","krnlss.exe");                                     Severity="DANGER" },
    @{ Name="Fluxus";             Files=@("fluxus.exe","flux.exe");                                     Severity="DANGER" },
    @{ Name="Oxygen U";           Files=@("oxygenbootstrapper.exe","oxygenx.exe");                      Severity="DANGER" },
    @{ Name="Sentinel";           Files=@("sentinel.exe","sentinelroblox.exe");                         Severity="DANGER" },
    @{ Name="Script-Ware";        Files=@("scriptware.exe","sw_roblox.exe");                            Severity="DANGER" },
    @{ Name="Arceus X";           Files=@("arceusx.exe","arceusxv3.exe");                               Severity="DANGER" },
    @{ Name="Trigon Evo";         Files=@("trigon.exe","trigonevolved.exe");                            Severity="DANGER" },
    @{ Name="Electron";           Files=@("electronexploit.exe");                                       Severity="DANGER" },
    @{ Name="ProtoSmasher";       Files=@("protosmasher.exe","ps_bin.exe");                             Severity="DANGER" },
    @{ Name="JJSploit";           Files=@("jjsploit.exe","wearedevs.exe");                              Severity="DANGER" },
    @{ Name="Vega X";             Files=@("vegax.exe","vega.exe");                                      Severity="DANGER" },
    @{ Name="Comet";              Files=@("comet.exe","cometexploit.exe");                              Severity="DANGER" },
    @{ Name="Proxo";              Files=@("proxo.exe");                                                  Severity="DANGER" },
    @{ Name="Delta Executor";     Files=@("delta.exe","deltaexecutor.exe","deltaui.exe");               Severity="DANGER" },
    @{ Name="Wave Executor";      Files=@("wave.exe","waveexecutor.exe");                               Severity="DANGER" },
    @{ Name="Hydrogen";           Files=@("hydrogen.exe","hydrogenexe.exe");                            Severity="DANGER" },
    @{ Name="Temple";             Files=@("temple.exe","templexpl.exe");                                Severity="DANGER" },
    @{ Name="Coco Z";             Files=@("cocoz.exe","coco_z.exe");                                    Severity="DANGER" },
    @{ Name="FishTrap/FishStrap"; Files=@("fishstrap.exe","fishtrap.exe","fishtrap_launcher.exe");      Severity="DANGER" },
    @{ Name="Xenos Injector";     Files=@("xenos.exe","xenos64.exe");                                   Severity="DANGER" },
    @{ Name="Cheat Engine";       Files=@("cheatengine-x86_64.exe","cheatengine.exe","ce64.exe");       Severity="DANGER" },
    @{ Name="ReClass.NET";        Files=@("reclass.net.exe","reclass64.exe");                           Severity="WARN"   },
    @{ Name="Process Hacker";     Files=@("processhacker.exe","processhacker2.exe");                    Severity="WARN"   }
)

# Injector install folders
$InjectorFolders = @(
    @{ Name="Synapse X";     Path="$env:APPDATA\Synapse X" },
    @{ Name="KRNL";          Path="$env:APPDATA\KRNL" },
    @{ Name="KRNL (Local)";  Path="$env:LOCALAPPDATA\KRNL" },
    @{ Name="Fluxus";        Path="$env:APPDATA\Fluxus" },
    @{ Name="Oxygen U";      Path="$env:APPDATA\Oxygen" },
    @{ Name="Script-Ware";   Path="$env:APPDATA\ScriptWare" },
    @{ Name="FishTrap";      Path="$env:LOCALAPPDATA\FishTrap" },
    @{ Name="Fishstrap";     Path="$env:LOCALAPPDATA\Fishstrap" },
    @{ Name="Delta";         Path="$env:APPDATA\Delta" },
    @{ Name="Wave";          Path="$env:APPDATA\Wave" },
    @{ Name="Trigon";        Path="$env:APPDATA\Trigon" },
    @{ Name="JJSploit";      Path="$env:APPDATA\JJSploit" },
    @{ Name="ProtoSmasher";  Path="$env:APPDATA\ProtoSmasher" },
    @{ Name="Sentinel";      Path="$env:APPDATA\Sentinel" }
)

# Illegal FastFlags (animation, physics, hitbox, rendering advantage)
$IllegalFlags = @(
    # Animation
    "DFFlagAnimatorPostStepJumpFix",
    "DFFlagAnimateCharacterEnable",
    "DFIntAnimationLodFacsDistanceMin",
    "FFlagAnimationEasingStyleLinear",
    "DFFlagAnimatorUseProcessorCount",
    "FFlagNewAnimationBlendingR15",
    "FFlagAvatarSelfViewEnabled",
    # Physics
    "DFIntMaxMissedWorldStepsRemembered",
    "DFIntPhysicsFPSRegulatorMaxStepsPerSec",
    "DFFlagSimWorldThrottleEnabled",
    "DFIntPhysicsReceiveNumConcurrentJobsMax",
    "DFFlagPhysicsPacketCompression",
    "DFIntPhysicsMtuOverride",
    "DFFlagFixIsGroundedExploit",
    "DFIntPhysicsGravity",
    "DFFlagDisableCSGv2",
    # Hitbox / LOD
    "DFIntCSGLevelOfDetailSwitchingDistanceL12",
    "DFIntCSGLevelOfDetailSwitchingDistance",
    "DFIntRenderLodsAutomaticBiasMultiplier",
    "FFlagFixedHitTest",
    # Rendering advantage (not FPS)
    "DFIntDebugFRMQualityLevelOverride",
    "FFlagCommitToGraphicsQualityFix",
    "FFlagDebugDisableShadows",
    "DFFlagTextureQualityOverrideEnabled"
)

# Network flags (all banned)
$NetworkFlags = @(
    "DFIntConnectionMTUSize",
    "DFIntOptimizeNetworkTransportTimout",
    "DFIntRakNetDatagramRangeMaxSize",
    "DFFlagNetworkTransportUseNewImplementation",
    "DFIntNetworkPredictionMaxMs",
    "DFIntLagCompensationMaxMs",
    "DFIntPhysicsInterpolationTimeoutMs",
    "DFFlagDebugSimIntercommunicateUseSendQueue",
    "DFIntSendDataChannelBandwidthLimit",
    "DFIntRemoteEventMaxSizeKB"
)

# FPS flags (allowed — still reported so user knows)
$FpsFlags = @(
    "DFIntTaskSchedulerTargetFps",
    "FFlagGameBasicSettingsFramerateCap",
    "FFlagDebugGraphicsPreferD3D11",
    "FFlagDebugGraphicsPreferD3D11FL10",
    "DFIntDefaultFrameRateCapLua",
    "FFlagEnableQuickGameLaunch",
    "DFFlagTextureCompositorEnabled",
    "FFlagGameBasicSettingsMemoryOptimization"
)

# FastFlags config file paths to scan
$FlagFiles = @(
    "$env:LOCALAPPDATA\Roblox\GlobalBasicSettings_13.xml",
    "$env:LOCALAPPDATA\Roblox\GlobalBasicSettings_13_api.xml",
    "$env:LOCALAPPDATA\Bloxstrap\FastFlagConfiguration.json",
    "$env:LOCALAPPDATA\FishTrap\FastFlagConfiguration.json",
    "$env:LOCALAPPDATA\Fishstrap\FastFlagConfiguration.json"
)

# Also scan ClientAppSettings.json in all Roblox version folders
$RobloxVersionsPath = "$env:LOCALAPPDATA\Roblox\Versions"
if (Test-Path $RobloxVersionsPath) {
    Get-ChildItem -Path $RobloxVersionsPath -Directory | ForEach-Object {
        $clientSettings = Join-Path $_.FullName "ClientSettings\ClientAppSettings.json"
        if (Test-Path $clientSettings) { $FlagFiles += $clientSettings }
    }
}

# Locations to scan for injector .exe files
$ScanPaths = @(
    $env:TEMP,
    $env:TMP,
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    $env:APPDATA,
    $env:LOCALAPPDATA,
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

# ─────────────────────────────────────────────────────────────────────────────
# TRACKING COUNTERS
# ─────────────────────────────────────────────────────────────────────────────
$totalHits   = 0
$totalDanger = 0
$totalWarn   = 0
$reportLines = [System.Collections.Generic.List[string]]::new()

function Log($line) { $reportLines.Add($line) }

# ─────────────────────────────────────────────────────────────────────────────
# START
# ─────────────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ██████╗  ██████╗ ██████╗ ██╗      ██████╗ ██╗  ██╗" -ForegroundColor Red
Write-Host "  ██╔══██╗██╔═══██╗██╔══██╗██║     ██╔═══██╗╚██╗██╔╝" -ForegroundColor Red
Write-Host "  ██████╔╝██║   ██║██████╔╝██║     ██║   ██║ ╚███╔╝ " -ForegroundColor Red
Write-Host "  ██╔══██╗██║   ██║██╔══██╗██║     ██║   ██║ ██╔██╗ " -ForegroundColor Red
Write-Host "  ██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝██╔╝ ██╗" -ForegroundColor Red
Write-Host "  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝" -ForegroundColor Red
Write-Host ""
Write-Host "         ROBLOX FAIR-PLAY SCANNER  v1.1" -ForegroundColor White
Write-Host "     Injectors · Illegal FastFlags · Network Flags" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Scan started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  User:         $env:USERNAME  |  Host: $env:COMPUTERNAME" -ForegroundColor DarkGray

Log "Roblox Fair-Play Scan Report"
Log "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log "User: $env:USERNAME | Host: $env:COMPUTERNAME"
Log ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — Running Processes
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 1 — Running Processes"
Log "`n[SECTION 1] Running Processes"

$runningProcesses = Get-Process | Select-Object -ExpandProperty Name
$foundRunning = $false

foreach ($inj in $KnownInjectors) {
    foreach ($file in $inj.Files) {
        $procName = [System.IO.Path]::GetFileNameWithoutExtension($file)
        if ($runningProcesses -contains $procName) {
            Write-Hit "PROCESS RUNNING: $($inj.Name)" "Process: $procName.exe  |  Severity: $($inj.Severity)" $inj.Severity
            Log "  [HIT] Process running: $procName ($($inj.Name)) [$($inj.Severity)]"
            $totalHits++
            if ($inj.Severity -eq "DANGER") { $totalDanger++ } else { $totalWarn++ }
            $foundRunning = $true
        }
    }
}
if (-not $foundRunning) {
    Write-Clean "No known injector processes currently running."
    Log "  [OK] No injector processes found running."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — Injector Install Folders
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 2 — Injector Install Folders"
Log "`n[SECTION 2] Injector Install Folders"

$foundFolders = $false
foreach ($folder in $InjectorFolders) {
    if (Test-Path $folder.Path) {
        Write-Hit "FOLDER FOUND: $($folder.Name)" $folder.Path "DANGER"
        Log "  [HIT] Folder found: $($folder.Name) => $($folder.Path) [DANGER]"
        $totalHits++
        $totalDanger++
        $foundFolders = $true
    }
}
if (-not $foundFolders) {
    Write-Clean "No known injector install folders found."
    Log "  [OK] No injector folders found."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — Injector .exe Files in Common Locations
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 3 — Injector Files in Common Directories"
Log "`n[SECTION 3] Injector Files (common directories)"
Write-Info "Scanning: Downloads, Desktop, AppData, Temp, Startup..."

$foundFiles = $false
$allInjectorFiles = $KnownInjectors | ForEach-Object { $_.Files } | Sort-Object -Unique

foreach ($scanPath in $ScanPaths) {
    if (-not (Test-Path $scanPath)) { continue }
    foreach ($fileName in $allInjectorFiles) {
        $fullPath = Join-Path $scanPath $fileName
        if (Test-Path $fullPath) {
            $injMatch  = $KnownInjectors | Where-Object { $_.Files -contains $fileName } | Select-Object -First 1
            $injName   = $injMatch.Name
            $severity  = $injMatch.Severity
            Write-Hit "FILE FOUND: $injName" $fullPath $severity
            Log "  [HIT] File: $fullPath ($injName) [$severity]"
            $totalHits++
            if ($severity -eq "DANGER") { $totalDanger++ } else { $totalWarn++ }
            $foundFiles = $true
        }
    }
}
if (-not $foundFiles) {
    Write-Clean "No injector files found in scanned directories."
    Log "  [OK] No injector files found."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — FastFlags Config Files
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 4 — FastFlags Config Files"
Log "`n[SECTION 4] FastFlags Analysis"

$foundAnyFlagFile = $false

foreach ($flagFile in $FlagFiles) {
    if (-not (Test-Path $flagFile)) { continue }
    $foundAnyFlagFile = $true
    Write-Section "Reading: $flagFile"
    Log "`n  File: $flagFile"

    try {
        $content = Get-Content -Path $flagFile -Raw -Encoding UTF8

        $illegalFound = @()
        $networkFound = @()
        $fpsFound     = @()

        foreach ($flag in $IllegalFlags) {
            if ($content -match [regex]::Escape($flag)) { $illegalFound += $flag }
        }
        foreach ($flag in $NetworkFlags) {
            if ($content -match [regex]::Escape($flag)) { $networkFound += $flag }
        }
        foreach ($flag in $FpsFlags) {
            if ($content -match [regex]::Escape($flag)) { $fpsFound += $flag }
        }

        if ($illegalFound.Count -gt 0) {
            Write-Host "  [!!] ILLEGAL FLAGS DETECTED ($($illegalFound.Count)):" -ForegroundColor Red
            foreach ($f in $illegalFound) {
                Write-Host "       - $f" -ForegroundColor Red
                Log "    [ILLEGAL] $f"
                $totalHits++
                $totalDanger++
            }
        }
        if ($networkFound.Count -gt 0) {
            Write-Host "  [!!] BANNED NETWORK FLAGS ($($networkFound.Count)):" -ForegroundColor Red
            foreach ($f in $networkFound) {
                Write-Host "       - $f" -ForegroundColor Red
                Log "    [NETWORK-BAN] $f"
                $totalHits++
                $totalDanger++
            }
        }
        if ($fpsFound.Count -gt 0) {
            Write-Host "  [OK] Allowed FPS flags ($($fpsFound.Count)) — these are fine:" -ForegroundColor Green
            foreach ($f in $fpsFound) {
                Write-Host "       - $f" -ForegroundColor DarkGreen
                Log "    [FPS-OK] $f"
            }
        }
        if ($illegalFound.Count -eq 0 -and $networkFound.Count -eq 0) {
            Write-Clean "No banned flags found in this file."
            Log "    [OK] No banned flags in this file."
        }
    }
    catch {
        Write-Host "  [ERR] Could not read file: $_" -ForegroundColor DarkRed
    }
}

if (-not $foundAnyFlagFile) {
    Write-Clean "No FastFlags config files found (Roblox may not be installed or never launched)."
    Log "  [OK] No FastFlag config files found."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — Startup Entries
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 5 — Startup Registry / Folder Entries"
Log "`n[SECTION 5] Startup Entries"

$startupPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$foundStartup = $false
foreach ($regPath in $startupPaths) {
    if (-not (Test-Path $regPath)) { continue }
    $entries = Get-ItemProperty -Path $regPath
    $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
        $val = $_.Value.ToLower()
        foreach ($inj in $KnownInjectors) {
            foreach ($file in $inj.Files) {
                if ($val -match [regex]::Escape($file.ToLower())) {
                    Write-Hit "STARTUP ENTRY: $($inj.Name)" "$($_.Name) => $($_.Value)" $inj.Severity
                    Log "  [HIT] Startup entry: $($_.Name) => $($_.Value) ($($inj.Name)) [$($inj.Severity)]"
                    $totalHits++
                    if ($inj.Severity -eq "DANGER") { $totalDanger++ } else { $totalWarn++ }
                    $foundStartup = $true
                }
            }
        }
    }
}

# Startup folder
$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $startupFolder) {
    Get-ChildItem -Path $startupFolder -File | ForEach-Object {
        $fileName = $_.Name.ToLower()
        foreach ($inj in $KnownInjectors) {
            foreach ($file in $inj.Files) {
                if ($fileName -eq $file.ToLower()) {
                    Write-Hit "STARTUP FOLDER FILE: $($inj.Name)" $_.FullName $inj.Severity
                    Log "  [HIT] Startup file: $($_.FullName) ($($inj.Name)) [$($inj.Severity)]"
                    $totalHits++
                    if ($inj.Severity -eq "DANGER") { $totalDanger++ } else { $totalWarn++ }
                    $foundStartup = $true
                }
            }
        }
    }
}

if (-not $foundStartup) {
    Write-Clean "No injector startup entries found."
    Log "  [OK] No injector startup entries found."
}

# ─────────────────────────────────────────────────────────────────────────────
# FINAL REPORT
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n"
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                     SCAN COMPLETE                           ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($totalDanger -gt 0) {
    Write-Host "  VERDICT: X  CHEATS / ILLEGAL FLAGS DETECTED" -ForegroundColor Red
    Write-Host ""
    Write-Host "  >> $totalDanger DANGER-level items found" -ForegroundColor Red
    Write-Host "  >> $totalWarn   WARNING-level items found" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ACTION REQUIRED:" -ForegroundColor White
    Write-Host "  - Uninstall or delete any injector listed above." -ForegroundColor DarkGray
    Write-Host "  - Remove banned flags from your FastFlags config files." -ForegroundColor DarkGray
    Write-Host "  - Run a full antivirus scan (Windows Defender)." -ForegroundColor DarkGray
    Write-Host "  - Check startup entries and remove any suspicious ones." -ForegroundColor DarkGray
} elseif ($totalWarn -gt 0) {
    Write-Host "  VERDICT: WARNING  WARNINGS FOUND — Review manually" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  >> $totalWarn WARNING-level items found (dual-use tools detected)" -ForegroundColor Yellow
    Write-Host "  >> These tools can be legitimate but are commonly misused with Roblox." -ForegroundColor DarkGray
} else {
    Write-Host "  VERDICT: OK  CLEAN — No cheats or illegal flags detected" -ForegroundColor Green
    Write-Host ""
    Write-Host "  >> No known injectors, executors, or banned FastFlags were found." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Total hits: $totalHits  |  Danger: $totalDanger  |  Warnings: $totalWarn" -ForegroundColor White

# Save report to desktop
$reportPath = "$env:USERPROFILE\Desktop\RobloxScanReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Log ""
Log "VERDICT: $(if ($totalDanger -gt 0) { 'CHEATS DETECTED' } elseif ($totalWarn -gt 0) { 'WARNINGS' } else { 'CLEAN' })"
Log "Total hits: $totalHits | Danger: $totalDanger | Warnings: $totalWarn"
$reportLines | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host ""
Write-Host "  Report saved to: $reportPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

#Requires -Version 5.1
<#
.SYNOPSIS
    Roblox Fair-Play Scanner v2.0 - Advanced Edition
    Deep scan: memory, DLLs, flags, injectors, drivers, registry, bypass detection.

.NOTES
    Run as Administrator for full coverage (memory scan, driver scan, HKLM registry).
    Some checks are user-level only if not elevated.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ─────────────────────────────────────────────────────────────────────────────
# ELEVATION CHECK
# ─────────────────────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
function Write-Header($text) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}
function Write-Section($text) { Write-Host "`n  ── $text ──" -ForegroundColor Yellow }
function Write-Hit($label, $detail, $severity) {
    $color = switch ($severity) { "DANGER" { "Red" } "WARN" { "Yellow" } default { "Green" } }
    Write-Host "  [!] $label" -ForegroundColor $color
    if ($detail) { Write-Host "      $detail" -ForegroundColor DarkGray }
}
function Write-Clean($text) { Write-Host "  [OK] $text" -ForegroundColor Green }
function Write-Info($text)  { Write-Host "  [i]  $text" -ForegroundColor Cyan }
function Write-Warn($text)  { Write-Host "  [W]  $text" -ForegroundColor Yellow }

$reportLines = [System.Collections.Generic.List[string]]::new()
function Log($line) { $reportLines.Add($line) }

$totalHits   = 0
$totalDanger = 0
$totalWarn   = 0

function Add-Hit($severity) {
    $script:totalHits++
    if ($severity -eq "DANGER") { $script:totalDanger++ } else { $script:totalWarn++ }
}

# ─────────────────────────────────────────────────────────────────────────────
# P/INVOKE — ReadProcessMemory (for memory scanning)
# ─────────────────────────────────────────────────────────────────────────────
$memCode = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class MemAPI {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int a, bool b, int c);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int sz, out int read);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("psapi.dll")]    public static extern bool EnumProcessModules(IntPtr h, [Out] IntPtr[] mods, int sz, out int needed);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)] public static extern uint GetModuleFileNameEx(IntPtr h, IntPtr mod, [Out] char[] fn, int sz);
    [DllImport("psapi.dll")]    public static extern bool GetModuleInformation(IntPtr h, IntPtr mod, out MODULEINFO mi, int sz);
    [StructLayout(LayoutKind.Sequential)] public struct MODULEINFO { public IntPtr BaseOfDll; public uint SizeOfImage; public IntPtr EntryPoint; }
    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
}
"@
try { Add-Type -TypeDefinition $memCode -Language CSharp } catch {}

# ─────────────────────────────────────────────────────────────────────────────
# DATABASES
# ─────────────────────────────────────────────────────────────────────────────

$KnownInjectors = @(
    @{ Name="Synapse X";          Files=@("synapse.exe","synapseui.exe","sxlib.dll","synapse x.exe");                   Severity="DANGER" },
    @{ Name="KRNL";               Files=@("krnl.exe","krnlss.exe","krnl_bootstrap.exe");                               Severity="DANGER" },
    @{ Name="Fluxus";             Files=@("fluxus.exe","flux.exe","fluxus_launcher.exe");                               Severity="DANGER" },
    @{ Name="Oxygen U";           Files=@("oxygenbootstrapper.exe","oxygenx.exe","oxygen.exe");                         Severity="DANGER" },
    @{ Name="Sentinel";           Files=@("sentinel.exe","sentinelroblox.exe","sentinel_launcher.exe");                 Severity="DANGER" },
    @{ Name="Script-Ware";        Files=@("scriptware.exe","sw_roblox.exe","scriptware_launcher.exe");                  Severity="DANGER" },
    @{ Name="Arceus X";           Files=@("arceusx.exe","arceusxv3.exe","arceus.exe");                                  Severity="DANGER" },
    @{ Name="Trigon Evo";         Files=@("trigon.exe","trigonevolved.exe","trigon_evo.exe");                           Severity="DANGER" },
    @{ Name="Electron";           Files=@("electronexploit.exe","electron_exploit.exe");                                Severity="DANGER" },
    @{ Name="ProtoSmasher";       Files=@("protosmasher.exe","ps_bin.exe","proto.exe");                                 Severity="DANGER" },
    @{ Name="JJSploit";           Files=@("jjsploit.exe","wearedevs.exe","jj.exe");                                    Severity="DANGER" },
    @{ Name="Vega X";             Files=@("vegax.exe","vega.exe","vegax_launcher.exe");                                 Severity="DANGER" },
    @{ Name="Comet";              Files=@("comet.exe","cometexploit.exe");                                              Severity="DANGER" },
    @{ Name="Proxo";              Files=@("proxo.exe","proxo_launcher.exe");                                            Severity="DANGER" },
    @{ Name="Delta Executor";     Files=@("delta.exe","deltaexecutor.exe","deltaui.exe","delta_launcher.exe");          Severity="DANGER" },
    @{ Name="Wave Executor";      Files=@("wave.exe","waveexecutor.exe","wave_launcher.exe");                           Severity="DANGER" },
    @{ Name="Hydrogen";           Files=@("hydrogen.exe","hydrogenexe.exe");                                            Severity="DANGER" },
    @{ Name="Temple";             Files=@("temple.exe","templexpl.exe");                                                Severity="DANGER" },
    @{ Name="Coco Z";             Files=@("cocoz.exe","coco_z.exe");                                                    Severity="DANGER" },
    @{ Name="FishTrap/Fishstrap"; Files=@("fishstrap.exe","fishtrap.exe","fishtrap_launcher.exe","fishstrap_launcher.exe"); Severity="DANGER" },
    @{ Name="Xenos Injector";     Files=@("xenos.exe","xenos64.exe");                                                   Severity="DANGER" },
    @{ Name="Cheat Engine";       Files=@("cheatengine-x86_64.exe","cheatengine.exe","ce64.exe","cheatengine-i386.exe"); Severity="DANGER" },
    @{ Name="Seliware";           Files=@("seliware.exe","seli.exe");                                                   Severity="DANGER" },
    @{ Name="Carat";              Files=@("carat.exe","caratexploit.exe");                                              Severity="DANGER" },
    @{ Name="Zorara";             Files=@("zorara.exe");                                                                Severity="DANGER" },
    @{ Name="Solara";             Files=@("solara.exe","solara_launcher.exe");                                          Severity="DANGER" },
    @{ Name="Evon";               Files=@("evon.exe","evonexploit.exe");                                                Severity="DANGER" },
    @{ Name="ReClass.NET";        Files=@("reclass.net.exe","reclass64.exe");                                           Severity="WARN"   },
    @{ Name="Process Hacker";     Files=@("processhacker.exe","processhacker2.exe","systeminformer.exe");               Severity="WARN"   },
    @{ Name="x64dbg/x32dbg";      Files=@("x64dbg.exe","x32dbg.exe");                                                  Severity="WARN"   },
    @{ Name="Wireshark";          Files=@("wireshark.exe");                                                             Severity="WARN"   }
)

# Known malicious DLLs injected into Roblox
$KnownBadDlls = @(
    "sxlib.dll","synapse.dll","krnl.dll","fluxlib.dll","celery.dll",
    "oxysdk.dll","sw_sdk.dll","trigon_sdk.dll","hydrogen_sdk.dll",
    "ProtoLib.dll","jjsploitlib.dll","vegalib.dll","cometlib.dll",
    "delta_sdk.dll","wave_sdk.dll","rbxfpsunlocker.dll",
    "lua51.dll","luau.dll","luajit.dll"
)

# Known suspicious driver names (kernel-level cheats)
$SuspiciousDrivers = @(
    "kdmapper","kduhelper","dbutil","dbutil_2_3","WinRing0x64",
    "RZPNK","rtcore64","mhyprot","mhyprot2","gdrv","capcom",
    "iqvw64e","nvflash","amifldrv64","glckio2","gmer"
)

$InjectorFolders = @(
    @{ Name="Synapse X";         Path="$env:APPDATA\Synapse X" },
    @{ Name="Synapse Z";         Path="$env:APPDATA\Synapse Z" },
    @{ Name="KRNL";              Path="$env:APPDATA\KRNL" },
    @{ Name="KRNL (Local)";      Path="$env:LOCALAPPDATA\KRNL" },
    @{ Name="Fluxus";            Path="$env:APPDATA\Fluxus" },
    @{ Name="Oxygen U";          Path="$env:APPDATA\Oxygen" },
    @{ Name="Script-Ware";       Path="$env:APPDATA\ScriptWare" },
    @{ Name="FishTrap";          Path="$env:LOCALAPPDATA\FishTrap" },
    @{ Name="Fishstrap";         Path="$env:LOCALAPPDATA\Fishstrap" },
    @{ Name="Delta";             Path="$env:APPDATA\Delta" },
    @{ Name="Wave";              Path="$env:APPDATA\Wave" },
    @{ Name="Trigon";            Path="$env:APPDATA\Trigon" },
    @{ Name="JJSploit";          Path="$env:APPDATA\JJSploit" },
    @{ Name="ProtoSmasher";      Path="$env:APPDATA\ProtoSmasher" },
    @{ Name="Sentinel";          Path="$env:APPDATA\Sentinel" },
    @{ Name="Seliware";          Path="$env:APPDATA\Seliware" },
    @{ Name="Solara";            Path="$env:LOCALAPPDATA\Solara" },
    @{ Name="Evon";              Path="$env:APPDATA\Evon" },
    @{ Name="Zorara";            Path="$env:APPDATA\Zorara" },
    @{ Name="Hydrogen";          Path="$env:APPDATA\Hydrogen" },
    @{ Name="Carat";             Path="$env:APPDATA\Carat" }
)

# ALL illegal FastFlags
$IllegalFlags = @(
    # === ANIMATION (BANNED) ===
    "DFFlagAnimatorPostStepJumpFix",
    "DFFlagAnimateCharacterEnable",
    "DFIntAnimationLodFacsDistanceMin",
    "FFlagAnimationEasingStyleLinear",
    "DFFlagAnimatorUseProcessorCount",
    "FFlagNewAnimationBlendingR15",
    "FFlagAvatarSelfViewEnabled",
    "DFFlagEnableAnimationEasingStyles",
    "FFlagFixAnimationWeightedBlend",
    "DFIntAnimationBuildLodFacsDistanceMax",

    # === PHYSICS (BANNED) ===
    "DFIntMaxMissedWorldStepsRemembered",
    "DFIntPhysicsFPSRegulatorMaxStepsPerSec",
    "DFFlagSimWorldThrottleEnabled",
    "DFIntPhysicsReceiveNumConcurrentJobsMax",
    "DFFlagPhysicsPacketCompression",
    "DFIntPhysicsMtuOverride",
    "DFFlagFixIsGroundedExploit",
    "DFIntPhysicsGravity",
    "DFFlagDisableCSGv2",
    "DFIntPhysicsStepsPerSecond",
    "DFFlagPhysicsSkipNonRealTimeKernelUpdates",
    "DFIntSimWorldThrottleAdjustTime",
    "DFIntSimWorldThrottleMaxJobs",
    "DFIntMegaReplicatorNumParallelTasks",
    "DFFlagUseDeltaTimeInFallingRagdoll",

    # === HITBOX / LOD (BANNED) ===
    "DFIntCSGLevelOfDetailSwitchingDistanceL12",
    "DFIntCSGLevelOfDetailSwitchingDistance",
    "DFIntRenderLodsAutomaticBiasMultiplier",
    "FFlagFixedHitTest",
    "DFIntCSGLevelOfDetailSwitchingDistanceL23",
    "DFIntCSGLevelOfDetailSwitchingDistanceL34",
    "FFlagHumanoidCacheRecalcOnResize",
    "DFIntHumanoidRootPartUpdateAlgorithm",

    # === RENDERING ADVANTAGE (BANNED - not FPS) ===
    "DFIntDebugFRMQualityLevelOverride",
    "FFlagCommitToGraphicsQualityFix",
    "FFlagDebugDisableShadows",
    "DFFlagTextureQualityOverrideEnabled",
    "DFIntRenderShadowmapBias",
    "FFlagDebugForceFSMCPULightCulling",
    "DFIntRenderClampRoughnessMax",
    "FFlagNewLightAttenuation",
    "DFFlagDebugRenderForceToonShader",
    "FFlagCloudsReflectOnWater",
    "FFlagResetInterpolatedCFrameOnTimeout",

    # === TELEPORT / SPEED ABUSE (BANNED) ===
    "DFIntMaxClientCharacterUpdateUnreliableGameDistance",
    "DFIntMinClientCharacterUpdateUnreliableGameDistance",
    "DFIntOptimizeNetworkTransportTimout",
    "DFIntReplicationDataCacheNumSamplesPerStep",
    "FFlagSimAdaptiveTimesteppingDefault2",
    "DFIntPhysicsPacketSendRateMax"
)

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
    "DFIntRemoteEventMaxSizeKB",
    "DFIntMaxDataModelSendBuffer",
    "DFIntNetworkPredictionNumSmoothingSteps",
    "DFIntMaxNetworkBytesPerSecond",
    "DFIntRakNetResendBufferArrayLength",
    "DFFlagNetworkTransportLoggedOutRateLimit"
)

$FpsFlags = @(
    "DFIntTaskSchedulerTargetFps",
    "FFlagGameBasicSettingsFramerateCap",
    "FFlagDebugGraphicsPreferD3D11",
    "FFlagDebugGraphicsPreferD3D11FL10",
    "DFIntDefaultFrameRateCapLua",
    "FFlagEnableQuickGameLaunch",
    "DFFlagTextureCompositorEnabled",
    "FFlagGameBasicSettingsMemoryOptimization",
    "FFlagGraphicsEnableD3D10Compute",
    "DFFlagGraphicsOptimizeVolumes"
)

# All places FastFlags can live
$FlagFiles = [System.Collections.Generic.List[string]]::new()
@(
    "$env:LOCALAPPDATA\Roblox\GlobalBasicSettings_13.xml",
    "$env:LOCALAPPDATA\Roblox\GlobalBasicSettings_13_api.xml",
    "$env:LOCALAPPDATA\Bloxstrap\FastFlagConfiguration.json",
    "$env:LOCALAPPDATA\FishTrap\FastFlagConfiguration.json",
    "$env:LOCALAPPDATA\Fishstrap\FastFlagConfiguration.json",
    "$env:APPDATA\Bloxstrap\FastFlagConfiguration.json",
    "$env:LOCALAPPDATA\Roblox\ClientSettings\ClientAppSettings.json"
) | ForEach-Object { $FlagFiles.Add($_) }

# Bloxstrap profiles
$bloxstrapProfiles = "$env:LOCALAPPDATA\Bloxstrap\Profiles"
if (Test-Path $bloxstrapProfiles) {
    Get-ChildItem -Path $bloxstrapProfiles -Filter "*.json" -Recurse | ForEach-Object { $FlagFiles.Add($_.FullName) }
}

# All Roblox version folders
$robloxVersions = "$env:LOCALAPPDATA\Roblox\Versions"
if (Test-Path $robloxVersions) {
    Get-ChildItem -Path $robloxVersions -Directory | ForEach-Object {
        $cs = Join-Path $_.FullName "ClientSettings\ClientAppSettings.json"
        if (Test-Path $cs) { $FlagFiles.Add($cs) }
    }
}

$ScanPaths = @(
    $env:TEMP, $env:TMP,
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    $env:APPDATA, $env:LOCALAPPDATA,
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:USERPROFILE\Documents",
    "C:\Users\Public"
)

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
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
Write-Host "      ROBLOX FAIR-PLAY SCANNER  v2.0  [ADVANCED]" -ForegroundColor White
Write-Host "  Memory · DLL Injection · FastFlags · Drivers · Registry" -ForegroundColor DarkGray
Write-Host ""
$adminLabel = if ($isAdmin) { "YES (Full scan)" } else { "NO  (Limited — run as Admin for memory/driver scan)" }
Write-Host "  Admin:        $adminLabel" -ForegroundColor $(if ($isAdmin) { "Green" } else { "Yellow" })
Write-Host "  Scan started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  User:         $env:USERNAME  |  Host: $env:COMPUTERNAME" -ForegroundColor DarkGray

Log "Roblox Fair-Play Scanner v2.0"
Log "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log "User: $env:USERNAME | Host: $env:COMPUTERNAME | Admin: $isAdmin"
Log ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — Running Processes
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 1 — Running Processes"
Log "`n[SECTION 1] Running Processes"

$runningProcs = Get-Process -ErrorAction SilentlyContinue
$foundRunning = $false

foreach ($inj in $KnownInjectors) {
    foreach ($file in $inj.Files) {
        $procName = [System.IO.Path]::GetFileNameWithoutExtension($file)
        $match = $runningProcs | Where-Object { $_.Name -ieq $procName }
        if ($match) {
            $pid_ = ($match | Select-Object -First 1).Id
            Write-Hit "PROCESS RUNNING: $($inj.Name)" "PID: $pid_  |  Process: $procName.exe  |  Severity: $($inj.Severity)" $inj.Severity
            Log "  [HIT] Process running: $procName (PID:$pid_) ($($inj.Name)) [$($inj.Severity)]"
            Add-Hit $inj.Severity
            $foundRunning = $true
        }
    }
}
if (-not $foundRunning) {
    Write-Clean "No known injector processes currently running."
    Log "  [OK] No injector processes running."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — DLLs Injected into Roblox Process
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 2 — DLL Injection in Roblox Process"
Log "`n[SECTION 2] DLL Injection"

$robloxProc = Get-Process -Name "RobloxPlayerBeta","eurotrucks2","RobloxPlayer" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($robloxProc) {
    Write-Info "Roblox is running (PID: $($robloxProc.Id)) — scanning loaded modules..."
    Log "  Roblox PID: $($robloxProc.Id)"
    $foundBadDll = $false

    try {
        $modules = $robloxProc.Modules | Select-Object -ExpandProperty ModuleName -ErrorAction SilentlyContinue
        foreach ($dll in $KnownBadDlls) {
            if ($modules -icontains $dll) {
                Write-Hit "INJECTED DLL: $dll" "Found in RobloxPlayerBeta.exe modules" "DANGER"
                Log "  [HIT] Injected DLL: $dll [DANGER]"
                Add-Hit "DANGER"
                $foundBadDll = $true
            }
        }
        # Also check for any dll not from Roblox/Windows folders
        $suspModules = $modules | Where-Object {
            $_ -notmatch "^(RobloxPlayerBeta|ntdll|kernel32|user32|gdi32|advapi32|ole32|shell32|ws2_32|msvcrt|vcruntime|msvcp|ucrtbase|winmm|d3d|dxgi|opengl|vulkan|nvidia|amd|intel)" -and
            $_ -match "\.dll$"
        }
        if ($suspModules) {
            Write-Warn "Unusual DLLs found in Roblox process (may be injected):"
            foreach ($m in $suspModules | Select-Object -First 20) {
                Write-Host "       ? $m" -ForegroundColor Yellow
                Log "  [SUSPICIOUS DLL] $m"
            }
        }
        if (-not $foundBadDll) {
            Write-Clean "No known malicious DLLs found in Roblox process."
            Log "  [OK] No known bad DLLs injected."
        }
    } catch {
        Write-Warn "Could not enumerate Roblox modules. Run as Administrator for full DLL scan."
        Log "  [WARN] Module enumeration failed (need Admin)."
    }
} else {
    Write-Info "Roblox is not currently running. Start Roblox then re-run for DLL injection scan."
    Log "  [INFO] Roblox not running — DLL scan skipped."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — FastFlags (ALL LOCATIONS including memory strings)
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 3 — FastFlags (Files + Registry + Memory)"
Log "`n[SECTION 3] FastFlags"

$foundAnyFlagFile = $false
$allFlagHits = [System.Collections.Generic.List[string]]::new()

# 3A — File scan
Write-Section "3A — Config File Scan"
$uniqueFlagFiles = $FlagFiles | Sort-Object -Unique
foreach ($flagFile in $uniqueFlagFiles) {
    if (-not (Test-Path $flagFile)) { continue }
    $foundAnyFlagFile = $true
    Write-Info "Scanning: $flagFile"
    Log "  File: $flagFile"

    try {
        $content = Get-Content -Path $flagFile -Raw -Encoding UTF8 -ErrorAction Stop
        $illegalFound = @(); $networkFound = @(); $fpsFound = @()

        foreach ($flag in $IllegalFlags) { if ($content -match [regex]::Escape($flag)) { $illegalFound += $flag } }
        foreach ($flag in $NetworkFlags) { if ($content -match [regex]::Escape($flag)) { $networkFound += $flag } }
        foreach ($flag in $FpsFlags)     { if ($content -match [regex]::Escape($flag)) { $fpsFound += $flag } }

        if ($illegalFound.Count -gt 0) {
            Write-Host "  [!!] ILLEGAL FLAGS ($($illegalFound.Count)) in $([System.IO.Path]::GetFileName($flagFile)):" -ForegroundColor Red
            foreach ($f in $illegalFound) {
                # Try to extract value
                $valMatch = [regex]::Match($content, [regex]::Escape($f) + '"?\s*[=:]\s*"?([^",}\s]+)')
                $valStr = if ($valMatch.Success) { " = $($valMatch.Groups[1].Value)" } else { "" }
                Write-Host "       - $f$valStr" -ForegroundColor Red
                Log "    [ILLEGAL] $f$valStr"
                $allFlagHits.Add($f)
                Add-Hit "DANGER"
            }
        }
        if ($networkFound.Count -gt 0) {
            Write-Host "  [!!] BANNED NETWORK FLAGS ($($networkFound.Count)):" -ForegroundColor Red
            foreach ($f in $networkFound) {
                Write-Host "       - $f" -ForegroundColor Red
                Log "    [NETWORK-BAN] $f"
                $allFlagHits.Add($f)
                Add-Hit "DANGER"
            }
        }
        if ($fpsFound.Count -gt 0) {
            Write-Host "  [OK] Allowed FPS flags ($($fpsFound.Count)) — OK:" -ForegroundColor Green
            foreach ($f in $fpsFound) { Write-Host "       - $f" -ForegroundColor DarkGreen; Log "    [FPS-OK] $f" }
        }
        if ($illegalFound.Count -eq 0 -and $networkFound.Count -eq 0) {
            Write-Clean "No banned flags in: $([System.IO.Path]::GetFileName($flagFile))"
            Log "    [OK] Clean."
        }
    } catch {
        Write-Warn "Could not read: $flagFile"
    }
}

if (-not $foundAnyFlagFile) {
    Write-Warn "No FastFlags config files found. Checking registry and memory..."
    Log "  [INFO] No config files found."
}

# 3B — Registry FastFlags scan
Write-Section "3B — Registry FastFlags Scan"
Log "  Registry FastFlags:"
$regFlagPaths = @(
    "HKCU:\Software\Roblox",
    "HKLM:\Software\Roblox",
    "HKCU:\Software\ROBLOX Corporation",
    "HKLM:\Software\ROBLOX Corporation"
)
$foundRegFlags = $false
foreach ($regPath in $regFlagPaths) {
    if (-not (Test-Path $regPath)) { continue }
    $allKeys = Get-ChildItem -Path $regPath -Recurse -ErrorAction SilentlyContinue
    foreach ($key in $allKeys) {
        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            $name = $_.Name; $val = $_.Value
            foreach ($flag in ($IllegalFlags + $NetworkFlags)) {
                if ($name -ieq $flag) {
                    Write-Hit "REGISTRY FLAG: $name = $val" $key.PSPath "DANGER"
                    Log "  [HIT] Registry flag: $name = $val @ $($key.PSPath)"
                    Add-Hit "DANGER"
                    $foundRegFlags = $true
                }
            }
        }
    }
}
if (-not $foundRegFlags) {
    Write-Clean "No illegal FastFlags found in registry."
    Log "  [OK] Registry clean."
}

# 3C — Memory scan of Roblox for active flags
Write-Section "3C — Live Memory Scan (Roblox process)"
Log "  Memory Scan:"
if ($robloxProc -and $isAdmin) {
    Write-Info "Scanning Roblox memory for active FastFlag strings..."
    $hProcess = [MemAPI]::OpenProcess(0x0010 -bor 0x0400, $false, $robloxProc.Id)
    if ($hProcess -ne [IntPtr]::Zero) {
        $foundMemFlags = $false
        # We scan the first heap regions — read 64KB chunks looking for flag strings
        $allSearchFlags = $IllegalFlags + $NetworkFlags
        $buf = New-Object byte[] 65536
        $baseAddr = [IntPtr]0x10000
        $maxAddr  = [IntPtr]0x7FFFFFFF
        $scanned  = 0
        $addr = $baseAddr
        while ($addr.ToInt64() -lt $maxAddr.ToInt64() -and $scanned -lt 500) {
            $read = 0
            $ok = [MemAPI]::ReadProcessMemory($hProcess, $addr, $buf, $buf.Length, [ref]$read)
            if ($ok -and $read -gt 0) {
                $str = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
                foreach ($flag in $allSearchFlags) {
                    if ($str.Contains($flag)) {
                        Write-Hit "MEMORY FLAG ACTIVE: $flag" "Found in Roblox process memory at ~0x$($addr.ToString('X'))" "DANGER"
                        Log "  [HIT] Memory flag: $flag @ ~0x$($addr.ToString('X'))"
                        if (-not $allFlagHits.Contains($flag)) {
                            Add-Hit "DANGER"
                            $allFlagHits.Add($flag)
                        }
                        $foundMemFlags = $true
                    }
                }
            }
            $addr = [IntPtr]($addr.ToInt64() + 65536)
            $scanned++
        }
        [MemAPI]::CloseHandle($hProcess) | Out-Null
        if (-not $foundMemFlags) {
            Write-Clean "No illegal flags found active in Roblox memory."
            Log "  [OK] Memory clean."
        }
    } else {
        Write-Warn "Could not open Roblox process handle for memory scan."
        Log "  [WARN] Memory handle failed."
    }
} elseif (-not $isAdmin) {
    Write-Warn "Memory scan requires Administrator. Re-run as Admin for live memory scan."
    Log "  [SKIP] Memory scan skipped (not Admin)."
} else {
    Write-Info "Roblox not running — memory scan skipped."
    Log "  [SKIP] Roblox not running."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — Injector Install Folders
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 4 — Injector Install Folders"
Log "`n[SECTION 4] Injector Folders"

$foundFolders = $false
foreach ($folder in $InjectorFolders) {
    if (Test-Path $folder.Path) {
        $size = (Get-ChildItem -Path $folder.Path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        $sizeMB = [math]::Round($size / 1MB, 2)
        Write-Hit "FOLDER: $($folder.Name)" "$($folder.Path)  [$sizeMB MB]" "DANGER"
        Log "  [HIT] Folder: $($folder.Name) => $($folder.Path) [$sizeMB MB]"
        Add-Hit "DANGER"
        $foundFolders = $true
    }
}
if (-not $foundFolders) {
    Write-Clean "No known injector install folders found."
    Log "  [OK] No injector folders."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — File Scan (Downloads, Desktop, AppData, etc.)
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 5 — Injector Files in Common Directories"
Log "`n[SECTION 5] File Scan"
Write-Info "Scanning common locations for injector executables..."

$foundFiles = $false
$allInjectorFiles = $KnownInjectors | ForEach-Object { $_.Files } | Sort-Object -Unique

foreach ($scanPath in $ScanPaths) {
    if (-not (Test-Path $scanPath)) { continue }
    foreach ($fileName in $allInjectorFiles) {
        $fullPath = Join-Path $scanPath $fileName
        if (Test-Path $fullPath) {
            $injMatch = $KnownInjectors | Where-Object { $_.Files -contains $fileName } | Select-Object -First 1
            # Get file hash for report
            $hash = (Get-FileHash -Path $fullPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            Write-Hit "FILE: $($injMatch.Name)" "$fullPath`n      SHA256: $hash" $injMatch.Severity
            Log "  [HIT] $fullPath ($($injMatch.Name)) [$($injMatch.Severity)] SHA256:$hash"
            Add-Hit $injMatch.Severity
            $foundFiles = $true
        }
    }
}
if (-not $foundFiles) {
    Write-Clean "No injector files found in scanned directories."
    Log "  [OK] No injector files found."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — Roblox Executable Integrity
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 6 — Roblox Executable Integrity"
Log "`n[SECTION 6] Exe Integrity"
Write-Info "Checking RobloxPlayerBeta.exe for signs of patching..."

$robloxExes = @()
if (Test-Path $robloxVersions) {
    Get-ChildItem -Path $robloxVersions -Filter "RobloxPlayerBeta.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $robloxExes += $_.FullName
    }
}
if (Test-Path "$env:LOCALAPPDATA\Roblox\RobloxPlayerBeta.exe") {
    $robloxExes += "$env:LOCALAPPDATA\Roblox\RobloxPlayerBeta.exe"
}

if ($robloxExes.Count -gt 0) {
    foreach ($exe in $robloxExes) {
        $sig = Get-AuthenticodeSignature -FilePath $exe -ErrorAction SilentlyContinue
        $hash = (Get-FileHash -Path $exe -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $size = (Get-Item $exe).Length
        Write-Info "File: $exe"
        Write-Info "SHA256: $hash"
        Write-Info "Size: $size bytes"
        Log "  Exe: $exe | SHA256: $hash | Size: $size"
        if ($sig.Status -ne "Valid") {
            Write-Hit "SIGNATURE INVALID: RobloxPlayerBeta.exe may be patched!" "Sig status: $($sig.Status)" "DANGER"
            Log "  [HIT] Invalid signature: $($sig.Status)"
            Add-Hit "DANGER"
        } else {
            Write-Clean "Authenticode signature valid."
            Log "  [OK] Signature valid."
        }
    }
} else {
    Write-Info "RobloxPlayerBeta.exe not found (Roblox may not be installed)."
    Log "  [INFO] Roblox exe not found."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — Suspicious Kernel Drivers
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 7 — Suspicious Kernel Drivers"
Log "`n[SECTION 7] Drivers"

if ($isAdmin) {
    Write-Info "Scanning loaded drivers..."
    $drivers = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue
    $foundDriver = $false
    foreach ($drv in $drivers) {
        foreach ($sus in $SuspiciousDrivers) {
            if ($drv.Name -imatch $sus -or $drv.PathName -imatch $sus) {
                Write-Hit "SUSPICIOUS DRIVER: $($drv.Name)" "Path: $($drv.PathName)  |  State: $($drv.State)" "DANGER"
                Log "  [HIT] Driver: $($drv.Name) @ $($drv.PathName)"
                Add-Hit "DANGER"
                $foundDriver = $true
            }
        }
    }
    if (-not $foundDriver) {
        Write-Clean "No suspicious kernel drivers found."
        Log "  [OK] No suspicious drivers."
    }
} else {
    Write-Warn "Driver scan requires Administrator. Re-run as Admin."
    Log "  [SKIP] Driver scan (not Admin)."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8 — Startup Entries
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 8 — Startup Entries"
Log "`n[SECTION 8] Startup"

$startupRegPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$foundStartup = $false
foreach ($regPath in $startupRegPaths) {
    if (-not (Test-Path $regPath)) { continue }
    $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if (-not $entries) { continue }
    $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
        $val = $_.Value.ToLower()
        foreach ($inj in $KnownInjectors) {
            foreach ($file in $inj.Files) {
                if ($val -match [regex]::Escape($file.ToLower())) {
                    Write-Hit "STARTUP ENTRY: $($inj.Name)" "$($_.Name) => $($_.Value)" $inj.Severity
                    Log "  [HIT] Startup: $($_.Name) => $($_.Value)"
                    Add-Hit $inj.Severity
                    $foundStartup = $true
                }
            }
        }
    }
}

$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $startupFolder) {
    Get-ChildItem -Path $startupFolder -File -ErrorAction SilentlyContinue | ForEach-Object {
        $fn = $_.Name.ToLower()
        foreach ($inj in $KnownInjectors) {
            foreach ($file in $inj.Files) {
                if ($fn -eq $file.ToLower()) {
                    Write-Hit "STARTUP FILE: $($inj.Name)" $_.FullName $inj.Severity
                    Log "  [HIT] Startup file: $($_.FullName)"
                    Add-Hit $inj.Severity
                    $foundStartup = $true
                }
            }
        }
    }
}

if (-not $foundStartup) {
    Write-Clean "No injector startup entries found."
    Log "  [OK] No startup entries."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9 — Hosts File Tampering
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 9 — Hosts File & Network Tampering"
Log "`n[SECTION 9] Hosts File"

$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
    $robloxLines  = $hostsContent | Where-Object { $_ -match "roblox" -and $_ -notmatch "^#" }
    if ($robloxLines) {
        Write-Hit "HOSTS FILE TAMPERED" "Roblox-related entries found in hosts file:" "WARN"
        foreach ($line in $robloxLines) {
            Write-Host "       $line" -ForegroundColor Yellow
            Log "  [WARN] Hosts entry: $line"
        }
        Add-Hit "WARN"
    } else {
        Write-Clean "Hosts file looks normal (no Roblox entries)."
        Log "  [OK] Hosts file clean."
    }
} else {
    Write-Warn "Could not read hosts file."
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10 — Suspicious Lua Scripts in Roblox folders
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SECTION 10 — Suspicious Script Files"
Log "`n[SECTION 10] Script Files"
Write-Info "Scanning for .lua / .luau / .rbxl script files outside normal paths..."

$scriptPaths = @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:APPDATA","$env:LOCALAPPDATA\Temp")
$suspKeywords = @("getrawmetatable","hookfunction","hookmetamethod","fireclickdetector","firetouchinterest","syn.","fluxus.","KRNL_","getgenv","getsenv","loadstring","game:HttpGet","require(","while true do","ESP","aimbot","wallhack","noclip","inf jump","speed hack","fly hack","kill all","bring all")
$foundScripts = $false

foreach ($sp in $scriptPaths) {
    if (-not (Test-Path $sp)) { continue }
    Get-ChildItem -Path $sp -Include "*.lua","*.luau","*.rbxl","*.rbxm" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 50 | ForEach-Object {
        $scriptContent = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $scriptContent) { return }
        $hits = $suspKeywords | Where-Object { $scriptContent -imatch [regex]::Escape($_) }
        if ($hits.Count -ge 2) {
            Write-Hit "SUSPICIOUS SCRIPT: $($_.Name)" "$($_.FullName)`n      Keywords: $($hits -join ', ')" "WARN"
            Log "  [HIT] Script: $($_.FullName) | Keywords: $($hits -join ',')"
            Add-Hit "WARN"
            $foundScripts = $true
        }
    }
}
if (-not $foundScripts) {
    Write-Clean "No suspicious script files found."
    Log "  [OK] No suspicious scripts."
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
    Write-Host "  VERDICT: [X] CHEATS / ILLEGAL FLAGS DETECTED" -ForegroundColor Red
    Write-Host ""
    Write-Host "  >> $totalDanger DANGER-level items found" -ForegroundColor Red
    Write-Host "  >> $totalWarn   WARNING-level items found" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ACTION REQUIRED:" -ForegroundColor White
    Write-Host "    1. Uninstall all injectors/executors listed above." -ForegroundColor DarkGray
    Write-Host "    2. Delete banned FastFlags from ALL config files." -ForegroundColor DarkGray
    Write-Host "    3. Run Windows Defender full scan." -ForegroundColor DarkGray
    Write-Host "    4. Remove any startup entries pointing to cheats." -ForegroundColor DarkGray
    Write-Host "    5. Reinstall Roblox if exe signature was invalid." -ForegroundColor DarkGray
} elseif ($totalWarn -gt 0) {
    Write-Host "  VERDICT: [W] WARNINGS — Review manually" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  >> $totalWarn WARNING-level items (dual-use tools or suspicious files)" -ForegroundColor Yellow
} else {
    Write-Host "  VERDICT: [OK] CLEAN — No cheats or illegal flags detected" -ForegroundColor Green
    Write-Host ""
    Write-Host "  >> No known injectors, executors, or banned FastFlags found." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Total hits: $totalHits  |  Danger: $totalDanger  |  Warnings: $totalWarn" -ForegroundColor White

# Save report
$reportPath = "$env:USERPROFILE\Desktop\RobloxScanReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Log ""
Log "VERDICT: $(if ($totalDanger -gt 0) { 'CHEATS DETECTED' } elseif ($totalWarn -gt 0) { 'WARNINGS' } else { 'CLEAN' })"
Log "Total hits: $totalHits | Danger: $totalDanger | Warnings: $totalWarn"
$reportLines | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host ""
Write-Host "  Report saved: $reportPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

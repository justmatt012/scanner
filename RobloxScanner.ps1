#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ╔══════════════════════════════════════════════════════════════════════════╗
#  ROBLOX ANTI-CHEAT SCANNER  v4.0  |  github.com/justmatt012/scanner
#  Scans: FastFlags · Injectors · Memory · DLLs · Drivers · Registry
# ╚══════════════════════════════════════════════════════════════════════════╝

$VER    = "4.0"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
$report  = [System.Collections.Generic.List[string]]::new()
$hits    = @{ CHEAT=0; NETWORK=0; PHYSICS=0; VISUAL=0; FPS=0; WARN=0 }

function Log($x) { $report.Add($x) }

# ──────────────────────────────────────────────────────────────────────────────
#  VISUAL ENGINE
# ──────────────────────────────────────────────────────────────────────────────
function Write-Banner {
    param($text, $color = "Cyan")
    $pad  = 64
    $line = [string]::new([char]0x2550, $pad)   # ══
    $tpad = $text.PadRight($pad - 2)
    Write-Host ""
    Write-Host "  $([char]0x2554)$line$([char]0x2557)" -ForegroundColor $color
    Write-Host "  $([char]0x2551)  $tpad$([char]0x2551)" -ForegroundColor White
    Write-Host "  $([char]0x255A)$line$([char]0x255D)" -ForegroundColor $color
}

function Write-Sub($t)  { Write-Host "`n  $([char]0x251C)$([char]0x2500) $t" -ForegroundColor Yellow }
function Write-OK($t)   { Write-Host "  $([char]0x2502)  $([char]0x2714) $t" -ForegroundColor Green }
function Write-INFO($t) { Write-Host "  $([char]0x2502)  $([char]0x25B8) $t" -ForegroundColor DarkCyan }
function Write-SKIP($t) { Write-Host "  $([char]0x2502)  - $t" -ForegroundColor DarkGray }

function Write-HIT {
    param($cat, $label, $detail = "")
    $col = switch ($cat) {
        "CHEAT"   { "Red"         }
        "NETWORK" { "DarkYellow"  }
        "PHYSICS" { "Magenta"     }
        "VISUAL"  { "DarkMagenta" }
        "FPS"     { "Green"       }
        default   { "Yellow"      }
    }
    $tag = "[$cat]".PadRight(9)
    Write-Host "  $([char]0x2502)  $tag $label" -ForegroundColor $col
    if ($detail) { Write-Host "  $([char]0x2502)           $([char]0x2514)$([char]0x2500) $detail" -ForegroundColor DarkGray }
    $script:hits[$cat]++
    Log "[$cat] $label | $detail"
}

function Write-FlagHit {
    param($cat, $name, $value, $desc = "")
    $col = switch ($cat) {
        "CHEAT"   { "Red"         }
        "NETWORK" { "DarkYellow"  }
        "PHYSICS" { "Magenta"     }
        "VISUAL"  { "DarkMagenta" }
        "FPS"     { "Green"       }
        default   { "Yellow"      }
    }
    $tag = "[$cat]".PadRight(9)
    Write-Host "  $([char]0x2502)  $tag $name" -NoNewline -ForegroundColor $col
    Write-Host " = " -NoNewline -ForegroundColor DarkGray
    Write-Host $value -ForegroundColor White
    if ($desc) { Write-Host "  $([char]0x2502)           $([char]0x2514)$([char]0x2500) $desc" -ForegroundColor DarkGray }
    $script:hits[$cat]++
    Log "[$cat] $name = $value | $desc"
}

# ──────────────────────────────────────────────────────────────────────────────
#  P/INVOKE FOR MEMORY SCAN
# ──────────────────────────────────────────────────────────────────────────────
try {
    Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class WinMem {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int a,bool b,int c);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] buf,int sz,out int rd);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@ -Language CSharp
} catch {}

# ──────────────────────────────────────────────────────────────────────────────
#  DATABASES
# ──────────────────────────────────────────────────────────────────────────────

# Safe/FPS flags — never flagged
$WHITELIST = [System.Collections.Generic.HashSet[string]]@(
    "DFIntTaskSchedulerTargetFps","FFlagGameBasicSettingsFramerateCap",
    "FFlagDebugGraphicsPreferD3D11","FFlagDebugGraphicsPreferD3D11FL10",
    "DFIntDefaultFrameRateCapLua","FFlagEnableQuickGameLaunch",
    "DFFlagTextureCompositorEnabled","FFlagGameBasicSettingsMemoryOptimization",
    "FFlagGraphicsEnableD3D10Compute","DFFlagGraphicsOptimizeVolumes",
    "FFlagDebugGraphicsPreferVulkan","FFlagDebugGraphicsPreferOpenGL",
    "FFlagHandleAltEnterFullscreenManually","FFlagEnableFRMQualityLevelOverride",
    "DFIntDebugFRMQualityLevelOverride","FFlagCommitToGraphicsQualityFix",
    "FIntRenderShadowIntensity","FIntTerrainArraySliceSize",
    "DFFlagEnableMeshPreloading2","DFFlagEnablePreloadAvatarAssets",
    "DFFlagEnableSoundPreloading","DFFlagDebugOverrideDPIScale",
    "DFFlagDebugPauseVoxelizer","DFFlagDebugSkipMeshVoxelizer",
    "DFFlagDebugPerfMode","FFlagEnableInGameMenuChromeABTest2",
    "FFlagLuaAppEnableFoundationColors2","DFFlagEnableNewNotificationService",
    "FFlagAvatarSelfViewEnabled","FFlagNewAnimationBlendingR15",
    "FFlagChatTranslationEnableVoice3","DFFlagAvatarEditorEnableShowHideUI"
)

# CHEAT flags — direct gameplay advantage
$FLAG_CHEAT = [ordered]@{
    # Hitbox manipulation
    "DFIntCSGLevelOfDetailSwitchingDistanceL12" = "Hitbox expansion (LOD L12) — makes hit registration easier"
    "DFIntCSGLevelOfDetailSwitchingDistance"    = "Hitbox expansion (LOD global)"
    "DFIntCSGLevelOfDetailSwitchingDistanceL23" = "Hitbox expansion (LOD L23)"
    "DFIntCSGLevelOfDetailSwitchingDistanceL34" = "Hitbox expansion (LOD L34)"
    "FFlagFixedHitTest"                         = "Hit detection override"
    "DFIntRenderLodsAutomaticBiasMultiplier"    = "LOD bias manipulation (hitbox)"
    "FFlagHumanoidCacheRecalcOnResize"          = "Humanoid hitbox resize exploit"
    "DFFlagDisableCSGv2"                        = "CSG v2 disabled (hitbox exploit)"
    # Gravity / Fly / Speed
    "DFIntPhysicsGravity"                       = "Gravity modified — fly/float exploit"
    "DFFlagFixIsGroundedExploit"                = "IsGrounded bypass — fly/noclip"
    "DFIntMaxMissedWorldStepsRemembered"        = "Physics steps override — speed/fly hack"
    "DFIntPhysicsFPSRegulatorMaxStepsPerSec"    = "Physics FPS override — speed hack"
    "DFFlagSimWorldThrottleEnabled"             = "Simulation throttle disabled — speed hack"
    "DFIntPhysicsStepsPerSecond"                = "Physics steps/sec override — speed hack"
    "DFFlagPhysicsSkipNonRealTimeKernelUpdates" = "Physics kernel skip — exploit"
    "DFIntSimWorldThrottleAdjustTime"           = "Throttle timing override"
    "DFIntSimWorldThrottleMaxJobs"              = "Throttle job override"
    "DFIntMegaReplicatorNumParallelTasks"       = "Replicator parallelism — speed"
    "DFFlagUseDeltaTimeInFallingRagdoll"        = "Ragdoll delta time exploit"
    "DFIntPhysicsPacketSendRateMax"             = "Packet send rate — teleport/speed"
    "FFlagSimAdaptiveTimesteppingDefault2"      = "Adaptive timestep — position desync"
    # Teleport / Position
    "DFIntMaxClientCharacterUpdateUnreliableGameDistance" = "Client position update max (teleport exploit)"
    "DFIntMinClientCharacterUpdateUnreliableGameDistance" = "Client position update min (teleport exploit)"
    # Animation exploit
    "DFFlagAnimatorPostStepJumpFix"             = "Animator jump bypass"
    "DFFlagAnimateCharacterEnable"              = "Character animation override"
    "DFIntAnimationLodFacsDistanceMin"          = "Animation LOD min — hitbox"
    "FFlagAnimationEasingStyleLinear"           = "Animation easing exploit"
    "DFFlagAnimatorUseProcessorCount"           = "Animator CPU override"
    "DFIntAnimationBuildLodFacsDistanceMax"     = "Animation LOD max"
    # ESP / Visual cheat
    "FFlagDebugDisableShadows"                  = "Shadows disabled — see-through walls (ESP)"
    "DFFlagTextureQualityOverrideEnabled"       = "Texture quality override — visual exploit"
    "DFFlagDebugRenderForceToonShader"          = "Toon shader forced — ESP visual advantage"
    "DFIntRenderShadowmapBias"                  = "Shadowmap bias — see through objects"
    "FFlagDebugForceFSMCPULightCulling"         = "Light culling override — ESP advantage"
    "DFIntRenderClampRoughnessMax"              = "Roughness override — visual cheat"
    # Packet compression bypass
    "DFFlagPhysicsPacketCompression"            = "Physics packet compression bypass"
    "DFIntPhysicsMtuOverride"                   = "Physics MTU override — packet exploit"
    "DFIntPhysicsReceiveNumConcurrentJobsMax"   = "Concurrent physics jobs — exploit"
}

# NETWORK flags — ping/lag advantage
$FLAG_NETWORK = [ordered]@{
    "DFIntConnectionMTUSize"                      = "MTU size override — ping manipulation"
    "DFIntOptimizeNetworkTransportTimout"         = "Transport timeout — lag switch"
    "DFIntRakNetDatagramRangeMaxSize"             = "RakNet datagram override"
    "DFFlagNetworkTransportUseNewImplementation"  = "Transport implementation override"
    "DFIntNetworkPredictionMaxMs"                 = "Prediction max ms — lag comp abuse"
    "DFIntLagCompensationMaxMs"                   = "Lag compensation override"
    "DFIntPhysicsInterpolationTimeoutMs"          = "Interpolation timeout — desync exploit"
    "DFFlagDebugSimIntercommunicateUseSendQueue"  = "Send queue debug — exploit"
    "DFIntSendDataChannelBandwidthLimit"          = "Bandwidth limit override"
    "DFIntRemoteEventMaxSizeKB"                   = "RemoteEvent size override"
    "DFIntMaxDataModelSendBuffer"                 = "Send buffer override"
    "DFIntNetworkPredictionNumSmoothingSteps"     = "Prediction smoothing — desync"
    "DFIntMaxNetworkBytesPerSecond"               = "Max network bytes/sec override"
    "DFIntRakNetResendBufferArrayLength"          = "RakNet resend buffer override"
    "DFFlagNetworkTransportLoggedOutRateLimit"    = "Rate limit bypass"
    "DFIntRakNetBandwidthPingSmoothingFactor"     = "Ping smoothing factor override"
    "DFIntPhysicsPacketRecvRateMax"               = "Packet receive rate override"
}

# PHYSICS flags
$FLAG_PHYSICS = [ordered]@{
    "DFIntPhysicsMtuOverride"                 = "Physics MTU override"
    "DFFlagPhysicsPacketCompression"          = "Physics compression disabled"
    "DFIntPhysicsReceiveNumConcurrentJobsMax" = "Concurrent physics jobs override"
    "DFIntSimWorldThrottleAdjustTime"         = "Throttle adjust time"
    "DFIntSimWorldThrottleMaxJobs"            = "Throttle max jobs"
}

# Keyword-based classification (for unknown flags)
$KW = @{
    CHEAT   = @("hitbox","hittest","noclip","exploit","bypass","isgrounded","godmode","teleport","aimbot","wallhack","esp","speedhack","fly","gravity","cheat","infinite","spin")
    PHYSICS = @("physics","physic","simulation","sim","interpolat","ragdoll","timestep","throttle","worldstep","rigidbody","collision","softbody","fluid","aerodyn","constraint")
    NETWORK = @("network","mtu","raknet","bandwidth","lagcomp","lag_comp","prediction","packet","transport","sendqueue","channel","datagram","replication","remoteevent","sendrate","recvrate","ping","timeout","socket","udp","tcp")
    FPS     = @("fps","framerate","framecap","taskscheduler","vsync","targetfps","frameratecap","frmlevel","frmquality","d3d11","vulkan","opengl","dx11","dx12")
    VISUAL  = @("shadow","texture","render","lod","graphic","light","shader","fog","bloom","reflection","dof","ssao","sky","cloud","water","terrain","mesh","voxel","material","postprocess","antialia","fxaa","msaa","ssgi","gi_","ambient","exposure","tonemapping")
}

# Injectors database
$Injectors = @(
    @{N="Synapse X";      F=@("synapse.exe","synapseui.exe","sxlib.dll","synapse x.exe");               S="CHEAT"},
    @{N="KRNL";           F=@("krnl.exe","krnlss.exe","krnl_bootstrap.exe");                            S="CHEAT"},
    @{N="Fluxus";         F=@("fluxus.exe","flux.exe","fluxus_launcher.exe");                           S="CHEAT"},
    @{N="Oxygen U";       F=@("oxygenbootstrapper.exe","oxygenx.exe");                                  S="CHEAT"},
    @{N="Sentinel";       F=@("sentinel.exe","sentinelroblox.exe");                                     S="CHEAT"},
    @{N="Script-Ware";    F=@("scriptware.exe","sw_roblox.exe");                                        S="CHEAT"},
    @{N="Arceus X";       F=@("arceusx.exe","arceusxv3.exe");                                           S="CHEAT"},
    @{N="Trigon Evo";     F=@("trigon.exe","trigonevolved.exe","trigon_evo.exe");                       S="CHEAT"},
    @{N="Electron";       F=@("electronexploit.exe","electron_exploit.exe");                            S="CHEAT"},
    @{N="ProtoSmasher";   F=@("protosmasher.exe","ps_bin.exe");                                         S="CHEAT"},
    @{N="JJSploit";       F=@("jjsploit.exe","wearedevs.exe");                                         S="CHEAT"},
    @{N="Vega X";         F=@("vegax.exe","vega.exe");                                                  S="CHEAT"},
    @{N="Comet";          F=@("comet.exe","cometexploit.exe");                                          S="CHEAT"},
    @{N="Delta";          F=@("delta.exe","deltaexecutor.exe","deltaui.exe","delta_launcher.exe");       S="CHEAT"},
    @{N="Wave";           F=@("wave.exe","waveexecutor.exe","wave_launcher.exe");                       S="CHEAT"},
    @{N="Hydrogen";       F=@("hydrogen.exe","hydrogenexe.exe");                                        S="CHEAT"},
    @{N="Solara";         F=@("solara.exe","solara_launcher.exe");                                      S="CHEAT"},
    @{N="Seliware";       F=@("seliware.exe","seli.exe");                                               S="CHEAT"},
    @{N="Evon";           F=@("evon.exe","evonexploit.exe");                                            S="CHEAT"},
    @{N="Zorara";         F=@("zorara.exe");                                                            S="CHEAT"},
    @{N="Proxo";          F=@("proxo.exe","proxo_launcher.exe");                                        S="CHEAT"},
    @{N="Carat";          F=@("carat.exe","caratexploit.exe");                                          S="CHEAT"},
    @{N="FishTrap";       F=@("fishstrap.exe","fishtrap.exe","fishtrap_launcher.exe","fishstrap_launcher.exe"); S="CHEAT"},
    @{N="Xenos";          F=@("xenos.exe","xenos64.exe");                                               S="CHEAT"},
    @{N="Cheat Engine";   F=@("cheatengine-x86_64.exe","cheatengine.exe","ce64.exe");                  S="CHEAT"},
    @{N="x64dbg";         F=@("x64dbg.exe","x32dbg.exe");                                              S="WARN"},
    @{N="ReClass.NET";    F=@("reclass.net.exe","reclass64.exe");                                       S="WARN"},
    @{N="ProcessHacker";  F=@("processhacker.exe","systeminformer.exe");                               S="WARN"}
)

$InjFolders = @(
    @{N="Synapse X";    P="$env:APPDATA\Synapse X"},
    @{N="Synapse Z";    P="$env:APPDATA\Synapse Z"},
    @{N="KRNL";         P="$env:APPDATA\KRNL"},
    @{N="KRNL";         P="$env:LOCALAPPDATA\KRNL"},
    @{N="Fluxus";       P="$env:APPDATA\Fluxus"},
    @{N="Oxygen U";     P="$env:APPDATA\Oxygen"},
    @{N="Script-Ware";  P="$env:APPDATA\ScriptWare"},
    @{N="FishTrap";     P="$env:LOCALAPPDATA\FishTrap"},
    @{N="Fishstrap";    P="$env:LOCALAPPDATA\Fishstrap"},
    @{N="Delta";        P="$env:APPDATA\Delta"},
    @{N="Wave";         P="$env:APPDATA\Wave"},
    @{N="Trigon";       P="$env:APPDATA\Trigon"},
    @{N="JJSploit";     P="$env:APPDATA\JJSploit"},
    @{N="ProtoSmasher"; P="$env:APPDATA\ProtoSmasher"},
    @{N="Sentinel";     P="$env:APPDATA\Sentinel"},
    @{N="Seliware";     P="$env:APPDATA\Seliware"},
    @{N="Solara";       P="$env:LOCALAPPDATA\Solara"},
    @{N="Evon";         P="$env:APPDATA\Evon"},
    @{N="Zorara";       P="$env:APPDATA\Zorara"},
    @{N="Hydrogen";     P="$env:APPDATA\Hydrogen"},
    @{N="Carat";        P="$env:APPDATA\Carat"}
)

$BadDlls = @(
    "sxlib.dll","synapse.dll","krnl.dll","fluxlib.dll","celery.dll","oxysdk.dll",
    "sw_sdk.dll","trigon_sdk.dll","hydrogen_sdk.dll","ProtoLib.dll","jjsploitlib.dll",
    "vegalib.dll","delta_sdk.dll","wave_sdk.dll","rbxfpsunlocker.dll","lunar.dll"
)

$BadDrivers  = @("kdmapper","kduhelper","dbutil_2_3","WinRing0x64","RZPNK","rtcore64","mhyprot","mhyprot2","gdrv","capcom","iqvw64e","nvflash","amifldrv64","glckio2","gmer")
$GoodDrivers = @("EhStorTcgDrv","WdBoot","WdFilter","WdNisDrv","WinDefend","MpKsl","HDAudBus","USBHUB3","iaStorAVC","nvlddmkm","dxgkrnl","BasicDisplay","BasicRender","bowser","mrxsmb","rdbss","acpiex","acpi","atapi","cdrom","disk","partmgr","volmgr","fvevol","rdyboost","iastora","intelpep","intelpmf","nvhda")

# ──────────────────────────────────────────────────────────────────────────────
#  FLAG CLASSIFIER
# ──────────────────────────────────────────────────────────────────────────────
function Get-FlagCat($name, $value) {
    if ($WHITELIST.Contains($name)) { return "SAFE" }
    if ($FLAG_CHEAT.ContainsKey($name))   { return "CHEAT"   }
    if ($FLAG_NETWORK.ContainsKey($name)) { return "NETWORK" }
    if ($FLAG_PHYSICS.ContainsKey($name)) { return "PHYSICS" }
    $nl = $name.ToLower()
    foreach ($kw in $KW.CHEAT)   { if ($nl -match $kw) { return "CHEAT"   } }
    foreach ($kw in $KW.NETWORK) { if ($nl -match $kw) { return "NETWORK" } }
    foreach ($kw in $KW.PHYSICS) { if ($nl -match $kw) { return "PHYSICS" } }
    foreach ($kw in $KW.FPS)     { if ($nl -match $kw) { return "FPS"     } }
    foreach ($kw in $KW.VISUAL)  { if ($nl -match $kw) { return "VISUAL"  } }
    # Numeric extreme values = suspicious
    $n = 0
    if ([int]::TryParse($value,[ref]$n)) {
        if ($n -eq 0 -and $nl -match "enable|gravity|active") { return "CHEAT" }
        if ($n -gt 99999 -or $n -lt -500) { return "WARN" }
    }
    return "WARN"
}

function Get-FlagDesc($name) {
    if ($FLAG_CHEAT.ContainsKey($name))   { return $FLAG_CHEAT[$name]   }
    if ($FLAG_NETWORK.ContainsKey($name)) { return $FLAG_NETWORK[$name] }
    if ($FLAG_PHYSICS.ContainsKey($name)) { return $FLAG_PHYSICS[$name] }
    return "Non-standard flag — manual review recommended"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PARSE FLAGS FROM ANY FORMAT
# ──────────────────────────────────────────────────────────────────────────────
function Parse-FlagFile($path) {
    $result = @{}
    $raw = Get-Content $path -Raw -Encoding UTF8 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $result }

    if ($path -match "\.json$") {
        try {
            $obj = $raw | ConvertFrom-Json
            # Check if it's wrapped in a "FastFlags" key (Bloxstrap format)
            if ($obj.PSObject.Properties.Name -contains "FastFlags") {
                $obj = $obj.FastFlags
            }
            # Also check for "ClientAppSettings" or other wrappers
            foreach ($key in @("FastFlagOverrides","Flags","Settings","Configuration")) {
                if ($obj.PSObject.Properties.Name -contains $key) {
                    $obj = $obj.$key
                    break
                }
            }
            $obj.PSObject.Properties | ForEach-Object {
                $result[$_.Name] = "$($_.Value)"
            }
        } catch {
            # Fallback: regex parse if JSON is malformed
            [regex]::Matches($raw, '"([A-Za-z0-9_]+)"\s*:\s*"?([^",}\r\n]+)"?') | ForEach-Object {
                $result[$_.Groups[1].Value] = $_.Groups[2].Value.Trim().Trim('"')
            }
        }
    } elseif ($path -match "\.xml$") {
        # GlobalBasicSettings format: <Item key="..." value="..."/> or <Item key="...">value</Item>
        [regex]::Matches($raw, 'key="([^"]+)"[^>]*(?:value="([^"]*)"|\>([^<]*))</') | ForEach-Object {
            $val = if ($_.Groups[2].Value) { $_.Groups[2].Value } else { $_.Groups[3].Value.Trim() }
            $result[$_.Groups[1].Value] = $val
        }
        # Also match <flag name="...">value</flag> format
        [regex]::Matches($raw, '<([A-Za-z][A-Za-z0-9_]+)>([^<]+)<\/') | ForEach-Object {
            if ($_.Groups[1].Value -match "^[DF]F(lag|Int|String)") {
                $result[$_.Groups[1].Value] = $_.Groups[2].Value.Trim()
            }
        }
    }
    return $result
}

# ──────────────────────────────────────────────────────────────────────────────
#  FIND ALL ROBLOX PATHS
# ──────────────────────────────────────────────────────────────────────────────
function Find-RobloxExes {
    $exes = @()
    $searchRoots = @(
        "$env:LOCALAPPDATA\Roblox\Versions",
        "$env:LOCALAPPDATA\Roblox",
        "C:\Program Files (x86)\Roblox\Versions",
        "C:\Program Files\Roblox\Versions",
        "$env:PROGRAMFILES\Roblox\Versions",
        "${env:PROGRAMFILES(X86)}\Roblox\Versions"
    )
    foreach ($root in $searchRoots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root -Filter "RobloxPlayerBeta.exe" -Recurse -EA SilentlyContinue |
            ForEach-Object { $exes += $_.FullName }
    }
    # Also check running process path
    $rbxProc = Get-Process -Name "RobloxPlayerBeta","RobloxPlayer" -EA SilentlyContinue | Select-Object -First 1
    if ($rbxProc) {
        try {
            $procPath = $rbxProc.MainModule.FileName
            if ($procPath -and (Test-Path $procPath) -and ($exes -notcontains $procPath)) {
                $exes += $procPath
            }
        } catch {}
    }
    return $exes | Sort-Object -Unique
}

function Find-FlagFiles {
    $files = [System.Collections.Generic.List[string]]::new()
    $candidates = @(
        "$env:LOCALAPPDATA\Roblox\GlobalBasicSettings_13.xml",
        "$env:LOCALAPPDATA\Roblox\GlobalBasicSettings_13_api.xml",
        "$env:LOCALAPPDATA\Bloxstrap\FastFlagConfiguration.json",
        "$env:APPDATA\Bloxstrap\FastFlagConfiguration.json",
        "$env:LOCALAPPDATA\FishTrap\FastFlagConfiguration.json",
        "$env:LOCALAPPDATA\Fishstrap\FastFlagConfiguration.json",
        "$env:LOCALAPPDATA\Roblox\ClientSettings\ClientAppSettings.json"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { $files.Add($c) } }

    # Bloxstrap profiles (each profile has its own flags)
    @("$env:LOCALAPPDATA\Bloxstrap\Profiles","$env:APPDATA\Bloxstrap\Profiles") | ForEach-Object {
        if (Test-Path $_) {
            Get-ChildItem $_ -Filter "*.json" -Recurse -EA SilentlyContinue | ForEach-Object { $files.Add($_.FullName) }
        }
    }
    # All Roblox version ClientAppSettings
    @("$env:LOCALAPPDATA\Roblox\Versions","C:\Program Files (x86)\Roblox\Versions") | ForEach-Object {
        if (Test-Path $_) {
            Get-ChildItem $_ -Directory -EA SilentlyContinue | ForEach-Object {
                $cs = Join-Path $_.FullName "ClientSettings\ClientAppSettings.json"
                if (Test-Path $cs) { $files.Add($cs) }
            }
        }
    }
    return $files | Sort-Object -Unique
}

# ══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════════════════
Clear-Host
Write-Host ""
Write-Host "        ____  __________  __    ____  _  __" -ForegroundColor Red
Write-Host "       / __ \/ ____/ __ )/ /   / __ \| |/ /" -ForegroundColor Red
Write-Host "      / /_/ / __/ / __  / /   / / / /|   / " -ForegroundColor Red
Write-Host "     / _, _/ /___/ /_/ / /___/ /_/ //   |  " -ForegroundColor Red
Write-Host "    /_/ |_/_____/_____/_____/\____//_/|_|  " -ForegroundColor Red
Write-Host ""
Write-Host "    ROBLOX ANTI-CHEAT SCANNER  v$VER" -ForegroundColor White
Write-Host "    FastFlags · Injectors · Memory · DLLs · Drivers · Registry" -ForegroundColor DarkGray
Write-Host ""
$adminTxt = if ($isAdmin) { "YES (Full Scan)" } else { "NO  (Limited — run as Admin for memory/driver scan)" }
$adminCol = if ($isAdmin) { "Green" } else { "Yellow" }
Write-Host "    Admin  : $adminTxt" -ForegroundColor $adminCol
Write-Host "    Date   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "    User   : $env:USERNAME  |  Host: $env:COMPUTERNAME" -ForegroundColor DarkGray

Log "ROBLOX ANTI-CHEAT SCANNER v$VER"
Log "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | User: $env:USERNAME | Admin: $isAdmin"

# Cache Roblox process and exe paths
$rbxProc = Get-Process -Name "RobloxPlayerBeta","RobloxPlayer" -EA SilentlyContinue | Select-Object -First 1
$rbxExes = Find-RobloxExes

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — FASTFLAGS
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 1 — FastFlags  (Full Scan + Auto-Classification)"
Log "`n[SECTION 1] FastFlags"

$flagFiles = Find-FlagFiles

if ($flagFiles.Count -eq 0) {
    Write-SKIP "No FastFlag config files found."
    Log "  [SKIP] No flag files found."
} else {
    foreach ($ff in $flagFiles) {
        $fname = [System.IO.Path]::GetFileName($ff)
        $fdir  = [System.IO.Path]::GetDirectoryName($ff)
        Write-Sub "File: $fname"
        Write-INFO "Path: $ff"
        Log "`n  File: $ff"

        try {
            $flags = Parse-FlagFile $ff

            if ($flags.Count -eq 0) {
                Write-OK "File is empty or has no flags."
                continue
            }

            Write-INFO "$($flags.Count) flag(s) found — classifying..."

            # Categorize all flags
            $bycat = @{ CHEAT=@(); NETWORK=@(); PHYSICS=@(); VISUAL=@(); FPS=@(); WARN=@(); SAFE=@() }
            foreach ($kv in $flags.GetEnumerator()) {
                $cat = Get-FlagCat $kv.Key $kv.Value
                $bycat[$cat] += [PSCustomObject]@{ Name=$kv.Key; Value=$kv.Value }
            }

            # Print by category (dangerous first)
            if ($bycat["CHEAT"].Count -gt 0) {
                Write-Host "  $([char]0x2502)" -ForegroundColor Red
                Write-Host "  $([char]0x2502)  [!] DIRECT ADVANTAGE FLAGS ($($bycat['CHEAT'].Count))" -ForegroundColor Red
                foreach ($f in $bycat["CHEAT"]) {
                    Write-FlagHit "CHEAT" $f.Name $f.Value (Get-FlagDesc $f.Name)
                }
            }
            if ($bycat["NETWORK"].Count -gt 0) {
                Write-Host "  $([char]0x2502)" -ForegroundColor DarkYellow
                Write-Host "  $([char]0x2502)  [!] NETWORK ADVANTAGE FLAGS ($($bycat['NETWORK'].Count))" -ForegroundColor DarkYellow
                foreach ($f in $bycat["NETWORK"]) {
                    Write-FlagHit "NETWORK" $f.Name $f.Value (Get-FlagDesc $f.Name)
                }
            }
            if ($bycat["PHYSICS"].Count -gt 0) {
                Write-Host "  $([char]0x2502)" -ForegroundColor Magenta
                Write-Host "  $([char]0x2502)  [!] PHYSICS EXPLOIT FLAGS ($($bycat['PHYSICS'].Count))" -ForegroundColor Magenta
                foreach ($f in $bycat["PHYSICS"]) {
                    Write-FlagHit "PHYSICS" $f.Name $f.Value (Get-FlagDesc $f.Name)
                }
            }
            if ($bycat["VISUAL"].Count -gt 0) {
                Write-Host "  $([char]0x2502)" -ForegroundColor DarkMagenta
                Write-Host "  $([char]0x2502)  [~] VISUAL / RENDER FLAGS ($($bycat['VISUAL'].Count))" -ForegroundColor DarkMagenta
                foreach ($f in $bycat["VISUAL"]) {
                    Write-FlagHit "VISUAL" $f.Name $f.Value "Modifies rendering pipeline"
                }
            }
            if ($bycat["FPS"].Count -gt 0) {
                Write-Host "  $([char]0x2502)" -ForegroundColor Green
                Write-Host "  $([char]0x2502)  [OK] FPS / ALLOWED FLAGS ($($bycat['FPS'].Count))" -ForegroundColor Green
                foreach ($f in $bycat["FPS"]) {
                    Write-Host "  $([char]0x2502)  [FPS]     $($f.Name) = $($f.Value)" -ForegroundColor DarkGreen
                    $hits["FPS"]++
                    Log "  [FPS] $($f.Name) = $($f.Value)"
                }
            }
            if ($bycat["WARN"].Count -gt 0) {
                Write-Host "  $([char]0x2502)" -ForegroundColor Yellow
                Write-Host "  $([char]0x2502)  [?] UNKNOWN / REVIEW ($($bycat['WARN'].Count))" -ForegroundColor Yellow
                foreach ($f in $bycat["WARN"]) {
                    Write-FlagHit "WARN" $f.Name $f.Value "Non-standard flag — review manually"
                }
            }
            if ($bycat["SAFE"].Count -gt 0) {
                Write-OK "Whitelisted safe flags: $($bycat['SAFE'].Count)"
            }

            $dangerous = $bycat["CHEAT"].Count + $bycat["NETWORK"].Count + $bycat["PHYSICS"].Count
            if ($dangerous -eq 0 -and $bycat["WARN"].Count -eq 0) {
                Write-OK "No dangerous flags detected in this file."
            }

        } catch {
            Write-Host "  $([char]0x2502)  [ERR] Cannot read file: $_" -ForegroundColor DarkRed
            Log "  [ERR] $ff : $_"
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — RUNNING PROCESSES
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 2 — Active Injector Processes"
Log "`n[SECTION 2] Processes"
$procs = Get-Process -EA SilentlyContinue
$found = $false
foreach ($inj in $Injectors) {
    foreach ($f in $inj.F) {
        $pn = [IO.Path]::GetFileNameWithoutExtension($f)
        $m  = $procs | Where-Object { $_.Name -ieq $pn } | Select-Object -First 1
        if ($m) {
            Write-HIT $inj.S "PROCESS RUNNING: $($inj.N)" "PID: $($m.Id)  |  $pn.exe"
            $found = $true
        }
    }
}
if (-not $found) { Write-OK "No known injector processes running." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — INJECTOR FOLDERS
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 3 — Injector Install Folders"
Log "`n[SECTION 3] Folders"
$found = $false
foreach ($f in $InjFolders) {
    if (Test-Path $f.P) {
        $sz = [math]::Round(((Get-ChildItem $f.P -Recurse -EA SilentlyContinue | Measure-Object Length -Sum).Sum)/1MB,2)
        Write-HIT "CHEAT" "FOLDER: $($f.N)" "$($f.P)  [$sz MB]"
        $found = $true
    }
}
if (-not $found) { Write-OK "No injector folders found." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — FILES ON DISK
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 4 — Injector Files on Disk"
Log "`n[SECTION 4] Files"
$scanDirs = @($env:TEMP,$env:TMP,"$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop",$env:APPDATA,$env:LOCALAPPDATA,"$env:USERPROFILE\Documents","C:\Users\Public")
$allFiles = $Injectors | ForEach-Object { $_.F } | Sort-Object -Unique
$found = $false
foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir -EA SilentlyContinue)) { continue }
    foreach ($fn in $allFiles) {
        $fp = Join-Path $dir $fn
        if (Test-Path $fp) {
            $inj  = $Injectors | Where-Object { $_.F -contains $fn } | Select-Object -First 1
            $hash = (Get-FileHash $fp SHA256 -EA SilentlyContinue).Hash
            Write-HIT $inj.S "FILE: $($inj.N)" "$fp`n  $([char]0x2502)           $([char]0x2514)$([char]0x2500) SHA256: $hash"
            $found = $true
        }
    }
}
if (-not $found) { Write-OK "No injector files found in common directories." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — DLL INJECTION IN ROBLOX
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 5 — DLL Injection in Roblox Process"
Log "`n[SECTION 5] DLLs"
if ($rbxProc) {
    Write-INFO "Roblox is running (PID: $($rbxProc.Id)) — scanning loaded modules..."
    $found = $false
    try {
        $mods = $rbxProc.Modules | Select-Object -ExpandProperty ModuleName -EA SilentlyContinue
        foreach ($dll in $BadDlls) {
            if ($mods -icontains $dll) {
                Write-HIT "CHEAT" "INJECTED DLL: $dll" "Found in RobloxPlayerBeta.exe module list"
                $found = $true
            }
        }
        $rbxProc.Modules | Where-Object {
            $_.FileName -and
            $_.FileName -notmatch "\\Windows\\|\\Roblox\\|\\Microsoft\.|System32|SysWOW64" -and
            $_.FileName -match "\.dll$"
        } | Select-Object -First 10 | ForEach-Object {
            Write-HIT "WARN" "EXTERNAL DLL: $($_.ModuleName)" $_.FileName
            $found = $true
        }
        if (-not $found) { Write-OK "No malicious DLLs found in Roblox process." }
    } catch {
        Write-Host "  $([char]0x2502)  [!] Run as Administrator to scan Roblox modules." -ForegroundColor Yellow
    }
} else {
    Write-SKIP "Roblox is not running. Launch Roblox and re-run for DLL scan."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — LIVE MEMORY SCAN
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 6 — Live Memory Scan (Roblox Process)"
Log "`n[SECTION 6] Memory"
if ($rbxProc -and $isAdmin) {
    Write-INFO "Scanning Roblox memory for active flag strings..."
    $dangerFlags = @($FLAG_CHEAT.Keys) + @($FLAG_NETWORK.Keys)
    $hProc = [WinMem]::OpenProcess(0x0010 -bor 0x0400, $false, $rbxProc.Id)
    if ($hProc -ne [IntPtr]::Zero) {
        $buf = New-Object byte[] 131072
        $addr = [IntPtr]0x10000
        $found = $false
        $seen  = @{}
        $scanned = 0
        while ($addr.ToInt64() -lt 0x7FFFFFFF -and $scanned -lt 1000) {
            $rd = 0
            if ([WinMem]::ReadProcessMemory($hProc, $addr, $buf, $buf.Length, [ref]$rd) -and $rd -gt 0) {
                $str = [System.Text.Encoding]::ASCII.GetString($buf, 0, $rd)
                foreach ($flag in $dangerFlags) {
                    if ($str.Contains($flag) -and -not $seen.ContainsKey($flag)) {
                        $cat = Get-FlagCat $flag "1"
                        Write-HIT $cat "ACTIVE IN MEMORY: $flag" "Found in Roblox RAM @ ~0x$($addr.ToString('X8'))"
                        $seen[$flag] = $true
                        $found = $true
                    }
                }
            }
            $addr = [IntPtr]($addr.ToInt64() + 131072)
            $scanned++
        }
        [WinMem]::CloseHandle($hProc) | Out-Null
        if (-not $found) { Write-OK "No illegal flags found active in Roblox memory." }
    } else {
        Write-Host "  $([char]0x2502)  [!] Failed to open process handle." -ForegroundColor Yellow
    }
} elseif (-not $isAdmin) {
    Write-SKIP "Requires Administrator. Re-run PowerShell as Admin."
} else {
    Write-SKIP "Roblox is not running."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — REGISTRY FLAGS
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 7 — FastFlags in Windows Registry"
Log "`n[SECTION 7] Registry"
$regPaths = @("HKCU:\Software\Roblox","HKLM:\Software\Roblox","HKCU:\Software\ROBLOX Corporation","HKLM:\Software\ROBLOX Corporation")
$found = $false
foreach ($rp in $regPaths) {
    if (-not (Test-Path $rp -EA SilentlyContinue)) { continue }
    Get-ChildItem $rp -Recurse -EA SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -EA SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $cat = Get-FlagCat $_.Name "$($_.Value)"
                if ($cat -notin @("SAFE","FPS")) {
                    Write-HIT $cat "REGISTRY FLAG: $($_.Name) = $($_.Value)" $_.PSPath
                    $found = $true
                }
            }
        }
    }
}
if (-not $found) { Write-OK "No dangerous flags found in Windows Registry." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — KERNEL DRIVERS
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 8 — Suspicious Kernel Drivers"
Log "`n[SECTION 8] Drivers"
if ($isAdmin) {
    $drivers = Get-WmiObject Win32_SystemDriver -EA SilentlyContinue
    $found = $false
    foreach ($drv in $drivers) {
        $skip = $false
        foreach ($wl in $GoodDrivers) { if ($drv.Name -imatch "^$wl$") { $skip = $true; break } }
        if ($skip) { continue }
        foreach ($bd in $BadDrivers) {
            if ($drv.Name -imatch $bd -or ($drv.PathName -and $drv.PathName -imatch $bd)) {
                Write-HIT "CHEAT" "DRIVER: $($drv.Name)" "Path: $($drv.PathName) | State: $($drv.State)"
                $found = $true
            }
        }
    }
    if (-not $found) { Write-OK "No suspicious kernel drivers found." }
} else {
    Write-SKIP "Requires Administrator to scan kernel drivers."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — STARTUP ENTRIES
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 9 — Startup Entries"
Log "`n[SECTION 9] Startup"
$startupReg = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce")
$found = $false
foreach ($rs in $startupReg) {
    if (-not (Test-Path $rs -EA SilentlyContinue)) { continue }
    $e = Get-ItemProperty $rs -EA SilentlyContinue
    if (-not $e) { continue }
    $e.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
        $v = $_.Value.ToLower()
        foreach ($inj in $Injectors) {
            foreach ($f in $inj.F) {
                if ($v -match [regex]::Escape($f.ToLower())) {
                    Write-HIT $inj.S "STARTUP ENTRY: $($inj.N)" "$($_.Name) => $($_.Value)"
                    $found = $true
                }
            }
        }
    }
}
$sf = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $sf) {
    Get-ChildItem $sf -File -EA SilentlyContinue | ForEach-Object {
        $fn = $_.Name.ToLower()
        foreach ($inj in $Injectors) {
            foreach ($f in $inj.F) {
                if ($fn -eq $f.ToLower()) {
                    Write-HIT $inj.S "STARTUP FILE: $($inj.N)" $_.FullName
                    $found = $true
                }
            }
        }
    }
}
if (-not $found) { Write-OK "No injector entries found in startup." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — ROBLOX EXE INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 10 — Roblox Executable Integrity"
Log "`n[SECTION 10] Exe Integrity"
if ($rbxExes.Count -gt 0) {
    Write-INFO "Found $($rbxExes.Count) Roblox executable(s)"
    foreach ($exe in $rbxExes) {
        $sig  = Get-AuthenticodeSignature $exe -EA SilentlyContinue
        $hash = (Get-FileHash $exe SHA256 -EA SilentlyContinue).Hash
        $size = (Get-Item $exe -EA SilentlyContinue).Length
        $ver  = (Get-Item $exe -EA SilentlyContinue).VersionInfo.FileVersion
        Write-Sub "$([System.IO.Path]::GetDirectoryName($exe) -replace '.*\\','')"
        Write-INFO "Path   : $exe"
        Write-INFO "Version: $ver"
        Write-INFO "SHA256 : $hash"
        Write-INFO "Size   : $([math]::Round($size/1MB,2)) MB"
        if ($sig -and $sig.Status -eq "Valid") {
            Write-OK "Authenticode signature: VALID"
            Log "  [OK] Signature valid: $exe"
        } else {
            $sigStatus = if ($sig) { $sig.Status } else { "Unknown" }
            Write-HIT "CHEAT" "INVALID SIGNATURE: RobloxPlayerBeta.exe" "Status: $sigStatus — file may be patched/modified"
        }
    }
} else {
    Write-SKIP "RobloxPlayerBeta.exe not found in standard locations."
    Write-SKIP "This is normal if Roblox was never launched on this PC."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 11 — HOSTS FILE
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner "SECTION 11 — Hosts File Tampering"
Log "`n[SECTION 11] Hosts"
$hc = Get-Content "C:\Windows\System32\drivers\etc\hosts" -EA SilentlyContinue
$rl = $hc | Where-Object { $_ -match "roblox" -and $_ -notmatch "^\s*#" }
if ($rl) {
    foreach ($l in $rl) { Write-HIT "WARN" "HOSTS ENTRY" $l }
} else {
    Write-OK "Hosts file is clean."
}

# ══════════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
$totalDanger = $hits["CHEAT"] + $hits["NETWORK"] + $hits["PHYSICS"]
$totalWarn   = $hits["WARN"]  + $hits["VISUAL"]

Write-Host ""
$w = 68
$line2 = [string]::new([char]0x2550, $w)
$line3 = [string]::new([char]0x2500, $w)
Write-Host "  $([char]0x2554)$line2$([char]0x2557)" -ForegroundColor Cyan
Write-Host "  $([char]0x2551)$("  SCAN SUMMARY".PadRight($w))$([char]0x2551)" -ForegroundColor White
Write-Host "  $([char]0x2560)$line2$([char]0x2563)" -ForegroundColor Cyan

function SummaryLine($label, $count, $col) {
    $countStr = "  $label".PadRight(40) + ": $count"
    Write-Host "  $([char]0x2551)  $($countStr.PadRight($w - 2))$([char]0x2551)" -ForegroundColor $col
}

SummaryLine "[CHEAT]   Direct advantage flags/tools" $hits["CHEAT"]   "Red"
SummaryLine "[NETWORK] Network/ping advantage flags"  $hits["NETWORK"] "DarkYellow"
SummaryLine "[PHYSICS] Physics exploit flags"         $hits["PHYSICS"] "Magenta"
SummaryLine "[VISUAL]  Render/visual flags"           $hits["VISUAL"]  "DarkMagenta"
SummaryLine "[FPS]     FPS flags (allowed)"           $hits["FPS"]     "Green"
SummaryLine "[WARN]    Unknown/review flags"          $hits["WARN"]    "Yellow"

Write-Host "  $([char]0x2560)$line2$([char]0x2563)" -ForegroundColor Cyan

if ($totalDanger -gt 0) {
    $verdict = "  VERDICT: [X] CHEATS / ILLEGAL FLAGS DETECTED"
    Write-Host "  $([char]0x2551)  $($verdict.PadRight($w - 2))$([char]0x2551)" -ForegroundColor Red
    Write-Host "  $([char]0x255A)$line2$([char]0x255D)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  REQUIRED ACTIONS:" -ForegroundColor White
    Write-Host "    1. Uninstall all listed injectors/executors" -ForegroundColor DarkGray
    Write-Host "    2. Remove banned flags from Bloxstrap / ClientAppSettings" -ForegroundColor DarkGray
    Write-Host "    3. Reinstall Roblox if exe signature is invalid" -ForegroundColor DarkGray
    Write-Host "    4. Run Windows Defender full scan" -ForegroundColor DarkGray
} elseif ($totalWarn -gt 0) {
    $verdict = "  VERDICT: [!] WARNINGS FOUND — Review manually"
    Write-Host "  $([char]0x2551)  $($verdict.PadRight($w - 2))$([char]0x2551)" -ForegroundColor Yellow
    Write-Host "  $([char]0x255A)$line2$([char]0x255D)" -ForegroundColor Cyan
} else {
    $verdict = "  VERDICT: [OK] CLEAN — No cheats or illegal flags detected"
    Write-Host "  $([char]0x2551)  $($verdict.PadRight($w - 2))$([char]0x2551)" -ForegroundColor Green
    Write-Host "  $([char]0x255A)$line2$([char]0x255D)" -ForegroundColor Cyan
}

# Save report
$rp = "$env:USERPROFILE\Desktop\RobloxScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Log ""
Log "VERDICT: $(if($totalDanger -gt 0){'CHEATS DETECTED'}elseif($totalWarn -gt 0){'WARNINGS'}else{'CLEAN'})"
Log "CHEAT=$($hits['CHEAT']) | NETWORK=$($hits['NETWORK']) | PHYSICS=$($hits['PHYSICS']) | VISUAL=$($hits['VISUAL']) | FPS=$($hits['FPS']) | WARN=$($hits['WARN'])"
$report | Out-File $rp -Encoding UTF8

Write-Host ""
Write-Host "  Report saved: $rp" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ═══════════════════════════════════════════════════════════════════════════════
#  ROBLOX ANTI-CHEAT SCANNER  v3.0
#  Scans: FastFlags (ALL) · Injectors · DLLs · Memory · Drivers · Registry
# ═══════════════════════════════════════════════════════════════════════════════

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

# ── Counters ──────────────────────────────────────────────────────────────────
$hits    = @{ CHEAT=0; PHYSICS=0; NETWORK=0; FPS=0; VISUAL=0; WARN=0 }
$report  = [System.Collections.Generic.List[string]]::new()
function Log($x) { $report.Add($x) }

# ── Output helpers ─────────────────────────────────────────────────────────────
function Banner($t) {
    $line = "═" * 66
    Write-Host "`n  ╔$line╗" -ForegroundColor Cyan
    Write-Host "  ║  $($t.PadRight(64))║" -ForegroundColor White
    Write-Host "  ╚$line╝" -ForegroundColor Cyan
}
function Sub($t) { Write-Host "`n  ┌─ $t" -ForegroundColor Yellow }
function OK($t)  { Write-Host "  │  [✓] $t" -ForegroundColor Green }
function INFO($t){ Write-Host "  │  [i] $t" -ForegroundColor DarkCyan }
function SKIP($t){ Write-Host "  │  [-] $t" -ForegroundColor DarkGray }

function HIT($cat, $label, $detail) {
    $col = switch($cat) {
        "CHEAT"   { "Red" }
        "PHYSICS" { "Magenta" }
        "NETWORK" { "DarkYellow" }
        "FPS"     { "Green" }
        "VISUAL"  { "DarkMagenta" }
        default   { "Yellow" }
    }
    Write-Host "  │  [$cat] $label" -ForegroundColor $col
    if ($detail) { Write-Host "  │       $detail" -ForegroundColor DarkGray }
    $script:hits[$cat]++
    Log "[$cat] $label | $detail"
}

# ── P/Invoke para memoria ──────────────────────────────────────────────────────
try {
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class WinMem {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int a,bool b,int c);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h,IntPtr addr,byte[] buf,int sz,out int read);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@ -Language CSharp } catch {}

# ══════════════════════════════════════════════════════════════════════════════
#  BASE DE DATOS
# ══════════════════════════════════════════════════════════════════════════════

# Whitelist de flags TOTALMENTE seguras (FPS/rendimiento normal)
$WHITELIST = @(
    "DFIntTaskSchedulerTargetFps","FFlagGameBasicSettingsFramerateCap",
    "FFlagDebugGraphicsPreferD3D11","FFlagDebugGraphicsPreferD3D11FL10",
    "DFIntDefaultFrameRateCapLua","FFlagEnableQuickGameLaunch",
    "DFFlagTextureCompositorEnabled","FFlagGameBasicSettingsMemoryOptimization",
    "FFlagGraphicsEnableD3D10Compute","DFFlagGraphicsOptimizeVolumes",
    "FFlagDebugGraphicsPreferVulkan","FFlagDebugGraphicsPreferOpenGL",
    "DFIntDebugFRMQualityLevelOverride","FFlagCommitToGraphicsQualityFix",
    "DFFlagEnableMeshPreloading2","DFFlagEnablePreloadAvatarAssets",
    "DFFlagEnableSoundPreloading","DFFlagDebugOverrideDPIScale",
    "FIntRenderShadowIntensity","FIntTerrainArraySliceSize",
    "FFlagHandleAltEnterFullscreenManually","DFFlagDebugPauseVoxelizer",
    "DFFlagDebugSkipMeshVoxelizer","DFFlagDebugPerfMode"
)

# Flags de CHEAT conocidas (ventaja directa en gameplay)
$FLAG_CHEAT = @{
    # Hitbox
    "DFIntCSGLevelOfDetailSwitchingDistanceL12" = "Hitbox expandido (LOD L12)"
    "DFIntCSGLevelOfDetailSwitchingDistance"    = "Hitbox expandido (LOD)"
    "DFIntCSGLevelOfDetailSwitchingDistanceL23" = "Hitbox expandido (LOD L23)"
    "DFIntCSGLevelOfDetailSwitchingDistanceL34" = "Hitbox expandido (LOD L34)"
    "FFlagFixedHitTest"                         = "Hitbox fix exploit"
    "DFIntRenderLodsAutomaticBiasMultiplier"    = "LOD bias manipulado"
    "FFlagHumanoidCacheRecalcOnResize"          = "Hitbox resize exploit"
    # Speed/Fly/NoClip physics
    "DFFlagFixIsGroundedExploit"                = "IsGrounded bypass (fly/noclip)"
    "DFIntPhysicsGravity"                       = "Gravedad modificada (fly/float)"
    "DFIntMaxMissedWorldStepsRemembered"        = "Physics steps manipulados (speed/fly)"
    "DFIntPhysicsFPSRegulatorMaxStepsPerSec"    = "Physics FPS override (speed hack)"
    "DFFlagSimWorldThrottleEnabled"             = "Sim throttle desactivado (speed)"
    "DFIntPhysicsStepsPerSecond"                = "Steps por segundo (speed hack)"
    "DFFlagPhysicsSkipNonRealTimeKernelUpdates" = "Physics kernel skip (exploit)"
    "DFIntSimWorldThrottleAdjustTime"           = "Throttle timing (speed)"
    "DFIntSimWorldThrottleMaxJobs"              = "Throttle jobs (speed)"
    "DFIntMegaReplicatorNumParallelTasks"       = "Replicator paralelo (speed)"
    "DFFlagUseDeltaTimeInFallingRagdoll"        = "Ragdoll delta exploit"
    # Animation exploit
    "DFFlagAnimatorPostStepJumpFix"             = "Animator jump bypass"
    "DFFlagAnimateCharacterEnable"              = "Character animate override"
    "DFIntAnimationLodFacsDistanceMin"          = "Animation LOD min (hitbox)"
    "FFlagAnimationEasingStyleLinear"           = "Animation easing exploit"
    "DFFlagAnimatorUseProcessorCount"           = "Animator CPU override"
    "FFlagNewAnimationBlendingR15"              = "R15 blend exploit"
    "DFIntAnimationBuildLodFacsDistanceMax"     = "Animation LOD max"
    # Teleport/Position
    "DFIntMaxClientCharacterUpdateUnreliableGameDistance" = "Client pos update max (teleport)"
    "DFIntMinClientCharacterUpdateUnreliableGameDistance" = "Client pos update min (teleport)"
    "FFlagSimAdaptiveTimesteppingDefault2"      = "Adaptive timestep (position desync)"
    "DFIntPhysicsPacketSendRateMax"             = "Packet rate max (speed/teleport)"
    # Visual cheat (wallhack/ESP equivalents)
    "FFlagDebugDisableShadows"                  = "Sombras desactivadas (ESP visual)"
    "DFFlagTextureQualityOverrideEnabled"       = "Texture override (ESP visual)"
    "DFFlagDebugRenderForceToonShader"          = "Toon shader forzado (ESP)"
    "DFIntRenderShadowmapBias"                  = "Shadow bias (wallhack visual)"
    "FFlagDebugForceFSMCPULightCulling"         = "Light culling (ESP visual)"
    "DFIntRenderClampRoughnessMax"              = "Roughness override (visual cheat)"
    # Compression bypass
    "DFFlagPhysicsPacketCompression"            = "Physics packet compression bypass"
    "DFIntPhysicsMtuOverride"                   = "Physics MTU override"
    "DFFlagDisableCSGv2"                        = "CSG v2 disabled (hitbox exploit)"
    "DFIntPhysicsReceiveNumConcurrentJobsMax"   = "Physics concurrent jobs (exploit)"
}

# Flags de NETWORK (ventaja de lag/ping)
$FLAG_NETWORK = @{
    "DFIntConnectionMTUSize"                        = "MTU personalizado (ping manipulation)"
    "DFIntOptimizeNetworkTransportTimout"           = "Transport timeout (lag switch)"
    "DFIntRakNetDatagramRangeMaxSize"               = "RakNet datagram override"
    "DFFlagNetworkTransportUseNewImplementation"    = "Transport impl override"
    "DFIntNetworkPredictionMaxMs"                   = "Prediction max ms (lag comp abuse)"
    "DFIntLagCompensationMaxMs"                     = "Lag compensation override"
    "DFIntPhysicsInterpolationTimeoutMs"            = "Interpolation timeout (desync)"
    "DFFlagDebugSimIntercommunicateUseSendQueue"    = "Send queue debug (exploit)"
    "DFIntSendDataChannelBandwidthLimit"            = "Bandwidth limit override"
    "DFIntRemoteEventMaxSizeKB"                     = "RemoteEvent size override"
    "DFIntMaxDataModelSendBuffer"                   = "Send buffer override"
    "DFIntNetworkPredictionNumSmoothingSteps"       = "Prediction smoothing (desync)"
    "DFIntMaxNetworkBytesPerSecond"                 = "Network bytes/s override"
    "DFIntRakNetResendBufferArrayLength"            = "RakNet resend buffer"
    "DFFlagNetworkTransportLoggedOutRateLimit"      = "Rate limit bypass"
    "DFIntRakNetBandwidthPingSmoothingFactor"       = "Ping smoothing factor"
    "DFIntPhysicsPacketRecvRateMax"                 = "Packet recv rate override"
}

# Flags de PHYSICS (afectan simulación sin ser cheat directo)
$FLAG_PHYSICS = @{
    "DFIntPhysicsMtuOverride"                   = "MTU physics override"
    "DFFlagPhysicsPacketCompression"            = "Physics compression desactivada"
    "DFIntPhysicsReceiveNumConcurrentJobsMax"   = "Concurrent physics jobs"
    "DFIntSimWorldThrottleAdjustTime"           = "Throttle adjust time"
}

# Keywords en nombre de flag que indican categoria
$KW_CHEAT   = @("hitbox","hittest","noclip","fly","speed","gravity","exploit","bypass","cheat","wallhack","esp","aimbot","godmode","infinite","teleport","isgrounded")
$KW_PHYSICS = @("physics","physic","simulation","sim","interpolat","ragdoll","timestep","throttle","megareplicat","worldstep","isgrounded","gravity","rigidbody","collision")
$KW_NETWORK = @("network","mtu","raknet","bandwidth","lagcomp","prediction","packet","transport","sendqueue","channel","datagram","replication","remoteevent","sendrate","recvrate","ping")
$KW_FPS     = @("fps","framerate","framecap","taskscheduler","vsync","targetfps","frameratecap","frmlevel","frmquality")
$KW_VISUAL  = @("shadow","texture","render","lod","graphic","light","shader","fog","bloom","reflection","dof","ssao","sky","cloud","water","terrain","mesh","voxel","material")

# Injectors
$KnownInjectors = @(
    @{N="Synapse X";     F=@("synapse.exe","synapseui.exe","sxlib.dll");            S="CHEAT"},
    @{N="KRNL";          F=@("krnl.exe","krnlss.exe","krnl_bootstrap.exe");         S="CHEAT"},
    @{N="Fluxus";        F=@("fluxus.exe","flux.exe","fluxus_launcher.exe");         S="CHEAT"},
    @{N="Oxygen U";      F=@("oxygenbootstrapper.exe","oxygenx.exe");               S="CHEAT"},
    @{N="Sentinel";      F=@("sentinel.exe","sentinelroblox.exe");                  S="CHEAT"},
    @{N="Script-Ware";   F=@("scriptware.exe","sw_roblox.exe");                     S="CHEAT"},
    @{N="Arceus X";      F=@("arceusx.exe","arceusxv3.exe");                        S="CHEAT"},
    @{N="Trigon Evo";    F=@("trigon.exe","trigonevolved.exe");                     S="CHEAT"},
    @{N="Electron";      F=@("electronexploit.exe");                                S="CHEAT"},
    @{N="ProtoSmasher";  F=@("protosmasher.exe","ps_bin.exe");                      S="CHEAT"},
    @{N="JJSploit";      F=@("jjsploit.exe","wearedevs.exe");                       S="CHEAT"},
    @{N="Vega X";        F=@("vegax.exe","vega.exe");                               S="CHEAT"},
    @{N="Comet";         F=@("comet.exe","cometexploit.exe");                       S="CHEAT"},
    @{N="Delta";         F=@("delta.exe","deltaexecutor.exe","deltaui.exe");         S="CHEAT"},
    @{N="Wave";          F=@("wave.exe","waveexecutor.exe");                         S="CHEAT"},
    @{N="Hydrogen";      F=@("hydrogen.exe","hydrogenexe.exe");                     S="CHEAT"},
    @{N="Solara";        F=@("solara.exe","solara_launcher.exe");                   S="CHEAT"},
    @{N="Seliware";      F=@("seliware.exe");                                       S="CHEAT"},
    @{N="Evon";          F=@("evon.exe","evonexploit.exe");                         S="CHEAT"},
    @{N="Zorara";        F=@("zorara.exe");                                         S="CHEAT"},
    @{N="Proxo";         F=@("proxo.exe");                                          S="CHEAT"},
    @{N="FishTrap";      F=@("fishstrap.exe","fishtrap.exe","fishtrap_launcher.exe","fishstrap_launcher.exe"); S="CHEAT"},
    @{N="Xenos";         F=@("xenos.exe","xenos64.exe");                            S="CHEAT"},
    @{N="Cheat Engine";  F=@("cheatengine-x86_64.exe","cheatengine.exe","ce64.exe"); S="CHEAT"},
    @{N="x64dbg";        F=@("x64dbg.exe","x32dbg.exe");                            S="WARN"},
    @{N="ReClass.NET";   F=@("reclass.net.exe","reclass64.exe");                    S="WARN"},
    @{N="Proc Hacker";   F=@("processhacker.exe","systeminformer.exe");             S="WARN"}
)

$InjectorFolders = @(
    @{N="Synapse X";   P="$env:APPDATA\Synapse X"},
    @{N="Synapse Z";   P="$env:APPDATA\Synapse Z"},
    @{N="KRNL";        P="$env:APPDATA\KRNL"},
    @{N="KRNL";        P="$env:LOCALAPPDATA\KRNL"},
    @{N="Fluxus";      P="$env:APPDATA\Fluxus"},
    @{N="Oxygen U";    P="$env:APPDATA\Oxygen"},
    @{N="Script-Ware"; P="$env:APPDATA\ScriptWare"},
    @{N="FishTrap";    P="$env:LOCALAPPDATA\FishTrap"},
    @{N="Fishstrap";   P="$env:LOCALAPPDATA\Fishstrap"},
    @{N="Delta";       P="$env:APPDATA\Delta"},
    @{N="Wave";        P="$env:APPDATA\Wave"},
    @{N="Trigon";      P="$env:APPDATA\Trigon"},
    @{N="JJSploit";    P="$env:APPDATA\JJSploit"},
    @{N="ProtoSmasher";P="$env:APPDATA\ProtoSmasher"},
    @{N="Sentinel";    P="$env:APPDATA\Sentinel"},
    @{N="Seliware";    P="$env:APPDATA\Seliware"},
    @{N="Solara";      P="$env:LOCALAPPDATA\Solara"},
    @{N="Evon";        P="$env:APPDATA\Evon"},
    @{N="Zorara";      P="$env:APPDATA\Zorara"},
    @{N="Hydrogen";    P="$env:APPDATA\Hydrogen"}
)

$KnownBadDlls = @(
    "sxlib.dll","synapse.dll","krnl.dll","fluxlib.dll","celery.dll",
    "oxysdk.dll","sw_sdk.dll","trigon_sdk.dll","hydrogen_sdk.dll",
    "ProtoLib.dll","jjsploitlib.dll","vegalib.dll","delta_sdk.dll",
    "wave_sdk.dll","rbxfpsunlocker.dll","luajit.dll","lunar.dll"
)

# Drivers sospechosos (excluyendo los de Windows)
$BadDrivers = @(
    "kdmapper","kduhelper","dbutil_2_3","WinRing0x64","RZPNK",
    "rtcore64","mhyprot","mhyprot2","gdrv","capcom","iqvw64e",
    "nvflash","amifldrv64","glckio2","gmer","be","easyanticheat_eosovh"
)
# Drivers legítimos de Windows (whitelist para no dar falsos positivos)
$DriverWhitelist = @(
    "EhStorTcgDrv","WdBoot","WdFilter","WdNisDrv","WinDefend",
    "MpKsl","hvservice","HDAudBus","USBHUB3","iaStorAVC","nvlddmkm",
    "dxgkrnl","BasicDisplay","BasicRender","bowser","mrxsmb","rdbss"
)

# ══════════════════════════════════════════════════════════════════════════════
#  FUNCIÓN CENTRAL: CLASIFICAR UNA FLAG
# ══════════════════════════════════════════════════════════════════════════════
function Get-FlagCategory($name, $value) {
    $nl = $name.ToLower()

    # 1. Whitelist = segura
    if ($WHITELIST -icontains $name) { return "SAFE" }

    # 2. Cheat conocido = CHEAT
    if ($FLAG_CHEAT.ContainsKey($name)) { return "CHEAT" }

    # 3. Network conocido
    if ($FLAG_NETWORK.ContainsKey($name)) { return "NETWORK" }

    # 4. Physics conocido
    if ($FLAG_PHYSICS.ContainsKey($name)) { return "PHYSICS" }

    # 5. Por keywords en el nombre
    foreach ($kw in $KW_CHEAT)   { if ($nl -match $kw) { return "CHEAT"   } }
    foreach ($kw in $KW_NETWORK) { if ($nl -match $kw) { return "NETWORK" } }
    foreach ($kw in $KW_PHYSICS) { if ($nl -match $kw) { return "PHYSICS" } }
    foreach ($kw in $KW_FPS)     { if ($nl -match $kw) { return "FPS"     } }
    foreach ($kw in $KW_VISUAL)  { if ($nl -match $kw) { return "VISUAL"  } }

    # 6. Valores extremos = sospechoso
    $num = 0
    if ([int]::TryParse($value, [ref]$num)) {
        if ($num -eq 0 -and $nl -match "enable|active|use") { return "CHEAT" }
        if ($num -gt 9999 -or $num -lt -100)                { return "WARN"  }
    }

    # 7. Sin categoría pero existe = WARN (flag personalizada = rara)
    return "WARN"
}

function Get-FlagDesc($name) {
    if ($FLAG_CHEAT.ContainsKey($name))   { return $FLAG_CHEAT[$name] }
    if ($FLAG_NETWORK.ContainsKey($name)) { return $FLAG_NETWORK[$name] }
    if ($FLAG_PHYSICS.ContainsKey($name)) { return $FLAG_PHYSICS[$name] }
    return "Flag no estándar detectada"
}

# ══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════════════════
Clear-Host
Write-Host ""
Write-Host "  ██████╗  ██████╗ ██████╗ ██╗      ██████╗ ██╗  ██╗" -ForegroundColor Red
Write-Host "  ██╔══██╗██╔═══██╗██╔══██╗██║     ██╔═══██╗╚██╗██╔╝" -ForegroundColor Red
Write-Host "  ██████╔╝██║   ██║██████╔╝██║     ██║   ██║ ╚███╔╝ " -ForegroundColor Red
Write-Host "  ██╔══██╗██║   ██║██╔══██╗██║     ██║   ██║ ██╔██╗ " -ForegroundColor Red
Write-Host "  ██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝██╔╝ ██╗" -ForegroundColor Red
Write-Host "  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝" -ForegroundColor Red
Write-Host ""
Write-Host "        ROBLOX ANTI-CHEAT SCANNER  v3.0" -ForegroundColor White
Write-Host "   FastFlags · Injectors · Memory · DLLs · Drivers" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Admin : $(if($isAdmin){'YES — Full scan'}else{'NO  — Corre como Admin para scan completo'})" -ForegroundColor $(if($isAdmin){"Green"}else{"Yellow"})
Write-Host "  Fecha : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  User  : $env:USERNAME  |  PC: $env:COMPUTERNAME" -ForegroundColor DarkGray
Log "ROBLOX ANTI-CHEAT SCANNER v3.0"
Log "Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | User: $env:USERNAME | Admin: $isAdmin"

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 1 — FASTFLAGS (SCAN COMPLETO DE TODOS LOS ARCHIVOS)
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 1 — FastFlags (Scan Completo + Clasificación)"
Log "`n[SECCION 1] FastFlags"

# Recolectar todos los archivos de flags
$flagFiles = [System.Collections.Generic.List[string]]::new()
@(
    "$env:LOCALAPPDATA\Roblox\GlobalBasicSettings_13.xml",
    "$env:LOCALAPPDATA\Roblox\GlobalBasicSettings_13_api.xml",
    "$env:LOCALAPPDATA\Bloxstrap\FastFlagConfiguration.json",
    "$env:APPDATA\Bloxstrap\FastFlagConfiguration.json",
    "$env:LOCALAPPDATA\FishTrap\FastFlagConfiguration.json",
    "$env:LOCALAPPDATA\Fishstrap\FastFlagConfiguration.json",
    "$env:LOCALAPPDATA\Roblox\ClientSettings\ClientAppSettings.json"
) | ForEach-Object { if (Test-Path $_) { $flagFiles.Add($_) } }

# Bloxstrap profiles
$bsProfiles = "$env:LOCALAPPDATA\Bloxstrap\Profiles"
if (Test-Path $bsProfiles) {
    Get-ChildItem $bsProfiles -Filter "*.json" -Recurse -EA SilentlyContinue | ForEach-Object { $flagFiles.Add($_.FullName) }
}
# Roblox version folders
$rbxVer = "$env:LOCALAPPDATA\Roblox\Versions"
if (Test-Path $rbxVer) {
    Get-ChildItem $rbxVer -Directory -EA SilentlyContinue | ForEach-Object {
        $p = Join-Path $_.FullName "ClientSettings\ClientAppSettings.json"
        if (Test-Path $p) { $flagFiles.Add($p) }
    }
}

if ($flagFiles.Count -eq 0) {
    SKIP "No se encontraron archivos de FastFlags."
    Log "  [INFO] No flag files found."
} else {
    foreach ($ff in ($flagFiles | Sort-Object -Unique)) {
        Sub "Archivo: $([System.IO.Path]::GetFileName($ff))"
        INFO "Path: $ff"
        Log "`n  Archivo: $ff"

        try {
            $raw = Get-Content $ff -Raw -Encoding UTF8 -EA Stop
            if ([string]::IsNullOrWhiteSpace($raw)) { OK "Archivo vacío."; continue }

            # Parse JSON si aplica
            $flags = @{}
            if ($ff -match "\.json$") {
                try {
                    $obj = $raw | ConvertFrom-Json
                    $obj.PSObject.Properties | ForEach-Object { $flags[$_.Name] = "$($_.Value)" }
                } catch {
                    # fallback regex si el JSON está malformado
                    $matches_ = [regex]::Matches($raw, '"([^"]+)"\s*:\s*"?([^",}\s]+)"?')
                    foreach ($m in $matches_) { $flags[$m.Groups[1].Value] = $m.Groups[2].Value }
                }
            } elseif ($ff -match "\.xml$") {
                $matches_ = [regex]::Matches($raw, 'key="([^"]+)"[^>]*>\s*([^<]+)')
                foreach ($m in $matches_) { $flags[$m.Groups[1].Value] = $m.Groups[2].Value.Trim() }
            }

            if ($flags.Count -eq 0) { SKIP "Sin flags encontradas."; continue }

            # Clasificar cada flag
            $bycat = @{ CHEAT=@(); PHYSICS=@(); NETWORK=@(); FPS=@(); VISUAL=@(); WARN=@(); SAFE=@() }
            foreach ($kv in $flags.GetEnumerator()) {
                $cat = Get-FlagCategory $kv.Key $kv.Value
                $bycat[$cat] += [PSCustomObject]@{ Name=$kv.Key; Value=$kv.Value }
            }

            # Mostrar CHEATS primero
            if ($bycat["CHEAT"].Count -gt 0) {
                Write-Host "  │" -ForegroundColor Red
                Write-Host "  │  ══ CHEATS / VENTAJA DIRECTA ($($bycat['CHEAT'].Count)) ══" -ForegroundColor Red
                foreach ($f in $bycat["CHEAT"]) {
                    $desc = Get-FlagDesc $f.Name
                    HIT "CHEAT" "$($f.Name) = $($f.Value)" $desc
                }
            }
            if ($bycat["NETWORK"].Count -gt 0) {
                Write-Host "  │" -ForegroundColor DarkYellow
                Write-Host "  │  ══ NETWORK / VENTAJA DE PING ($($bycat['NETWORK'].Count)) ══" -ForegroundColor DarkYellow
                foreach ($f in $bycat["NETWORK"]) {
                    $desc = Get-FlagDesc $f.Name
                    HIT "NETWORK" "$($f.Name) = $($f.Value)" $desc
                }
            }
            if ($bycat["PHYSICS"].Count -gt 0) {
                Write-Host "  │" -ForegroundColor Magenta
                Write-Host "  │  ══ PHYSICS / SIMULACIÓN ($($bycat['PHYSICS'].Count)) ══" -ForegroundColor Magenta
                foreach ($f in $bycat["PHYSICS"]) {
                    $desc = Get-FlagDesc $f.Name
                    HIT "PHYSICS" "$($f.Name) = $($f.Value)" $desc
                }
            }
            if ($bycat["VISUAL"].Count -gt 0) {
                Write-Host "  │" -ForegroundColor DarkMagenta
                Write-Host "  │  ══ VISUAL / RENDERING ($($bycat['VISUAL'].Count)) ══" -ForegroundColor DarkMagenta
                foreach ($f in $bycat["VISUAL"]) {
                    HIT "VISUAL" "$($f.Name) = $($f.Value)" "Modifica renderizado"
                }
            }
            if ($bycat["FPS"].Count -gt 0) {
                Write-Host "  │" -ForegroundColor Green
                Write-Host "  │  ══ FPS / PERMITIDAS ($($bycat['FPS'].Count)) ══" -ForegroundColor Green
                foreach ($f in $bycat["FPS"]) {
                    Write-Host "  │  [FPS] $($f.Name) = $($f.Value)" -ForegroundColor DarkGreen
                    $hits["FPS"]++
                    Log "  [FPS-OK] $($f.Name) = $($f.Value)"
                }
            }
            if ($bycat["WARN"].Count -gt 0) {
                Write-Host "  │" -ForegroundColor Yellow
                Write-Host "  │  ══ DESCONOCIDAS / REVISAR ($($bycat['WARN'].Count)) ══" -ForegroundColor Yellow
                foreach ($f in $bycat["WARN"]) {
                    HIT "WARN" "$($f.Name) = $($f.Value)" "Flag no estándar — revisar manualmente"
                }
            }
            if ($bycat["SAFE"].Count -gt 0) {
                OK "Flags seguras (whitelistadas): $($bycat['SAFE'].Count)"
            }
            if (($bycat["CHEAT"].Count + $bycat["NETWORK"].Count + $bycat["PHYSICS"].Count + $bycat["WARN"].Count) -eq 0) {
                OK "Ninguna flag peligrosa en este archivo."
            }

        } catch {
            Write-Host "  │  [ERR] No se pudo leer el archivo: $_" -ForegroundColor DarkRed
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 2 — PROCESOS CORRIENDO
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 2 — Procesos Activos"
Log "`n[SECCION 2] Procesos"
$procs = Get-Process -EA SilentlyContinue
$found = $false
foreach ($inj in $KnownInjectors) {
    foreach ($f in $inj.F) {
        $pn = [IO.Path]::GetFileNameWithoutExtension($f)
        $m = $procs | Where-Object { $_.Name -ieq $pn } | Select-Object -First 1
        if ($m) {
            HIT $inj.S "PROCESO: $($inj.N)  PID=$($m.Id)" "Ejecutable: $pn.exe"
            $found = $true
        }
    }
}
if (-not $found) { OK "Ningún proceso de injector detectado." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 3 — CARPETAS DE INJECTORS
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 3 — Carpetas de Injectors"
Log "`n[SECCION 3] Carpetas"
$found = $false
foreach ($f in $InjectorFolders) {
    if (Test-Path $f.P) {
        $sz = [math]::Round(((Get-ChildItem $f.P -Recurse -EA SilentlyContinue | Measure-Object Length -Sum).Sum)/1MB,1)
        HIT "CHEAT" "CARPETA: $($f.N)" "$($f.P)  [$sz MB]"
        $found = $true
    }
}
if (-not $found) { OK "Sin carpetas de injectors encontradas." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 4 — ARCHIVOS EN DISCO
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 4 — Archivos de Injector en Disco"
Log "`n[SECCION 4] Archivos"
$scanDirs = @(
    $env:TEMP,$env:TMP,
    "$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop",
    $env:APPDATA,$env:LOCALAPPDATA,"$env:USERPROFILE\Documents","C:\Users\Public"
)
$allFiles = $KnownInjectors | ForEach-Object { $_.F } | Sort-Object -Unique
$found = $false
foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir)) { continue }
    foreach ($fn in $allFiles) {
        $fp = Join-Path $dir $fn
        if (Test-Path $fp) {
            $inj = $KnownInjectors | Where-Object { $_.F -contains $fn } | Select-Object -First 1
            $hash = (Get-FileHash $fp SHA256 -EA SilentlyContinue).Hash
            HIT $inj.S "ARCHIVO: $($inj.N)" "$fp`n  │       SHA256: $hash"
            $found = $true
        }
    }
}
if (-not $found) { OK "Sin archivos de injector encontrados." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 5 — DLLs INYECTADAS EN ROBLOX
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 5 — DLL Injection en Roblox"
Log "`n[SECCION 5] DLLs"
$rbxProc = Get-Process -Name "RobloxPlayerBeta","RobloxPlayer" -EA SilentlyContinue | Select-Object -First 1
if ($rbxProc) {
    INFO "Roblox corriendo (PID $($rbxProc.Id)) — escaneando módulos..."
    $found = $false
    try {
        $mods = $rbxProc.Modules | Select-Object -ExpandProperty ModuleName -EA SilentlyContinue
        foreach ($dll in $KnownBadDlls) {
            if ($mods -icontains $dll) {
                HIT "CHEAT" "DLL INYECTADA: $dll" "Encontrada en módulos de RobloxPlayerBeta.exe"
                $found = $true
            }
        }
        # Módulos de paths sospechosos
        $rbxProc.Modules | Where-Object {
            $_.FileName -notmatch "Windows\\|Roblox\\|Microsoft\." -and
            $_.FileName -match "\.dll$"
        } | Select-Object -First 15 | ForEach-Object {
            HIT "WARN" "DLL EXTERNA: $($_.ModuleName)" $_.FileName
            $found = $true
        }
        if (-not $found) { OK "Sin DLLs maliciosas en Roblox." }
    } catch {
        Write-Host "  │  [!] Ejecuta como Admin para escanear módulos de Roblox." -ForegroundColor Yellow
    }
} else {
    SKIP "Roblox no está corriendo — abre Roblox y vuelve a ejecutar para scan de DLLs."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 6 — SCAN DE MEMORIA (ROBLOX VIVO)
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 6 — Scan de Memoria de Roblox"
Log "`n[SECCION 6] Memoria"
if ($rbxProc -and $isAdmin) {
    INFO "Escaneando memoria de Roblox para flags activas..."
    $allDangerFlags = @($FLAG_CHEAT.Keys) + @($FLAG_NETWORK.Keys) + @($FLAG_PHYSICS.Keys)
    $hProc = [WinMem]::OpenProcess(0x0010 -bor 0x0400, $false, $rbxProc.Id)
    if ($hProc -ne [IntPtr]::Zero) {
        $buf = New-Object byte[] 131072
        $addr = [IntPtr]0x10000
        $found = $false; $scanned = 0; $memFound = @{}
        while ($addr.ToInt64() -lt 0x7FFFFFFF -and $scanned -lt 800) {
            $read = 0
            if ([WinMem]::ReadProcessMemory($hProc, $addr, $buf, $buf.Length, [ref]$read) -and $read -gt 0) {
                $str = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
                foreach ($flag in $allDangerFlags) {
                    if ($str.Contains($flag) -and -not $memFound.ContainsKey($flag)) {
                        $cat = Get-FlagCategory $flag "1"
                        HIT $cat "MEMORIA ACTIVA: $flag" "Flag detectada en RAM de Roblox @ ~0x$($addr.ToString('X'))"
                        $memFound[$flag] = $true
                        $found = $true
                    }
                }
            }
            $addr = [IntPtr]($addr.ToInt64() + 131072)
            $scanned++
        }
        [WinMem]::CloseHandle($hProc) | Out-Null
        if (-not $found) { OK "Sin flags ilegales en memoria de Roblox." }
    } else { Write-Host "  │  [!] No se pudo abrir handle de proceso." -ForegroundColor Yellow }
} elseif (-not $isAdmin) {
    SKIP "Requiere Admin. Ejecuta PowerShell como Administrador."
} else {
    SKIP "Roblox no está corriendo."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 7 — REGISTRY FASTFLAGS
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 7 — FastFlags en Registro de Windows"
Log "`n[SECCION 7] Registry"
$regPaths = @("HKCU:\Software\Roblox","HKLM:\Software\Roblox","HKCU:\Software\ROBLOX Corporation","HKLM:\Software\ROBLOX Corporation")
$found = $false
foreach ($rp in $regPaths) {
    if (-not (Test-Path $rp)) { continue }
    Get-ChildItem $rp -Recurse -EA SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -EA SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $cat = Get-FlagCategory $_.Name "$($_.Value)"
                if ($cat -ne "SAFE" -and $cat -ne "FPS") {
                    HIT $cat "REGISTRY: $($_.Name) = $($_.Value)" $_.PSPath
                    $found = $true
                }
            }
        }
    }
}
if (-not $found) { OK "Sin flags peligrosas en el registro." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 8 — DRIVERS SOSPECHOSOS
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 8 — Drivers de Kernel"
Log "`n[SECCION 8] Drivers"
if ($isAdmin) {
    $drivers = Get-WmiObject Win32_SystemDriver -EA SilentlyContinue
    $found = $false
    foreach ($drv in $drivers) {
        # Saltar whitelist de Windows
        $skip = $false
        foreach ($wl in $DriverWhitelist) { if ($drv.Name -imatch $wl) { $skip = $true; break } }
        if ($skip) { continue }
        foreach ($bd in $BadDrivers) {
            if ($drv.Name -imatch $bd -or $drv.PathName -imatch $bd) {
                HIT "CHEAT" "DRIVER: $($drv.Name)" "Path: $($drv.PathName) | Estado: $($drv.State)"
                $found = $true
            }
        }
    }
    if (-not $found) { OK "Sin drivers sospechosos encontrados." }
} else {
    SKIP "Requiere Admin para escanear drivers."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 9 — STARTUP ENTRIES
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 9 — Entradas de Inicio (Startup)"
Log "`n[SECCION 9] Startup"
$regStartup = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$found = $false
foreach ($rs in $regStartup) {
    if (-not (Test-Path $rs)) { continue }
    $e = Get-ItemProperty $rs -EA SilentlyContinue
    if (-not $e) { continue }
    $e.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
        $v = $_.Value.ToLower()
        foreach ($inj in $KnownInjectors) {
            foreach ($f in $inj.F) {
                if ($v -match [regex]::Escape($f.ToLower())) {
                    HIT $inj.S "STARTUP: $($inj.N)" "$($_.Name) => $($_.Value)"
                    $found = $true
                }
            }
        }
    }
}
$sfolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $sfolder) {
    Get-ChildItem $sfolder -File -EA SilentlyContinue | ForEach-Object {
        $fn = $_.Name.ToLower()
        foreach ($inj in $KnownInjectors) {
            foreach ($f in $inj.F) {
                if ($fn -eq $f.ToLower()) {
                    HIT $inj.S "STARTUP FILE: $($inj.N)" $_.FullName
                    $found = $true
                }
            }
        }
    }
}
if (-not $found) { OK "Sin entradas de injector en startup." }

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 10 — INTEGRIDAD DE ROBLOX EXE
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 10 — Integridad del Ejecutable de Roblox"
Log "`n[SECCION 10] Exe Integrity"
$exes = @()
if (Test-Path $rbxVer) {
    Get-ChildItem $rbxVer -Filter "RobloxPlayerBeta.exe" -Recurse -EA SilentlyContinue | ForEach-Object { $exes += $_.FullName }
}
if ($exes.Count -gt 0) {
    foreach ($exe in $exes) {
        $sig  = Get-AuthenticodeSignature $exe -EA SilentlyContinue
        $hash = (Get-FileHash $exe SHA256 -EA SilentlyContinue).Hash
        $size = (Get-Item $exe -EA SilentlyContinue).Length
        INFO "$([System.IO.Path]::GetDirectoryName($exe).Split('\')[-2])"
        INFO "SHA256: $hash | Size: $size bytes"
        if ($sig.Status -ne "Valid") {
            HIT "CHEAT" "FIRMA INVÁLIDA: RobloxPlayerBeta.exe" "Firma: $($sig.Status) — puede estar parcheado"
        } else {
            OK "Firma Authenticode válida."
        }
    }
} else {
    SKIP "RobloxPlayerBeta.exe no encontrado."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 11 — HOSTS FILE
# ══════════════════════════════════════════════════════════════════════════════
Banner "SECCIÓN 11 — Hosts File"
Log "`n[SECCION 11] Hosts"
$hc = Get-Content "C:\Windows\System32\drivers\etc\hosts" -EA SilentlyContinue
$rl = $hc | Where-Object { $_ -match "roblox" -and $_ -notmatch "^#" }
if ($rl) {
    foreach ($l in $rl) { HIT "WARN" "HOSTS ENTRY: $l" "Roblox redirigido en hosts file" }
} else { OK "Hosts file limpio." }

# ══════════════════════════════════════════════════════════════════════════════
#  RESUMEN FINAL
# ══════════════════════════════════════════════════════════════════════════════
$totalDanger = $hits["CHEAT"] + $hits["PHYSICS"] + $hits["NETWORK"]
$totalWarn   = $hits["WARN"] + $hits["VISUAL"]

Write-Host "`n"
Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                    RESUMEN DEL SCAN                             ║" -ForegroundColor Cyan
Write-Host "  ╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "  ║  [CHEAT]   Ventaja directa  : $($hits['CHEAT'].ToString().PadRight(3))                              ║" -ForegroundColor Red
Write-Host "  ║  [NETWORK] Ventaja de red   : $($hits['NETWORK'].ToString().PadRight(3))                              ║" -ForegroundColor DarkYellow
Write-Host "  ║  [PHYSICS] Physics exploit  : $($hits['PHYSICS'].ToString().PadRight(3))                              ║" -ForegroundColor Magenta
Write-Host "  ║  [VISUAL]  Visual/Render    : $($hits['VISUAL'].ToString().PadRight(3))                              ║" -ForegroundColor DarkMagenta
Write-Host "  ║  [FPS]     FPS (permitidas) : $($hits['FPS'].ToString().PadRight(3))                              ║" -ForegroundColor Green
Write-Host "  ║  [WARN]    Desconocidas     : $($hits['WARN'].ToString().PadRight(3))                              ║" -ForegroundColor Yellow
Write-Host "  ╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan

if ($totalDanger -gt 0) {
    Write-Host "  ║  VEREDICTO: ❌ TRAMPAS / FLAGS ILEGALES DETECTADAS              ║" -ForegroundColor Red
    Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ACCIONES REQUERIDAS:" -ForegroundColor White
    Write-Host "   1. Desinstala todos los injectors/executors listados." -ForegroundColor DarkGray
    Write-Host "   2. Borra las flags ilegales de Bloxstrap / ClientAppSettings." -ForegroundColor DarkGray
    Write-Host "   3. Reinstala Roblox si la firma del exe es inválida." -ForegroundColor DarkGray
    Write-Host "   4. Ejecuta Windows Defender (scan completo)." -ForegroundColor DarkGray
} elseif ($totalWarn -gt 0) {
    Write-Host "  ║  VEREDICTO: ⚠️  ADVERTENCIAS — Revisar manualmente              ║" -ForegroundColor Yellow
    Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
} else {
    Write-Host "  ║  VEREDICTO: ✅ LIMPIO — Sin trampas ni flags ilegales           ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

# Guardar reporte
$rp = "$env:USERPROFILE\Desktop\RobloxScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Log "`nVEREDICTO: $(if($totalDanger -gt 0){'TRAMPAS DETECTADAS'}elseif($totalWarn -gt 0){'ADVERTENCIAS'}else{'LIMPIO'})"
Log "CHEAT=$($hits['CHEAT']) | NETWORK=$($hits['NETWORK']) | PHYSICS=$($hits['PHYSICS']) | VISUAL=$($hits['VISUAL']) | FPS=$($hits['FPS']) | WARN=$($hits['WARN'])"
$report | Out-File $rp -Encoding UTF8

Write-Host ""
Write-Host "  Reporte guardado en: $rp" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Presiona cualquier tecla para salir..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

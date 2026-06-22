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

# ────────────────────────────────────────────────────────────────────────────
#  COLORS / OUTPUT HELPERS
# ────────────────────────────────────────────────────────────────────────────
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

# ────────────────────────────────────────────────────────────────────────────
#  DATABASES
# ────────────────────────────────────────────────────────────────────────────

# Known injector executables
$KnownInjectors = @(
    @{ Name="Synapse X";          Files=@("synapse.exe","synapseui.exe","sxlib.dll");                    Severity="DANGER" },
    @{ Name="KRNL";               Files=@("krnl.exe","krnlss.exe");                                      Severity="DANGER" },
    @{ Name="Fluxus";             Files=@("fluxus.exe","flux.exe");                                      Severity="DANGER" },
    @{ Name="Oxygen U";           Files=@("oxygenbootstrapper.exe","oxygenx.exe");                       Severity="DANGER" },
    @{ Name="Sentinel

# Build a Go program for the PS5 and wrap it in the launcher payload.
#   .\tools\build-payload.ps1 -GoDir tsd -Name tailscale -Version 0.5.2 -HomeIcon
#   .\tools\build-payload.ps1 -GoDir probe-go -Name probe [-DebugLoader] [-Watchdog 120] [-Send]
param(
    [Parameter(Mandatory = $true)][string]$GoDir,
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Package = '.',
    [string]$Tags = '',
    [string]$Version = '',     # sets main.version in the Go program
    [string[]]$Set = @(),      # extra Go variables, e.g. -Set main.releasesAPI=http://127.0.0.1:18099/latest.json
    [string]$MaxProcs = '',    # GOMAXPROCS for the Go program (launcher default: 4)
    [string]$GoDebug = '',     # GODEBUG value baked into the launcher
    [int]$Watchdog = 0,        # test builds: kill the process after this many seconds
    [switch]$HomeIcon,         # embed the helper that adds the home screen icon on first run
    [switch]$DebugLoader,      # print loader details and early crash registers
    [switch]$KeepSymbols,
    [switch]$Send,
    [int]$Seconds = 60
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1')

$out = Join-Path $DevRoot 'out'
New-Item -ItemType Directory -Force $out | Out-Null
$bin = Join-Path $out "$Name.bin"
$elf = Join-Path $out "$Name.elf"

$ldflags = @()
if (-not $KeepSymbols) { $ldflags += '-s', '-w' }
if ($Version) { $ldflags += "-X main.version=$Version" }
foreach ($s in $Set) { $ldflags += "-X $s" }
$goArgs = @('build', '-buildmode=pie', '-trimpath', "-ldflags=$($ldflags -join ' ')", '-o', $bin)
if ($Tags) { $goArgs += "-tags=$Tags" }
$goArgs += $Package

Push-Location (Join-Path $DevRoot $GoDir)
try { Invoke-PS5Go @goArgs } finally { Pop-Location }

$img = $bin -replace '\\', '/'
# String -D defines go to clang through a response file: PowerShell eats the
# embedded quotes when building the child's command line, which leaves
# "#define GO_IMAGE C:\..." behind instead of a string literal. Inside the
# response file the quotes must be backslash-escaped, or clang's own parser
# would strip them as well.
$defines = @()
if ($DebugLoader) { $defines += '-DGOLOAD_DEBUG' }
if ($Watchdog -gt 0) { $defines += "-DGOLOAD_WATCHDOG=$Watchdog" }
if ($MaxProcs) { $defines += ('-DGO_MAXPROCS=\"' + $MaxProcs + '\"') }
if ($GoDebug) { $defines += ('-DGO_DEBUG=\"' + $GoDebug + '\"') }
$defines += ('-DGO_IMAGE=\"' + $img + '\"')
$ccArgs = @('-O2', '-Wall')
if ($HomeIcon) {
    # The icon helper is a payload of its own. The app installer library only
    # loads when these come with it, in this order (as in the SDK's
    # install_app sample); with libSceAppInstUtil alone the payload is never
    # started.
    $helper = Join-Path $out 'appicon.elf'
    $assets = (Join-Path $DevRoot 'appicon') -replace '\\', '/'
    $assetRsp = Join-Path $out 'appicon.defines'
    [IO.File]::WriteAllLines($assetRsp, @('-DASSET_DIR=\"' + $assets + '\"'), [Text.UTF8Encoding]::new($false))
    Invoke-PS5CC -O2 -Wall "@$assetRsp" `
        -lSceIpmi -lSceAppInstUtil -lSceUserService -lSceSystemService `
        -o $helper (Join-Path $DevRoot 'appicon\main.c')
    $defines += ('-DICON_HELPER=\"' + ($helper -replace '\\', '/') + '\"')
}
$rsp = Join-Path $out 'launcher.defines'
[IO.File]::WriteAllLines($rsp, $defines, [Text.UTF8Encoding]::new($false))
$ccArgs += "@$rsp"
$ccArgs += @('-o', $elf, (Join-Path $DevRoot 'launcher\main.c'), (Join-Path $DevRoot 'launcher\goload.c'),
    (Join-Path $DevRoot 'launcher\homeicon.c'), (Join-Path $DevRoot 'launcher\report.c'))
Invoke-PS5CC @ccArgs

Write-Host ("built {0} ({1:N1} MB)" -f $elf, ((Get-Item $elf).Length / 1MB))
if ($Send) {
    & (Join-Path $PSScriptRoot 'ps5send.ps1') -File $elf -Seconds $Seconds
}

param(
    [string]$Iface     = "Wi-Fi",
    [int]$WsPort       = 8765,
    [int]$HttpPort     = 8766,
    [int]$DashPort     = 3000,
    [string]$PythonExe = ""
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

Write-Host ""
Write-Host "  WhoApp Live Capture - Starting..." -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [!] Requesting Administrator privileges..." -ForegroundColor Yellow
    
    $pyExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pyExe) { $pyExe = "python" }
    
    $argList = "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Iface `"$Iface`" -WsPort $WsPort -HttpPort $HttpPort -DashPort $DashPort -PythonExe `"$pyExe`""
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit
}

if ($PythonExe -eq "") { $PythonExe = "python" }

$npcapDll = "C:\Windows\System32\Npcap\wpcap.dll"
if (-not (Test-Path $npcapDll)) {
    Write-Host "  [!] Npcap not found. Please install from https://npcap.com" -ForegroundColor Red
    exit 1
}

Write-Host "  [*] Checking Python dependencies..." -ForegroundColor Yellow
& $PythonExe -m pip install scapy websockets aiohttp python-dotenv pyyaml --quiet --disable-pip-version-check

Write-Host "  [*] Freeing ports..." -ForegroundColor Yellow
@($WsPort, $HttpPort, $DashPort) | ForEach-Object {
    $procs = Get-NetTCPConnection -LocalPort $_ -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
    $procs | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
}
Start-Sleep -Milliseconds 500

Write-Host "  [*] Starting live capture server..." -ForegroundColor Yellow
$pyArgs = "`"$Root\live_server.py`" --iface `"$Iface`" --ws-port $WsPort --http-port $HttpPort"
$captureJob = Start-Process $PythonExe -ArgumentList $pyArgs -PassThru -WindowStyle Normal

Start-Sleep -Seconds 2

Write-Host "  [*] Starting dashboard..." -ForegroundColor Yellow
$dashJob = Start-Process cmd -ArgumentList "/c npm run dev" -WorkingDirectory "$Root\dashboard" -PassThru -WindowStyle Minimized

Write-Host "  [+] All services started successfully." -ForegroundColor Green
Write-Host ""

Start-Sleep -Seconds 4
Start-Process "http://localhost:$DashPort"

try {
    Wait-Process -Id $captureJob.Id
} catch {
    Write-Host "Shutting down..."
    Stop-Process -Id $captureJob.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $dashJob.Id -Force -ErrorAction SilentlyContinue
}

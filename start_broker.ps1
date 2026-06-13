$mosquittoPath = "C:\Program Files\mosquitto\mosquitto.exe"
if (-not (Test-Path $mosquittoPath)) {
    $mosquittoPath = "C:\Program Files (x86)\mosquitto\mosquitto.exe"
}

if (-not (Test-Path $mosquittoPath)) {
    Write-Host "Error: Mosquitto not found in standard paths." -ForegroundColor Red
    Write-Host "Please install 'mosquitto-install-windows-x64.exe' found in this folder."
    exit 1
}

Write-Host "Found Mosquitto at: $mosquittoPath"

# Attempt to stop existing instances
Write-Host "Attempting to stop existing Mosquitto service/process..."
Stop-Service mosquitto -Force -ErrorAction SilentlyContinue
Get-Process mosquitto -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Verify port 1883 is free
$netstat = netstat -ano | Select-String ":1883"
if ($netstat) {
    Write-Host "Warning: Port 1883 still in use. Service restart might fail." -ForegroundColor Yellow
}

# Start with local config
$configPath = Join-Path (Get-Location) "mosquitto.conf"
Write-Host "Starting Mosquitto with config: $configPath"

# Run in foreground so we can see output
& $mosquittoPath -c "$configPath" -v

@echo off
setlocal

:: Determine where python is - try venv first, then PATH
if exist "venv\Scripts\python.exe" (
    set "PYTHON_CMD=venv\Scripts\python.exe"
    echo [INFO] Using virtual environment Python.
) else (
    set "PYTHON_CMD=python"
    echo [INFO] Using system Python (venv not found).
)

echo ========================================================
echo   STARTING EVM PROJECT SUPPORT SERVICES 
echo ========================================================
echo.

:: 1. Start Log Server
echo [1/3] Starting Log Server (UDP)...
start "Log Server" cmd /k "%PYTHON_CMD% log_server.py"

:: 2. Start Backup Node
echo [2/3] Starting Backup Node (MQTT Listener)...
start "Backup Node" cmd /k "%PYTHON_CMD% backup_node.py"

:: 3. Start Health Monitor
echo [3/3] Starting Health Monitor...
start "Health Monitor" cmd /k "%PYTHON_CMD% health_monitor.py"

:: 4. Start Admin Client (Interactive)
echo [4/4] Starting Admin Client...
start "Admin Client" cmd /k "%PYTHON_CMD% admin_client.py"

echo.
echo ========================================================
echo   ALL SERVICES LAUNCHED
echo ========================================================
echo   - Log Server window open
echo   - Backup Node window open
echo   - Health Monitor window open
echo   - Admin Client window open
echo.
echo   Note: Run 'server.py' and 'client.py' separately as requested.
echo.
pause

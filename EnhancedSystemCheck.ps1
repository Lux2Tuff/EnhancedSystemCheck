# Enhanced PowerShell script for cheat detection, malware detection, and PCIe slot data logging
# Requires administrative privileges

# Global configuration
$LogDir = "./SystemCheckLogs"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$MainLogFile = "$LogDir/SystemCheck_$Timestamp.log"
$CombinedMarkdown = "$LogDir/Summary_$Timestamp.md"

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Initialize logging
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $LogMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $MainLogFile -Value $LogMessage
    Write-Host $LogMessage
}

# Load required modules
function Invoke-EnhancedModules {
    param (
        [string[]]$Vars
    )
    $modules = @(
        'Write-Header.ps1',
        'Test-SecureBoot.ps1',
        'Get-InstalledApplications.ps1',
        'Get-RecentFiles.ps1',
        'Find-SuspiciousFiles.ps1'
    )

    if ($Vars -contains "-dev") {
        foreach ($module in $modules) {
            $modulePath = "./modules/$module"
            if (Test-Path $modulePath) {
                . $modulePath
                Write-Log "Loaded module $module from local path"
            } else {
                Write-Log "Module $module not found in './modules/'" "ERROR"
            }
        }
    } else {
        foreach ($module in $modules) {
            try {
                $url = "https://raw.githubusercontent.com/Annabxlla/art/refs/heads/master/modules/$module"
                Invoke-Expression (Invoke-WebRequest $url -UseBasicParsing).Content
                Write-Log "Loaded module $module from $url"
            } catch {
                Write-Log "Failed to load module $module from $url : $_" "ERROR"
            }
        }
    }
}

# Cheat detection: Analyze running processes and memory
function Invoke-CheatDetection {
    Write-Log "Starting cheat detection scan"
    
    # Check for known cheat-related processes
    $suspiciousProcesses = @(
        "cheatengine", "artmoney", "trainer", "hack", "injector", "debugger"
    )
    
    Get-Process | ForEach-Object {
        foreach ($pattern in $suspiciousProcesses) {
            if ($_.Name -like "*$pattern*" -or $_.Path -like "*$pattern*") {
                Write-Log "Suspicious process detected: $($_.Name) (PID: $($_.Id)) Path: $($_.Path)" "WARNING"
            }
        }
    }

    # Check for unsigned drivers (potential kernel-level cheats)
    $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.IsSigned -eq $false }
    foreach ($driver in $drivers) {
        Write-Log "Unsigned driver detected: $($driver.FriendlyName) - $($driver.DriverProviderName)" "WARNING"
    }

    # Memory scanning for suspicious modules
    $processes = Get-Process
    foreach ($process in $processes) {
        try {
            $modules = $process.Modules | Where-Object { $_.CompanyName -eq $null -or $_.FileName -match "\.sys$|\.dll$" }
            foreach ($module in $modules) {
                Write-Log "Suspicious module in $($process.Name): $($module.ModuleName) - $($module.FileName)" "WARNING"
            }
        } catch {
            Write-Log "Error scanning modules for process $($process.Name): $_" "ERROR"
        }
    }
}

# Malware detection: Scan for known malware signatures and behaviors
function Invoke-MalwareDetection {
    Write-Log "Starting malware detection scan"
    
    # Scan for suspicious files in common malware locations
    $pathsToScan = @(
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:TEMP",
        "$env:PROGRAMDATA"
    )
    
    foreach ($path in $pathsToScan) {
        Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | 
        Where-Object { 
            $_.Extension -in @(".exe", ".dll", ".bat", ".vbs", ".ps1") -and
            $_.LastWriteTime -gt (Get-Date).AddDays(-7)
        } | ForEach-Object {
            Write-Log "Recent suspicious file found: $($_.FullName) - Last Modified: $($_.LastWriteTime)" "WARNING"
        }
    }

    # Check for suspicious scheduled tasks
    $tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -and $_.Author -ne "Microsoft Corporation" }
    foreach ($task in $tasks) {
        Write-Log "Non-Microsoft scheduled task detected: $($task.TaskName) - Author: $($task.Author)" "WARNING"
    }

    # Check for unusual network connections
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            Write-Log "Network connection by $($process.Name): Remote Address $($conn.RemoteAddress):$($conn
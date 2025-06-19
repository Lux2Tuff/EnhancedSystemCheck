# Enhanced PowerShell script for cheat detection, malware detection, and PCIe slot data logging
# Requires administrative privileges

# Global configuration
$LogDir = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'SystemCheckLogs')
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$MainLogFile = "$LogDir\SystemCheck_$Timestamp.log"
$CombinedMarkdown = "$LogDir\Summary_$Timestamp.md"

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    try {
        New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Error "Failed to create log directory: $($_.Exception.Message)"
        Exit 1
    }
}

# Initialize logging
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $LogMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    try {
        Add-Content -Path $MainLogFile -Value $LogMessage -ErrorAction Stop
        Write-Host $LogMessage
    } catch {
        Write-Error "Failed to write to log: $($_.Exception.Message)"
    }
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
                Write-Log "Failed to load module $module from $url: $($_.Exception.Message)" "ERROR"
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
            if ($_.Name -like "*$pattern*" -or ($_.Path -and $_.Path -like "*$pattern*")) {
                Write-Log "Suspicious process detected: $($_.Name) (PID: $($_.Id)) Path: $($_.Path)" "WARNING"
            }
        }
    }

    # Check for unsigned drivers
    $drivers = Get-WmiObject Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.IsSigned -eq $false }
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
            Write-Log "Error scanning modules for process $($process.Name): $($_.Exception.Message)" "ERROR"
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
        try {
            Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { 
                $null -ne $_.Extension -and 
                $_.Extension -in @(".exe", ".dll", ".bat", ".vbs", ".ps1") -and
                $_.LastWriteTime -gt (Get-Date).AddDays(-7)
            } | ForEach-Object {
                Write-Log "Recent suspicious file found: $($_.FullName) - Last Modified: $($_.LastWriteTime)" "WARNING"
            }
        } catch {
            Write-Log "Error scanning path ${path}: $($_.Exception.Message)" "ERROR"
        }
    }

    # Check for suspicious scheduled tasks
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Ready" -and $_.Author -ne "Microsoft Corporation" }
    foreach ($task in $tasks) {
        Write-Log "Non-Microsoft scheduled task detected: $($task.TaskName) - Author: $($task.Author)" "WARNING"
    }

    # Check for unusual network connections
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" }
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            Write-Log "Network connection by $($process.Name): Remote Address $($conn.RemoteAddress):$($conn.RemotePort)"
        }
    }
}

# PCIe slot data collection
function Get-PCIeSlotData {
    Write-Log "Collecting PCIe slot data"
    
    $pnpDevices = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -like "PCI\*" }
    foreach ($device in $pnpDevices) {
        try {
            $deviceInfo = [PSCustomObject]@{
                Name        = if ($device.Name) { $device.Name } else { "Unknown" }
                DeviceID    = if ($device.DeviceID) { $device.DeviceID } else { "Unknown" }
                Status      = if ($device.Status) { $device.Status } else { "Unknown" }
                Manufacturer = if ($device.Manufacturer) { $device.Manufacturer } else { "Unknown" }
            }
            Write-Log "PCIe Device: $($deviceInfo.Name) - ID: $($deviceInfo.DeviceID) - Status: $($deviceInfo.Status)"
            $deviceInfo | Export-Csv -Path "$LogDir\PCIeDevices_$Timestamp.csv" -Append -NoTypeInformation -ErrorAction Stop
        } catch {
            Write-Log "Error processing PCIe device: $($_.Exception.Message)" "ERROR"
        }
    }
}

# Generate summary markdown
function Write-SummaryMarkdown {
    $markdown = @"
# System Check Summary - $Timestamp

## System Information
- OS: $([System.Environment]::OSVersion.VersionString)
- Secure Boot: $(try { Test-SecureBoot } catch { "Unknown" })
- Admin: $([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

## Cheat Detection Findings
- Suspicious processes: $(try { Get-Content $MainLogFile -ErrorAction Stop | Where-Object { $_ -like "*Suspicious process detected*" } | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 })
- Unsigned drivers: $(try { Get-Content $MainLogFile -ErrorAction Stop | Where-Object { $_ -like "*Unsigned driver detected*" } | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 })

## Malware Detection Findings
- Suspicious files: $(try { Get-Content $MainLogFile -ErrorAction Stop | Where-Object { $_ -like "*Recent suspicious file found*" } | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 })
- Non-Microsoft tasks: $(try { Get-Content $MainLogFile -ErrorAction Stop | Where-Object { $_ -like "*Non-Microsoft scheduled task*" } | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 })

## PCIe Devices
- See PCIeDevices_$Timestamp.csv for details

## Full Log
- Detailed log available at $MainLogFile
"@
    try {
        $markdown | Out-File -FilePath $CombinedMarkdown -Encoding UTF8 -ErrorAction Stop
        Write-Log "Summary markdown generated at $CombinedMarkdown"
    } catch {
        Write-Log "Failed to generate summary markdown: $($_.Exception.Message)" "ERROR"
    }
}

# Main execution
function Main {
    param (
        [string[]]$Vars
    )
    
    Write-Log "Starting enhanced system check"
    
    # Set execution policy
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
    } catch {
        Write-Log "Failed to set execution policy: $($_.Exception.Message)" "ERROR"
        Exit 1
    }
    
    # Load modules
    Invoke-EnhancedModules -Vars $Vars
    
    # Run detection functions
    Invoke-CheatDetection
    Invoke-MalwareDetection
    Get-PCIeSlotData
    
    # Generate summary
    Write-SummaryMarkdown
    
    # Copy summary to clipboard
    try {
        Get-Content $CombinedMarkdown -ErrorAction Stop | Set-Clipboard
        Write-Log "Summary copied to clipboard"
    } catch {
        Write-Log "Failed to copy summary to clipboard: $($_.Exception.Message)" "ERROR"
    }
    
    Write-Host "`nPress any key to exit..."
    [void][System.Console]::ReadKey($true)
}

# Admin check
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host "Script requires administrative privileges. Relaunching as admin..."
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($args -contains "-dev") {
        Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -File `"$scriptPath`" -Vars $args"
    } else {
        Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -Command Invoke-Expression (Invoke-WebRequest 'https://raw.githubusercontent.com/Annabxlla/art/refs/heads/master/main.ps1')"
    }
    Exit
} else {
    Main -Vars $args
}
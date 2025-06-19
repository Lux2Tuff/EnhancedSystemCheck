# DeepCheatScan.ps1
# PowerShell script for deep scanning of Windows systems to detect video game cheats, cheat loaders, or their remnants
# Requires administrative privileges
# Created by Grok for detecting cheats in games like Rainbow Six Siege
# Date: June 18, 2025

# Global configuration
$LogDir = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'DeepCheatScanLogs')
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$MainLogFile = "$LogDir\DeepCheatScan_$Timestamp.log"
$SummaryMarkdown = "$LogDir\CheatScanSummary_$Timestamp.md"

# Trusted publishers to filter out legitimate DLLs
$TrustedPublishers = @(
    "Microsoft Corporation",
    "Microsoft Windows",
    "NVIDIA Corporation",
    "Intel Corporation",
    "Advanced Micro Devices, Inc.",
    "Realtek Semiconductor Corp.",
    "Adobe Inc.",
    "Apple Inc.",
    "Google LLC",
    "Dell Inc.",
    "Hewlett-Packard Company",
    "Lenovo Group Limited",
    "Cisco Systems, Inc.",
    "Ubisoft Entertainment"
)

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    try {
        New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction Stop | Out-Null
        Write-Host "Created log directory: $LogDir"
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

# Load external modules
function Invoke-Modules {
    param (
        [string[]]$Vars
    )
    $modules = @(
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
                Write-Log "Loaded module $module from ${url}"
            } catch {
                Write-Log "Failed to load module $module from ${url}: $($_.Exception.Message)" "ERROR"
            }
        }
    }
}

# Check running processes for cheat-related names or paths
function Invoke-ProcessScan {
    Write-Log "Scanning running processes for cheat-related activity"
    $suspiciousPatterns = @(
        "cheatengine", "artmoney", "trainer", "hack", "injector", "debugger",
        "unknowncheats", "battleye_bypass", "esp", "aimbot", "wallhack"
    )
    Get-Process | ForEach-Object {
        foreach ($pattern in $suspiciousPatterns) {
            if ($_.Name -like "*$pattern*" -or ($_.Path -and $_.Path -like "*$pattern*")) {
                Write-Log "Suspicious process detected: $($_.Name) (PID: $($_.Id)) Path: $($_.Path)" "WARNING"
            }
        }
    }
}

# Scan loaded DLLs for untrusted or unsigned modules
function Invoke-DLLScan {
    Write-Log "Scanning loaded DLLs for untrusted or unsigned modules"
    $processes = Get-Process
    foreach ($process in $processes) {
        try {
            $modules = $process.Modules | Where-Object { $_.FileName -match "\.dll$" }
            foreach ($module in $modules) {
                try {
                    $signature = Get-AuthenticodeSignature -FilePath $module.FileName -ErrorAction SilentlyContinue
                    if ($null -eq $signature -or $signature.Status -ne "Valid" -or $signature.SignerCertificate -eq $null) {
                        Write-Log "Unsigned or invalid DLL in $($process.Name): $($module.ModuleName) - $($module.FileName)" "WARNING"
                        continue
                    }
                    $publisher = $signature.SignerCertificate.Subject -replace '.*CN=([^,]+).*', '$1'
                    if ($TrustedPublishers -notcontains $publisher) {
                        Write-Log "Untrusted DLL in $($process.Name): $($module.ModuleName) - $($module.FileName) (Publisher: $publisher)" "WARNING"
                    }
                } catch {
                    Write-Log "Error verifying signature for DLL in $($process.Name): $($module.ModuleName) - $($module.FileName): $($_.Exception.Message)" "ERROR"
                }
            }
        } catch {
            Write-Log "Error scanning modules for process $($process.Name): $($_.Exception.Message)" "ERROR"
        }
    }
}

# Scan file system for suspicious files
function Invoke-FileSystemScan {
    Write-Log "Scanning file system for suspicious files"
    $pathsToScan = @(
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:TEMP",
        "$env:PROGRAMDATA",
        "$env:USERPROFILE\Documents"
    )
    $suspiciousExtensions = @(".exe", ".dll", ".bat", ".vbs", ".ps1", ".sys")
    foreach ($path in $pathsToScan) {
        try {
            Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -in $suspiciousExtensions -and
                $_.LastWriteTime -gt (Get-Date).AddDays(-30)
            } | ForEach-Object {
                try {
                    $signature = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
                    if ($null -eq $signature -or $signature.Status -ne "Valid") {
                        Write-Log "Unsigned or suspicious file found: $($_.FullName) - Last Modified: $($_.LastWriteTime)" "WARNING"
                    } else {
                        $publisher = $signature.SignerCertificate.Subject -replace '.*CN=([^,]+).*', '$1'
                        if ($TrustedPublishers -notcontains $publisher) {
                            Write-Log "Untrusted file found: $($_.FullName) - Last Modified: $($_.LastWriteTime) (Publisher: $publisher)" "WARNING"
                        }
                    }
                } catch {
                    Write-Log "Error verifying signature for file: $($_.FullName): $($_.Exception.Message)" "ERROR"
                }
            }
        } catch {
            Write-Log "Error scanning path ${path}: $($_.Exception.Message)" "ERROR"
        }
    }
}

# Scan prefetch files for evidence of deleted cheats
function Invoke-PrefetchScan {
    Write-Log "Scanning prefetch files for evidence of deleted cheats"
    $prefetchPath = "$env:SYSTEMROOT\Prefetch"
    if (Test-Path $prefetchPath) {
        try {
            Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
            ForEach-Object {
                if ($_.Name -match "cheat|hack|injector|unknowncheats|battleye|esp|aimbot|wallhack") {
                    Write-Log "Suspicious prefetch file found: $($_.FullName) - Last Modified: $($_.LastWriteTime)" "WARNING"
                }
            }
        } catch {
            Write-Log "Error scanning prefetch files: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "Prefetch directory not found or inaccessible" "INFO"
    }
}

# Scan registry for cheat-related keys
function Invoke-RegistryScan {
    Write-Log "Scanning registry for cheat-related keys"
    $registryPaths = @(
        "HKCU:\Software\CheatEngine",
        "HKLM:\Software\CheatEngine",
        "HKCU:\Software\UnknownCheats",
        "HKLM:\Software\UnknownCheats",
        "HKCU:\Software\Ubisoft"
    )
    foreach ($regPath in $registryPaths) {
        try {
            if (Test-Path $regPath) {
                Write-Log "Suspicious registry key found: $regPath" "WARNING"
                Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Write-Log "Property: $($_.PSChildName) = $($_.PSValue)" "INFO"
                }
            }
        } catch {
            Write-Log "Error scanning registry path $regPath: $($_.Exception.Message)" "ERROR"
        }
    }
}

# Scan network connections for cheat-related activity
function Invoke-NetworkScan {
    Write-Log "Scanning network connections for cheat-related activity"
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($conn in $connections) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($process) {
                Write-Log "Network connection by $($process.Name): Remote Address $($conn.RemoteAddress):$($conn.RemotePort)" "INFO"
            }
        }
    } catch {
        Write-Log "Error scanning network connections: $($_.Exception.Message)" "ERROR"
    }
}

# Generate summary markdown
function Write-SummaryMarkdown {
    Write-Log "Generating summary markdown"
    $markdown = @"
# Deep Cheat Scan Summary - $Timestamp

## System Information
- OS: $([System.Environment]::OSVersion.VersionString)
- Secure Boot: $(try { Test-SecureBoot } catch { "Unknown" })
- Admin: $([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

## Cheat Detection Findings
- Suspicious Processes: $(try { Get-Content $MainLogFile -ErrorAction Stop | Where-Object { $_ -like "*Suspicious process detected*" } | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 })
- Untrusted DLLs: $(try { Get-Content $MainLogFile -ErrorAction Stop | Where-Object { $_ -like "*Untrusted DLL*" } | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 })
- Suspicious Files: $(try { Get-Content $MainLogFile -ErrorAction Stop | Where-Object { $_ -like "*Unsigned or suspicious file*" } | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 })
- Suspicious Prefetch Files: $(try { Get-Content $MainLogFile -ErrorAction Stop | Where-Object { $_ -like "*Suspicious prefetch file*" } | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 })
- Suspicious Registry Keys: $(try { Get-Content $MainLogFile -ErrorAction Stop | Where-Object { $_ -like "*Suspicious registry key*" } | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 })

## Full Log
- Detailed log available at $MainLogFile
"@
    try {
        $markdown | Out-File -FilePath $SummaryMarkdown -Encoding UTF8 -ErrorAction Stop
        Write-Log "Summary markdown generated at $SummaryMarkdown"
    } catch {
        Write-Log "Failed to generate summary markdown: $($_.Exception.Message)" "ERROR"
    }
}

# Main execution
function Main {
    param (
        [string[]]$Vars
    )
    Write-Log "Starting deep cheat scan"
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
    } catch {
        Write-Log "Failed to set execution policy: $($_.Exception.Message)" "ERROR"
        Exit 1
    }
    Invoke-Modules -Vars $Vars
    Invoke-ProcessScan
    Invoke-DLLScan
    Invoke-FileSystemScan
    Invoke-PrefetchScan
    Invoke-RegistryScan
    Invoke-NetworkScan
    Write-SummaryMarkdown
    try {
        Get-Content $SummaryMarkdown -ErrorAction Stop | Set-Clipboard
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
        try {
            Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -File `"$scriptPath`" -Vars $args"
        } catch {
            Write-Error "Failed to relaunch script as admin: $($_.Exception.Message)"
            Exit
        }
    } else {
        try {
            Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -Command Invoke-Expression (Invoke-WebRequest 'https://raw.githubusercontent.com/Annabxlla/art/refs/heads/master/main.ps1' -UseBasicParsing).Content"
        } catch {
            Write-Error "Failed to download and relaunch script from GitHub: $($_.Exception.Message)"
            Exit
        }
    }
    Exit
} else {
    Main -Vars $args
}
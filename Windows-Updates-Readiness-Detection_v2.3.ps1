<#
.SYNOPSIS
    Windows Updates Readiness - Detection Script v2.3

.DESCRIPTION
    Comprehensive detection script that checks ALL readiness factors for Windows Updates/Upgrades:
    - Registry/Policy compliance for WUfB
    - Hardware eligibility (TPM, SecureBoot, RAM) for Windows 11
    - Disk space availability
    - Cleanup opportunities (Recycle Bin, Temp, WU Cache, etc.)
    - Windows Update component health
    - Update pause states
    - Update history

    Returns exit code 1 if issues detected, 0 if compliant.
    Designed for use as Intune Proactive Remediation DETECTION script.

.NOTES
    Version: 2.3
    Author: Yoennis Olmo
    Execution Mode: Proactive Remediation Detection (Intune)

    Changelog v2.3:
    - Fixed false positive remediation triggers from optional cleanup tasks
    - Cleanup flags now informational only unless disk space is critically low
    - Proxy detection is informational only (does not trigger remediation)
    - Only CRITICAL issues trigger remediation: registry problems, disabled services, 
      missing critical DLLs, paused updates, low disk space (<30GB)

    Intune Settings:
    Run this script using the logged on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell Host: Yes
#>

[CmdletBinding()]
param()

#region --- CONFIGURATION ---
$MinimumFreeSpaceGB = 30
$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = "$LogPath\Windows-Updates-Readiness-Detection.log"

$RegistryPaths = @{
    AU         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    WU         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    GWX        = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX"
    UX         = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    UPSettings = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings"
}

$CriticalSettings = @('NoAutoUpdate', 'UseWUServer', 'DisableDualScan')

$AuditSettings = @(
    'DoNotConnectToWindowsUpdateInternetLocations',
    'SetPolicyDrivenUpdateSourceForDriverUpdates',
    'SetPolicyDrivenUpdateSourceForOtherUpdates',
    'SetPolicyDrivenUpdateSourceForQualityUpdates',
    'SetPolicyDrivenUpdateSourceForFeatureUpdates',
    'DisableWindowsUpdateAccess',
    'WUServer', 'TargetGroup', 'WUStatusServer', 'TargetGroupEnabled', 'GStatus'
)

$PauseKeys = @(
    'PausedFeatureDate', 'PausedQualityDate', 'PausedFeatureStatus', 'PausedQualityStatus',
    'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
    'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime',
    'PauseUpdatesExpiryTime', 'PauseUpdatesStartTime'
)

$WUServices = @("wuauserv", "bits", "cryptsvc", "msiserver", "usosvc", "dosvc")

$WUDLLs = @(
    "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll",
    "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll",
    "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll",
    "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll",
    "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll",
    "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
    "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
)

# Legacy DLLs that are missing on modern Windows 11 builds (24H2/25H2)
$LegacyDLLs = @(
    "msxml.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "initpki.dll",
    "wuaueng1.dll", "wucltui.dll", "wuweb.dll", "qmgrprxy.dll",
    "wucltux.dll", "muweb.dll", "wuwebv.dll"
)

# Detection Results
$Global:Detection = @{
    Issues              = @()
    Warnings            = @()
    Status              = 'Compliant'
    RequiresRemediation = $false
    # Feature Flags
    RegistryPolicyIssues     = $false
    HardwareEligible         = $true
    DiskSpaceLow             = $false
    RecycleBinNeedsCleanup   = $false
    TempNeedsCleanup         = $false
    WUCacheNeedsCleanup      = $false
    DOCacheNeedsCleanup      = $false
    WERNeedsCleanup          = $false
    InstallerCacheNeedsCleanup = $false
    ThumbnailCacheNeedsCleanup = $false
    DISMCleanupNeeded        = $false
    WindowsOldExists         = $false
    WUComponentsNeedRepair   = $false
    WinsockProxyNeedsReset   = $false
    UpdatesPaused            = $false
}
#endregion

#region --- LOGGING ---
if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    Write-Host $LogEntry
}

Write-Log "==== Windows Updates Readiness Detection v2.3 ===="
#endregion

#region --- HELPER FUNCTIONS ---
function Get-RegistryValue {
    param([string]$Path, [string]$Property, [object]$ExpectedValue)
    try {
        $Value = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Property
        if ($null -ne $Value) {
            return @{ Exists = $true; Value = $Value; MatchesExpected = ($PSBoundParameters.ContainsKey('ExpectedValue') -and $Value -eq $ExpectedValue) }
        }
        return @{ Exists = $false; Value = $null }
    } catch { return @{ Exists = $false; Value = $null } }
}

function Get-WindowsVersion {
    param([int]$BuildNumber)
    if ($BuildNumber -ge 22000) { return "Windows 11" } else { return "Windows 10" }
}

function Test-WindowsUpdateService {
    try {
        $ServiceManager = New-Object -ComObject 'Microsoft.Update.ServiceManager'
        $UpdateService = $ServiceManager.Services | Where-Object { $_.Name -eq 'Microsoft Update' }
        if ($UpdateService) { return @{ Exists = $true; IsDefault = $UpdateService.IsDefaultAUService } }
        return @{ Exists = $false; IsDefault = $false }
    } catch { return @{ Exists = $false; IsDefault = $false } }
}
#endregion

#region --- DEVICE INFO ---
function Get-DeviceInfo {
    Write-Log "Gathering device information..."
    try {
        $CV = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $CS = Get-CimInstance Win32_ComputerSystem
        $OS = Get-CimInstance Win32_OperatingSystem
        $TPM = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        $SecureBoot = $false
        try { $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue } catch {}

        $BuildNumber = [int]$CV.CurrentBuild
        $DeviceInfo = [PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            WindowsVersion = Get-WindowsVersion -BuildNumber $BuildNumber
            DisplayVersion = $CV.DisplayVersion
            CurrentBuild   = "$($CV.CurrentBuild).$($CV.UBR)"
            BuildNumber    = $BuildNumber
            TotalRAM_GB    = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
            TPMPresent     = [bool]$TPM
            TPMEnabled     = if ($TPM) { $TPM.IsEnabled_InitialValue } else { $false }
            TPMVersion     = if ($TPM) { $TPM.SpecVersion.Split(",")[0] } else { "N/A" }
            SecureBoot     = $SecureBoot
        }

        Write-Log "Device: $($DeviceInfo.ComputerName) | $($DeviceInfo.WindowsVersion) $($DeviceInfo.DisplayVersion) (Build $($DeviceInfo.CurrentBuild))"
        Write-Log "RAM: $($DeviceInfo.TotalRAM_GB)GB | TPM: $($DeviceInfo.TPMPresent) (v$($DeviceInfo.TPMVersion)) | SecureBoot: $($DeviceInfo.SecureBoot)"
        return $DeviceInfo
    } catch {
        Write-Log "Error gathering device info: $_" "ERROR"
        return $null
    }
}
#endregion

#region --- HARDWARE ELIGIBILITY ---
function Test-HardwareEligibility {
    param($DeviceInfo)

    if ($DeviceInfo.WindowsVersion -eq "Windows 11") {
        Write-Log "Device already on Windows 11 - hardware check skipped"
        return
    }

    Write-Log "Checking Windows 11 hardware eligibility..."

    if ($DeviceInfo.TotalRAM_GB -lt 4) {
        $Global:Detection.Issues += "Hardware: RAM < 4GB ($($DeviceInfo.TotalRAM_GB)GB)"
        $Global:Detection.HardwareEligible = $false
    }
    if (-not $DeviceInfo.TPMPresent) {
        $Global:Detection.Issues += "Hardware: TPM not detected"
        $Global:Detection.HardwareEligible = $false
    }
    if ($DeviceInfo.TPMPresent -and -not $DeviceInfo.TPMEnabled) {
        $Global:Detection.Issues += "Hardware: TPM not enabled"
        $Global:Detection.HardwareEligible = $false
    }
    if ($DeviceInfo.TPMPresent -and $DeviceInfo.TPMVersion -notlike "2*") {
        $Global:Detection.Issues += "Hardware: TPM version < 2.0 ($($DeviceInfo.TPMVersion))"
        $Global:Detection.HardwareEligible = $false
    }
    if (-not $DeviceInfo.SecureBoot) {
        $Global:Detection.Issues += "Hardware: Secure Boot disabled"
        $Global:Detection.HardwareEligible = $false
    }

    if ($Global:Detection.HardwareEligible) {
        Write-Log "Hardware eligibility: PASSED"
    } else {
        Write-Log "Hardware eligibility: FAILED" "WARNING"
        $Global:Detection.RequiresRemediation = $true
    }
}
#endregion

#region --- REGISTRY/POLICY DETECTION ---
function Test-RegistryPolicy {
    Write-Log "Checking registry/policy compliance..."

    foreach ($Setting in $CriticalSettings) {
        $Path = if ($Setting -eq 'DisableDualScan') { $RegistryPaths.WU } else { $RegistryPaths.AU }
        $Result = Get-RegistryValue -Path $Path -Property $Setting -ExpectedValue 0
        if ($Result.Exists -and $Result.Value -eq 1) {
            Write-Log "ISSUE: $Setting = 1 (should be 0)" "WARNING"
            $Global:Detection.Issues += "Registry: $Setting = 1"
            $Global:Detection.RegistryPolicyIssues = $true
            $Global:Detection.RequiresRemediation = $true
        }
    }

    $UseUpdateClass = Get-RegistryValue -Path $RegistryPaths.AU -Property 'UseUpdateClassPolicySource' -ExpectedValue 1
    if (-not $UseUpdateClass.Exists -or $UseUpdateClass.Value -ne 1) {
        Write-Log "ISSUE: UseUpdateClassPolicySource misconfigured" "WARNING"
        $Global:Detection.Issues += "Registry: UseUpdateClassPolicySource misconfigured"
        $Global:Detection.RegistryPolicyIssues = $true
        $Global:Detection.RequiresRemediation = $true
    }

    $WUService = Test-WindowsUpdateService
    if (-not $WUService.IsDefault) {
        Write-Log "ISSUE: Microsoft Update not default service" "WARNING"
        $Global:Detection.Issues += "Service: Microsoft Update not default"
        $Global:Detection.RegistryPolicyIssues = $true
        $Global:Detection.RequiresRemediation = $true
    }

    # Audit additional settings
    foreach ($Setting in $AuditSettings) {
        $Check = Get-RegistryValue -Path $RegistryPaths.WU -Property $Setting
        if ($Check.Exists) { Write-Log "Audit: $Setting = $($Check.Value)" }
    }

    if (-not $Global:Detection.RegistryPolicyIssues) {
        Write-Log "Registry/Policy compliance: PASSED"
    }
}
#endregion

#region --- UPDATE PAUSE DETECTION ---
function Test-UpdatePauseStates {
    Write-Log "Checking for update pause states..."

    foreach ($PausePath in @($RegistryPaths.UX, $RegistryPaths.UPSettings)) {
        if (Test-Path $PausePath) {
            foreach ($Key in $PauseKeys) {
                $Result = Get-RegistryValue -Path $PausePath -Property $Key
                if ($Result.Exists -and $Result.Value) {
                    Write-Log "ISSUE: Update paused - $Key detected" "WARNING"
                    $Global:Detection.Issues += "Pause: $Key active"
                    $Global:Detection.UpdatesPaused = $true
                    $Global:Detection.RequiresRemediation = $true
                }
            }
        }
    }

    if (-not $Global:Detection.UpdatesPaused) {
        Write-Log "Update pause states: NONE DETECTED"
    }
}
#endregion

#region --- DISK SPACE & CLEANUP DETECTION ---
function Get-FolderSizeGB {
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            $Size = (Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            return [math]::Round($Size / 1GB, 2)
        }
    } catch {}
    return 0
}

function Test-DiskSpaceAndCleanup {
    Write-Log "Checking disk space and cleanup opportunities..."

    try {
        $SystemDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
        $FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
        Write-Log "Free disk space: $FreeSpaceGB GB (minimum: $MinimumFreeSpaceGB GB)"

        if ($FreeSpaceGB -lt $MinimumFreeSpaceGB) {
            $Global:Detection.DiskSpaceLow = $true
            $Global:Detection.Issues += "Low disk space: $FreeSpaceGB GB"
            $Global:Detection.RequiresRemediation = $true
        }
    } catch {
        Write-Log "Error checking disk space: $_" "ERROR"
    }

    # Recycle Bin (informational only - does not trigger remediation)
    try {
        $Shell = New-Object -ComObject Shell.Application
        $RecycleBin = $Shell.NameSpace(0x0a)
        $RecycleBinSize = 0
        if ($RecycleBin -and $RecycleBin.Items()) {
            foreach ($Item in $RecycleBin.Items()) { try { $RecycleBinSize += $Item.Size } catch {} }
        }
        $RecycleBinGB = [math]::Round($RecycleBinSize / 1GB, 2)
        if ($RecycleBinGB -gt 0.5) {
            Write-Log "Recycle Bin: $RecycleBinGB GB (cleanup available)" "INFO"
            $Global:Detection.RecycleBinNeedsCleanup = $true
        } else {
            Write-Log "Recycle Bin: $RecycleBinGB GB (OK)"
        }
    } catch { Write-Log "Error checking Recycle Bin: $_" "WARNING" }

    # User Temp (informational only)
    $UserTempSize = Get-FolderSizeGB -Path $env:TEMP
    if ($UserTempSize -gt 0.5) {
        Write-Log "User Temp: $UserTempSize GB (cleanup available)" "INFO"
        $Global:Detection.TempNeedsCleanup = $true
    } else { Write-Log "User Temp: $UserTempSize GB (OK)" }

    # System Temp (informational only)
    $SystemTempSize = Get-FolderSizeGB -Path "$env:SystemRoot\Temp"
    if ($SystemTempSize -gt 0.5) {
        Write-Log "System Temp: $SystemTempSize GB (cleanup available)" "INFO"
        $Global:Detection.TempNeedsCleanup = $true
    } else { Write-Log "System Temp: $SystemTempSize GB (OK)" }

    # Windows Update Cache (informational only)
    $WUCacheSize = Get-FolderSizeGB -Path "$env:SystemRoot\SoftwareDistribution\Download"
    if ($WUCacheSize -gt 0.5) {
        Write-Log "WU Cache: $WUCacheSize GB (cleanup available)" "INFO"
        $Global:Detection.WUCacheNeedsCleanup = $true
    } else { Write-Log "WU Cache: $WUCacheSize GB (OK)" }

    # Delivery Optimization Cache (informational only)
    $DOCacheSize = Get-FolderSizeGB -Path "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
    if ($DOCacheSize -gt 0.5) {
        Write-Log "DO Cache: $DOCacheSize GB (cleanup available)" "INFO"
        $Global:Detection.DOCacheNeedsCleanup = $true
    } else { Write-Log "DO Cache: $DOCacheSize GB (OK)" }

    # Windows Error Reporting (informational only)
    $WERSize = 0
    $WERSize += Get-FolderSizeGB -Path "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
    $WERSize += Get-FolderSizeGB -Path "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
    if ($WERSize -gt 0.2) {
        Write-Log "WER: $WERSize GB (cleanup available)" "INFO"
        $Global:Detection.WERNeedsCleanup = $true
    } else { Write-Log "WER: $WERSize GB (OK)" }

    # Windows Installer Patch Cache (informational only)
    $InstallerCacheSize = Get-FolderSizeGB -Path "$env:SystemRoot\Installer\`$PatchCache`$"
    if ($InstallerCacheSize -gt 0.5) {
        Write-Log "Installer Cache: $InstallerCacheSize GB (cleanup available)" "INFO"
        $Global:Detection.InstallerCacheNeedsCleanup = $true
    } else { Write-Log "Installer Cache: $InstallerCacheSize GB (OK)" }

    # Thumbnail Cache (informational only)
    $ThumbCachePath = "$env:LocalAppData\Microsoft\Windows\Explorer"
    if (Test-Path $ThumbCachePath) {
        $ThumbFiles = Get-ChildItem -Path $ThumbCachePath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue
        $ThumbSize = [math]::Round(($ThumbFiles | Measure-Object -Property Length -Sum).Sum / 1GB, 2)
        if ($ThumbSize -gt 0.1) {
            Write-Log "Thumbnail Cache: $ThumbSize GB (cleanup available)" "INFO"
            $Global:Detection.ThumbnailCacheNeedsCleanup = $true
        } else { Write-Log "Thumbnail Cache: $ThumbSize GB (OK)" }
    }

    # DISM Component Store (informational only)
    try {
        $ComponentStore = Get-ChildItem -Path "$env:SystemRoot\WinSxS" -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
        $ComponentStoreGB = [math]::Round($ComponentStore.Sum / 1GB, 2)
        if ($ComponentStoreGB -gt 10) {
            Write-Log "Component Store (WinSxS): $ComponentStoreGB GB (cleanup available)" "INFO"
            $Global:Detection.DISMCleanupNeeded = $true
        } else { Write-Log "Component Store: $ComponentStoreGB GB (OK)" }
    } catch {}

    # Windows.old (informational only)
    if (Test-Path "$env:SystemDrive\Windows.old") {
        $WindowsOldSize = Get-FolderSizeGB -Path "$env:SystemDrive\Windows.old"
        Write-Log "Windows.old: $WindowsOldSize GB EXISTS (cleanup available)" "INFO"
        $Global:Detection.WindowsOldExists = $true
    } else { Write-Log "Windows.old: Not present" }
}
#endregion

#region --- WU COMPONENT HEALTH ---
function Test-WUComponentHealth {
    Write-Log "Checking Windows Update component health..."

    # Detect Windows version
    $CV = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $BuildNumber = [int]$CV.CurrentBuild
    $IsWindows11 = ($BuildNumber -ge 22000)

    # Check WU Services
    $ServicesOK = $true
    foreach ($Svc in $WUServices) {
        try {
            $Service = Get-Service -Name $Svc -ErrorAction SilentlyContinue
            if ($Service) {
                if ($Service.StartType -eq 'Disabled') {
                    Write-Log "ISSUE: Service $Svc is Disabled" "WARNING"
                    $ServicesOK = $false
                }
            }
        } catch {}
    }

    # Check critical DLLs exist (excluding legacy DLLs on Windows 11)
    $MissingDLLs = @()
    foreach ($DLL in $WUDLLs) {
        $DLLPath = "$env:SystemRoot\System32\$DLL"
        if (-not (Test-Path $DLLPath)) {
            # Check if this is a legacy DLL on Windows 11
            if ($IsWindows11 -and $LegacyDLLs -contains $DLL) {
                Write-Log "Note: Legacy DLL $DLL is missing (Expected on modern Windows 11 builds)" "INFO"
            } else {
                $MissingDLLs += $DLL
            }
        }
    }

    if ($MissingDLLs.Count -gt 0) {
        Write-Log "ISSUE: Missing WU DLLs: $($MissingDLLs -join ', ')" "WARNING"
        $Global:Detection.Issues += "Missing critical WU DLLs: $($MissingDLLs -join ', ')"
        $Global:Detection.WUComponentsNeedRepair = $true
        $Global:Detection.RequiresRemediation = $true
    }

    if (-not $ServicesOK) {
        $Global:Detection.Issues += "WU Services disabled"
        $Global:Detection.WUComponentsNeedRepair = $true
        $Global:Detection.RequiresRemediation = $true
    }

    # Check for proxy issues (informational only - does not trigger remediation)
    try {
        $ProxySettings = netsh winhttp show proxy 2>$null
        if ($ProxySettings -match "Proxy Server") {
            Write-Log "Proxy configured (informational only)" "INFO"
            $Global:Detection.WinsockProxyNeedsReset = $true
        }
    } catch {}

    if (-not $Global:Detection.WUComponentsNeedRepair) {
        Write-Log "WU Component health: OK"
    }
}
#endregion

#region --- UPDATE HISTORY ---
function Get-RecentUpdateHistory {
    Write-Log "Retrieving recent Windows Update history..."
    try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $HistoryCount = $Searcher.GetTotalHistoryCount()

        if ($HistoryCount -gt 0) {
            $History = $Searcher.QueryHistory(0, [Math]::Min(10, $HistoryCount))
            Write-Log "Recent Update History:"
            foreach ($Update in $History) {
                $Status = switch ($Update.ResultCode) {
                    0 { "NotStarted" }; 1 { "InProgress" }; 2 { "Succeeded" }
                    3 { "SucceededWithErrors" }; 4 { "Failed" }; 5 { "Aborted" }
                    default { "Unknown" }
                }
                Write-Log "  [$Status] $($Update.Title) - $($Update.Date)"
            }
        } else { Write-Log "No update history found" }
    } catch { Write-Log "Error retrieving update history: $_" "ERROR" }
}
#endregion

#region --- MAIN EXECUTION ---
try {
    $DeviceInfo = Get-DeviceInfo
    if ($DeviceInfo) { Test-HardwareEligibility -DeviceInfo $DeviceInfo }

    Test-RegistryPolicy
    Test-UpdatePauseStates
    Test-DiskSpaceAndCleanup
    Test-WUComponentHealth
    Get-RecentUpdateHistory

    # Summary
    Write-Log "==== DETECTION SUMMARY ===="
    Write-Log "Hardware Eligible: $($Global:Detection.HardwareEligible)"
    Write-Log "Registry/Policy Issues: $($Global:Detection.RegistryPolicyIssues)"
    Write-Log "Updates Paused: $($Global:Detection.UpdatesPaused)"
    Write-Log "Disk Space Low: $($Global:Detection.DiskSpaceLow)"
    Write-Log "Recycle Bin Cleanup: $($Global:Detection.RecycleBinNeedsCleanup)"
    Write-Log "Temp Cleanup: $($Global:Detection.TempNeedsCleanup)"
    Write-Log "WU Cache Cleanup: $($Global:Detection.WUCacheNeedsCleanup)"
    Write-Log "DO Cache Cleanup: $($Global:Detection.DOCacheNeedsCleanup)"
    Write-Log "WER Cleanup: $($Global:Detection.WERNeedsCleanup)"
    Write-Log "Installer Cache Cleanup: $($Global:Detection.InstallerCacheNeedsCleanup)"
    Write-Log "Thumbnail Cache Cleanup: $($Global:Detection.ThumbnailCacheNeedsCleanup)"
    Write-Log "DISM Cleanup Needed: $($Global:Detection.DISMCleanupNeeded)"
    Write-Log "Windows.old Exists: $($Global:Detection.WindowsOldExists)"
    Write-Log "WU Components Need Repair: $($Global:Detection.WUComponentsNeedRepair)"
    Write-Log "Winsock/Proxy Reset: $($Global:Detection.WinsockProxyNeedsReset)"
    Write-Log "Issues Found: $($Global:Detection.Issues.Count)"
    foreach ($Issue in $Global:Detection.Issues) { Write-Log "  - $Issue" }
    Write-Log "Requires Remediation: $($Global:Detection.RequiresRemediation)"
    Write-Log "===="

    if ($Global:Detection.RequiresRemediation) {
        Write-Log "STATUS: NON-COMPLIANT - Remediation required" "WARNING"
        exit 1
    } else {
        Write-Log "STATUS: COMPLIANT"
        exit 0
    }
} catch {
    Write-Log "Critical error: $($_.Exception.Message)" "ERROR"
    exit 1
}
#endregion

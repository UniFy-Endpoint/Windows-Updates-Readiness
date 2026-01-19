<#
.SYNOPSIS
    Windows Updates Readiness - Unified Detection and Remediation Script v2.3

.DESCRIPTION
    Comprehensive script that:
    - Detects and remediates Windows Update configuration issues
    - Checks hardware eligibility for Windows 11
    - Repairs Windows Update components
    - Clears update pause states
    - Manages disk space for updates (with granular detection flags)
    - Forces policy refresh and triggers updates
    Designed for use as a Platform Script in Microsoft Intune.

.PARAMETER DetectOnly
    Run in detection-only mode without making changes

.PARAMETER AggressiveCleanup
    Enable aggressive disk cleanup including Windows.old (removes rollback capability)

.PARAMETER SkipHardwareCheck
    Skip Windows 11 hardware eligibility checks

.NOTES
    Version: 2.3
    Author: Yoennis Olmo
    Execution Mode: Platform Script (Intune) - Run as SYSTEM
    
    Changelog v2.3:
    - Fixed false positive remediation triggers from optional cleanup tasks
    - Cleanup flags now informational only unless disk space is critically low
    - Added legacy DLL detection (skips re-registration if DLL doesn't exist on disk)
    - Only CRITICAL issues trigger remediation: registry problems, disabled services, 
      missing critical DLLs, paused updates, low disk space (<30GB)

    Intune Info:
    Script type: Platform Script
    Assign to: (Devices)
    Script Settings:
    Run this script using the logged on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell Host: Yes

.EXAMPLE
    .\Windows-Updates-Readiness_v2.3.ps1
    .\Windows-Updates-Readiness_v2.3.ps1 -DetectOnly
    .\Windows-Updates-Readiness_v2.3.ps1 -AggressiveCleanup
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$DetectOnly = $false,

    [Parameter(Mandatory=$false)]
    [switch]$AggressiveCleanup = $false,

    [Parameter(Mandatory=$false)]
    [switch]$SkipHardwareCheck = $false
)

#region --- LOGGING SETUP ---
$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = "$LogPath\Windows-Updates-Readiness.log"

if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    Write-Host $LogEntry
}

Write-Log "===="
Write-Log "Windows Updates Readiness Script v2.3"
Write-Log "Execution Mode: $(if ($DetectOnly) { 'Detection Only' } else { 'Detection and Remediation' })"
Write-Log "Aggressive Cleanup: $AggressiveCleanup"
Write-Log "Skip Hardware Check: $SkipHardwareCheck"
Write-Log "===="
#endregion

#region --- CONFIGURATION ---
# Minimum free disk space in GB
$MinimumFreeSpaceGB = 30

# Cleanup thresholds (in MB) - flag if exceeds these values
$CleanupThresholds = @{
    RecycleBin = 500        # 500 MB
    TempFiles = 500         # 500 MB
    WUCache = 500           # 500 MB
    DOCache = 200           # 200 MB
    WER = 100               # 100 MB
    InstallerCache = 200    # 200 MB
    ThumbnailCache = 100    # 100 MB
    WinSxS = 5000           # 5 GB (component store)
}

$RegistryPaths = @{
    AU  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    WU  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    GWX = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX"
    UX  = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    UPSettings = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings"
}

# Critical settings that should be 0
$CriticalSettings = @('NoAutoUpdate', 'UseWUServer', 'DisableDualScan')

$AuditSettings = @(
    'DoNotConnectToWindowsUpdateInternetLocations',
    'SetPolicyDrivenUpdateSourceForDriverUpdates',
    'SetPolicyDrivenUpdateSourceForOtherUpdates',
    'SetPolicyDrivenUpdateSourceForQualityUpdates',
    'SetPolicyDrivenUpdateSourceForFeatureUpdates',
    'DisableWindowsUpdateAccess',
    'WUServer',
    'TargetGroup',
    'WUStatusServer',
    'TargetGroupEnabled',
    'GStatus'
)

$SettingsToReset = @(
    @{ Path='AU'; Name='NoAutoUpdate'; Value=0 }
    @{ Path='WU'; Name='DoNotConnectToWindowsUpdateInternetLocations'; Value=0 }
    @{ Path='WU'; Name='DisableDualScan'; Value=0 }
    @{ Path='WU'; Name='SetPolicyDrivenUpdateSourceForDriverUpdates'; Value=0 }
    @{ Path='WU'; Name='SetPolicyDrivenUpdateSourceForOtherUpdates'; Value=0 }
    @{ Path='WU'; Name='SetPolicyDrivenUpdateSourceForQualityUpdates'; Value=0 }
    @{ Path='WU'; Name='SetPolicyDrivenUpdateSourceForFeatureUpdates'; Value=0 }
    @{ Path='WU'; Name='DisableWindowsUpdateAccess'; Value=0 }
    @{ Path='AU'; Name='UseWUServer'; Value=0 }
    @{ Path='AU'; Name='UseUpdateClassPolicySource'; Value=1 }
    @{ Path='GWX'; Name='GStatus'; Value=2 }
)

$SettingsToRemove = @('WUServer', 'WUStatusServer', 'TargetGroup', 'TargetGroupEnabled')

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

# Detection result object with granular flags
$Global:DetectionResult = @{
    Issues = @()
    Warnings = @()
    Status = 'Compliant'
    RequiresRemediation = $false
    HardwareEligible = $true
    DiskSpaceLow = $false
    # Granular detection flags
    Flags = @{
        RecycleBinNeedsCleanup = $false
        TempFilesNeedCleanup = $false
        WUCacheNeedsCleanup = $false
        DOCacheNeedsCleanup = $false
        WERNeedsCleanup = $false
        InstallerCacheNeedsCleanup = $false
        ThumbnailCacheNeedsCleanup = $false
        WinSxSNeedsCleanup = $false
        WindowsOldExists = $false
        WUDLLsMissing = $false
        WUServicesNotRunning = $false
        WinsockCorrupted = $false
        ProxyConfigured = $false
        UpdatesPaused = $false
        PolicyNonCompliant = $false
    }
    # Size tracking (in MB)
    Sizes = @{
        RecycleBin = 0
        TempFiles = 0
        WUCache = 0
        DOCache = 0
        WER = 0
        InstallerCache = 0
        ThumbnailCache = 0
        WinSxS = 0
        WindowsOld = 0
    }
}
#endregion

#region --- HELPER FUNCTIONS ---
function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Property,
        [object]$ExpectedValue
    )
    try {
        $Value = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Property
        if ($null -ne $Value) {
            return @{
                Exists = $true
                Value = $Value
                MatchesExpected = ($PSBoundParameters.ContainsKey('ExpectedValue') -and $Value -eq $ExpectedValue)
            }
        } else {
            return @{ Exists = $false; Value = $null }
        }
    } catch {
        return @{ Exists = $false; Value = $null }
    }
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    try {
        if (-not (Test-Path $Path)) {
            Write-Log "Creating registry path: $Path" "INFO"
            New-Item -Path $Path -Force | Out-Null
        }
        $CurrentValue = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Name
        if ($CurrentValue -ne $Value) {
            Write-Log "Setting ${Path}\${Name} to $Value (was: $CurrentValue)" "INFO"
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
            return $true
        } else {
            Write-Log "${Path}\${Name} already set to $Value" "INFO"
            return $false
        }
    } catch {
        Write-Log "Failed to set ${Path}\${Name}: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $Property = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if ($Property -and ($Property.PSObject.Properties.Name -contains $Name)) {
            Write-Log "Removing registry value: ${Path}\${Name}" "INFO"
            Remove-ItemProperty -Path $Path -Name $Name -Force
            return $true
        }
        return $false
    } catch {
        Write-Log "Failed to remove ${Path}\${Name}: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-WindowsUpdateService {
    try {
        $ServiceManager = New-Object -ComObject 'Microsoft.Update.ServiceManager'
        $UpdateService = $ServiceManager.Services | Where-Object { $_.Name -eq 'Microsoft Update' }
        if ($UpdateService) {
            return @{ Exists = $true; IsDefault = $UpdateService.IsDefaultAUService }
        }
        return @{ Exists = $false; IsDefault = $false }
    } catch {
        Write-Log "Failed to check Windows Update Service: $($_.Exception.Message)" "WARNING"
        return @{ Exists = $false; IsDefault = $false }
    }
}

function Get-WindowsVersion {
    param([int]$BuildNumber)
    if ($BuildNumber -ge 22000) { return "Windows 11" }
    else { return "Windows 10" }
}

function Get-FolderSizeMB {
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            $Size = (Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            return [math]::Round($Size / 1MB, 2)
        }
        return 0
    } catch {
        return 0
    }
}
#endregion

#region --- DEVICE INFO & HARDWARE CHECK ---
function Get-DeviceInfo {
    Write-Log "Gathering device information..." "INFO"

    try {
        $CV = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $CS = Get-CimInstance Win32_ComputerSystem
        $OS = Get-CimInstance Win32_OperatingSystem
        $TPM = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue

        $SecureBoot = $false
        try { $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue } catch {}

        $BuildNumber = [int]$CV.CurrentBuild
        $WindowsVersion = Get-WindowsVersion -BuildNumber $BuildNumber
        $Edition = $CV.EditionID

        $DeviceInfo = [PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            CurrentOS      = "$WindowsVersion $Edition"
            WindowsVersion = $WindowsVersion
            DisplayVersion = $CV.DisplayVersion
            CurrentBuild   = "$($CV.CurrentBuild).$($CV.UBR)"
            BuildNumber    = $BuildNumber
            Architecture   = $OS.OSArchitecture
            TotalRAM_GB    = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
            TPMPresent     = if ($TPM) { $true } else { $false }
            TPMEnabled     = if ($TPM) { $TPM.IsEnabled_InitialValue } else { $false }
            TPMVersion     = if ($TPM) { $TPM.SpecVersion.Split(",")[0] } else { "N/A" }
            SecureBoot     = $SecureBoot
        }

        Write-Log "Computer: $($DeviceInfo.ComputerName)" "INFO"
        Write-Log "Current OS: $($DeviceInfo.CurrentOS) - $($DeviceInfo.DisplayVersion) (Build $($DeviceInfo.CurrentBuild))" "INFO"
        Write-Log "RAM: $($DeviceInfo.TotalRAM_GB) GB | TPM: $($DeviceInfo.TPMPresent) (v$($DeviceInfo.TPMVersion)) | SecureBoot: $($DeviceInfo.SecureBoot)" "INFO"

        return $DeviceInfo
    } catch {
        Write-Log "Error gathering device info: $_" "ERROR"
        return $null
    }
}

function Test-HardwareEligibility {
    param($DeviceInfo)

    if ($SkipHardwareCheck) {
        Write-Log "Hardware check skipped by parameter" "INFO"
        return $true
    }

    if ($DeviceInfo.WindowsVersion -eq "Windows 11") {
        Write-Log "Device is already on Windows 11 - skipping hardware eligibility check" "INFO"
        return $true
    }

    Write-Log "Checking Windows 11 hardware eligibility..." "INFO"

    $Eligible = $true
    $BlockReasons = @()

    if ($DeviceInfo.TotalRAM_GB -lt 4) { 
        $Eligible = $false
        $BlockReasons += "RAM < 4GB ($($DeviceInfo.TotalRAM_GB) GB)"
    }
    if (-not $DeviceInfo.TPMPresent) { 
        $Eligible = $false
        $BlockReasons += "TPM not detected"
    }
    if ($DeviceInfo.TPMPresent -and -not $DeviceInfo.TPMEnabled) { 
        $Eligible = $false
        $BlockReasons += "TPM not enabled"
    }
    if ($DeviceInfo.TPMPresent -and $DeviceInfo.TPMVersion -notlike "2*") { 
        $Eligible = $false
        $BlockReasons += "TPM version < 2.0 ($($DeviceInfo.TPMVersion))"
    }
    if ($DeviceInfo.SecureBoot -eq $false) { 
        $Eligible = $false
        $BlockReasons += "Secure Boot disabled"
    }

    if (-not $Eligible) {
        foreach ($Reason in $BlockReasons) {
            Write-Log "HARDWARE BLOCK: $Reason" "ERROR"
            $Global:DetectionResult.Issues += "Hardware: $Reason"
        }
        $Global:DetectionResult.HardwareEligible = $false
        $Global:DetectionResult.RequiresRemediation = $true
    } else {
        Write-Log "Device passes Windows 11 hardware eligibility checks" "INFO"
    }

    return $Eligible
}
#endregion

#region --- DISK SPACE & CLEANUP DETECTION ---
function Get-RecycleBinSize {
    Write-Log "Calculating Recycle Bin size..." "INFO"
    try {
        $Shell = New-Object -ComObject Shell.Application
        $RecycleBin = $Shell.NameSpace(0x0a)
        $TotalSize = 0

        if ($RecycleBin -and $RecycleBin.Items()) {
            foreach ($Item in $RecycleBin.Items()) {
                try { $TotalSize += $Item.Size } catch {}
            }
        }

        $SizeMB = [math]::Round($TotalSize / 1MB, 2)
        Write-Log "Recycle Bin size: $SizeMB MB" "INFO"
        return $SizeMB
    } catch {
        Write-Log "Error calculating Recycle Bin size: $_" "WARNING"
        return 0
    }
}

function Test-DiskSpaceAndCleanupNeeds {
    Write-Log "Checking disk space and cleanup needs..." "INFO"

    try {
        $SystemDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
        $FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
        $TotalSpaceGB = [math]::Round($SystemDrive.Size / 1GB, 2)

        Write-Log "Disk space on $env:SystemDrive - Free: $FreeSpaceGB GB / Total: $TotalSpaceGB GB" "INFO"

        # 1. Recycle Bin (informational only)
        $RecycleBinMB = Get-RecycleBinSize
        $Global:DetectionResult.Sizes.RecycleBin = $RecycleBinMB
        if ($RecycleBinMB -gt $CleanupThresholds.RecycleBin) {
            $Global:DetectionResult.Flags.RecycleBinNeedsCleanup = $true
            Write-Log "Recycle Bin: $RecycleBinMB MB (cleanup available)" "INFO"
        }

        # 2. Temp Files (informational only)
        $UserTempMB = Get-FolderSizeMB -Path $env:TEMP
        $SystemTempMB = Get-FolderSizeMB -Path "$env:SystemRoot\Temp"
        $TotalTempMB = $UserTempMB + $SystemTempMB
        $Global:DetectionResult.Sizes.TempFiles = $TotalTempMB
        if ($TotalTempMB -gt $CleanupThresholds.TempFiles) {
            $Global:DetectionResult.Flags.TempFilesNeedCleanup = $true
            Write-Log "Temp files: $TotalTempMB MB (cleanup available)" "INFO"
        }

        # 3. Windows Update Cache (informational only)
        $WUCacheMB = Get-FolderSizeMB -Path "$env:SystemRoot\SoftwareDistribution\Download"
        $Global:DetectionResult.Sizes.WUCache = $WUCacheMB
        if ($WUCacheMB -gt $CleanupThresholds.WUCache) {
            $Global:DetectionResult.Flags.WUCacheNeedsCleanup = $true
            Write-Log "WU cache: $WUCacheMB MB (cleanup available)" "INFO"
        }

        # 4. Delivery Optimization Cache (informational only)
        $DOCachePath = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
        $DOCacheMB = Get-FolderSizeMB -Path $DOCachePath
        $Global:DetectionResult.Sizes.DOCache = $DOCacheMB
        if ($DOCacheMB -gt $CleanupThresholds.DOCache) {
            $Global:DetectionResult.Flags.DOCacheNeedsCleanup = $true
            Write-Log "DO cache: $DOCacheMB MB (cleanup available)" "INFO"
        }

        # 5. Windows Error Reporting (informational only)
        $WERArchiveMB = Get-FolderSizeMB -Path "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
        $WERQueueMB = Get-FolderSizeMB -Path "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
        $TotalWERMB = $WERArchiveMB + $WERQueueMB
        $Global:DetectionResult.Sizes.WER = $TotalWERMB
        if ($TotalWERMB -gt $CleanupThresholds.WER) {
            $Global:DetectionResult.Flags.WERNeedsCleanup = $true
            Write-Log "WER: $TotalWERMB MB (cleanup available)" "INFO"
        }

        # 6. Installer Patch Cache (informational only)
        $InstallerCacheMB = Get-FolderSizeMB -Path "$env:SystemRoot\Installer\`$PatchCache`$"
        $Global:DetectionResult.Sizes.InstallerCache = $InstallerCacheMB
        if ($InstallerCacheMB -gt $CleanupThresholds.InstallerCache) {
            $Global:DetectionResult.Flags.InstallerCacheNeedsCleanup = $true
            Write-Log "Installer cache: $InstallerCacheMB MB (cleanup available)" "INFO"
        }

        # 7. Thumbnail Cache (informational only)
        $ThumbCachePath = "$env:LocalAppData\Microsoft\Windows\Explorer"
        $ThumbCacheMB = 0
        if (Test-Path $ThumbCachePath) {
            $ThumbCacheMB = [math]::Round((Get-ChildItem -Path $ThumbCachePath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum / 1MB, 2)
        }
        $Global:DetectionResult.Sizes.ThumbnailCache = $ThumbCacheMB
        if ($ThumbCacheMB -gt $CleanupThresholds.ThumbnailCache) {
            $Global:DetectionResult.Flags.ThumbnailCacheNeedsCleanup = $true
            Write-Log "Thumbnail cache: $ThumbCacheMB MB (cleanup available)" "INFO"
        }

        # 8. WinSxS / Component Store (informational only)
        $WinSxSMB = Get-FolderSizeMB -Path "$env:SystemRoot\WinSxS"
        $Global:DetectionResult.Sizes.WinSxS = $WinSxSMB
        if ($WinSxSMB -gt $CleanupThresholds.WinSxS) {
            $Global:DetectionResult.Flags.WinSxSNeedsCleanup = $true
            Write-Log "WinSxS: $WinSxSMB MB (cleanup available)" "INFO"
        }

        # 9. Windows.old (informational only)
        $WindowsOldPath = "$env:SystemDrive\Windows.old"
        if (Test-Path $WindowsOldPath) {
            $WindowsOldMB = Get-FolderSizeMB -Path $WindowsOldPath
            $Global:DetectionResult.Sizes.WindowsOld = $WindowsOldMB
            $Global:DetectionResult.Flags.WindowsOldExists = $true
            Write-Log "Windows.old: $WindowsOldMB MB (cleanup available with -AggressiveCleanup)" "INFO"
        }

        # Overall disk space check (CRITICAL - triggers remediation)
        if ($FreeSpaceGB -lt $MinimumFreeSpaceGB) {
            Write-Log "WARNING: Less than ${MinimumFreeSpaceGB}GB free. Windows upgrades may fail!" "WARNING"
            $Global:DetectionResult.DiskSpaceLow = $true
            $Global:DetectionResult.Issues += "Low disk space: $FreeSpaceGB GB free (${MinimumFreeSpaceGB}GB+ required)"
            $Global:DetectionResult.RequiresRemediation = $true
        }

        return @{ Sufficient = ($FreeSpaceGB -ge $MinimumFreeSpaceGB); FreeGB = $FreeSpaceGB }
    } catch {
        Write-Log "Error checking disk space: $_" "ERROR"
        return @{ Sufficient = $true; FreeGB = 0 }
    }
}

function Test-WUComponentHealth {
    Write-Log "Checking Windows Update component health..." "INFO"

    # Detect Windows version
    $CV = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $BuildNumber = [int]$CV.CurrentBuild
    $IsWindows11 = ($BuildNumber -ge 22000)

    # Check critical WU DLLs exist
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
        $Global:DetectionResult.Flags.WUDLLsMissing = $true
        Write-Log "ISSUE: Critical WU DLLs missing: $($MissingDLLs -join ', ')" "ERROR"
        $Global:DetectionResult.Issues += "Missing critical WU DLLs: $($MissingDLLs -join ', ')"
        $Global:DetectionResult.RequiresRemediation = $true
    }

    # Check WU services status
    $DisabledServices = @()
    foreach ($Svc in $WUServices) {
        try {
            $Service = Get-Service -Name $Svc -ErrorAction SilentlyContinue
            if ($Service -and $Service.StartType -eq 'Disabled') {
                $DisabledServices += $Svc
            }
        } catch {}
    }

    if ($DisabledServices.Count -gt 0) {
        $Global:DetectionResult.Flags.WUServicesNotRunning = $true
        $Global:DetectionResult.Issues += "WU services disabled: $($DisabledServices -join ', ')"
        $Global:DetectionResult.RequiresRemediation = $true
        Write-Log "ISSUE: WU services disabled: $($DisabledServices -join ', ')" "WARNING"
    }

    # Check proxy configuration (informational only - does not trigger remediation)
    try {
        $ProxyOutput = netsh winhttp show proxy 2>&1
        if ($ProxyOutput -match "Proxy Server" -and $ProxyOutput -notmatch "Direct access") {
            $Global:DetectionResult.Flags.ProxyConfigured = $true
            Write-Log "Proxy configured (informational only)" "INFO"
        }
    } catch {}
}
#endregion

#region --- POLICY DETECTION ---
function Invoke-PolicyDetection {
    Write-Log "Starting policy detection phase..." "INFO"

    # Check critical settings
    foreach ($Setting in $CriticalSettings) {
        $Path = if ($Setting -eq 'DisableDualScan') { $RegistryPaths.WU } else { $RegistryPaths.AU }
        $Result = Get-RegistryValue -Path $Path -Property $Setting -ExpectedValue 0

        if ($Result.Exists -and $Result.Value -eq 1) {
            $IssueMessage = "$Setting is set to 1 (should be 0)"
            Write-Log $IssueMessage "WARNING"
            $Global:DetectionResult.Issues += $IssueMessage
            $Global:DetectionResult.RequiresRemediation = $true
            $Global:DetectionResult.Flags.PolicyNonCompliant = $true
        }
    }

    # Check UseUpdateClassPolicySource
    $UseUpdateClass = Get-RegistryValue -Path $RegistryPaths.AU -Property 'UseUpdateClassPolicySource' -ExpectedValue 1
    if (-not $UseUpdateClass.Exists -or $UseUpdateClass.Value -ne 1) {
        $IssueMessage = "UseUpdateClassPolicySource is misconfigured or missing"
        Write-Log $IssueMessage "WARNING"
        $Global:DetectionResult.Issues += $IssueMessage
        $Global:DetectionResult.RequiresRemediation = $true
        $Global:DetectionResult.Flags.PolicyNonCompliant = $true
    }

    # Check Windows Update Service
    $WUService = Test-WindowsUpdateService
    if (-not $WUService.IsDefault) {
        $IssueMessage = "Microsoft Update service is not set as default"
        Write-Log $IssueMessage "WARNING"
        $Global:DetectionResult.Issues += $IssueMessage
        $Global:DetectionResult.RequiresRemediation = $true
    }

    # Check for pause states
    foreach ($PausePath in @($RegistryPaths.UX, $RegistryPaths.UPSettings)) {
        if (Test-Path $PausePath) {
            foreach ($Key in $PauseKeys) {
                $Result = Get-RegistryValue -Path $PausePath -Property $Key
                if ($Result.Exists -and $Result.Value) {
                    $IssueMessage = "Update pause detected: $Key"
                    Write-Log $IssueMessage "WARNING"
                    $Global:DetectionResult.Issues += $IssueMessage
                    $Global:DetectionResult.RequiresRemediation = $true
                    $Global:DetectionResult.Flags.UpdatesPaused = $true
                }
            }
        }
    }

    # Audit additional settings
    Write-Log "Auditing additional Windows Update settings..." "INFO"
    foreach ($Setting in $AuditSettings) {
        $Check = Get-RegistryValue -Path $RegistryPaths.WU -Property $Setting
        if ($Check.Exists) {
            Write-Log "Audit: $Setting = $($Check.Value)" "INFO"
        }
    }

    # Update status
    if ($Global:DetectionResult.RequiresRemediation) {
        $Global:DetectionResult.Status = 'NonCompliant'
        Write-Log "Detection complete: $($Global:DetectionResult.Issues.Count) issue(s) found" "WARNING"
    } else {
        $Global:DetectionResult.Status = 'Compliant'
        Write-Log "Detection complete: System is compliant" "INFO"
    }
}
#endregion

#region --- REMEDIATION ---
function Clear-RecycleBinContents {
    Write-Log "Clearing Recycle Bin..." "INFO"
    try {
        try {
            Clear-RecycleBin -Force -ErrorAction Stop
            Write-Log "Recycle Bin cleared successfully" "INFO"
            return $true
        } catch {
            Write-Log "Clear-RecycleBin cmdlet failed, trying alternative method..." "INFO"
        }

        try {
            $Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }
            foreach ($Drive in $Drives) {
                $RecyclePath = "$($Drive.Root)`$Recycle.Bin"
                if (Test-Path $RecyclePath) {
                    Get-ChildItem -Path $RecyclePath -Force -ErrorAction SilentlyContinue | 
                    ForEach-Object {
                    try { Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
                    }
                }
            }
            Write-Log "Recycle Bin cleared using direct folder cleanup" "INFO"
            return $true
        } catch {
            Write-Log "Direct folder cleanup failed: $_" "WARNING"
        }
        return $false
    } catch {
        Write-Log "Error clearing Recycle Bin: $_" "ERROR"
        return $false
    }
}

function Invoke-DiskCleanup {
    param([switch]$Aggressive)

    Write-Log "Starting disk cleanup..." "INFO"
    $SpaceFreed = 0

    try {
        $BeforeSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace

        # 1. Clear Recycle Bin
        if ($Global:DetectionResult.Flags.RecycleBinNeedsCleanup -or $Aggressive) {
            Clear-RecycleBinContents
        }

        # 2. Clear Temp folders
        if ($Global:DetectionResult.Flags.TempFilesNeedCleanup -or $Aggressive) {
            Write-Log "Clearing temp folders..." "INFO"
            @($env:TEMP, "$env:SystemRoot\Temp") | ForEach-Object {
                if (Test-Path $_) {
                    Get-ChildItem -Path $_ -Recurse -Force -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # 3. Clear WU Cache
        if ($Global:DetectionResult.Flags.WUCacheNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing Windows Update cache..." "INFO"
            $WUCache = "$env:SystemRoot\SoftwareDistribution\Download"
            if (Test-Path $WUCache) {
                Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
                Get-ChildItem -Path $WUCache -Recurse -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Start-Service wuauserv -ErrorAction SilentlyContinue
            }
        }

        # 4. Clear DO Cache
        if ($Global:DetectionResult.Flags.DOCacheNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing Delivery Optimization cache..." "INFO"
            try {
                Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue
            } catch {
                $DOCache = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
                if (Test-Path $DOCache) {
                    Remove-Item -Path "$DOCache\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # 5. Clear WER
        if ($Global:DetectionResult.Flags.WERNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing Windows Error Reporting..." "INFO"
            @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
              "$env:ProgramData\Microsoft\Windows\WER\ReportQueue") | ForEach-Object {
                if (Test-Path $_) {
                    Remove-Item -Path "$_\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # 6. Clear Installer Cache
        if ($Global:DetectionResult.Flags.InstallerCacheNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing Installer patch cache..." "INFO"
            $InstallerCache = "$env:SystemRoot\Installer\`$PatchCache`$"
            if (Test-Path $InstallerCache) {
                Remove-Item -Path "$InstallerCache\*" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        # 7. Clear Thumbnail Cache
        if ($Global:DetectionResult.Flags.ThumbnailCacheNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing thumbnail cache..." "INFO"
            $ThumbCachePath = "$env:LocalAppData\Microsoft\Windows\Explorer"
            if (Test-Path $ThumbCachePath) {
                Get-ChildItem -Path $ThumbCachePath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }

        # 8. DISM Component Cleanup
        if ($Global:DetectionResult.Flags.WinSxSNeedsCleanup -or $Aggressive) {
            Write-Log "Running DISM component cleanup..." "INFO"
            Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        }

        # 9. Aggressive: Windows.old removal
        if ($Aggressive -and $Global:DetectionResult.Flags.WindowsOldExists) {
            Write-Log "Running aggressive cleanup (Windows.old removal)..." "WARNING"
            $WindowsOld = "$env:SystemDrive\Windows.old"
            if (Test-Path $WindowsOld) {
                Write-Log "Removing Windows.old folder..." "WARNING"
                takeown /F "$WindowsOld" /R /A /D Y 2>$null
                icacls "$WindowsOld" /grant Administrators:F /T /C 2>$null
                Remove-Item -Path $WindowsOld -Recurse -Force -ErrorAction SilentlyContinue
            }
            Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        }

        $AfterSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
        $SpaceFreed = [math]::Round(($AfterSpace - $BeforeSpace) / 1GB, 2)

        Write-Log "Disk cleanup complete. Space freed: $SpaceFreed GB" "INFO"

    } catch {
        Write-Log "Error during disk cleanup: $_" "ERROR"
    }

    return $SpaceFreed
}

function Invoke-PolicyRemediation {
    Write-Log "Starting policy remediation..." "INFO"
    $RemediationCount = 0

    foreach ($Setting in $SettingsToReset) {
        $Path = $RegistryPaths[$Setting.Path]
        if ($Path) {
            $Changed = Set-RegistryValue -Path $Path -Name $Setting.Name -Value $Setting.Value
            if ($Changed) { $RemediationCount++ }
        }
    }

    foreach ($Setting in $SettingsToRemove) {
        $Removed = Remove-RegistryValue -Path $RegistryPaths.WU -Name $Setting
        if ($Removed) { $RemediationCount++ }
    }

    Write-Log "Policy remediation complete: $RemediationCount change(s) made" "INFO"
    return $RemediationCount
}

function Clear-UpdatePauseStates {
    Write-Log "Clearing update pause states..." "INFO"
    $ClearedCount = 0

    foreach ($PausePath in @($RegistryPaths.UX, $RegistryPaths.UPSettings)) {
        if (Test-Path $PausePath) {
            foreach ($Key in $PauseKeys) {
                try {
                    $Value = Get-ItemProperty -Path $PausePath -Name $Key -ErrorAction SilentlyContinue
                    if ($Value) {
                    Remove-ItemProperty -Path $PausePath -Name $Key -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed pause key: $PausePath\$Key" "INFO"
                    $ClearedCount++
                    }
                } catch {}
            }
        }
    }

    Write-Log "Pause states cleared: $ClearedCount key(s) removed" "INFO"
    return $ClearedCount
}

function Repair-WindowsUpdateComponents {
    Write-Log "Repairing Windows Update components..." "INFO"

    try {
        # Stop WU services
        foreach ($Svc in $WUServices) {
            try { Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue } catch {}
        }
        Write-Log "Stopped Windows Update services" "INFO"

        # Re-register DLLs (only if they exist on disk)
        $RegisteredCount = 0
        $SkippedCount = 0
        foreach ($DLL in $WUDLLs) {
            $DLLPath = "$env:SystemRoot\System32\$DLL"
            if (Test-Path $DLLPath) {
                Start-Process "regsvr32.exe" -ArgumentList "/s `"$DLLPath`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                $RegisteredCount++
            } else {
                # Skip DLL if it doesn't exist (likely legacy DLL on Windows 11)
                if ($LegacyDLLs -contains $DLL) {
                    Write-Log "Skipped legacy DLL: $DLL (not present on this build)" "INFO"
                } else {
                    Write-Log "Skipped missing DLL: $DLL" "WARNING"
                }
                $SkippedCount++
            }
        }
        Write-Log "Re-registered $RegisteredCount DLLs (Skipped: $SkippedCount)" "INFO"

        # Reset Winsock and proxy (if flagged)
        if ($Global:DetectionResult.Flags.WinsockCorrupted -or $Global:DetectionResult.Flags.ProxyConfigured) {
            Start-Process "netsh" -ArgumentList "winsock reset" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Process "netsh" -ArgumentList "winhttp reset proxy" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            Write-Log "Reset Winsock and WinHTTP proxy" "INFO"
        }

        # Start WU services
        foreach ($Svc in $WUServices) {
            try {
                Set-Service -Name $Svc -StartupType Manual -ErrorAction SilentlyContinue
                Start-Service -Name $Svc -ErrorAction SilentlyContinue
            } catch {}
        }
        Write-Log "Started Windows Update services" "INFO"

    } catch {
        Write-Log "Error repairing WU components: $_" "ERROR"
    }
}

function Start-WindowsUpdateScan {
    Write-Log "Triggering Windows Update scan and download..." "INFO"

    $UsoClient = "$env:SystemRoot\System32\UsoClient.exe"

    if (Test-Path $UsoClient) {
        try {
            Write-Log "Refreshing Windows Update settings..." "INFO"
            Start-Process $UsoClient -ArgumentList "RefreshSettings" -WindowStyle Hidden -Wait
            Start-Sleep -Seconds 10

            Write-Log "Starting update scan..." "INFO"
            Start-Process $UsoClient -ArgumentList "StartScan" -WindowStyle Hidden -Wait
            Start-Sleep -Seconds 15

            Write-Log "Starting update download..." "INFO"
            Start-Process $UsoClient -ArgumentList "StartDownload" -WindowStyle Hidden -Wait
            Start-Sleep -Seconds 10

            Write-Log "Starting update install..." "INFO"
            Start-Process $UsoClient -ArgumentList "StartInstall" -WindowStyle Hidden -Wait

            Write-Log "Update orchestration triggered successfully" "INFO"
            return $true
        } catch {
            Write-Log "Failed to trigger update scan: $($_.Exception.Message)" "WARNING"
            return $false
        }
    } else {
        Write-Log "UsoClient.exe not found!" "ERROR"
        return $false
    }
}
#endregion

#region --- UPDATE HISTORY ---
function Get-RecentUpdateHistory {
    Write-Log "Retrieving recent Windows Update history..." "INFO"

    try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $HistoryCount = $Searcher.GetTotalHistoryCount()

        if ($HistoryCount -gt 0) {
            $History = $Searcher.QueryHistory(0, [Math]::Min(10, $HistoryCount))
            Write-Log "Recent Windows Update History:" "INFO"

            foreach ($Update in $History) {
                $Status = switch ($Update.ResultCode) {
                    0 { "Not Started" }
                    1 { "In Progress" }
                    2 { "Succeeded" }
                    3 { "Succeeded With Errors" }
                    4 { "Failed" }
                    5 { "Aborted" }
                    default { "Unknown" }
                }
                Write-Log "  [$Status] $($Update.Title) - $($Update.Date)" "INFO"
            }
        } else {
            Write-Log "No update history found" "INFO"
        }
    } catch {
        Write-Log "Error retrieving update history: $_" "ERROR"
    }
}
#endregion

#region --- MAIN EXECUTION ---
try {
    # Get device info
    $DeviceInfo = Get-DeviceInfo

    # Hardware eligibility check
    if ($DeviceInfo) {
        Test-HardwareEligibility -DeviceInfo $DeviceInfo | Out-Null
    }

    # Disk space and cleanup needs detection
    Test-DiskSpaceAndCleanupNeeds

    # WU Component health check
    Test-WUComponentHealth

    # Policy detection
    Invoke-PolicyDetection

    # Display detection results with granular flags
    Write-Log "----" "INFO"
    Write-Log "DETECTION SUMMARY:" "INFO"
    Write-Log "Status: $($Global:DetectionResult.Status)" "INFO"
    Write-Log "Hardware Eligible: $($Global:DetectionResult.HardwareEligible)" "INFO"
    Write-Log "Disk Space Sufficient: $(-not $Global:DetectionResult.DiskSpaceLow)" "INFO"
    Write-Log "Issues Found: $($Global:DetectionResult.Issues.Count)" "INFO"
    foreach ($Issue in $Global:DetectionResult.Issues) {
        Write-Log "  - $Issue" "INFO"
    }

    # Display granular flags
    Write-Log "----" "INFO"
    Write-Log "GRANULAR FLAGS:" "INFO"
    Write-Log "  PolicyNonCompliant: $($Global:DetectionResult.Flags.PolicyNonCompliant)" "INFO"
    Write-Log "  UpdatesPaused: $($Global:DetectionResult.Flags.UpdatesPaused)" "INFO"
    Write-Log "  WUDLLsMissing: $($Global:DetectionResult.Flags.WUDLLsMissing)" "INFO"
    Write-Log "  WUServicesNotRunning: $($Global:DetectionResult.Flags.WUServicesNotRunning)" "INFO"
    Write-Log "  WinsockCorrupted: $($Global:DetectionResult.Flags.WinsockCorrupted)" "INFO"
    Write-Log "  ProxyConfigured: $($Global:DetectionResult.Flags.ProxyConfigured)" "INFO"
    Write-Log "  RecycleBinNeedsCleanup: $($Global:DetectionResult.Flags.RecycleBinNeedsCleanup) ($($Global:DetectionResult.Sizes.RecycleBin) MB)" "INFO"
    Write-Log "  TempFilesNeedCleanup: $($Global:DetectionResult.Flags.TempFilesNeedCleanup) ($($Global:DetectionResult.Sizes.TempFiles) MB)" "INFO"
    Write-Log "  WUCacheNeedsCleanup: $($Global:DetectionResult.Flags.WUCacheNeedsCleanup) ($($Global:DetectionResult.Sizes.WUCache) MB)" "INFO"
    Write-Log "  DOCacheNeedsCleanup: $($Global:DetectionResult.Flags.DOCacheNeedsCleanup) ($($Global:DetectionResult.Sizes.DOCache) MB)" "INFO"
    Write-Log "  WERNeedsCleanup: $($Global:DetectionResult.Flags.WERNeedsCleanup) ($($Global:DetectionResult.Sizes.WER) MB)" "INFO"
    Write-Log "  InstallerCacheNeedsCleanup: $($Global:DetectionResult.Flags.InstallerCacheNeedsCleanup) ($($Global:DetectionResult.Sizes.InstallerCache) MB)" "INFO"
    Write-Log "  ThumbnailCacheNeedsCleanup: $($Global:DetectionResult.Flags.ThumbnailCacheNeedsCleanup) ($($Global:DetectionResult.Sizes.ThumbnailCache) MB)" "INFO"
    Write-Log "  WinSxSNeedsCleanup: $($Global:DetectionResult.Flags.WinSxSNeedsCleanup) ($($Global:DetectionResult.Sizes.WinSxS) MB)" "INFO"
    Write-Log "  WindowsOldExists: $($Global:DetectionResult.Flags.WindowsOldExists) ($($Global:DetectionResult.Sizes.WindowsOld) MB)" "INFO"

    if ($Global:DetectionResult.Warnings.Count -gt 0) {
        Write-Log "Warnings: $($Global:DetectionResult.Warnings.Count)" "INFO"
        foreach ($Warning in $Global:DetectionResult.Warnings) {
            Write-Log "  - $Warning" "INFO"
        }
    }
    Write-Log "----" "INFO"

    # Remediation phase (only if critical issues found)
    if ($Global:DetectionResult.RequiresRemediation) {
        if ($DetectOnly) {
            Write-Log "Detection-only mode: Remediation required but not performed" "WARNING"
            Write-Log "===="
            Write-Log "Script completed with issues detected"
            Write-Log "===="
            exit 1
        } else {
            Write-Log "Starting remediation phase..." "INFO"

            # Disk cleanup if needed
            if ($Global:DetectionResult.DiskSpaceLow) {
                $SpaceFreed = Invoke-DiskCleanup -Aggressive:$AggressiveCleanup
                Write-Log "Disk cleanup freed $SpaceFreed GB" "INFO"
            }

            # Policy remediation
            Invoke-PolicyRemediation

            # Clear pause states
            Clear-UpdatePauseStates

            # Repair WU components
            Repair-WindowsUpdateComponents

            # Trigger update scan
            Start-WindowsUpdateScan

            # Get update history
            Get-RecentUpdateHistory

            Write-Log "Remediation completed successfully" "INFO"
            Write-Log "===="
            Write-Log "Script completed successfully"
            Write-Log "===="
            exit 0
        }
    } else {
        Write-Log "No remediation required: System is compliant" "INFO"

        # Still trigger update scan for compliant systems
        if (-not $DetectOnly) {
            Write-Log "Triggering update scan for compliant system..." "INFO"
            Start-WindowsUpdateScan
            Get-RecentUpdateHistory
        }

        Write-Log "===="
        Write-Log "Script completed successfully"
        Write-Log "===="
        exit 0
    }

} catch {
    Write-Log "Critical error during script execution: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    Write-Log "===="
    Write-Log "Script completed with errors"
    Write-Log "===="
    exit 1
}
#endregion
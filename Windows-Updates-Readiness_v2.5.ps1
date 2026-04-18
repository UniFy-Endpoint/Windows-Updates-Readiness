<#
.SYNOPSIS
    Windows Updates Readiness - Unified Detection and Remediation Script

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
    Version: 2.5
    Author: Yoennis Olmo
    Execution Mode: Platform Script (Intune) - Run as SYSTEM
    
    - Updated cleanup thresholds based on real-world enterprise experience:
      * Recycle Bin: 2 GB (was 5 GB) - catches most cases without being too aggressive
      * Temp Folders (User + System combined): 500 MB (was 1 GB) - indicates stale files
      * WU Cache: 500 MB (was 1 GB) - indicates stuck/failed updates
      * DO Cache: 500 MB (was 1 GB) - reasonable for non-peer-caching scenarios
      * WER: 200 MB (was 1 GB) - indicates persistent crash issues
      * Installer Cache: 500 MB (was 1 GB) - catches orphaned patches
      * Thumbnail Cache: 200 MB (was 1 GB) - indicates corruption or excessive regeneration
      * DISM/WinSxS: 8 GB (was 10 GB) - typical healthy range is 6-10 GB
    - Cleanup flags now properly set RequiresRemediation = $true when thresholds exceeded

    Intune Info:
    Script type: Platform Script
    Run this script using the logged on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell Host: Yes

.EXAMPLE
    .\Windows-Updates-Readiness_v2.5.ps1
    .\Windows-Updates-Readiness_v2.5.ps1 -DetectOnly
    .\Windows-Updates-Readiness_v2.5.ps1 -AggressiveCleanup
#>

[CmdletBinding()]
param(
    [switch]$DetectOnly = $false,
    [switch]$AggressiveCleanup = $false,
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
Write-Log "==== Windows Updates Readiness Script v2.5 ===="
Write-Log "Mode: $(if ($DetectOnly) { 'Detection Only' } else { 'Detection + Remediation' })"
Write-Log "Aggressive Cleanup: $AggressiveCleanup | Skip Hardware Check: $SkipHardwareCheck"
Write-Log "===="
#endregion

#region --- CONFIGURATION ---
$MinimumFreeSpaceGB = 30

# v2.5 Cleanup thresholds (in GB) - triggers remediation when exceeded
# Based on real-world enterprise experience - balances cleanup with avoiding unnecessary remediation
$CleanupThresholds = @{
    RecycleBin     = 2      # 2 GB - users typically accumulate 1-5 GB
    TempFiles      = 0.5    # 500 MB (combined User + System) - healthy systems: 50-200 MB
    WUCache        = 0.5    # 500 MB - should be near 0 after successful updates
    DOCache        = 0.5    # 500 MB - default behavior stays under 500 MB
    WER            = 0.2    # 200 MB - normal is 10-50 MB
    InstallerCache = 0.5    # 500 MB - grows with cumulative updates
    ThumbnailCache = 0.2    # 200 MB - normal is 50-150 MB
    WinSxS         = 8      # 8 GB - Win10: 5-8 GB, Win11: 7-10 GB typical
}

$RegistryPaths = @{
    AU         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    WU         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    GWX        = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX"
    UX         = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    UPSettings = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings"
}

$CriticalSettings = @('NoAutoUpdate', 'UseWUServer', 'DisableDualScan')
$AuditSettings = @('DoNotConnectToWindowsUpdateInternetLocations','SetPolicyDrivenUpdateSourceForDriverUpdates',
    'SetPolicyDrivenUpdateSourceForOtherUpdates','SetPolicyDrivenUpdateSourceForQualityUpdates',
    'SetPolicyDrivenUpdateSourceForFeatureUpdates','DisableWindowsUpdateAccess','WUServer','TargetGroup',
    'WUStatusServer','TargetGroupEnabled','GStatus')

$SettingsToReset = @(
    @{Path='AU';Name='NoAutoUpdate';Value=0},@{Path='WU';Name='DoNotConnectToWindowsUpdateInternetLocations';Value=0},
    @{Path='WU';Name='DisableDualScan';Value=0},@{Path='WU';Name='SetPolicyDrivenUpdateSourceForDriverUpdates';Value=0},
    @{Path='WU';Name='SetPolicyDrivenUpdateSourceForOtherUpdates';Value=0},
    @{Path='WU';Name='SetPolicyDrivenUpdateSourceForQualityUpdates';Value=0},
    @{Path='WU';Name='SetPolicyDrivenUpdateSourceForFeatureUpdates';Value=0},
    @{Path='WU';Name='DisableWindowsUpdateAccess';Value=0},@{Path='AU';Name='UseWUServer';Value=0},
    @{Path='AU';Name='UseUpdateClassPolicySource';Value=1},@{Path='GWX';Name='GStatus';Value=2}
)
$SettingsToRemove = @('WUServer','WUStatusServer','TargetGroup','TargetGroupEnabled')
$PauseKeys = @('PausedFeatureDate','PausedQualityDate','PausedFeatureStatus','PausedQualityStatus',
    'PauseFeatureUpdatesStartTime','PauseFeatureUpdatesEndTime','PauseQualityUpdatesStartTime',
    'PauseQualityUpdatesEndTime','PauseUpdatesExpiryTime','PauseUpdatesStartTime')
$WUServices = @("wuauserv","bits","cryptsvc","msiserver","usosvc","dosvc")
$WUDLLs = @("atl.dll","urlmon.dll","mshtml.dll","shdocvw.dll","browseui.dll","jscript.dll","vbscript.dll",
    "scrrun.dll","msxml.dll","msxml3.dll","msxml6.dll","actxprxy.dll","softpub.dll","wintrust.dll",
    "dssenh.dll","rsaenh.dll","gpkcsp.dll","sccbase.dll","slbcsp.dll","cryptdlg.dll","oleaut32.dll",
    "ole32.dll","shell32.dll","initpki.dll","wuapi.dll","wuaueng.dll","wuaueng1.dll","wucltui.dll",
    "wups.dll","wups2.dll","wuweb.dll","qmgr.dll","qmgrprxy.dll","wucltux.dll","muweb.dll","wuwebv.dll")
$LegacyDLLs = @("msxml.dll","gpkcsp.dll","sccbase.dll","slbcsp.dll","initpki.dll","wuaueng1.dll",
    "wucltui.dll","wuweb.dll","qmgrprxy.dll","wucltux.dll","muweb.dll","wuwebv.dll")

$Global:DetectionResult = @{
    Issues=@(); Warnings=@(); Status='Compliant'; RequiresRemediation=$false; HardwareEligible=$true; DiskSpaceLow=$false
    Flags = @{
        RecycleBinNeedsCleanup=$false; TempFilesNeedCleanup=$false; WUCacheNeedsCleanup=$false
        DOCacheNeedsCleanup=$false; WERNeedsCleanup=$false; InstallerCacheNeedsCleanup=$false
        ThumbnailCacheNeedsCleanup=$false; WinSxSNeedsCleanup=$false; WindowsOldExists=$false
        WUDLLsMissing=$false; WUServicesNotRunning=$false; WinsockCorrupted=$false
        ProxyConfigured=$false; UpdatesPaused=$false; PolicyNonCompliant=$false
    }
    Sizes = @{RecycleBin=0;TempFiles=0;WUCache=0;DOCache=0;WER=0;InstallerCache=0;ThumbnailCache=0;WinSxS=0;WindowsOld=0}
}
#endregion

#region --- HELPER FUNCTIONS ---
function Get-RegistryValue {
    param([string]$Path,[string]$Property,[object]$ExpectedValue)
    try {
        $Value = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Property
        if ($null -ne $Value) { return @{Exists=$true;Value=$Value;MatchesExpected=($PSBoundParameters.ContainsKey('ExpectedValue') -and $Value -eq $ExpectedValue)} }
        return @{Exists=$false;Value=$null}
    } catch { return @{Exists=$false;Value=$null} }
}

function Set-RegistryValue {
    param([string]$Path,[string]$Name,[int]$Value)
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        $CurrentValue = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Name
        if ($CurrentValue -ne $Value) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
            Write-Log "Set $Name = $Value (was: $CurrentValue)"
            return $true
        }
        return $false
    } catch { Write-Log "Failed to set $Name : $_" "ERROR"; return $false }
}

function Remove-RegistryValue {
    param([string]$Path,[string]$Name)
    try {
        $Property = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if ($Property -and ($Property.PSObject.Properties.Name -contains $Name)) {
            Remove-ItemProperty -Path $Path -Name $Name -Force
            Write-Log "Removed $Name from $Path"
            return $true
        }
        return $false
    } catch { return $false }
}

function Test-WindowsUpdateService {
    try {
        $ServiceManager = New-Object -ComObject 'Microsoft.Update.ServiceManager'
        $UpdateService = $ServiceManager.Services | Where-Object { $_.Name -eq 'Microsoft Update' }
        if ($UpdateService) { return @{Exists=$true;IsDefault=$UpdateService.IsDefaultAUService} }
        return @{Exists=$false;IsDefault=$false}
    } catch { return @{Exists=$false;IsDefault=$false} }
}

function Get-WindowsVersion { param([int]$BuildNumber); if ($BuildNumber -ge 22000) { return "Windows 11" } else { return "Windows 10" } }

function Get-FolderSizeGB {
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            $Size = (Get-ChildItem -Path $Path -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            return [math]::Round($Size / 1GB, 2)
        }
        return 0
    } catch { return 0 }
}
#endregion

#region --- DEVICE INFO & HARDWARE CHECK ---
function Get-DeviceInfo {
    Write-Log "Gathering device information..."
    try {
        $CV = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $CS = Get-CimInstance Win32_ComputerSystem
        $TPM = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        $SecureBoot = $false; try { $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue } catch {}
        $BuildNumber = [int]$CV.CurrentBuild
        $DeviceInfo = [PSCustomObject]@{
            ComputerName=$env:COMPUTERNAME; WindowsVersion=Get-WindowsVersion -BuildNumber $BuildNumber
            DisplayVersion=$CV.DisplayVersion; CurrentBuild="$($CV.CurrentBuild).$($CV.UBR)"; BuildNumber=$BuildNumber
            TotalRAM_GB=[math]::Round($CS.TotalPhysicalMemory/1GB,2); TPMPresent=[bool]$TPM
            TPMEnabled=if($TPM){$TPM.IsEnabled_InitialValue}else{$false}
            TPMVersion=if($TPM){$TPM.SpecVersion.Split(",")[0]}else{"N/A"}; SecureBoot=$SecureBoot
        }
        Write-Log "Device: $($DeviceInfo.ComputerName) | $($DeviceInfo.WindowsVersion) $($DeviceInfo.DisplayVersion) (Build $($DeviceInfo.CurrentBuild))"
        Write-Log "RAM: $($DeviceInfo.TotalRAM_GB)GB | TPM: $($DeviceInfo.TPMPresent) (v$($DeviceInfo.TPMVersion)) | SecureBoot: $($DeviceInfo.SecureBoot)"
        return $DeviceInfo
    } catch { Write-Log "Error gathering device info: $_" "ERROR"; return $null }
}

function Test-HardwareEligibility {
    param($DeviceInfo)
    if ($SkipHardwareCheck) { Write-Log "Hardware check skipped"; return $true }
    if ($DeviceInfo.WindowsVersion -eq "Windows 11") { Write-Log "Already on Windows 11 - hardware check skipped"; return $true }
    Write-Log "Checking Windows 11 hardware eligibility..."
    $Eligible = $true
    if ($DeviceInfo.TotalRAM_GB -lt 4) { $Global:DetectionResult.Issues += "RAM < 4GB"; $Eligible = $false }
    if (-not $DeviceInfo.TPMPresent) { $Global:DetectionResult.Issues += "TPM not detected"; $Eligible = $false }
    if ($DeviceInfo.TPMPresent -and -not $DeviceInfo.TPMEnabled) { $Global:DetectionResult.Issues += "TPM not enabled"; $Eligible = $false }
    if ($DeviceInfo.TPMPresent -and $DeviceInfo.TPMVersion -notlike "2*") { $Global:DetectionResult.Issues += "TPM < 2.0"; $Eligible = $false }
    if (-not $DeviceInfo.SecureBoot) { $Global:DetectionResult.Issues += "Secure Boot disabled"; $Eligible = $false }
    if (-not $Eligible) { $Global:DetectionResult.HardwareEligible = $false; $Global:DetectionResult.RequiresRemediation = $true; Write-Log "Hardware eligibility: FAILED" "WARNING" }
    else { Write-Log "Hardware eligibility: PASSED" }
    return $Eligible
}
#endregion

#region --- DISK SPACE & CLEANUP DETECTION ---
function Test-DiskSpaceAndCleanupNeeds {
    Write-Log "Checking disk space and cleanup needs..."
    try {
        $SystemDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
        $FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
        Write-Log "Free disk space: $FreeSpaceGB GB (minimum: $MinimumFreeSpaceGB GB)"

        # 1. Recycle Bin - Threshold: 2 GB
        $RecycleBinPath = "$env:SystemDrive\`$Recycle.Bin"
        $RecycleBinSize = 0
        if (Test-Path $RecycleBinPath) {
            $BinItems = Get-ChildItem -Path $RecycleBinPath -Recurse -Force -File -ErrorAction SilentlyContinue
            if ($BinItems) { $RecycleBinSize = ($BinItems | Measure-Object -Property Length -Sum).Sum }
        }
        $RecycleBinGB = [math]::Round($RecycleBinSize / 1GB, 2)
        $Global:DetectionResult.Sizes.RecycleBin = $RecycleBinGB
        if ($RecycleBinGB -ge $CleanupThresholds.RecycleBin) {
            Write-Log "Recycle Bin: $RecycleBinGB GB (>= $($CleanupThresholds.RecycleBin) GB - REQUIRES REMEDIATION)" "WARNING"
            $Global:DetectionResult.Flags.RecycleBinNeedsCleanup = $true
            $Global:DetectionResult.Issues += "Recycle Bin: $RecycleBinGB GB"
            $Global:DetectionResult.RequiresRemediation = $true
        } else { Write-Log "Recycle Bin: $RecycleBinGB GB (OK)" }

        # 2. Temp Files (Combined) - Threshold: 500 MB
        $UserTempGB = Get-FolderSizeGB -Path $env:TEMP
        $SystemTempGB = Get-FolderSizeGB -Path "$env:SystemRoot\Temp"
        $TotalTempGB = [math]::Round($UserTempGB + $SystemTempGB, 2)
        $Global:DetectionResult.Sizes.TempFiles = $TotalTempGB
        if ($TotalTempGB -ge $CleanupThresholds.TempFiles) {
            Write-Log "Temp Folders: $TotalTempGB GB (>= $($CleanupThresholds.TempFiles) GB - REQUIRES REMEDIATION)" "WARNING"
            Write-Log "  User Temp: $UserTempGB GB | System Temp: $SystemTempGB GB"
            $Global:DetectionResult.Flags.TempFilesNeedCleanup = $true
            $Global:DetectionResult.Issues += "Temp: $TotalTempGB GB"
            $Global:DetectionResult.RequiresRemediation = $true
        } else { 
            Write-Log "User Temp: $UserTempGB GB (OK)"
            Write-Log "System Temp: $SystemTempGB GB (OK)"
            Write-Log "Temp Folders (Combined): $TotalTempGB GB (OK)"
        }

        # 3. WU Cache - Threshold: 500 MB
        $WUCacheGB = Get-FolderSizeGB -Path "$env:SystemRoot\SoftwareDistribution\Download"
        $Global:DetectionResult.Sizes.WUCache = $WUCacheGB
        if ($WUCacheGB -ge $CleanupThresholds.WUCache) {
            Write-Log "WU Cache: $WUCacheGB GB (>= $($CleanupThresholds.WUCache) GB - REQUIRES REMEDIATION)" "WARNING"
            $Global:DetectionResult.Flags.WUCacheNeedsCleanup = $true
            $Global:DetectionResult.Issues += "WU Cache: $WUCacheGB GB"
            $Global:DetectionResult.RequiresRemediation = $true
        } else { Write-Log "WU Cache: $WUCacheGB GB (OK)" }

        # 4. DO Cache - Threshold: 500 MB
        $DOCacheGB = Get-FolderSizeGB -Path "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
        $Global:DetectionResult.Sizes.DOCache = $DOCacheGB
        if ($DOCacheGB -ge $CleanupThresholds.DOCache) {
            Write-Log "DO Cache: $DOCacheGB GB (>= $($CleanupThresholds.DOCache) GB - REQUIRES REMEDIATION)" "WARNING"
            $Global:DetectionResult.Flags.DOCacheNeedsCleanup = $true
            $Global:DetectionResult.Issues += "DO Cache: $DOCacheGB GB"
            $Global:DetectionResult.RequiresRemediation = $true
        } else { Write-Log "DO Cache: $DOCacheGB GB (OK)" }

        # 5. WER - Threshold: 200 MB
        $WERGB = [math]::Round((Get-FolderSizeGB -Path "$env:ProgramData\Microsoft\Windows\WER\ReportArchive") + (Get-FolderSizeGB -Path "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"), 2)
        $Global:DetectionResult.Sizes.WER = $WERGB
        if ($WERGB -ge $CleanupThresholds.WER) {
            Write-Log "WER: $WERGB GB (>= $($CleanupThresholds.WER) GB - REQUIRES REMEDIATION)" "WARNING"
            $Global:DetectionResult.Flags.WERNeedsCleanup = $true
            $Global:DetectionResult.Issues += "WER: $WERGB GB"
            $Global:DetectionResult.RequiresRemediation = $true
        } else { Write-Log "WER: $WERGB GB (OK)" }

        # 6. Installer Cache - Threshold: 500 MB
        $InstallerCacheGB = Get-FolderSizeGB -Path "$env:SystemRoot\Installer\`$PatchCache`$"
        $Global:DetectionResult.Sizes.InstallerCache = $InstallerCacheGB
        if ($InstallerCacheGB -ge $CleanupThresholds.InstallerCache) {
            Write-Log "Installer Cache: $InstallerCacheGB GB (>= $($CleanupThresholds.InstallerCache) GB - REQUIRES REMEDIATION)" "WARNING"
            $Global:DetectionResult.Flags.InstallerCacheNeedsCleanup = $true
            $Global:DetectionResult.Issues += "Installer Cache: $InstallerCacheGB GB"
            $Global:DetectionResult.RequiresRemediation = $true
        } else { Write-Log "Installer Cache: $InstallerCacheGB GB (OK)" }

        # 7. Thumbnail Cache - Threshold: 200 MB
        $ThumbCachePath = "$env:LocalAppData\Microsoft\Windows\Explorer"
        $ThumbCacheGB = 0
        if (Test-Path $ThumbCachePath) {
            $ThumbFiles = Get-ChildItem -Path $ThumbCachePath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue
            if ($ThumbFiles) { $ThumbCacheGB = [math]::Round(($ThumbFiles | Measure-Object -Property Length -Sum).Sum / 1GB, 2) }
        }
        $Global:DetectionResult.Sizes.ThumbnailCache = $ThumbCacheGB
        if ($ThumbCacheGB -ge $CleanupThresholds.ThumbnailCache) {
            Write-Log "Thumbnail Cache: $ThumbCacheGB GB (>= $($CleanupThresholds.ThumbnailCache) GB - REQUIRES REMEDIATION)" "WARNING"
            $Global:DetectionResult.Flags.ThumbnailCacheNeedsCleanup = $true
            $Global:DetectionResult.Issues += "Thumbnail Cache: $ThumbCacheGB GB"
            $Global:DetectionResult.RequiresRemediation = $true
        } else { Write-Log "Thumbnail Cache: $ThumbCacheGB GB (OK)" }

        # 8. WinSxS - Threshold: 8 GB (ALIGNED - now uses Get-FolderSizeGB)
        try {
            $WinSxSGB = Get-FolderSizeGB -Path "$env:SystemRoot\WinSxS"
            $Global:DetectionResult.Sizes.WinSxS = $WinSxSGB
            if ($WinSxSGB -ge $CleanupThresholds.WinSxS) {
                Write-Log "WinSxS: $WinSxSGB GB (>= $($CleanupThresholds.WinSxS) GB - REQUIRES REMEDIATION)" "WARNING"
                $Global:DetectionResult.Flags.WinSxSNeedsCleanup = $true
                $Global:DetectionResult.Issues += "WinSxS: $WinSxSGB GB"
                $Global:DetectionResult.RequiresRemediation = $true
            } else { Write-Log "WinSxS: $WinSxSGB GB (OK)" }
        } catch { Write-Log "Error checking WinSxS: $_" "WARNING" }

        # 9. Windows.old (informational)
        if (Test-Path "$env:SystemDrive\Windows.old") {
            $WindowsOldGB = Get-FolderSizeGB -Path "$env:SystemDrive\Windows.old"
            $Global:DetectionResult.Sizes.WindowsOld = $WindowsOldGB
            $Global:DetectionResult.Flags.WindowsOldExists = $true
            Write-Log "Windows.old: $WindowsOldGB GB EXISTS (cleanup with -AggressiveCleanup)"
        } else { Write-Log "Windows.old: Not present" }

        # Overall disk space check
        if ($FreeSpaceGB -lt $MinimumFreeSpaceGB) {
            Write-Log "WARNING: Less than ${MinimumFreeSpaceGB}GB free!" "WARNING"
            $Global:DetectionResult.DiskSpaceLow = $true
            $Global:DetectionResult.Issues += "Low disk space: $FreeSpaceGB GB"
            $Global:DetectionResult.RequiresRemediation = $true
        }
    } catch { Write-Log "Error checking disk space: $_" "ERROR" }
}
#endregion

#region --- WU COMPONENT HEALTH ---
function Test-WUComponentHealth {
    Write-Log "Checking Windows Update component health..."
    $CV = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $IsWindows11 = ([int]$CV.CurrentBuild -ge 22000)
    $MissingDLLs = @()
    foreach ($DLL in $WUDLLs) {
        $DLLPath = "$env:SystemRoot\System32\$DLL"
        if (-not (Test-Path $DLLPath)) {
            if ($IsWindows11 -and $LegacyDLLs -contains $DLL) { Write-Log "Note: Legacy DLL $DLL missing (Expected on modern Windows 11 builds)" }
            else { $MissingDLLs += $DLL }
        }
    }
    if ($MissingDLLs.Count -gt 0) {
        Write-Log "ISSUE: Missing DLLs: $($MissingDLLs -join ', ')" "WARNING"
        $Global:DetectionResult.Flags.WUDLLsMissing = $true
        $Global:DetectionResult.Issues += "Missing DLLs"
        $Global:DetectionResult.RequiresRemediation = $true
    }
    $DisabledServices = @()
    foreach ($Svc in $WUServices) {
        try { $Service = Get-Service -Name $Svc -ErrorAction SilentlyContinue
            if ($Service -and $Service.StartType -eq 'Disabled') { $DisabledServices += $Svc }
        } catch {}
    }
    if ($DisabledServices.Count -gt 0) {
        Write-Log "ISSUE: Disabled services: $($DisabledServices -join ', ')" "WARNING"
        $Global:DetectionResult.Flags.WUServicesNotRunning = $true
        $Global:DetectionResult.Issues += "WU services disabled"
        $Global:DetectionResult.RequiresRemediation = $true
    }
    try { $ProxyOutput = netsh winhttp show proxy 2>&1
        if ($ProxyOutput -match "Proxy Server" -and $ProxyOutput -notmatch "Direct access") {
            $Global:DetectionResult.Flags.ProxyConfigured = $true
            Write-Log "Proxy configured (informational)"
        }
    } catch {}
    if (-not $Global:DetectionResult.Flags.WUDLLsMissing -and -not $Global:DetectionResult.Flags.WUServicesNotRunning) { Write-Log "WU Component health: OK" }
}
#endregion

#region --- POLICY DETECTION ---
function Invoke-PolicyDetection {
    Write-Log "Checking policy compliance..."
    foreach ($Setting in $CriticalSettings) {
        $Path = if ($Setting -eq 'DisableDualScan') { $RegistryPaths.WU } else { $RegistryPaths.AU }
        $Result = Get-RegistryValue -Path $Path -Property $Setting -ExpectedValue 0
        if ($Result.Exists -and $Result.Value -eq 1) {
            Write-Log "ISSUE: $Setting = 1" "WARNING"
            $Global:DetectionResult.Issues += "$Setting = 1"
            $Global:DetectionResult.RequiresRemediation = $true
            $Global:DetectionResult.Flags.PolicyNonCompliant = $true
        }
    }
    $UseUpdateClass = Get-RegistryValue -Path $RegistryPaths.AU -Property 'UseUpdateClassPolicySource' -ExpectedValue 1
    if (-not $UseUpdateClass.Exists -or $UseUpdateClass.Value -ne 1) {
        Write-Log "ISSUE: UseUpdateClassPolicySource misconfigured" "WARNING"
        $Global:DetectionResult.Issues += "UseUpdateClassPolicySource issue"
        $Global:DetectionResult.RequiresRemediation = $true
        $Global:DetectionResult.Flags.PolicyNonCompliant = $true
    }
    
    # ALIGNED: Detect WSUS server strings (symmetry with remediation removal)
    foreach ($Name in @('WUServer','WUStatusServer','TargetGroup','TargetGroupEnabled')) {
        $Check = Get-RegistryValue -Path $RegistryPaths.WU -Property $Name
        if ($Check.Exists -and $null -ne $Check.Value -and "$($Check.Value)".Length -gt 0) {
            Write-Log "ISSUE: $Name is present ($($Check.Value))" "WARNING"
            $Global:DetectionResult.Issues += "Registry: $Name present"
            $Global:DetectionResult.RequiresRemediation = $true
            $Global:DetectionResult.Flags.PolicyNonCompliant = $true
        }
    }
    
    $WUService = Test-WindowsUpdateService
    if (-not $WUService.IsDefault) {
        Write-Log "ISSUE: Microsoft Update not default" "WARNING"
        $Global:DetectionResult.Issues += "Microsoft Update not default"
        $Global:DetectionResult.RequiresRemediation = $true
        $Global:DetectionResult.Flags.PolicyNonCompliant = $true
    }
    foreach ($PausePath in @($RegistryPaths.UX, $RegistryPaths.UPSettings)) {
        if (Test-Path $PausePath) {
            foreach ($Key in $PauseKeys) {
                $Result = Get-RegistryValue -Path $PausePath -Property $Key
                if ($Result.Exists -and $Result.Value) {
                    Write-Log "ISSUE: Update pause detected: $Key" "WARNING"
                    $Global:DetectionResult.Issues += "Pause: $Key"
                    $Global:DetectionResult.RequiresRemediation = $true
                    $Global:DetectionResult.Flags.UpdatesPaused = $true
                }
            }
        }
    }
    foreach ($Setting in $AuditSettings) {
        $Check = Get-RegistryValue -Path $RegistryPaths.WU -Property $Setting
        if ($Check.Exists) { Write-Log "Audit: $Setting = $($Check.Value)" }
    }
    if ($Global:DetectionResult.RequiresRemediation) { $Global:DetectionResult.Status = 'NonCompliant' }
}
#endregion

#region --- REMEDIATION FUNCTIONS ---
function Clear-RecycleBinContents {
    Write-Log "Clearing Recycle Bin..."
    try {
        $RecyclePath = "$env:SystemDrive\`$Recycle.Bin"
        if (Test-Path $RecyclePath) {
            $UserBins = Get-ChildItem -Path $RecyclePath -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "S-1-*" }
            foreach ($Bin in $UserBins) { try { Get-ChildItem -Path $Bin.FullName -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
            Write-Log "Recycle Bin cleared via File System"
            return $true
        }
    } catch { Write-Log "Recycle Bin cleanup failed: $_" "WARNING" }
    try { Clear-RecycleBin -Force -ErrorAction Stop; return $true } catch { return $false }
}

function Invoke-DiskCleanup {
    param([switch]$Aggressive)
    Write-Log "Starting disk cleanup..."
    $SpaceFreed = 0
    try {
        $BeforeSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace

        if ($Global:DetectionResult.Flags.RecycleBinNeedsCleanup -or $Aggressive) { Clear-RecycleBinContents }

        if ($Global:DetectionResult.Flags.TempFilesNeedCleanup -or $Aggressive) {
            Write-Log "Clearing temp folders..."
            @($env:TEMP, "$env:SystemRoot\Temp") | ForEach-Object {
                if (Test-Path $_) { Get-ChildItem -Path $_ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
            }
        }

        if ($Global:DetectionResult.Flags.WUCacheNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing WU cache..."
            $WUCache = "$env:SystemRoot\SoftwareDistribution\Download"
            if (Test-Path $WUCache) {
                Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
                Get-ChildItem -Path $WUCache -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Start-Service wuauserv -ErrorAction SilentlyContinue
            }
        }

        if ($Global:DetectionResult.Flags.DOCacheNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing DO cache..."
            try { Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue } catch {
                $DOCache = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
                if (Test-Path $DOCache) { Remove-Item -Path "$DOCache\*" -Recurse -Force -ErrorAction SilentlyContinue }
            }
        }

        if ($Global:DetectionResult.Flags.WERNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing WER..."
            @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive","$env:ProgramData\Microsoft\Windows\WER\ReportQueue") | ForEach-Object {
                if (Test-Path $_) { Remove-Item -Path "$_\*" -Recurse -Force -ErrorAction SilentlyContinue }
            }
        }

        if ($Global:DetectionResult.Flags.InstallerCacheNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing Installer cache..."
            $InstallerCache = "$env:SystemRoot\Installer\`$PatchCache`$"
            if (Test-Path $InstallerCache) { Remove-Item -Path "$InstallerCache\*" -Recurse -Force -ErrorAction SilentlyContinue }
        }

        if ($Global:DetectionResult.Flags.ThumbnailCacheNeedsCleanup -or $Aggressive) {
            Write-Log "Clearing thumbnail cache..."
            $ThumbPath = "$env:LocalAppData\Microsoft\Windows\Explorer"
            if (Test-Path $ThumbPath) { Get-ChildItem -Path $ThumbPath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue }
        }

        if ($Global:DetectionResult.Flags.WinSxSNeedsCleanup -or $Aggressive) {
            Write-Log "Running DISM cleanup..."
            Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        }

        if ($Aggressive -and $Global:DetectionResult.Flags.WindowsOldExists) {
            Write-Log "Removing Windows.old (AGGRESSIVE)..." "WARNING"
            $WindowsOld = "$env:SystemDrive\Windows.old"
            if (Test-Path $WindowsOld) {
                takeown /F "$WindowsOld" /R /A /D Y 2>$null
                icacls "$WindowsOld" /grant Administrators:F /T /C 2>$null
                Remove-Item -Path $WindowsOld -Recurse -Force -ErrorAction SilentlyContinue
            }
            Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        }

        $AfterSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
        $SpaceFreed = [math]::Round(($AfterSpace - $BeforeSpace) / 1GB, 2)
        Write-Log "Disk cleanup complete. Space freed: $SpaceFreed GB"
    } catch { Write-Log "Error during cleanup: $_" "ERROR" }
    return $SpaceFreed
}

function Invoke-PolicyRemediation {
    Write-Log "Starting policy remediation..."
    $Count = 0
    foreach ($Setting in $SettingsToReset) {
        $Path = $RegistryPaths[$Setting.Path]
        if ($Path -and (Set-RegistryValue -Path $Path -Name $Setting.Name -Value $Setting.Value)) { $Count++ }
    }
    foreach ($Setting in $SettingsToRemove) { if (Remove-RegistryValue -Path $RegistryPaths.WU -Name $Setting) { $Count++ } }
    Write-Log "Policy remediation complete: $Count changes"
    return $Count
}

function Clear-UpdatePauseStates {
    Write-Log "Clearing update pause states..."
    $Count = 0
    foreach ($PausePath in @($RegistryPaths.UX, $RegistryPaths.UPSettings)) {
        if (Test-Path $PausePath) {
            foreach ($Key in $PauseKeys) {
                try { $Value = Get-ItemProperty -Path $PausePath -Name $Key -ErrorAction SilentlyContinue
                    if ($Value) { Remove-ItemProperty -Path $PausePath -Name $Key -Force -ErrorAction SilentlyContinue; Write-Log "Removed: $Key"; $Count++ }
                } catch {}
            }
        }
    }
    Write-Log "Pause states cleared: $Count"
    return $Count
}

function Repair-WindowsUpdateComponents {
    Write-Log "Repairing WU components..."
    try {
        foreach ($Svc in $WUServices) { try { Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue } catch {} }
        Write-Log "Stopped WU services"
        $Registered = 0; $Skipped = 0
        foreach ($DLL in $WUDLLs) {
            $DLLPath = "$env:SystemRoot\System32\$DLL"
            if (Test-Path $DLLPath) {
                if ($DLL -in @("vbscript.dll","scrrun.dll","mshtml.dll","shdocvw.dll","browseui.dll")) { $Skipped++; continue }
                $Process = Start-Process "regsvr32.exe" -ArgumentList "/s `"$DLLPath`"" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                if ($Process.ExitCode -eq 0) { $Registered++ } else { Write-Log "Failed to register $DLL" "WARNING" }
            } else { $Skipped++ }
        }
        Write-Log "Re-registered $Registered DLLs (Skipped: $Skipped)"
        if ($Global:DetectionResult.Flags.WinsockCorrupted -or $Global:DetectionResult.Flags.ProxyConfigured) {
            Start-Process "netsh" -ArgumentList "winsock reset" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Process "netsh" -ArgumentList "winhttp reset proxy" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            Write-Log "Reset Winsock and WinHTTP proxy"
        }
        foreach ($Svc in $WUServices) { try { Set-Service -Name $Svc -StartupType Manual -ErrorAction SilentlyContinue; Start-Service -Name $Svc -ErrorAction SilentlyContinue } catch {} }
        Write-Log "Started WU services"
    } catch { Write-Log "Error repairing WU components: $_" "ERROR" }
}

function Start-WindowsUpdateScan {
    Write-Log "Triggering Windows Update..."
    $UsoClient = "$env:SystemRoot\System32\UsoClient.exe"
    if (Test-Path $UsoClient) {
        try {
            Start-Process $UsoClient -ArgumentList "RefreshSettings" -WindowStyle Hidden -Wait; Start-Sleep -Seconds 5
            Start-Process $UsoClient -ArgumentList "StartScan" -WindowStyle Hidden -Wait; Start-Sleep -Seconds 10
            Start-Process $UsoClient -ArgumentList "StartDownload" -WindowStyle Hidden -Wait; Start-Sleep -Seconds 5
            Start-Process $UsoClient -ArgumentList "StartInstall" -WindowStyle Hidden -Wait
            Write-Log "Update orchestration triggered"
            return $true
        } catch { Write-Log "Failed to trigger update: $_" "WARNING"; return $false }
    } else { Write-Log "UsoClient.exe not found!" "ERROR"; return $false }
}

function Get-RecentUpdateHistory {
    Write-Log "Retrieving update history..."
    try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $HistoryCount = $Searcher.GetTotalHistoryCount()
        if ($HistoryCount -gt 0) {
            $History = $Searcher.QueryHistory(0, [Math]::Min(10, $HistoryCount))
            foreach ($Update in $History) {
                $Status = switch ($Update.ResultCode) { 0 {"NotStarted"};1{"InProgress"};2{"Succeeded"};3{"SucceededWithErrors"};4{"Failed"};5{"Aborted"};default{"Unknown"} }
                Write-Log "  [$Status] $($Update.Title)"
            }
        }
    } catch { Write-Log "Error retrieving history: $_" "ERROR" }
}
#endregion

#region --- MAIN EXECUTION ---
try {
    $DeviceInfo = Get-DeviceInfo
    if ($DeviceInfo) { Test-HardwareEligibility -DeviceInfo $DeviceInfo | Out-Null }
    Test-DiskSpaceAndCleanupNeeds
    Test-WUComponentHealth
    Invoke-PolicyDetection

    # Summary
    Write-Log "==== DETECTION SUMMARY ===="
    Write-Log "Status: $($Global:DetectionResult.Status)"
    Write-Log "Hardware Eligible: $($Global:DetectionResult.HardwareEligible)"
    Write-Log "Disk Space Low: $($Global:DetectionResult.DiskSpaceLow)"
    Write-Log "Issues Found: $($Global:DetectionResult.Issues.Count)"
    foreach ($Issue in $Global:DetectionResult.Issues) { Write-Log "  - $Issue" }
    Write-Log "---- FLAGS ----"
    Write-Log "  RecycleBin: $($Global:DetectionResult.Flags.RecycleBinNeedsCleanup) ($($Global:DetectionResult.Sizes.RecycleBin) GB)"
    Write-Log "  TempFiles: $($Global:DetectionResult.Flags.TempFilesNeedCleanup) ($($Global:DetectionResult.Sizes.TempFiles) GB)"
    Write-Log "  WUCache: $($Global:DetectionResult.Flags.WUCacheNeedsCleanup) ($($Global:DetectionResult.Sizes.WUCache) GB)"
    Write-Log "  DOCache: $($Global:DetectionResult.Flags.DOCacheNeedsCleanup) ($($Global:DetectionResult.Sizes.DOCache) GB)"
    Write-Log "  WER: $($Global:DetectionResult.Flags.WERNeedsCleanup) ($($Global:DetectionResult.Sizes.WER) GB)"
    Write-Log "  InstallerCache: $($Global:DetectionResult.Flags.InstallerCacheNeedsCleanup) ($($Global:DetectionResult.Sizes.InstallerCache) GB)"
    Write-Log "  ThumbnailCache: $($Global:DetectionResult.Flags.ThumbnailCacheNeedsCleanup) ($($Global:DetectionResult.Sizes.ThumbnailCache) GB)"
    Write-Log "  WinSxS: $($Global:DetectionResult.Flags.WinSxSNeedsCleanup) ($($Global:DetectionResult.Sizes.WinSxS) GB)"
    Write-Log "  WindowsOld: $($Global:DetectionResult.Flags.WindowsOldExists) ($($Global:DetectionResult.Sizes.WindowsOld) GB)"
    Write-Log "  PolicyNonCompliant: $($Global:DetectionResult.Flags.PolicyNonCompliant)"
    Write-Log "  UpdatesPaused: $($Global:DetectionResult.Flags.UpdatesPaused)"
    Write-Log "  WUDLLsMissing: $($Global:DetectionResult.Flags.WUDLLsMissing)"
    Write-Log "  WUServicesNotRunning: $($Global:DetectionResult.Flags.WUServicesNotRunning)"
    Write-Log "  ProxyConfigured: $($Global:DetectionResult.Flags.ProxyConfigured)"
    Write-Log "Requires Remediation: $($Global:DetectionResult.RequiresRemediation)"
    Write-Log "===="

    if ($Global:DetectionResult.RequiresRemediation) {
        if ($DetectOnly) {
            Write-Log "Detection-only mode: Remediation needed but not performed" "WARNING"
            exit 1
        } else {
            Write-Log "Starting remediation..."
            $SpaceFreed = Invoke-DiskCleanup -Aggressive:$AggressiveCleanup
            Write-Log "Disk cleanup freed $SpaceFreed GB"
            Invoke-PolicyRemediation
            Clear-UpdatePauseStates
            Repair-WindowsUpdateComponents
            Start-WindowsUpdateScan
            Get-RecentUpdateHistory
            Write-Log "Remediation completed"
            Write-Log "==== Script completed successfully ===="
            exit 0
        }
    } else {
        Write-Log "No remediation required: System is compliant"
        if (-not $DetectOnly) {
            Write-Log "Triggering update scan for compliant system..."
            Start-WindowsUpdateScan
            Get-RecentUpdateHistory
        }
        Write-Log "==== Script completed successfully ===="
        exit 0
    }
} catch {
    Write-Log "Critical error: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
#endregion
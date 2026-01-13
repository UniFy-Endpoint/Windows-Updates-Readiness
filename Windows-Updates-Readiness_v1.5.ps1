<#
.SYNOPSIS
    Windows Updates Readiness - Unified Detection and Remediation Script
.DESCRIPTION
    Comprehensive script that:
    - Detects and remediates Windows Update configuration issues
    - Checks hardware eligibility for Windows 11
    - Repairs Windows Update components
    - Clears update pause states
    - Manages disk space for updates (including Recycle Bin)
    - Forces policy refresh and triggers updates
    Designed for use as a Platform Script in Microsoft Intune.
.PARAMETER DetectOnly
    Run in detection-only mode without making changes
.PARAMETER AggressiveCleanup
    Enable aggressive disk cleanup including Windows.old (removes rollback capability)
.PARAMETER SkipHardwareCheck
    Skip Windows 11 hardware eligibility checks
.NOTES
    Version: 1.5
    Author: Yoennis Olmo
    Execution Mode: Platform Script (Intune) - Run as SYSTEM
.EXAMPLE
    .\Windows-Updates-Readiness_v1.5.ps1
    .\Windows-Updates-Readiness_v1.5.ps1 -DetectOnly
    .\Windows-Updates-Readiness_v1.5.ps1 -AggressiveCleanup
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

Write-Log "========================================"
Write-Log "Windows Updates Readiness Script v1.5"
Write-Log "Execution Mode: $(if ($DetectOnly) { 'Detection Only' } else { 'Detection and Remediation' })"
Write-Log "Aggressive Cleanup: $AggressiveCleanup"
Write-Log "Skip Hardware Check: $SkipHardwareCheck"
Write-Log "========================================"
#endregion

#region --- CONFIGURATION ---
# Minimum free disk space in GB (Windows 11 needs 64GB total, ~30GB free recommended for upgrades)
$MinimumFreeSpaceGB = 30

$RegistryPaths = @{
    AU  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    WU  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    GWX = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX"
    UX  = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    UPSettings = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings"
}

# Critical settings that should be 0 (always remediate these)
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

# Detection result object
$Global:DetectionResult = @{
    Issues = @()
    Warnings = @()
    Status = 'Compliant'
    RequiresRemediation = $false
    HardwareEligible = $true
    DiskSpaceLow = $false
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
    
    # Windows 11 starts at build 22000
    if ($BuildNumber -ge 22000) {
        return "Windows 11"
    } else {
        return "Windows 10"
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
        
        # Determine actual Windows version based on build number
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
    
    # Only check hardware eligibility if device is on Windows 10 (potential upgrade to Windows 11)
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
    } else {
        Write-Log "Device passes Windows 11 hardware eligibility checks" "INFO"
    }
    
    return $Eligible
}
#endregion

#region --- DISK SPACE MANAGEMENT ---
function Get-RecycleBinSize {
    Write-Log "Calculating Recycle Bin size..." "INFO"
    
    try {
        $Shell = New-Object -ComObject Shell.Application
        $RecycleBin = $Shell.NameSpace(0x0a)
        $TotalSize = 0
        
        if ($RecycleBin -and $RecycleBin.Items()) {
            foreach ($Item in $RecycleBin.Items()) {
                try {
                    $TotalSize += $Item.Size
                } catch {}
            }
        }
        
        $SizeGB = [math]::Round($TotalSize / 1GB, 2)
        Write-Log "Recycle Bin size: $SizeGB GB" "INFO"
        return $SizeGB
    } catch {
        Write-Log "Error calculating Recycle Bin size: $_" "WARNING"
        return 0
    }
}

function Clear-RecycleBinContents {
    Write-Log "Clearing Recycle Bin..." "INFO"
    
    try {
        # Method 1: Use Clear-RecycleBin cmdlet (Windows 10+)
        try {
            Clear-RecycleBin -Force -ErrorAction Stop
            Write-Log "Recycle Bin cleared successfully" "INFO"
            return $true
        } catch {
            Write-Log "Clear-RecycleBin cmdlet failed, trying alternative method..." "INFO"
        }
        
        # Method 2: Use rd command on $Recycle.Bin folders
        try {
            $Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }
            foreach ($Drive in $Drives) {
                $RecyclePath = "$($Drive.Root)`$Recycle.Bin"
                if (Test-Path $RecyclePath) {
                    Get-ChildItem -Path $RecyclePath -Force -ErrorAction SilentlyContinue | 
                        ForEach-Object {
                            try {
                                Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                            } catch {}
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

function Test-DiskSpace {
    Write-Log "Checking available disk space..." "INFO"
    
    try {
        $SystemDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
        $FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
        $TotalSpaceGB = [math]::Round($SystemDrive.Size / 1GB, 2)
        
        Write-Log "Disk space on $env:SystemDrive - Free: $FreeSpaceGB GB / Total: $TotalSpaceGB GB" "INFO"
        
        # Check Recycle Bin size
        $RecycleBinSizeGB = Get-RecycleBinSize
        
        if ($FreeSpaceGB -lt $MinimumFreeSpaceGB) {
            Write-Log "WARNING: Less than ${MinimumFreeSpaceGB}GB free. Windows upgrades may fail!" "WARNING"
            $Global:DetectionResult.DiskSpaceLow = $true
            $Global:DetectionResult.Warnings += "Low disk space: $FreeSpaceGB GB free (${MinimumFreeSpaceGB}GB+ recommended)"
            
            if ($RecycleBinSizeGB -gt 0.5) {
                Write-Log "Recycle Bin contains $RecycleBinSizeGB GB that can be recovered" "INFO"
            }
            
            return @{ Sufficient = $false; FreeGB = $FreeSpaceGB; RecycleBinGB = $RecycleBinSizeGB }
        }
        
        return @{ Sufficient = $true; FreeGB = $FreeSpaceGB; RecycleBinGB = $RecycleBinSizeGB }
    } catch {
        Write-Log "Error checking disk space: $_" "ERROR"
        return @{ Sufficient = $true; FreeGB = 0; RecycleBinGB = 0 }
    }
}

function Invoke-DiskCleanup {
    param([switch]$Aggressive)
    
    Write-Log "Starting disk cleanup..." "INFO"
    $SpaceFreed = 0
    
    try {
        $BeforeSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
        
        # 1. Clear Recycle Bin FIRST (often contains significant space)
        Clear-RecycleBinContents
        
        # 2. Clear User Temp folder
        Write-Log "Clearing user temp folder..." "INFO"
        $UserTemp = $env:TEMP
        if (Test-Path $UserTemp) {
            Get-ChildItem -Path $UserTemp -Recurse -Force -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # 3. Clear System Temp folder
        Write-Log "Clearing system temp folder..." "INFO"
        $SystemTemp = "$env:SystemRoot\Temp"
        if (Test-Path $SystemTemp) {
            Get-ChildItem -Path $SystemTemp -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # 4. Clear Windows Update Download Cache
        Write-Log "Clearing Windows Update download cache..." "INFO"
        $WUCache = "$env:SystemRoot\SoftwareDistribution\Download"
        if (Test-Path $WUCache) {
            Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
            Get-ChildItem -Path $WUCache -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Start-Service wuauserv -ErrorAction SilentlyContinue
        }
        
        # 5. Clear Delivery Optimization Cache
        Write-Log "Clearing Delivery Optimization cache..." "INFO"
        try {
            Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue
        } catch {
            $DOCache = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
            if (Test-Path $DOCache) {
                Remove-Item -Path "$DOCache\*" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        # 6. Clear Windows Error Reporting
        Write-Log "Clearing Windows Error Reporting..." "INFO"
        $WERPaths = @(
            "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
            "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
        )
        foreach ($WERPath in $WERPaths) {
            if (Test-Path $WERPath) {
                Remove-Item -Path "$WERPath\*" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        # 7. Clear Windows Installer Cache (orphaned patches)
        Write-Log "Clearing orphaned Windows Installer patches..." "INFO"
        $InstallerCache = "$env:SystemRoot\Installer\`$PatchCache`$"
        if (Test-Path $InstallerCache) {
            Remove-Item -Path "$InstallerCache\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # 8. Clear Thumbnail Cache
        Write-Log "Clearing thumbnail cache..." "INFO"
        $ThumbCachePath = "$env:LocalAppData\Microsoft\Windows\Explorer"
        if (Test-Path $ThumbCachePath) {
            Get-ChildItem -Path $ThumbCachePath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
        }
        
        # 9. Run DISM component cleanup
        Write-Log "Running DISM component cleanup..." "INFO"
        Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        
        # 10. Aggressive cleanup (optional)
        if ($Aggressive) {
            Write-Log "Running aggressive cleanup (Windows.old removal)..." "WARNING"
            
            # Remove Windows.old
            $WindowsOld = "$env:SystemDrive\Windows.old"
            if (Test-Path $WindowsOld) {
                Write-Log "Removing Windows.old folder..." "WARNING"
                takeown /F "$WindowsOld" /R /A /D Y 2>$null
                icacls "$WindowsOld" /grant Administrators:F /T /C 2>$null
                Remove-Item -Path $WindowsOld -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            # Remove previous Windows installations via DISM
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
        }
    }
    
    # Check UseUpdateClassPolicySource
    $UseUpdateClass = Get-RegistryValue -Path $RegistryPaths.AU -Property 'UseUpdateClassPolicySource' -ExpectedValue 1
    if (-not $UseUpdateClass.Exists -or $UseUpdateClass.Value -ne 1) {
        $IssueMessage = "UseUpdateClassPolicySource is misconfigured or missing"
        Write-Log $IssueMessage "WARNING"
        $Global:DetectionResult.Issues += $IssueMessage
        $Global:DetectionResult.RequiresRemediation = $true
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
function Invoke-PolicyRemediation {
    Write-Log "Starting policy remediation..." "INFO"
    $RemediationCount = 0
    
    # Reset registry settings
    foreach ($Setting in $SettingsToReset) {
        $Path = $RegistryPaths[$Setting.Path]
        if ($Path) {
            $Changed = Set-RegistryValue -Path $Path -Name $Setting.Name -Value $Setting.Value
            if ($Changed) { $RemediationCount++ }
        }
    }
    
    # Remove WSUS-related settings
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
        
        # Re-register DLLs
        foreach ($DLL in $WUDLLs) {
            $DLLPath = "$env:SystemRoot\System32\$DLL"
            if (Test-Path $DLLPath) {
                Start-Process "regsvr32.exe" -ArgumentList "/s `"$DLLPath`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            }
        }
        Write-Log "Re-registered Windows Update DLLs" "INFO"
        
        # Reset Winsock and proxy
        Start-Process "netsh" -ArgumentList "winsock reset" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Process "netsh" -ArgumentList "winhttp reset proxy" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Log "Reset Winsock and WinHTTP proxy" "INFO"
        
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
    
    # Hardware eligibility check (only for Windows 10 devices)
    if ($DeviceInfo) {
        Test-HardwareEligibility -DeviceInfo $DeviceInfo | Out-Null
    }
    
    # Disk space check
    $DiskCheck = Test-DiskSpace
    
    # Policy detection
    Invoke-PolicyDetection
    
    # Display detection results
    Write-Log "----------------------------------------" "INFO"
    Write-Log "DETECTION SUMMARY:" "INFO"
    Write-Log "Status: $($Global:DetectionResult.Status)" "INFO"
    Write-Log "Hardware Eligible: $($Global:DetectionResult.HardwareEligible)" "INFO"
    Write-Log "Disk Space Sufficient: $(-not $Global:DetectionResult.DiskSpaceLow)" "INFO"
    Write-Log "Issues Found: $($Global:DetectionResult.Issues.Count)" "INFO"
    foreach ($Issue in $Global:DetectionResult.Issues) {
        Write-Log "  - $Issue" "INFO"
    }
    if ($Global:DetectionResult.Warnings.Count -gt 0) {
        Write-Log "Warnings: $($Global:DetectionResult.Warnings.Count)" "INFO"
        foreach ($Warning in $Global:DetectionResult.Warnings) {
            Write-Log "  - $Warning" "INFO"
        }
    }
    Write-Log "----------------------------------------" "INFO"
    
    # Remediation phase
    if ($Global:DetectionResult.RequiresRemediation -or $Global:DetectionResult.DiskSpaceLow) {
        if ($DetectOnly) {
            Write-Log "Detection-only mode: Remediation required but not performed" "WARNING"
            Write-Log "========================================"
            Write-Log "Script completed with issues detected"
            Write-Log "========================================"
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
            
            # Re-run detection to verify
            Write-Log "Re-running detection to verify remediation..." "INFO"
            $Global:DetectionResult = @{
                Issues = @()
                Warnings = @()
                Status = 'Compliant'
                RequiresRemediation = $false
                HardwareEligible = $true
                DiskSpaceLow = $false
            }
            Invoke-PolicyDetection
            
            if ($Global:DetectionResult.RequiresRemediation) {
                Write-Log "Remediation completed but some issues remain" "WARNING"
                Write-Log "========================================"
                Write-Log "Script completed with remaining issues"
                Write-Log "========================================"
                exit 1
            } else {
                Write-Log "Remediation successful: All policy issues resolved" "INFO"
                Write-Log "========================================"
                Write-Log "Script completed successfully"
                Write-Log "========================================"
                exit 0
            }
        }
    } else {
        Write-Log "No remediation required: System is compliant" "INFO"
        
        # Still trigger update scan to ensure updates are checked
        if (-not $DetectOnly) {
            Write-Log "Triggering update scan for compliant system..." "INFO"
            Start-WindowsUpdateScan
            Get-RecentUpdateHistory
        }
        
        Write-Log "========================================"
        Write-Log "Script completed successfully"
        Write-Log "========================================"
        exit 0
    }
    
} catch {
    Write-Log "Critical error during script execution: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    Write-Log "========================================"
    Write-Log "Script completed with errors"
    Write-Log "========================================"
    exit 1
}
#endregion
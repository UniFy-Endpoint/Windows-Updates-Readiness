<#
.SYNOPSIS
    Windows Updates Readiness - Remediation Script

.DESCRIPTION
    Comprehensive remediation script that fixes issues detected by the Detection script.
    Designed for Intune Proactive Remediation REMEDIATION script.

.PARAMETER AggressiveCleanup
    Enable aggressive cleanup including Windows.old removal (removes rollback capability)

.NOTES
    Version: 2.5
    Author: Yoennis Olmo
    
    Changelog v2.5:
    - Aligned with Detection v2.5 cleanup thresholds based on real-world enterprise experience
    - All cleanup tasks run when remediation is triggered

    Intune Settings:
    Run this script using the logged on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell Host: Yes
#>

[CmdletBinding()]
param([switch]$AggressiveCleanup = $false)

#region --- CONFIGURATION ---
$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = "$LogPath\Windows-Updates-Readiness-Remediation.log"

$RegistryPaths = @{
    AU         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    WU         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    GWX        = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX"
    UX         = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    UPSettings = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings"
}

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

$Global:Stats = @{RegistryChanges=0;PauseKeysCleared=0;SpaceFreedGB=0;DLLsReregistered=0;DLLsSkipped=0;ServicesRestarted=0}
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
Write-Log "==== Windows Updates Readiness Remediation v2.6 ===="
Write-Log "Aggressive Cleanup: $AggressiveCleanup"
#endregion

#region --- HELPER FUNCTIONS ---
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
#endregion

#region --- REGISTRY/POLICY REMEDIATION ---
function Invoke-RegistryRemediation {
    Write-Log "--- REGISTRY/POLICY REMEDIATION ---"
    foreach ($Setting in $SettingsToReset) {
        $Path = $RegistryPaths[$Setting.Path]
        if ($Path -and (Set-RegistryValue -Path $Path -Name $Setting.Name -Value $Setting.Value)) { $Global:Stats.RegistryChanges++ }
    }
    foreach ($Setting in $SettingsToRemove) {
        if (Remove-RegistryValue -Path $RegistryPaths.WU -Name $Setting) { $Global:Stats.RegistryChanges++ }
    }
    Write-Log "Registry changes: $($Global:Stats.RegistryChanges)"
}
#endregion

#region --- CLEAR UPDATE PAUSE STATES ---
function Clear-UpdatePauseStates {
    Write-Log "--- CLEARING UPDATE PAUSE STATES ---"
    foreach ($PausePath in @($RegistryPaths.UX, $RegistryPaths.UPSettings)) {
        if (Test-Path $PausePath) {
            foreach ($Key in $PauseKeys) {
                try {
                    $Value = Get-ItemProperty -Path $PausePath -Name $Key -ErrorAction SilentlyContinue
                    if ($Value) { Remove-ItemProperty -Path $PausePath -Name $Key -Force -ErrorAction SilentlyContinue; Write-Log "Cleared: $Key"; $Global:Stats.PauseKeysCleared++ }
                } catch {}
            }
        }
    }
    Write-Log "Pause keys cleared: $($Global:Stats.PauseKeysCleared)"
}
#endregion

#region --- DISK CLEANUP ---
function Invoke-RecycleBinCleanup {
    Write-Log "--- RECYCLE BIN CLEANUP ---"
    try {
        $RecyclePath = "$env:SystemDrive\`$Recycle.Bin"
        if (Test-Path $RecyclePath) {
            $UserBins = Get-ChildItem -Path $RecyclePath -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "S-1-*" }
            foreach ($Bin in $UserBins) { try { Get-ChildItem -Path $Bin.FullName -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
            Write-Log "Recycle Bin cleared"
            return $true
        }
    } catch { Write-Log "Recycle Bin cleanup failed: $_" "WARNING" }
    try { Clear-RecycleBin -Force -ErrorAction SilentlyContinue; return $true } catch { return $false }
}

function Invoke-TempCleanup {
    Write-Log "--- TEMP FOLDER CLEANUP ---"
    if (Test-Path $env:TEMP) {
        Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "User Temp cleaned"
    }
    $SystemTemp = "$env:SystemRoot\Temp"
    if (Test-Path $SystemTemp) {
        Get-ChildItem -Path $SystemTemp -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "System Temp cleaned"
    }
}

function Invoke-WUCacheCleanup {
    Write-Log "--- WINDOWS UPDATE CACHE CLEANUP ---"
    $WUCache = "$env:SystemRoot\SoftwareDistribution\Download"
    if (Test-Path $WUCache) {
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $WUCache -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service wuauserv -ErrorAction SilentlyContinue
        Write-Log "WU Cache cleaned"
    }
}

function Invoke-DOCacheCleanup {
    Write-Log "--- DELIVERY OPTIMIZATION CACHE CLEANUP ---"
    try { Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue; Write-Log "DO Cache cleaned (cmdlet)" }
    catch {
        $DOCache = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
        if (Test-Path $DOCache) { Remove-Item -Path "$DOCache\*" -Recurse -Force -ErrorAction SilentlyContinue; Write-Log "DO Cache cleaned (manual)" }
    }
}

function Invoke-WERCleanup {
    Write-Log "--- WINDOWS ERROR REPORTING CLEANUP ---"
    @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive","$env:ProgramData\Microsoft\Windows\WER\ReportQueue") | ForEach-Object {
        if (Test-Path $_) { Remove-Item -Path "$_\*" -Recurse -Force -ErrorAction SilentlyContinue }
    }
    Write-Log "WER cleaned"
}

function Invoke-InstallerCacheCleanup {
    Write-Log "--- WINDOWS INSTALLER PATCH CACHE CLEANUP ---"
    $InstallerCache = "$env:SystemRoot\Installer\`$PatchCache`$"
    if (Test-Path $InstallerCache) { Remove-Item -Path "$InstallerCache\*" -Recurse -Force -ErrorAction SilentlyContinue; Write-Log "Installer Cache cleaned" }
}

function Invoke-ThumbnailCacheCleanup {
    Write-Log "--- THUMBNAIL CACHE CLEANUP ---"
    $ThumbCachePath = "$env:LocalAppData\Microsoft\Windows\Explorer"
    if (Test-Path $ThumbCachePath) {
        Get-ChildItem -Path $ThumbCachePath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "Thumbnail Cache cleaned"
    }
}

function Invoke-DISMCleanup {
    Write-Log "--- DISM COMPONENT CLEANUP ---"
    Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Log "DISM Cleanup completed"
}

function Invoke-WindowsOldRemoval {
    Write-Log "--- WINDOWS.OLD REMOVAL (AGGRESSIVE) ---"
    $WindowsOld = "$env:SystemDrive\Windows.old"
    if (Test-Path $WindowsOld) {
        Write-Log "Removing Windows.old - REMOVES ROLLBACK CAPABILITY" "WARNING"
        takeown /F "$WindowsOld" /R /A /D Y 2>$null
        icacls "$WindowsOld" /grant Administrators:F /T /C 2>$null
        Remove-Item -Path $WindowsOld -Recurse -Force -ErrorAction SilentlyContinue
        Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Log "Windows.old removed"
    } else { Write-Log "Windows.old not present" }
}

function Invoke-AllDiskCleanup {
    Write-Log "=== STARTING DISK CLEANUP ==="
    try {
        $BeforeSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
        Invoke-RecycleBinCleanup
        Invoke-TempCleanup
        Invoke-WUCacheCleanup
        Invoke-DOCacheCleanup
        Invoke-WERCleanup
        Invoke-InstallerCacheCleanup
        Invoke-ThumbnailCacheCleanup
        Invoke-DISMCleanup
        if ($AggressiveCleanup) { Invoke-WindowsOldRemoval }
        $AfterSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
        $Global:Stats.SpaceFreedGB = [math]::Round(($AfterSpace - $BeforeSpace) / 1GB, 2)
        Write-Log "=== DISK CLEANUP COMPLETE - Freed: $($Global:Stats.SpaceFreedGB) GB ==="
    } catch { Write-Log "Disk cleanup error: $_" "ERROR" }
}
#endregion

#region --- WU COMPONENT REPAIR ---
function Repair-WUComponents {
    Write-Log "--- WU COMPONENT REPAIR ---"
    foreach ($Svc in $WUServices) { try { Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue } catch {} }
    Write-Log "Stopped WU services"
    foreach ($DLL in $WUDLLs) {
        $DLLPath = "$env:SystemRoot\System32\$DLL"
        if (Test-Path $DLLPath) {
            if ($DLL -in @("vbscript.dll","scrrun.dll","mshtml.dll","shdocvw.dll","browseui.dll")) { $Global:Stats.DLLsSkipped++; continue }
            $Process = Start-Process "regsvr32.exe" -ArgumentList "/s `"$DLLPath`"" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            if ($Process.ExitCode -eq 0) { $Global:Stats.DLLsReregistered++ } else { Write-Log "Failed to register $DLL" "WARNING" }
        } else {
            if ($LegacyDLLs -contains $DLL) { Write-Log "Skipped legacy DLL: $DLL" } else { Write-Log "Skipped missing DLL: $DLL" "WARNING" }
            $Global:Stats.DLLsSkipped++
        }
    }
    Write-Log "Re-registered $($Global:Stats.DLLsReregistered) DLLs (Skipped: $($Global:Stats.DLLsSkipped))"
    foreach ($Svc in $WUServices) {
        try { Set-Service -Name $Svc -StartupType Manual -ErrorAction SilentlyContinue; Start-Service -Name $Svc -ErrorAction SilentlyContinue; $Global:Stats.ServicesRestarted++ } catch {}
    }
    Write-Log "Restarted WU services"
}

function Reset-WinsockProxy {
    Write-Log "--- WINSOCK/PROXY RESET ---"
    Start-Process "netsh" -ArgumentList "winsock reset" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Process "netsh" -ArgumentList "winhttp reset proxy" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Log "Winsock and WinHTTP proxy reset"
}
#endregion

#region --- TRIGGER UPDATE ---
function Start-WindowsUpdateScan {
    Write-Log "--- TRIGGERING WINDOWS UPDATE ---"
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
#endregion

#region --- UPDATE HISTORY ---
function Get-RecentUpdateHistory {
    Write-Log "--- UPDATE HISTORY ---"
    try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $HistoryCount = $Searcher.GetTotalHistoryCount()
        if ($HistoryCount -gt 0) {
            $History = $Searcher.QueryHistory(0, [Math]::Min(10, $HistoryCount))
            foreach ($Update in $History) {
                $Status = switch ($Update.ResultCode) { 0{"NotStarted"};1{"InProgress"};2{"Succeeded"};3{"SucceededWithErrors"};4{"Failed"};5{"Aborted"};default{"Unknown"} }
                Write-Log "  [$Status] $($Update.Title)"
            }
        }
    } catch { Write-Log "Error retrieving history: $_" "ERROR" }
}
#endregion

#region --- MAIN EXECUTION ---
try {
    Invoke-RegistryRemediation
    Clear-UpdatePauseStates
    Invoke-AllDiskCleanup
    Repair-WUComponents
    Reset-WinsockProxy
    Start-WindowsUpdateScan
    Get-RecentUpdateHistory

    Write-Log "==== REMEDIATION SUMMARY ===="
    Write-Log "Registry Changes: $($Global:Stats.RegistryChanges)"
    Write-Log "Pause Keys Cleared: $($Global:Stats.PauseKeysCleared)"
    Write-Log "Space Freed: $($Global:Stats.SpaceFreedGB) GB"
    Write-Log "DLLs Re-registered: $($Global:Stats.DLLsReregistered)"
    Write-Log "DLLs Skipped: $($Global:Stats.DLLsSkipped)"
    Write-Log "Services Restarted: $($Global:Stats.ServicesRestarted)"
    Write-Log "===="
    Write-Log "Remediation completed successfully"
    exit 0
} catch { Write-Log "Critical error: $($_.Exception.Message)" "ERROR"; exit 1 }
#endregion
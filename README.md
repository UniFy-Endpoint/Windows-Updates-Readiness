# Windows Updates Readiness Script

A comprehensive PowerShell script designed to detect and remediate Windows Update configuration issues, ensuring devices are ready to receive updates via Microsoft Intune and Windows Update for Business (WUfB).

## Purpose

This script solves common Windows Update problems that prevent devices from receiving updates, particularly useful when:

- Migrating from WSUS/GPO to Intune WUfB
- Devices are stuck and not receiving Feature Updates (e.g., Windows 10 to Windows 11 upgrades)
- Legacy registry settings are blocking Windows Update
- Devices have paused updates or insufficient disk space

## Features

### Detection & Reporting
- **OS Detection** - Accurately identifies Windows 10 vs Windows 11 based on build number
- **Hardware Eligibility** - Validates TPM 2.0, Secure Boot, and RAM requirements for Windows 11
- **Disk Space Analysis** - Checks free space and Recycle Bin size (30GB+ recommended for upgrades)
- **Policy Audit** - Detects WSUS conflicts, update pauses, and misconfigured registry settings

### Remediation
- **Registry Cleanup** - Removes legacy WSUS/GPO settings that block WUfB
- **Pause State Clearing** - Removes all update pause flags
- **Windows Update Repair** - Re-registers DLLs, resets Winsock, restarts services
- **Disk Cleanup** - Clears temp files, Recycle Bin, WU cache, Delivery Optimization cache
- **Update Trigger** - Forces Windows Update scan, download, and install

## What It Checks & Fixes

| Category | Detection | Remediation |
|:---------|:----------|:------------|
| `NoAutoUpdate` | Detects if set to 1 | Resets to 0 |
| `UseWUServer` | Detects WSUS configuration | Removes WSUS settings |
| `DisableDualScan` | Detects dual scan block | Resets to 0 |
| `WUServer/WUStatusServer` | Detects WSUS server URLs | Removes entries |
| Update Pause States | Detects all pause flags | Clears all pause keys |
| Disk Space | Warns if < 30GB free | Runs cleanup routines |
| TPM/SecureBoot/RAM | Validates Win11 eligibility | Reports blockers |

## Disk Cleanup Details

When disk space is below 30GB (or when running remediation), the script cleans the following locations:

### Standard Cleanup

| Location | Description | Path |
|:---------|:------------|:-----|
| **Recycle Bin** | Deleted files from all drives | `$Recycle.Bin` on all drives |
| **User Temp Folder** | Temporary files older than 1 day | `%TEMP%` |
| **System Temp Folder** | System temporary files older than 1 day | `%SystemRoot%\Temp` |
| **Windows Update Cache** | Downloaded update files | `%SystemRoot%\SoftwareDistribution\Download` |
| **Delivery Optimization Cache** | P2P update delivery cache | `%SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache` |
| **Windows Error Reporting** | Crash dumps and error reports | `%ProgramData%\Microsoft\Windows\WER\ReportArchive`<br>`%ProgramData%\Microsoft\Windows\WER\ReportQueue` |
| **Windows Installer Patches** | Orphaned installer patches | `%SystemRoot%\Installer\$PatchCache$` |
| **Thumbnail Cache** | Explorer thumbnail database files | `%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db` |
| **DISM Component Cleanup** | Superseded Windows components | Runs `DISM /Online /Cleanup-Image /StartComponentCleanup` |

### Aggressive Cleanup (with `-AggressiveCleanup` flag)

| Location | Description | Path |
|:---------|:------------|:-----|
| **Windows.old** | Previous Windows installation | `%SystemDrive%\Windows.old` |
| **DISM ResetBase** | All superseded components (no rollback) | Runs `DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase` |

>**Warning:** Aggressive cleanup removes the ability to roll back to the previous Windows version and uninstall updates. Use with caution!

## Usage

### Basic Usage

```powershell
# Run detection and remediation
.\Windows-Updates-Readiness_v1.5.ps1

# Detection only (no changes made)
.\Windows-Updates-Readiness_v1.5.ps1 -DetectOnly

# Include aggressive cleanup (removes Windows.old - no rollback!)
.\Windows-Updates-Readiness_v1.5.ps1 -AggressiveCleanup

# Skip hardware eligibility check
.\Windows-Updates-Readiness_v1.5.ps1 -SkipHardwareCheck
```

### Parameters

| Parameter | Type | Description |
|:----------|:-----|:------------|
| `-DetectOnly` | Switch | Run in detection-only mode without making changes |
| `-AggressiveCleanup` | Switch | Enable aggressive disk cleanup including Windows.old (removes rollback capability) |
| `-SkipHardwareCheck` | Switch | Skip Windows 11 hardware eligibility checks |

## Intune Deployment

### As a Platform Script

1. Go to **Microsoft Intune admin center**
2. Navigate to **Devices** > **Scripts and remediations** > **Platform scripts**
3. Click **+ Add** > **Windows 10 and later**
4. Configure:
   - **Name:** Windows Updates Readiness
   - **Script:** Upload `Windows-Updates-Readiness_v1.5.ps1`
   - **Run this script using the logged on credentials:** No
   - **Enforce script signature check:** No
   - **Run script in 64 bit PowerShell Host:** Yes
5. Assign to device groups

### As a Remediation Script

You can also deploy this as a **Proactive Remediation** by splitting detection and remediation:

**Detection Script:**
```powershell
.\Windows-Updates-Readiness_v1.5.ps1 -DetectOnly
# Exit code 1 = Non-compliant (issues found)
# Exit code 0 = Compliant
```

**Remediation Script:**
```powershell
.\Windows-Updates-Readiness_v1.5.ps1
```

## Logging

All actions are logged to:
```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Windows-Updates-Readiness.log
```

### Sample Log Output

```
[2026-01-13 11:46:46] [INFO] ========================================
[2026-01-13 11:46:46] [INFO] Windows Updates Readiness Script v1.5
[2026-01-13 11:46:46] [INFO] Execution Mode: Detection and Remediation
[2026-01-13 11:46:46] [INFO] ========================================
[2026-01-13 11:46:46] [INFO] Computer: DESKTOP-ABC123
[2026-01-13 11:46:46] [INFO] Current OS: Windows 11 Enterprise - 24H2 (Build 26100.7462)
[2026-01-13 11:46:46] [INFO] RAM: 16 GB | TPM: True (v2.0) | SecureBoot: True
[2026-01-13 11:46:46] [INFO] Disk space on C: - Free: 45.23 GB / Total: 256 GB
[2026-01-13 11:46:46] [INFO] Recycle Bin size: 2.5 GB
[2026-01-13 11:46:46] [WARNING] NoAutoUpdate is set to 1 (should be 0)
[2026-01-13 11:46:47] [INFO] Starting remediation phase...
[2026-01-13 11:46:47] [INFO] Clearing Recycle Bin...
[2026-01-13 11:46:47] [INFO] Recycle Bin cleared successfully
[2026-01-13 11:46:47] [INFO] Setting registry value to 0...
[2026-01-13 11:46:48] [INFO] Disk cleanup complete. Space freed: 3.2 GB
[2026-01-13 11:46:48] [INFO] Remediation successful: All policy issues resolved
```

## Registry Keys Modified

### Keys Reset to 0
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\UseWUServer`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableDualScan`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DoNotConnectToWindowsUpdateInternetLocations`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableWindowsUpdateAccess`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetPolicyDrivenUpdateSourceFor*`

### Keys Set to Specific Values
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\UseUpdateClassPolicySource` → `1`
- `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX\GStatus` → `2`

### Keys Removed
- `WUServer`
- `WUStatusServer`
- `TargetGroup`
- `TargetGroupEnabled`

### Pause Keys Cleared
- `PausedFeatureDate`, `PausedQualityDate`
- `PausedFeatureStatus`, `PausedQualityStatus`
- `PauseFeatureUpdatesStartTime`, `PauseFeatureUpdatesEndTime`
- `PauseQualityUpdatesStartTime`, `PauseQualityUpdatesEndTime`
- `PauseUpdatesExpiryTime`, `PauseUpdatesStartTime`

## Windows Update Components Repaired

The script repairs Windows Update by:

1. **Stopping Services:** `wuauserv`, `bits`, `cryptsvc`, `msiserver`, `usosvc`, `dosvc`
2. **Re-registering DLLs:** 36 Windows Update related DLLs including `wuapi.dll`, `wuaueng.dll`, `wups.dll`, etc.
3. **Resetting Network:** Winsock reset and WinHTTP proxy reset
4. **Restarting Services:** All stopped services are restarted

## Exit Codes

| Code | Meaning |
|:-----|:--------|
| `0` | Success - System is compliant or remediation successful |
| `1` | Issues detected (detection-only) or remediation incomplete |

## Requirements

- **PowerShell:** 5.1 or later
- **OS:** Windows 10 or Windows 11
- **Permissions:** Must run as SYSTEM or Administrator
- **Disk Space:** 30GB+ free recommended for Windows upgrades

## Support

If you encounter issues or have questions:
1. Check the log file at `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Windows-Updates-Readiness.log`
2. Open an issue on this repository with the log output

---

**Note:** Always test in a non-production environment before deploying to production devices.

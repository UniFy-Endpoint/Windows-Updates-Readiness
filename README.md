# Windows Updates Readiness Scripts v2.1

A comprehensive set of PowerShell scripts designed to detect and remediate Windows Update configuration issues, ensuring devices are ready to receive updates via Microsoft Intune and Windows Update for Business (WUfB).

---

## Purpose

This script solves common Windows Update problems that prevent devices from receiving updates, particularly useful when:

- Migrating from WSUS/GPO to Intune WUfB
- Devices are stuck and not receiving Feature Updates (e.g., Windows 10 to Windows 11 upgrades)
- Legacy registry settings are blocking Windows Update
- Devices have paused updates or insufficient disk space

---

## Overview

This release includes three scripts to manage Windows Update readiness:

- **Windows-Updates-Readiness_v2.1.ps1**  
  Unified Platform Script combining detection and remediation capabilities with options to run detection only (`-DetectOnly`), enable aggressive cleanup (`-AggressiveCleanup`), or skip hardware eligibility checks (`-SkipHardwareCheck`). Designed as a Platform Script in Intune running as SYSTEM.
  
- **Windows-Updates-Readiness-Detection_v2.1.ps1**  
  Detection-only script that checks all readiness factors including registry/policy compliance, hardware eligibility for Windows 11, disk space, cleanup opportunities, Windows Update component health, and update pause states.  
  Returns exit code 1 if issues are detected, 0 if compliant. Designed for use as an Intune Proactive Remediation Detection script.

- **Windows-Updates-Readiness-Remediation_v2.1.ps1**  
  Remediation-only script that fixes all issues detected by the Detection script. It remediates registry/policy settings, cleans up disk space (Recycle Bin, Temp, WU Cache, Delivery Optimization Cache, etc.), repairs Windows Update components, resets Winsock/proxy, clears update pause states, and triggers Windows Update scan/download/install.  
  Supports an `-AggressiveCleanup` switch to remove Windows.old and perform DISM ResetBase cleanup. Designed for use as an Intune Proactive Remediation Remediation script.

---

## Features

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


### Detection

- **Hardware Eligibility**: Validates TPM 2.0 presence and enabled state, Secure Boot enabled, and minimum 4GB RAM for Windows 11 eligibility.
- **Registry/Policy Compliance**: Checks critical Windows Update policies and WSUS-related settings that may block updates.
- **Update Pause States**: Detects if updates are paused via registry keys.
- **Disk Space & Cleanup Needs**: Checks free disk space and flags cleanup needs for Recycle Bin, Temp folders, Windows Update cache, Delivery Optimization cache, Windows Error Reporting, Installer patch cache, Thumbnail cache, and WinSxS component store.
- **Windows Update Component Health**: Verifies critical Windows Update services are running and essential DLLs are present.
- **Proxy and Winsock Status**: Detects proxy configuration and potential Winsock corruption.
- **Update History**: Retrieves recent Windows Update installation history.

### Remediation

- **Registry/Policy Fixes**: Resets critical registry keys to recommended values and removes legacy WSUS settings.
- **Clear Update Pause States**: Removes all update pause flags.
- **Disk Cleanup**: Cleans Recycle Bin, Temp folders, Windows Update cache, Delivery Optimization cache, Windows Error Reporting files, Installer patch cache, Thumbnail cache, and runs DISM component cleanup.
- **Aggressive Cleanup**: Optionally removes Windows.old folder and performs DISM ResetBase cleanup (removes rollback capability).
- **Windows Update Component Repair**: Stops Windows Update services, re-registers essential DLLs, resets Winsock and WinHTTP proxy, and restarts services.
- **Trigger Windows Update Scan**: Initiates Windows Update scan, download, and install process.

---

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

---

## Usage

## Parameters

| Parameter | Type | Description |
|:----------|:-----|:------------|
| `-DetectOnly` | Switch | Run in detection-only mode without remediation or making changes |
| `-AggressiveCleanup` | Switch | Enable aggressive disk cleanup including Windows.old (removes rollback capability) |
| `-SkipHardwareCheck` | Switch | Skip Windows 11 hardware eligibility checks |


### Detection Script

```powershell
.\Windows-Updates-Readiness-Detection_v2.1.ps1
```

- Exit code `0` means compliant, `1` means issues detected.

### Remediation Script

```powershell
.\Windows-Updates-Readiness-Remediation_v2.1.ps1 [-AggressiveCleanup]
```

- Use `-AggressiveCleanup` to remove Windows.old and perform DISM ResetBase cleanup.

### Unified Script

```powershell
.\Windows-Updates-Readiness_v2.1.ps1 [-DetectOnly] [-AggressiveCleanup] [-SkipHardwareCheck]
```

---

## Intune Deployment

### Proactive Remediation

- Use **Windows-Updates-Readiness-Detection_v2.1.ps1** as the Detection script.
- Use **Windows-Updates-Readiness-Remediation_v2.1.ps1** as the Remediation script.

```powershell
# Exit code 1 = Non-compliant (issues found)
# Exit code 0 = Compliant
```

### Platform Script

- Use **Windows-Updates-Readiness_v2.1.ps1** as a Platform Script running as SYSTEM.
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

---

## Logging

All scripts log detailed information to:

```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\
```

- Detection logs: `Windows-Updates-Readiness-Detection.log`
- Remediation logs: `Windows-Updates-Readiness-Remediation.log`
- Unified script logs: `Windows-Updates-Readiness.log`

---

## Registry Keys Managed

### Keys Reset to Recommended Values

### Keys Reset to 0
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\UseWUServer`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableDualScan`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DoNotConnectToWindowsUpdateInternetLocations`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableWindowsUpdateAccess`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetPolicyDrivenUpdateSourceForDriverUpdates`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetPolicyDrivenUpdateSourceForOtherUpdates`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetPolicyDrivenUpdateSourceForQualityUpdates`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetPolicyDrivenUpdateSourceForFeatureUpdates`

### Keys Set to Specific Values
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\UseUpdateClassPolicySource` → `1`
- `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX\GStatus` → `2`


### Keys Removed

- `WUServer`
- `WUStatusServer`
- `TargetGroup`
- `TargetGroupEnabled`

### Update Pause Keys Cleared

- `PausedFeatureDate`, `PausedQualityDate`
- `PausedFeatureStatus`, `PausedQualityStatus`
- `PauseFeatureUpdatesStartTime`, `PauseFeatureUpdatesEndTime`
- `PauseQualityUpdatesStartTime`, `PauseQualityUpdatesEndTime`
- `PauseUpdatesExpiryTime`, `PauseUpdatesStartTime`

---

## Windows Update Components Repaired

The script repairs Windows Update by:

1. **Stops Windows Update related services:** `wuauserv`, `bits`, `cryptsvc`, `msiserver`, `usosvc`, `dosvc`
2. **Re-registering DLLs:** 36 Windows Update related DLLs including `wuapi.dll`, `wuaueng.dll`, `wups.dll`, etc.
3. **Resetting Network:** Winsock reset and WinHTTP proxy reset
4. **Restarts Windows Update services:** All stopped services are restarted


---

## Requirements

- **PowerShell:** 5.1 or later
- **OS:** Windows 10 or Windows 11
- **Permissions:** Must run as SYSTEM or Administrator
- **Disk Space:** 30GB+ free recommended for Windows upgrades

---

## Contributing

Contributions and feedback are welcome! Please submit issues or pull requests on GitHub.

---

**Note:** Always test scripts in a non-production environment before deploying widely to production devices.

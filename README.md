# Windows Updates Readiness Scripts

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

- **Windows-Updates-Readiness-Detection_v2.5.ps1**  
  Detection-only script that checks all readiness factors including registry/policy compliance, hardware eligibility for Windows 11, disk space, cleanup opportunities, Windows Update component health, and update pause states.  
  Returns exit code 1 if issues are detected, 0 if compliant. Designed for use as an Intune Proactive Remediation Detection script.

- **Windows-Updates-Readiness-Remediation_v2.5.ps1**  
  Remediation-only script that fixes all issues detected by the Detection script. It remediates registry/policy settings, cleans up disk space (Recycle Bin, Temp, WU Cache, Delivery Optimization Cache, etc.), repairs Windows Update components, resets Winsock/proxy, clears update pause states, and triggers Windows Update scan/download/install.  
  Supports an `-AggressiveCleanup` switch to remove Windows.old and perform DISM ResetBase cleanup. Designed for use as an Intune Proactive Remediation Remediation script.

- **Windows-Updates-Readiness_v2.5.ps1**  
  Unified script combining detection and remediation capabilities with options to run detection only (`-DetectOnly`), enable aggressive cleanup (`-AggressiveCleanup`), or skip hardware eligibility checks (`-SkipHardwareCheck`). Designed as a Platform Script in Intune running as SYSTEM.


---

## Recent Updates (v2.5)

**Enhancement:** Change recommended cleanup thresholds based on real-world enterprise Windows device management experience.

- Recycle Bin >= 2 GB
- User Temp/System Folder Folders >= 500 MB Combined
- Healthy system: >= 200 MB
- WU Cache >= 500 MB
- DO Cache >= 500 MB
- Windows Error Reporting (WER) >= 200 MB
- Installer Patch Cache >= 500 MB
- Thumbnail Cache >= 200 MB
- WinSxS/Component Store >= 8 GB

**Fix Applied to:**
- `Keep the space in the system healthy and optimized`
- `Maximize disk space recovery when remediation runs`

**Impact:** The amount and size of the data to be cleaned in the system were not being properly optimized to trigger remediation needs.

---

## Recent Updates (v2.4)

### WSUS Registry Key Removal

**Enhancement:** Scripts now completely remove legacy WSUS registry keys to ensure clean migration to Windows Update for Business (WUfB).

**Keys Removed:**
- `WUServer` - Legacy WSUS server URL
- `WUStatusServer` - Legacy WSUS status server URL
- `TargetGroup` - WSUS target group assignment
- `TargetGroupEnabled` - WSUS target group enabled flag

**Impact:** Devices migrating from WSUS/GPO environments to Intune WUfB will have all legacy WSUS configurations completely removed, preventing conflicts and ensuring proper cloud-based update management.

---

## Recent Updates (v2.3)

### Windows 11 24H2/25H2 Compatibility Fix

**Issue Resolved:** Detection scripts were incorrectly flagging certain Windows Update DLLs as missing on Windows 11 24H2/25H2 builds, causing false "non-compliant" status and remediation loops.

**Fix Applied:**
- **Detection Logic:** Scripts now detect Windows version (build ≥22000 for Windows 11) and gracefully handle these DLLs by logging their absence as informational rather than errors on Windows 11 systems
- **Remediation Logic:** DLL registration now checks if files physically exist on disk before attempting to register them, preventing errors during remediation

**Impact:** Windows 11 24H2/25H2 devices will no longer show false positives for missing legacy DLLs and will correctly report compliant status when no actual issues exist.

---

## Features

## What It Checks & Fixes

| Category | Detection | Remediation |
|:----|:----|:----|
| `NoAutoUpdate` | Detects if set to 1 | Resets to 0 |
| `UseWUServer` | Detects WSUS configuration | Resets to 0 and removes WSUS keys |
| `DisableDualScan` | Detects dual scan block | Resets to 0 |
| `WUServer/WUStatusServer` | Detects WSUS server URLs | Completely removes keys |
| `TargetGroup/TargetGroupEnabled` | Detects WSUS target group | Completely removes keys |
| Update Pause States | Detects all pause flags | Clears all pause keys |
| Disk Space | Warns if < 30GB free | Runs cleanup routines |
| TPM/SecureBoot/RAM | Validates Win11 eligibility | Reports blockers |
| Windows Update DLLs | Checks critical DLLs (Windows 11 aware) | Re-registers existing DLLs only |


### Detection

- **Hardware Eligibility**: Validates TPM 2.0 presence and enabled state, Secure Boot enabled, and minimum 4GB RAM for Windows 11 eligibility.
- **Registry/Policy Compliance**: Checks critical Windows Update policies and WSUS-related settings that may block updates.
- **Update Pause States**: Detects if updates are paused via registry keys.
- **Disk Space & Cleanup Needs**: Checks free disk space and flags cleanup needs for Recycle Bin, Temp folders, Windows Update cache, Delivery Optimization cache, Windows Error Reporting, Installer patch cache, Thumbnail cache, and WinSxS component store.
- **Windows Update Component Health**: Verifies critical Windows Update services are running and essential DLLs are present. **Now Windows 11 aware** - gracefully handles legacy DLLs that don't exist on modern Windows 11 builds.
- **Proxy and Winsock Status**: Detects proxy configuration and potential Winsock corruption.
- **Update History**: Retrieves recent Windows Update installation history.

### Remediation

- **Registry/Policy Fixes**: Resets critical registry keys to recommended values and completely removes legacy WSUS settings.
- **Clear Update Pause States**: Removes all update pause flags.
- **Disk Cleanup**: Cleans Recycle Bin, Temp folders, Windows Update cache, Delivery Optimization cache, Windows Error Reporting files, Installer patch cache, Thumbnail cache, and runs DISM component cleanup.
- **Aggressive Cleanup**: Optionally removes Windows.old folder and performs DISM ResetBase cleanup (removes rollback capability).
- **Windows Update Component Repair**: Stops Windows Update services, re-registers essential DLLs **(only if they exist on disk)**, resets Winsock and WinHTTP proxy, and restarts services.
- **Trigger Windows Update Scan**: Initiates Windows Update scan, download, and install process.

---

## Disk Cleanup Details

### These are the recommended cleanup Thresholds based on real-world enterprise Windows device management experience.

| Component | Recommendation | Description | 
|:----|:----|:----|
| Recycle Bin | 2 GB | Users typically accumulate 1-5 GB; 2 GB catches most cases without being too aggressive. Recycle Bin grows quickly with deleted downloads, installers, and documents. |
| Temp Folders (combined) | 500 MB | Temp files rarely need to exceed 500 MB for normal operation. Larger amounts indicate stale files from failed installs or crashed apps. |
| WU Cache | 500 MB | After updates complete, the download cache should be minimal. >500 MB often means stuck/failed updates or orphaned files. |
| DO Cache | 500 MB | Delivery Optimization should manage itself, but can accumulate. 500 MB is reasonable as it's often smaller unless heavily used for peer caching. |
| Win Error Report (WER) | 200 MB | Windows Error reports rarely exceed 200 MB unless there are persistent crash issues. Large WER folders indicate app stability problems worth cleaning. |
| Installer Cache | 500 MB | Patch cache grows over time with cumulative updates. 500 MB is reasonable; larger amounts are often orphaned patches. |
| Thumbnail Cache | 200 MB | Thumbnail DBs rarely exceed 200 MB even with heavy media use. Larger sizes indicate corruption or excessive regeneration. |
| DISM/WinSxS | 8 GB | WinSxS naturally grows to 6-10 GB on healthy systems. 8 GB threshold catches systems that need cleanup without flagging normal systems. On Windows 11, 7-9 GB is typical. |
| Minimum Free Space | 30 GB | Keep at 30 GB - Feature Updates require 20-25 GB working space, plus buffer for extraction and rollback. |


## When disk space is below 30GB (or when running remediation), the script cleans the following locations:

### Standard Cleanup

| Location | Description | Path |
|:----|:----|:----|
| **Recycle Bin** | Deleted files from all drives | `$Recycle.Bin` on all drives |
| **User Temp Folder** | Temporary files older than 1 day | `%TEMP%` |
| **System Temp Folder** | System temporary files older than 1 day | `%SystemRoot%\Temp` |
| **Windows Update Cache** | Downloaded update files | `%SystemRoot%\SoftwareDistribution\Download` |
| **Delivery Optimization Cache** | P2P update delivery cache | `%SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache` |
| **Windows Error Reporting** | Crash dumps and error reports | `%ProgramData%\Microsoft\Windows\WER\ReportArchive`<br>`%ProgramData%\Microsoft\Windows\WER\ReportQueue` |
| **Windows Installer Patches** | Orphaned installer patches | `%SystemRoot%\Installer\$PatchCache$` |
| **Thumbnail Cache** | Explorer thumbnail database files | `%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db` |
| **DISM Component Cleanup** | Superseded Windows components | Runs `DISM /Online /Cleanup-Image /StartComponentCleanup` |



### Aggressive Disk Cleanup

| Location | Description | Path |
|:----|:----|:----|
| **Windows.old** | Previous Windows installation | `%SystemDrive%\Windows.old` |
| **DISM ResetBase** | All superseded components (no rollback) | Runs `DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase` |

>**Warning:** Aggressive cleanup removes the ability to roll back to the previous Windows version and uninstall updates. Use with caution!

---

## Usage

### Only when manually run as Local Admin on a device 

## Parameters

| Parameter | Type | Description |
|:----|:----|:----|
| `-DetectOnly` | Switch | Run in detection-only mode without remediation or making changes |
| `-AggressiveCleanup` | Switch | Enable aggressive disk cleanup including Windows.old (removes rollback capability) |
| `-SkipHardwareCheck` | Switch | Skip Windows 11 hardware eligibility checks |


### Detection Script

```powershell
.\Windows-Updates-Readiness-Detection_v2.5.ps1
```

- Exit code `0` means compliant, `1` means issues detected.
- **Note:** This script does not have parameters - it always runs in detection-only mode.

### Remediation Script

```powershell
.\Windows-Updates-Readiness-Remediation_v2.5.ps1 [-AggressiveCleanup]
```

- Use `-AggressiveCleanup` to remove Windows.old and perform DISM ResetBase cleanup.

### Unified Script

```powershell
.\Windows-Updates-Readiness_v2.5.ps1 [-DetectOnly] [-AggressiveCleanup] [-SkipHardwareCheck]
```

---

## Intune Deployment

### Important Note on Parameters in Intune

**Intune does not support passing parameters to scripts.** When uploading scripts to Intune (either as Platform Scripts or Proactive Remediation), you can only browse and upload the script file itself - you cannot specify parameters like `-DetectOnly`, `-AggressiveCleanup`, or `-SkipHardwareCheck`.

To configure script behavior for Intune deployment, you must **modify the script file before uploading** to set the desired default parameter values.

---

### Proactive Remediation

#### Detection Script
- **Script:** `Windows-Updates-Readiness-Detection_v2.5.ps1`
- **Parameters:** None - this script always runs in detection-only mode
- **Exit Codes:** 
  - `1` = Non-compliant (issues found)
  - `0` = Compliant

#### Remediation Script
- **Script:** `Windows-Updates-Readiness-Remediation_v2.5.ps1`
- **Parameters:** `-AggressiveCleanup` (optional)
- **Configuration for Intune:**  
  Before uploading to Intune, edit the script and set the desired value for the `-AggressiveCleanup` parameter in the param block. Default value in the param block, is set to `$false`

  ```powershell
  param(
      [Parameter(Mandatory=$false)]
      [switch]$AggressiveCleanup = $false  # Set to $true to enable aggressive cleanup
  )
  ```

  Then upload the modified script to Intune.

#### Deployment Steps
1. Go to **Microsoft Intune admin center**
2. Navigate to **Devices** > **Scripts and remediations**
3. Click **Create**
4. Configure:
   - **Name:** Windows Updates Readiness
   - **Script:** Upload `Windows-Updates-Readiness-Detection_v2.5.ps1` and `Windows-Updates-Readiness-Remediation_v2.5.ps1`
   - **Run this script using the logged on credentials:** No
   - **Enforce script signature check:** No
   - **Run script in 64 bit PowerShell Host:** Yes
5. Assign to device groups

---

### Platform Script

- **Script:** `Windows-Updates-Readiness_v2.5.ps1`
- **Parameters:** `-DetectOnly`, `-AggressiveCleanup`, `-SkipHardwareCheck`
- **Configuration for Intune:**  
  Before uploading to Intune, edit the script and set the desired default values in the param block:

  ```powershell
  param(
      [Parameter(Mandatory=$false)]
      [switch]$DetectOnly = $false,        # Set to $true for detection-only mode
      [Parameter(Mandatory=$false)]
      [switch]$AggressiveCleanup = $false,  # Set to $true to enable aggressive cleanup
      [Parameter(Mandatory=$false)]
      [switch]$SkipHardwareCheck = $false   # Set to $true to skip hardware checks
  )
  ```

  Then upload the modified script to Intune.

#### Deployment Steps
1. Go to **Microsoft Intune admin center**
2. Navigate to **Devices** > **Scripts and remediations** > **Platform scripts**
3. Click **+ Add** > **Windows 10 and later**
4. Configure:
   - **Name:** Windows Updates Readiness
   - **Script:** Upload `Windows-Updates-Readiness_v2.5.ps1` (with your configured defaults)
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

### Keys Completely Removed (WSUS Legacy Settings)

The following legacy WSUS registry keys are completely removed to ensure clean migration to Windows Update for Business:

- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUStatusServer`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\TargetGroup`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\TargetGroupEnabled`

> **Note:** These keys are not set to 0 or blank - they are completely deleted from the registry to prevent any residual WSUS configuration from interfering with cloud-based update management.

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
2. **Re-registering DLLs:** 36 Windows Update related DLLs including `wuapi.dll`, `wuaueng.dll`, `wups.dll`, etc. **(Only attempts registration if DLL file exists on disk)**
3. **Resetting Network:** Winsock reset and WinHTTP proxy reset
4. **Restarts Windows Update services:** All stopped services are restarted


---

## Requirements

- **PowerShell:** 5.1 or later
- **OS:** Windows 10 or Windows 11 (including 24H2/25H2)
- **Permissions:** Must run as SYSTEM or Administrator
- **Disk Space:** 30GB+ free recommended for Windows upgrades

---

## Contributing

Contributions and feedback are welcome! Please submit issues or pull requests on GitHub.

---

**Note:** Always test scripts in a non-production environment before deploying widely to production devices.

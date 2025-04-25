# windows_azure_prep.ps1

![Platform: VMware→Azure](https://img.shields.io/badge/Platform-VMware%20%E2%86%92%20Azure-blue)
![PowerShell](https://img.shields.io/badge/Language-PowerShell-informational)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

> A fully idempotent PowerShell script to prepare a **VMware Windows VM** for Azure VHD upload, executing pre- and post-migration tasks.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Parameters](#parameters)
6. [Configuration](#configuration)
7. [Logging & State Tracking](#logging--state-tracking)
8. [Workflow](#workflow)
9. [Important Notes](#important-notes)
10. [Troubleshooting](#troubleshooting)
11. [Author](#author)
12. [License](#license)

---

## 🔍 Overview

`windows_azure_prep.ps1` automates:

- Installation and configuration of **Azure VM Agent**
- Application of **Hyper-V Integration Services** (for Azure)
- Optimization of power settings, time service, and BCD configurations
- Configure TMP and TEMP environment variables to default values
- Configure startup type for mandatory Windows services
- Enabling kernel and user-mode crash dump collection
- Post-migration cleanup: persistent routes, proxy settings, DNS suffix, offline disks, vmware tools
- Update Remote Desktop registry settingd
- Configure firewall rules
- Schedule ChkDsk for next boot on Azure
- Self-removal and reboot after completion

It uses a **state file** (`windows_azure_prep.state`) and logs actions to `windows_azure_prep.log` to guarantee that each phase runs exactly once.

---

## 🔧 Prerequisites

- **VMware** virtual machine configured for migration to **Azure** virtual machine
- Windows Server 2008 or later
- PowerShell 2.x or newer
- Administrative privileges
- Working directory: `C:\vmware-to-azure-vms-prep\azure\windows`

---

## ⚙️ Installation

1. Create the working directory:
   ```powershell
   New-Item -Path 'C:\vmware-to-azure-vms-prep\azure\windows' -ItemType Directory -Force
   ```
2. Copy the following files into that folder:
   - `windows_azure_prep.ps1`
   - `WindowsAzureVmAgent.amd64_*.msi`
   - `windows6.2-hypervintegrationservices-x64.cab`
   - `windows6.x-hypervintegrationservices-x64.cab`

---

## 🚀 Usage

From an elevated PowerShell prompt in the script directory:

```powershell
Set-Location 'C:\vmware-to-azure-vms-prep\azure\windows'
Set-ExecutionPolicy RemoteSigned -Force
.\windows_azure_prep.ps1 -DomainSuffix 'bnet.corp' [-ProxyAddress 'proxy.bnet.corp'] [-ProxyBypassList '*.corp;168.63.129.16']
```

1. **First run**: executes *pre-migration* tasks and creates a Scheduled Task for reboot.
2. **After reboot (only if on Azure)**: the Scheduled Task triggers *post-migration* cleanup automatically.

---

## 📝 Parameters

| Parameter          | Required | Description                                      |
|--------------------|----------|--------------------------------------------------|
| `-DomainSuffix`    | Yes      | DNS search suffix (e.g., `bnet.corp`)           |
| `-ProxyAddress`    | No       | Proxy server address (e.g., `proxy.bnet.corp`)  |
| `-ProxyBypassList` | No       | Addresses to bypass proxy (e.g., `*.corp;168.63.129.16`) |

---

## ⚙️ Configuration

- To change the base directory, edit the `$MainDir` variable at the top of the script.
- Ensure all required assets are present in the new location.

---

## 📑 Logging & State Tracking

- **Log file**: `windows_azure_prep.log` (timestamped entries)
- **State file**: `windows_azure_prep.state`

  ```text
  PRE;POST
  FALSE;FALSE
  ```

  Updated to `TRUE;FALSE` after pre-migration and to `TRUE;TRUE` after post-migration.

---

## 🛠 Workflow

1. **Initialize-StateFile**: creates state file if missing.
2. **Pre-Migration** (on VMware only):
   - Configure Scheduled Task
   - Install Azure VM Agent & Integration Services
   - Run SFC, configure time service, power profile, BCD, environment variable, windows services, crash dumps
   - Mark `PRE=TRUE`
3. **Post-Migration** (after boot on Azure):
   - Remove persistent routes, reset proxy, set DNS suffix
   - Bring offline disks online, configure RDP & firewall
   - Remove VMware tools, execute chkdsk
   - Delete Scheduled Task, remove working directory, reboot
   - Mark `POST=TRUE`

---

## ⚠️ Important Notes

- **Run exclusively on VMware VMs** before conversion to Azure.
  Running on Hyper-V or native Azure VMs may trigger both phases in one session, causing **network loss** or **system instability**.

- **Generalize the VM with Sysprep** if you need a reusable image. Follow Microsoft’s guidelines:
  https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image#determine-when-to-use-sysprep

---

## 🆘 Troubleshooting

- Inspect `windows_azure_prep.log` for detailed error messages.
- Verify that all required files exist in the base directory.
- Check that the Scheduled Task `AzurePrep_PreMigration` is present after the first run.
- Confirm the VM is VMware-based before launching the script.

---

## 👤 Author

**Lorenzo Biosa**
✉️ lorenzo.biosa@yahoo.it

---

## 📜 License

Distributed under the **MIT License**.


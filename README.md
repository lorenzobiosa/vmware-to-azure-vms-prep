# vm-prep

![Platform: VMware→Azure](https://img.shields.io/badge/Platform-VMware%20%E2%86%92%20Azure-blue) ![Version](https://img.shields.io/badge/Version-1.0.0-blue) ![License: MIT](https://img.shields.io/badge/License-MIT-green)

> 🛠️ Automates the preparation of VMware VMs for migration to Azure VMs, saving time for sysadmins.

---

## 🌐 Supported Environments

![Source: VMware](https://img.shields.io/badge/Source-VMware-green) ![Target: Azure](https://img.shields.io/badge/Target-Microsoft%20Azure-0078D4?logo=microsoft-azure&logoColor=white)  
At the moment, the only supported environments for migration are:
- **VMware** as **source** environment
- **Microsoft Azure** as **target** environment

Future support for other cloud providers planned.

---

## 🖥️ Supported Operating Systems

![Windows](https://img.shields.io/badge/Windows-00A4EF?logo=windows&logoColor=white) ![Linux (RHEL)](https://img.shields.io/badge/Linux%20(RHEL)-CC0000?logo=red-hat&logoColor=white)  

Currently supports:

- **Windows** (Server 2008 or later)
- **Linux (RHEL)** (Version 6 or later)

---

## ⚙️ Execution Notes

> These scripts are **non-disruptive** and safe on **live production systems**.  
> Run at **T=0**, before data sync; actual cutover can occur later.  
> Idempotent—even if the VM reboots during/after execution, no adverse effects.

---

## 📚 Documentation References

- ![MS Docs](https://img.shields.io/badge/Microsoft%20Docs-0078D4?logo=microsoft&logoColor=white) [Prepare a Windows VM for Upload to Azure](https://learn.microsoft.com/azure/virtual-machines/windows/prepare-for-upload-vhd-image)  
- ![MS Docs](https://img.shields.io/badge/Microsoft%20Docs-0078D4?logo=microsoft&logoColor=white) [Prepare a Linux (RHEL) VM for Upload to Azure](https://learn.microsoft.com/azure/virtual-machines/linux/redhat-create-upload-vhd)

---

## 🤝 Contribution

![GitHub PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)  
If you'd like to contribute or add support for other environments, feel free to open a pull request!

---

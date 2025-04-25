<# 
.SYNOPSIS
    Prepare a Windows VM for Azure VHD upload with pre- and post-migration steps.

.DESCRIPTION
    - Tracks progress in a state file to ensure idempotency.
    - Configures scheduled task, Azure agent, Hyper-V integration, power settings,
      BCD, and crash dump collection before migration.
    - Cleans up routes, proxy settings, DNS suffix, offline disks, and finally
      removes itself after migration.

.PARAMETER DomainSuffix
    DNS search suffix to configure (e.g. bnet.corp)

.PARAMETER ProxyAddress
    (Optional) Proxy server address to configure

.PARAMETER ProxyBypassList
    (Optional) List of addresses that must bypass proxy server (e.g. '<your list of bypasses>;168.63.129.16')

.EXAMPLE
    .\windows_azure_prep.ps1 -DomainSuffix 'bnet.corp' -ProxyAddress 'proxy.bnet.corp' -ProxyBypassList '*.bnet.corp;168.63.129.16'

.AUTHOR
    Lorenzo Biosa

.EMAIL
    lorenzo.biosa@yahoo.it
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainSuffix,
    [Parameter(Mandatory=$false)]
    [string]$ProxyAddress,
    [string]$ProxyBypassList
)

# Enforce strict mode v2.0 and terminate on errors
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# Paths
$MainDir        = 'C:\vmware-to-azure-vms-prep'
$BaseDir        = Join-Path $MainDir 'windows'
$ScriptFullPath = $MyInvocation.MyCommand.Definition
$StateFilePath  = Join-Path $BaseDir 'windows_azure_prep.state'
$LogFile        = Join-Path $BaseDir 'windows_azure_prep.log'
$MsiFile        = Join-Path $BaseDir 'WindowsAzureVmAgent.amd64_2.7.41491.1117_2403281117.fre.msi'
$Cab2012        = Join-Path $BaseDir 'windows6.2-hypervintegrationservices-x64.cab'
$Cab2008        = Join-Path $BaseDir 'windows6.x-hypervintegrationservices-x64.cab'

function Log-Message {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "$ts - $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

function Initialize-StateFile {
    if (-not (Test-Path $StateFilePath -PathType Leaf)) {
        Log-Message "Creating state file at $StateFilePath"
        "PRE;POST","FALSE;FALSE" | Set-Content -Path $StateFilePath -Encoding UTF8
    }
}

function Get-State {
    $line = Get-Content $StateFilePath | Select-Object -Last 1
    $flags = $line -split ';'
    return ([bool]($flags[0] -eq 'TRUE')), ([bool]($flags[1] -eq 'TRUE'))
}

function Update-State {
    param([Switch]$SetPre, [Switch]$SetPost)
    $csv = Import-Csv -Path $StateFilePath -Delimiter ';'
    foreach ($row in $csv) {
        if ($SetPre)  { $row.PRE  = 'TRUE' }
        if ($SetPost) { $row.POST = 'TRUE' }
    }
    $csv | Export-Csv -Path $StateFilePath -Delimiter ';' -NoTypeInformation
    Log-Message "State file updated"
}

function Configure-ScheduledTask {
    $taskName = 'AzurePrep_PreMigration'
    $cmd = "PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ScriptFullPath`" -DomainSuffix `"$DomainSuffix`""
    schtasks.exe /Create /tn $taskName /tr $cmd /sc ONSTART /ru 'SYSTEM' /rl HIGHEST /f | Out-Null
    Log-Message "Scheduled task '$taskName' created"
}

function Install-AzureAgent {
    Start-Process -FilePath 'msiexec.exe' `
        -ArgumentList "/I `"$MsiFile`" /qn" -Wait
    Log-Message "Azure VM Agent installed"
}

function Install-HyperVIntegration {
    $os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    if ($os -match '2012') {
        $cab = $Cab2012
    } elseif ($os -match '2008') {
        $cab = $Cab2008
    }
    if ($cab) {
        Start-Process -FilePath 'pkgmgr.exe' `
            -ArgumentList "/ip /m:`"$cab`" /quiet /norestart" -Wait
        Log-Message "Hyper-V Integration applied for $os"
    }
}

function Execute-SFC {
    sfc /scannow | Out-Null
    Log-Message "Executed System File Checker"
}

function Enable-Time {
    Set-Service -Name w32time -StartupType Automatic | Out-Null
    Log-Message "Enabled automatic startup for w32time service"
}

function Set-PowerProfile {
    powercfg /setactive SCHEME_MIN  | Out-Null
    powercfg /setacvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 0 | Out-Null
    Log-Message "High performance power profile enabled"
}

function Configure-Temp {
    $cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    Set-ItemProperty -Path $cc -Name TEMP -Type ExpandString -Force -Value "%SystemRoot%\TEMP" | Out-Null
    Set-ItemProperty -Path $cc -Name TMP -Type ExpandString -Force -Value "%SystemRoot%\TEMP" | Out-Null
    Log-Message "Configured TEMP and TMP environmnent variables to default values"
}

function Configure-WindowsServices {
    $autoServices = "BFE", "Dhcp", "Dnscache", "IKEEXT", "iphlpsvc", "nsi", "mpssvc", "RemoteRegistry"
    $manualServices = "Netlogon", "Netman", "TermService"
    foreach ($svc in $autoServices) {
        $service = Get-WmiObject -Class Win32_Service -Filter "Name = '$svc'"
        if ($service.StartMode -ne "Auto") {
            $service.ChangeStartMode("Automatic") | Out-Null
        }
    }
    foreach ($svc in $manualServices) {
        $service = Get-WmiObject -Class Win32_Service -Filter "Name = '$svc'"
        if ($service.StartMode -ne "Manual") {
            $service.ChangeStartMode("Manual") | Out-Null
        }
    }
    Log-Message "Configured Windows services startup type"
}

function Configure-BCD {
    bcdedit /set "{bootmgr}" integrityservices enable | Out-Null
    bcdedit /set "{default}" device partition=C: | Out-Null
    bcdedit /set "{default}" integrityservices enable | Out-Null
    bcdedit /set "{default}" recoveryenabled Off | Out-Null
    bcdedit /set "{default}" osdevice partition=C: | Out-Null
    bcdedit /set "{default}" bootstatuspolicy IgnoreAllFailures | Out-Null
    bcdedit /set "{bootmgr}" displaybootmenu yes | Out-Null
    bcdedit /set "{bootmgr}" timeout 5 | Out-Null
    bcdedit /set "{bootmgr}" bootems yes | Out-Null
    bcdedit /ems "{current}" ON | Out-Null
    bcdedit /emssettings EMSPORT:1 EMSBAUDRATE:115200 | Out-Null
    Log-Message "BCD configured"
}

function Enable-DumpCollection {
    $cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    Set-ItemProperty -Path $cc -Name CrashDumpEnabled -Type DWord -Force -Value 2 | Out-Null
    Set-ItemProperty -Path $cc -Name DumpFile -Type ExpandString -Force -Value '%SystemRoot%\MEMORY.DMP' | Out-Null
    Set-ItemProperty -Path $cc -Name NMICrashDump -Type DWord -Force -Value 1 | Out-Null
    $dumpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
    if (-not (Test-Path $dumpKey)) { New-Item -Path $dumpKey -Name LocalDumps -Force | Out-Null }
    New-ItemProperty -Path $dumpKey -Name DumpFolder -Type ExpandString -Force -Value 'C:\CrashDumps' | Out-Null
    New-ItemProperty -Path $dumpKey -Name CrashCount -Type DWord -Force -Value 10 | Out-Null
    New-ItemProperty -Path $dumpKey -Name DumpType -Type DWord -Force -Value 2 | Out-Null
    Set-Service -Name WerSvc -StartupType Manual  | Out-Null
    Log-Message "Crash dump collection enabled"
}

function Pre-Migration {
    Log-Message "=== Starting pre-migration tasks ==="
    $preDone, $postDone = Get-State
    if (-not $preDone) {
        Configure-ScheduledTask
        Install-AzureAgent
        Install-HyperVIntegration
        Execute-SFC
        Enable-Time
        Set-PowerProfile
        Configure-Temp
        Configure-WindowsServices
        Configure-BCD
        Enable-DumpCollection
        Update-State -SetPre
        Log-Message "Pre-migration completed"
    } else {
        Log-Message "Pre-migration already done"
    }
}

function Remove-PersistentRoutes {
    Get-WmiObject Win32_IP4PersistedRouteTable | Select-Object Destination, Mask, Nexthop, Metric1 | ForEach-Object {ROUTE DELETE $_.Destination} | Out-Null
    Log-Message "Persistent routes removed"
}

function Set-ProxySettings {
    if ($ProxyAddress) {
        netsh winhttp set proxy $proxyAddress $proxyBypassList | Out-Null
        Log-Message "Proxy settings configured"
    }
    else {
        netsh winhttp reset proxy | Out-Null
        Log-Message "Proxy settings reset"
    }
}

function Set-DNSSuffix {
    $adapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    $adapter.SetDNSDomain($DomainSuffix) | Out-Null
    Log-Message "DNS suffix set to $DomainSuffix"
}

function Online-OfflineDisks {
    "san policy=OnlineAll noerr" | diskpart | Out-Null
    Log-Message "Disk SAN policy changed to OnlineAll"

    $offline = "list disk" | diskpart | Where-Object { $_ -match 'Disk.*Offline' } | ForEach-Object {
        if ($_ -match 'Disk (\d+)') {
            $matches[1]
        }
    }
    foreach ($diskIndex in $offline) {
        "select disk $($diskIndex)", "online disk" | diskpart | Out-Null
    }
    Log-Message "Offline disks brought online"
}

function Update-RemoteDesktopRegistrySettings {
    $cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    Set-ItemProperty -Path $cc -Name fDenyTSConnections -Value 0 -Type DWord -Force | Out-Null
    $cc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    Set-ItemProperty -Path $cc -Name fDenyTSConnections -Value 0 -Type DWord -Force 2>$null | Out-Null
    Set-ItemProperty -Path $cc -Name KeepAliveEnable -Value 1  -Type DWord -Force 2>$null | Out-Null
    Set-ItemProperty -Path $cc -Name KeepAliveInterval -Value 1  -Type DWord -Force 2>$null | Out-Null
    Set-ItemProperty -Path $cc -Name fDisableAutoReconnect -Value 0 -Type DWord -Force 2>$null | Out-Null
    $cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp'
    Set-ItemProperty -Path $cc -Name PortNumber -Value 3389 -Type DWord -Force | Out-Null
    Set-ItemProperty -Path $cc -Name LanAdapter -Value 0 -Type DWord -Force | Out-Null
    Set-ItemProperty -Path $cc -Name UserAuthentication -Value 1 -Type DWord -Force | Out-Null
    Set-ItemProperty -Path $cc -Name KeepAliveTimeout -Value 1 -Type DWord -Force | Out-Null
    Set-ItemProperty -Path $cc -Name fInheritReconnectSame -Value 1 -Type DWord -Force | Out-Null
    Set-ItemProperty -Path $cc -Name fReconnectSame -Value 0 -Type DWord -Force | Out-Null
    Set-ItemProperty -Path $cc -Name MaxInstanceCount -Value 2147483647 -Type DWord -Force | Out-Null
    Set-ItemProperty -Path $cc -Name MaxInstanceCount -Value 4294967295 -Type DWord -Force 2>$null | Out-Null
    if ((Get-Item -Path $cc).Property -contains 'SSLCertificateSHA1Hash')
    {
        Remove-ItemProperty -Path $cc -Name SSLCertificateSHA1Hash -Force | Out-Null
    }
    Log-Message "Remote Desktop Registry settings updated"
}

function Configure-FirewallRules {
    netsh advfirewall set allprofiles state on | Out-Null
    winrm quickconfig -q | Out-Null
    netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes | Out-Null
    netsh advfirewall firewall set rule group="FPS-ICMP4-ERQ-In" new enable=yes | Out-Null
    netsh advfirewall firewall add rule name="AzurePlatform" dir=in action=allow remoteip=168.63.129.16 profile=any edge=yes | Out-Null
    netsh advfirewall firewall add rule name="AzurePlarform" dir=out action=allow remoteip=168.63.129.16 profile=any | Out-Null
    Log-Message "Firewall rules configured"
}

function Remove-VMwareTools {
    Get-WmiObject -Class Win32_Product -Filter "Name = 'VMware Tools'" | ForEach-Object { $_.Uninstall() } | Out-Null
    Log-Message "Removed VMware tools"
}

function Execute-ChkDsk {
    "Y" | chkdsk /f | Out-Null
    Log-Message "Scheduled chkdsk for the next-boot"
}

function Post-Migration {
    Log-Message "=== Starting post-migration tasks ==="
    $preDone, $postDone = Get-State
    $manuf = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    if ($manuf -like '*Microsoft Corporation*' -and -not $postDone) {
        Remove-PersistentRoutes
        Set-ProxySettings
        Set-DNSSuffix
        Online-OfflineDisks
        Update-RemoteDesktopRegistrySettings
        Configure-FirewallRules
        Remove-VMwareTools
        Execute-ChkDsk
        Update-State -SetPost
        Log-Message "Post-migration completed"

        # final cleanup
        $task = 'AzurePrep_PreMigration'
        schtasks.exe /Delete /tn $task /f | Out-Null
        cd 'C:\'
        Remove-Item -Path $MainDir -Recurse -Force | Out-Null
        Restart-Computer -Force | Out-Null
    } else {
        Log-Message "Post-migration skipped or already done"
    }
}

# Main
try {
    Initialize-StateFile
    Pre-Migration
    Post-Migration
}
catch {
    Log-Message "ERROR: $_"
    exit 1
}

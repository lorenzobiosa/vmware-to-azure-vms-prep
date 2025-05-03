#!/bin/bash

# =============================================================================
# Script Name: rhel_azure_prep.bash
# Author: Lorenzo Biosa
# Email: lorenzo.biosa@yahoo.it
#
# Description:
#   This script configures a RHEL virtual machine running on Microsoft Azure.
#   It handles the PRE and POST provisioning phases, configuring network,
#   serial console, NTP servers, WAAgent, and other Azure-related optimizations.
#   It uses a state file to track progress between reboots.
#
# Arguments:
#   --ntp <server1> [server2 server3 ...]  : Specify one or more NTP servers to configure
#
# Usage Example:
#   ./rhel_azure_prep.bash --domain example.com --ntp ntp1.example.com ntp2.example.com
#
# Notes: 
#   - The script must be run as root.
#   - It requires a reboot after the PRE phase to complete the POST configuration.
# =============================================================================

set -euo pipefail

# Variables
STATE_FILE="${PWD}/.$(basename "$0").state"
CRON_FILE="/var/spool/cron/root"
SCRIPT_PATH="/root/$(basename "$0")"
SCRIPT_LOG="/root/$(basename "$0").log"
HOSTNAME=$(hostname)
DOMAIN=""
NTP_SERVERS=()


# ----------------------------------------
# Log to File
# ----------------------------------------
log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" >> "$LOGFILE"
}

# ----------------------------------------
# Parse Arguments
# ----------------------------------------
function parse_args() {
    if [ "$#" -eq 0 ]; then
        echo "Error: Missing arguments."
        echo "Usage: $0 --domain <domain> --ntp <ntp_server1> [ntp_server2 ...]"
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)
                shift
                if [[ $# -eq 0 || "$1" =~ ^-- ]]; then
                    echo "Error: Missing domain after --domain."
                    exit 1
                fi
                DOMAIN="$1"
                shift
            ;;
            --ntp)
                shift
                if [[ $# -eq 0 || "$1" =~ ^-- ]]; then
                    echo "Error: Missing ntp server after --ntp."
                    exit 1
                fi
                while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do
                    NTP_SERVERS+=("$1")
                    shift
                done
                ;;
            *)
                echo "Unknown argument: $1"
                echo "Usage: $0 --ntp <ntp_server1> [ntp_server2 ...]"
                exit 1
                ;;
        esac
    done

    if [ "${#NTP_SERVERS[@]}" -eq 0 ]; then
        echo "Error: No NTP servers specified after --ntp."
        exit 1
    fi
}

# ----------------------------------------
# Initialize the state file if it does not exist
# ----------------------------------------
function init_state() {
    if [ ! -f "$STATE_FILE" ]; then
        echo -e "PRE;POST\nFALSE;FALSE" > "$STATE_FILE"
        log INFO "State file $STATE_FILE created with initial values."
    else
        log INFO "State file $STATE_FILE already exists. No action taken."
    fi
}

# ----------------------------------------
# Read the current state (PRE/POST)
# ----------------------------------------
read_state() {
    if [ ! -f "$STATE_FILE" ]; then
        log ERROR "State file $STATE_FILE does not exist."
        exit 1
    fi

    PRE=$(awk -F';' 'NR==2{print $1}' "$STATE_FILE")
    POST=$(awk -F';' 'NR==2{print $2}' "$STATE_FILE")

    if [[ -n "$PRE" && -n "$POST" ]]; then
        log INFO "Successfully read state file $STATE_FILE. PRE=$PRE, POST=$POST."
    else
        log ERROR "Failed to read valid values from state file $STATE_FILE. PRE=$PRE, POST=$POST."
        exit 1
    fi
}

# ----------------------------------------
# Update the state file
# ----------------------------------------
update_state() {
    local phase="$1"
    case "$phase" in
        PRE)
            sed -i "2s/^[^;]*;/TRUE;/" "$STATE_FILE"
            log INFO "State updated: phase PRE set to TRUE in $STATE_FILE."
            ;;
        POST)
            sed -i "2s/;[^;]*$/;TRUE/" "$STATE_FILE"
            log INFO "State updated: phase POST set to TRUE in $STATE_FILE."
            ;;
        *)
            log ERROR "Invalid phase: $phase. Valid values are PRE or POST."
            exit 1
            ;;
    esac
}

# ----------------------------------------
# Get the RHEL version
# ----------------------------------------
get_rhel_version() {
    local version
    local release_file="/etc/redhat-release"

    if [ -f "$release_file" ]; then
        version=$(grep -oP 'release\s+\K[0-9]+' "$release_file")
        if [[ -n "$version" ]]; then
            log INFO "Detected RHEL major version: $version from $release_file"
            echo "$version"
        else
            log ERROR "Failed to parse RHEL version from $release_file."
            exit 1
        fi
    else
        log ERROR "$release_file file not found."
        exit 1
    fi
}

# ----------------------------------------
# Check if the VM is running on Azure
# ----------------------------------------
function is_azure_vm() {
    /usr/sbin/dmidecode -s system-manufacturer | grep -q "Microsoft Corporation"
}

# ----------------------------------------
# Configure script execution at startup via cron @reboot
# ----------------------------------------
function configure_cron() {
    if ! grep -q "@reboot $SCRIPT_PATH" "$CRON_FILE" 2>/dev/null; then
        echo "@reboot $SCRIPT_PATH --domain ${DOMAIN} --ntp ${NTP_SERVERS[*]} >> $SCRIPT_LOG 2>&1" >> "$CRON_FILE"
    fi
}

# ----------------------------------------
# Configure WAAgent
# ----------------------------------------
function configure_waagent() {
    local config_file="/etc/waagent.conf"
    local backup_file="${config_file}.bak"

    if [ ! -f "$config_file" ]; then
        log ERROR "$config_file not found."
        return 1
    fi

    cp "$config_file" "$backup_file"
    log INFO "Backup of $config_file created at $backup_file"

    declare -A settings=(
        ["Provisioning.Agent"]="disabled"
        ["ResourceDisk.EnableSwap"]="n"
        ["Provisioning.DeleteRootPassword"]="n"
        ["Provisioning.RegenerateSshHostKeyPair"]="n"
        ["ResourceDisk.Format"]="n"
    )

    for key in "${!settings[@]}"; do
        value="${settings[$key]}"
        if grep -q "^$key=" "$config_file"; then
            sed -i "s|^$key=.*|$key=$value|" "$config_file"
            log INFO "Updated $key=$value in $config_file"
        else
            echo "$key=$value" >> "$config_file"
            log INFO "Appended $key=$value to $config_file"
        fi
    done
}

# ----------------------------------------
# Configure Cloud-init RHEL 7/8/9
# ----------------------------------------
function configure_cloud_init() {
    local phase="$1"
    local cloud_cfg="/etc/cloud/cloud.cfg"
    local disable_flag="/etc/cloud/cloud-init.disabled"
    local logging_cfg="/etc/cloud/cloud.cfg.d/05_logging.cfg"

    if [ ! -f "$cloud_cfg" ]; then
        log ERROR "$cloud_cfg not found."
        return 1
    fi

    cp "$cloud_cfg" "${cloud_cfg}.bak"
    log INFO "Backup created: ${cloud_cfg}.bak"

    case "$phase" in
        PRE)
            # Enable password auth for SSH if not already set
            if grep -q "ssh_pwauth:" "$cloud_cfg"; then
                sed -i 's/^ssh_pwauth:.*$/ssh_pwauth:   1/' "$cloud_cfg"
                log INFO "Updated ssh_pwauth to 1 in $cloud_cfg"
            else
                echo "ssh_pwauth:   1" >> "$cloud_cfg"
                log INFO "Appended ssh_pwauth: 1 to $cloud_cfg"
            fi

            touch "$disable_flag"
            log INFO "Created flag file: $disable_flag"

            systemctl disable cloud-init.service > /dev/null 2>&1
            log INFO "Disabled cloud-init.service"
            ;;
        POST)
            if [ -f "$disable_flag" ]; then
                rm -f "$disable_flag"
                log INFO "Removed flag file: $disable_flag"
            fi

            systemctl enable cloud-init.service > /dev/null 2>&1
            log INFO "Enabled cloud-init.service"

            if [ ! -f "$logging_cfg" ]; then
                cat > "$logging_cfg" <<EOF
# cloud-init output redirection
output: {all: '| tee -a /var/log/cloud-init-output.log'}
EOF
                log INFO "Created $logging_cfg"
            else
                log INFO "$logging_cfg already exists. Skipping."
            fi
            ;;
        *)
            log ERROR "Invalid argument: $phase. Use PRE or POST."
            return 1
            ;;
    esac
}

# ----------------------------------------
# Add Hyper-V modules on RHEL
# ----------------------------------------
function add_hyperv_drivers() {
    local current_drivers
    local missing_drivers=()

    if ! grep -q '^add_drivers=' "$DRACUT_CONF"; then
        echo 'add_drivers="'${HYPERV_DRIVERS[*]}'"' >> "$DRACUT_CONF"
        log INFO "add_drivers entry not found. Created with: ${HYPERV_DRIVERS[*]}"
    else
        current_drivers=$(grep '^add_drivers=' "$DRACUT_CONF" | sed -E 's/.*"(.*)"/\1/')
        for driver in "${HYPERV_DRIVERS[@]}"; do
            if ! grep -qw "$driver" <<< "$current_drivers"; then
                missing_drivers+=("$driver")
            fi
        done

        if [[ ${#missing_drivers[@]} -gt 0 ]]; then
            local new_drivers="$current_drivers ${missing_drivers[*]}"
            if grep -qE '^[[:space:]]*#?[[:space:]]*add_drivers=' "$DRACUT_CONF"; then
                sed -i -E "s#^[[:space:]]*#?[[:space:]]*add_drivers=\"[^\"]*\"#add_drivers=\"${new_drivers}\"#" "$DRACUT_CONF"
                log INFO "Updated existing add_drivers entry in $DRACUT_CONF."
            else
                echo "add_drivers=\"${new_drivers}\"" >> "$DRACUT_CONF"
                log INFO "Created new add_drivers entry in $DRACUT_CONF."
            fi
        else
            log INFO "All required Hyper-V drivers are already present. No changes made."
        fi
    fi

    dracut -f -v > /dev/null 2>&1
    log INFO "Initramfs regenerated successfully."
}

# ----------------------------------------
# Configure serial console on RHEL 6
# ----------------------------------------
function configure_serial_console_rhel6() {
    local grub_files=(/boot/grub/menu.lst /etc/grub.conf /boot/grub/grub.conf)
    local kernel_opts_remove=("rhgb" "quiet" "crashkernel=auto")
    local serial_opts="console=ttyS0 earlyprintk=ttyS0"

    for grub_file in "${grub_files[@]}"; do
        if [ -f "$grub_file" ]; then
            cp "$grub_file" "${grub_file}.bak"
            log INFO "Backup created: ${grub_file}.bak"

            for opt in "${kernel_opts_remove[@]}"; do
                sed -i "s/\b${opt}\b//g" "$grub_file"
            done

            if ! grep -q "$serial_opts" "$grub_file"; then
                sed -i "/^[^#]*kernel/s/$/ ${serial_opts}/" "$grub_file"
                log INFO "Appended '$serial_opts' to kernel line in $grub_file"
            else
                log INFO "'$serial_opts' already present in $grub_file"
            fi
        else
            log INFO "GRUB file not found: $grub_file. Skipping."
        fi
    done
}

# ----------------------------------------
# Configure serial console on RHEL 7/8/9
# ----------------------------------------
function configure_serial_console_rhel7_8_9() {
    local grub_file="/etc/default/grub"
    local backup_file="${grub_file}.bak"

    if [ ! -f "$grub_file" ]; then
        log ERROR "$grub_file not found."
        return 1
    fi

    cp "$grub_file" "$backup_file"
    log INFO "Backup of $grub_file created at $backup_file"

    # Sanitize GRUB_CMDLINE_LINUX
    sed -i \
        -e '/^GRUB_CMDLINE_LINUX=/ s/\brhgb\b//g' \
        -e '/^GRUB_CMDLINE_LINUX=/ s/\bquiet\b//g' \
        -e '/^GRUB_CMDLINE_LINUX=/ s/\bcrashkernel=auto\b//g' "$grub_file"

    # Ensure required serial console params are present
    if ! grep -q 'console=ttyS0' "$grub_file"; then
        sed -i '/^GRUB_CMDLINE_LINUX=/ s/"$/ console=tty1 console=ttyS0,115200n8 earlyprintk=ttyS0,115200 earlyprintk=ttyS0"/' "$grub_file"
        log INFO "Added serial console parameters to GRUB_CMDLINE_LINUX"
    else
        log INFO "Serial console parameters already present in GRUB_CMDLINE_LINUX"
    fi

    # Add GRUB_TERMINAL_OUTPUT if missing
    if ! grep -q '^GRUB_TERMINAL_OUTPUT="console serial"' "$grub_file"; then
        echo 'GRUB_TERMINAL_OUTPUT="console serial"' >> "$grub_file"
        log INFO 'Added GRUB_TERMINAL_OUTPUT="console serial" to grub config'
    fi

    # Add GRUB_SERIAL_COMMAND if missing
    if ! grep -q '^GRUB_SERIAL_COMMAND=' "$grub_file"; then
        echo 'GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"' >> "$grub_file"
        log INFO "Added GRUB_SERIAL_COMMAND for serial console"
    fi

    # Update GRUB configuration
    grub2-mkconfig -o /boot/grub2/grub.cfg > /dev/null 2>&1 && \
        log INFO "Updated GRUB config at /boot/grub2/grub.cfg"

    if [ -d /boot/efi/EFI/redhat ]; then
        grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg > /dev/null 2>&1 && \
            log INFO "Updated GRUB config at /boot/efi/EFI/redhat/grub.cfg"
    fi
}

# ----------------------------------------
# Configure network on RHEL 6
# ----------------------------------------
function configure_network_rhel6() {
    local iface="eth0"
    local ifcfg="/etc/sysconfig/network-scripts/ifcfg-${iface}"
    local network_file="/etc/sysconfig/network"
    local udev_persist="/etc/udev/rules.d/75-persistent-net-generator.rules"
    local dhclient_conf="/etc/dhclient-${iface}.conf"

    # Remove NetworkManager if installed (non-interactively)
    if rpm -q NetworkManager > /dev/null 2>&1; then
        rpm -e --nodeps NetworkManager && log INFO "Removed NetworkManager"
    else
        log INFO "NetworkManager is not installed"
    fi

    # Configure basic network file with hostname
    if [ ! -f "$network_file" ] || ! grep -q "NETWORKING=yes" "$network_file"; then
        echo -e "NETWORKING=yes\nHOSTNAME=$HOSTNAME" > "$network_file"
        log INFO "Configured basic networking in $network_file"
    fi

    # Recreate the interface configuration for eth0
    rm -f /etc/sysconfig/network-scripts/ifcfg-eth* 2>/dev/null
    cat > "$ifcfg" <<EOF
DEVICE=${iface}
BOOTPROTO=dhcp
ONBOOT=yes
TYPE=Ethernet
USERCTL=no
PEERDNS=yes
IPV6INIT=no
EOF
    log INFO "Created network interface configuration: $ifcfg"

    # Disable persistent network interface name generation
    ln -sf /dev/null "$udev_persist"
    log INFO "Linked $udev_persist to /dev/null to disable name persistence"

    # Remove existing persistent network naming rules if present
    rm -f /etc/udev/rules.d/70-persistent-net.rules
    log INFO "Removed existing persistent network rule: 70-persistent-net.rules"

    # Add rule to prevent NetworkManager from managing SR-IOV interfaces
    local sriov_rule="/etc/udev/rules.d/68-azure-sriov-nm-unmanaged.rules"
    cat > "$sriov_rule" <<EOF
SUBSYSTEM=="net", DRIVERS=="hv_pci", ACTION=="add", ENV{NM_UNMANAGED}="1"
EOF
    log INFO "Created Azure SR-IOV unmanaged rule: $sriov_rule"

    # Remove legacy DHCP client configurations
    rm -rf /etc/dhclient-eth*.conf /etc/dhclient-ens*.conf
    log INFO "Removed legacy dhclient configuration files"

    # Create dhclient configuration for custom domain
    echo "supersede domain-name \"${DOMAIN}\";" > "$dhclient_conf"
    log INFO "Created new dhclient config: $dhclient_conf"

    # Enable legacy network service
    chkconfig network on
    log INFO "Enabled legacy 'network' service on boot"
}

# ----------------------------------------
# Configure network on RHEL 7/8
# ----------------------------------------
function configure_network_rhel7_8_9() {
    local iface="eth0"
    local ifcfg="/etc/sysconfig/network-scripts/ifcfg-${iface}"
    local network_file="/etc/sysconfig/network"
    local dhclient_conf="/etc/dhclient-${iface}.conf"

    # Create basic network configuration
    if [ ! -f "$network_file" ] || ! grep -q "NETWORKING=yes" "$network_file"; then
        echo -e "NETWORKING=yes\nHOSTNAME=$HOSTNAME" > "$network_file"
        log INFO "Configured basic networking in $network_file"
    else
        log INFO "$network_file already contains NETWORKING configuration"
    fi

    # Remove old interface configs to avoid conflicts
    rm -f /etc/sysconfig/network-scripts/ifcfg-eth* /etc/sysconfig/network-scripts/ifcfg-ens* 2>/dev/null
    log INFO "Removed existing eth*/ens* ifcfg files"

    # Create interface config for eth0
    cat > "$ifcfg" <<EOF
DEVICE=${iface}
BOOTPROTO=dhcp
ONBOOT=yes
TYPE=Ethernet
USERCTL=no
PEERDNS=yes
IPV6INIT=no
PERSISTENT_DHCLIENT=yes
NM_CONTROLLED=yes
EOF
    log INFO "Created interface configuration at $ifcfg"

    # Remove old dhclient configurations
    rm -rf /etc/dhclient-eth*.conf /etc/dhclient-ens*.conf 2>/dev/null
    log INFO "Removed old dhclient configuration files"

    # Create dhclient config with custom domain
    echo "supersede domain-name \"${DOMAIN}\";" > "$dhclient_conf"
    log INFO "Created dhclient config for $iface at $dhclient_conf"

    # Enable legacy network service
    if systemctl is-enabled network &>/dev/null; then
        log INFO "'network' service already enabled"
    else
        systemctl enable network && log INFO "Enabled 'network' service"
    fi
}

# -------------------------------------------
# Disable Systemd interface names RHEL 7/8/9
# -------------------------------------------
disable_ifnames() {
    local grub_file="/etc/default/grub"
    local option="net.ifnames=0"
    local grub_cmdline_key="GRUB_CMDLINE_LINUX"

    if [ ! -f "$grub_file" ]; then
        log ERROR "$grub_file not found."
        return 1
    fi

    if grep -qE "\b${option}\b" "$grub_file"; then
        log INFO "'$option' already present in $grub_file. Skipping update."
    else
        cp "$grub_file" "${grub_file}.bak"
        log INFO "Backup created: ${grub_file}.bak"

        sed -i "/^${grub_cmdline_key}=/s/\"\(.*\)\"/\"\1 ${option}\"/" "$grub_file"
        log INFO "Appended '$option' to $grub_cmdline_key in $grub_file."
    fi

    if [ -d /boot/grub2 ]; then
        grub2-mkconfig -o /boot/grub2/grub.cfg > /dev/null 2>&1
        log INFO "grub.cfg updated at /boot/grub2/grub.cfg"
    fi

    if [ -f /boot/efi/EFI/redhat/grub.cfg ]; then
        grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg > /dev/null 2>&1
        log INFO "grub.cfg updated at /boot/efi/EFI/redhat/grub.cfg"
    fi
}

# ----------------------------------------
# Configure NTP for RHEL 6
# ----------------------------------------
function configure_ntp_rhel6() {
    local ntp_conf="/etc/ntp.conf"
    local drift_dir="/var/lib/ntp"
    local crypto_pw="/etc/ntp/crypto/pw"
    local ntp_keys="/etc/ntp/keys"

    # Backup current config if exists
    if [ -f "$ntp_conf" ]; then
        cp "$ntp_conf" "${ntp_conf}.bak"
        log INFO "Backed up existing $ntp_conf to ${ntp_conf}.bak"
    fi

    # Write new minimal configuration
    cat > "$ntp_conf" <<EOF
driftfile $drift_dir/drift
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict -6 ::1
includefile $crypto_pw
keys $ntp_keys
EOF
    log INFO "Created new base NTP configuration at $ntp_conf"

    # Add NTP servers from array
    if [ "${#NTP_SERVERS[@]}" -gt 0 ]; then
        for server in "${NTP_SERVERS[@]}"; do
            echo "server $server" >> "$ntp_conf"
            log INFO "Added NTP server: $server"
        done
    else
        log WARN "No NTP servers defined in NTP_SERVERS array"
    fi
}

# ----------------------------------------
# Configure NTP for RHEL 7/8
# ----------------------------------------
function configure_ntp_rhel7_8() {
    echo > /etc/chrony.conf
    for server in "${NTP_SERVERS[@]}"; do
        echo "server $server iburst" >> /etc/chrony.conf
    done
    cat <<EOF >> /etc/chrony.conf
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF
}

# ----------------------------------------
# Configure NTP for RHEL 9
# ----------------------------------------
function configure_ntp_rhel9() {
    echo > /etc/chrony.conf
    for server in "${NTP_SERVERS[@]}"; do
        echo "server $server iburst" >> /etc/chrony.conf
    done
    cat <<EOF >> /etc/chrony.conf
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
keyfile /etc/chrony.keys
ntsdumpdir /var/lib/chrony
leapsectz right/UTC
logdir /var/log/chrony
EOF
}

# ----------------------------------------
# Final cleanup and reboot
# ----------------------------------------
function final_cleanup_and_reboot() {
    sed -i "/$SCRIPT_PATH/d" "$CRON_FILE"
    rm -f "$SCRIPT_PATH" "$SCRIPT_LOG" "$STATE_FILE"
    reboot
}

# ========================================
# MAIN
# ========================================

parse_args "$@"
init_state
read_state
RHEL_VERSION=$(get_rhel_version)

case "$RHEL_VERSION" in
    6)
        if [ "$PRE" == "FALSE" ]; then
            configure_cron
            subscription-manager repos --enable=rhel-6-server-extras-rpms || true
            yum install -y WALinuxAgent
            configure_waagent
            chkconfig waagent on && service waagent start
            add_hyperv_drivers
            configure_serial_console_rhel6
            update_state PRE
        fi
        if [ "$POST" == "FALSE" ]; then
            if is_azure_vm; then
                configure_network_rhel6
                configure_ntp_rhel6
                update_state POST
                if grep -q "TRUE;TRUE" "$STATE_FILE"; then
                    final_cleanup_and_reboot
                fi
            else
                echo "The machine is not running on Azure. Exiting."
                exit 1
            fi
        fi
        ;;
    7|8)
        if [ "$PRE" == "FALSE" ]; then
            configure_cron
            subscription-manager repos --enable="rhel-${RHEL_VERSION}-server-extras-rpms" || true
            yum install -y WALinuxAgent cloud-init cloud-utils-growpart gdisk hyperv-daemons dhcp-client
            configure_cloud-init PRE
            configure_waagent
            systemctl enable --now waagent
            add_hyperv_drivers
            configure_serial_console_rhel7_8_9
            update_state PRE
        fi
        if [ "$POST" == "FALSE" ]; then
            if is_azure_vm; then
                disable_ifnames
                configure_cloud-init POST
                configure_network_rhel7_8_9
                configure_ntp_rhel7_8
                update_state POST
                if grep -q "TRUE;TRUE" "$STATE_FILE"; then
                    final_cleanup_and_reboot
                fi
            else
                echo "The machine is not running on Azure. Exiting."
                exit 1
            fi
        fi
        ;;
    9)
        if [ "$PRE" == "FALSE" ]; then
            configure_cron
            subscription-manager repos --enable="rhel-${RHEL_VERSION}-server-extras-rpms" || true
            yum install -y WALinuxAgent cloud-init cloud-utils-growpart gdisk hyperv-daemons dhcp-client
            configure_cloud-init PRE
            configure_waagent
            systemctl enable --now waagent
            add_hyperv_drivers
            configure_serial_console_rhel7_8_9
            update_state PRE
        fi
        if [ "$POST" == "FALSE" ]; then
            if is_azure_vm; then
                disable_ifnames
                configure_cloud-init POST
                configure_network_rhel7_8_9
                configure_ntp_rhel9
                update_state POST
                if grep -q "TRUE;TRUE" "$STATE_FILE"; then
                    final_cleanup_and_reboot
                fi
            else
                echo "The machine is not running on Azure. Exiting."
                exit 1
            fi
        fi
        ;;
    *)
        echo "Unsupported RHEL version: $RHEL_VERSION"
        exit 1
        ;;
esac

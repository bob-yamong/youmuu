#!/bin/bash

# Function to check kernel version
check_kernel_version() {
    local required_major=5
    local required_minor=7
    local current_version
    current_version=$(uname -r | awk -F. '{ printf("%d.%d", $1, $2) }')

    # Extract major and minor version numbers
    local current_major
    local current_minor
    current_major=$(echo "$current_version" | awk -F. '{print $1}')
    current_minor=$(echo "$current_version" | awk -F. '{print $2}')

    if [[ "$current_major" -gt "$required_major" ]] || \
       [[ "$current_major" -eq "$required_major" && "$current_minor" -ge "$required_minor" ]]; then
        echo "Kernel version is $current_version (>= $required_major.$required_minor). Proceeding..."
    else
        echo "Kernel version is $current_version (< $required_major.$required_minor). BPF LSM requires kernel 5.7 or higher."
        exit 1
    fi
}

# Function to check if BPF LSM is enabled in the kernel config
check_bpf_lsm_config() {
    local config
    config=$(cat /boot/config-"$(uname -r)" | grep BPF_LSM)

    if [[ "$config" == "CONFIG_BPF_LSM=y" ]]; then
        echo "BPF LSM is supported in the kernel configuration."
    else
        echo "BPF LSM is not supported in the kernel configuration. Exiting."
        exit 1
    fi
}

# Function to check if BPF LSM is active in the LSM list
check_bpf_lsm_active() {
    local lsm_list
    lsm_list=$(cat /sys/kernel/security/lsm)

    if [[ "$lsm_list" == *"bpf"* ]]; then
        echo "BPF LSM is already active in the LSM list."
        exit 0
    else
        echo "BPF LSM is not active. Proceeding to update GRUB configuration..."
    fi
}

# Function to update GRUB configuration
update_grub_config() {
    local grub_file="/etc/default/grub"
    local grub_cmdline
    grub_cmdline=$(grep "GRUB_CMDLINE_LINUX=" "$grub_file")

    if [[ "$grub_cmdline" == *"bpf"* ]]; then
        echo "BPF is already in the GRUB command line. No changes needed."
    else
        echo "Adding BPF to the GRUB command line..."
        sudo sed -i 's/GRUB_CMDLINE_LINUX="/&lsm=ndlock,lockdown,yama,integrity,apparmor,bpf /' "$grub_file"
        echo "GRUB configuration updated."
    fi

    # Update GRUB
    if command -v update-grub2 &> /dev/null; then
        sudo update-grub2
    elif command -v update-grub &> /dev/null; then
        sudo update-grub
    else
        echo "Could not find update-grub2 or update-grub command. Please update GRUB manually."
        exit 1
    fi
}

# Main script execution
check_kernel_version
check_bpf_lsm_config
check_bpf_lsm_active
update_grub_config

echo "GRUB configuration has been updated. Please restart your system to apply the changes."

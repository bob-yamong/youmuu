# **Youmuu's Ghostblade**

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

Welcome to the **`Youmuu's Ghostblade`**! This project is an eBPF based container runtime engine.

## **How to use**

### **1. Clone your new repository**

Clone your newly created repository to your local machine:

```sh
git clone https://github.com/bob-yamong/youmuu.git --recursive
```

Or after clone the repo, you can update the git submodule with following commands:

```sh
git submodule update --init --recursive
```

### **2. Install dependencies**

For dependencies, it varies from distribution to distribution. You can refer to shell.nix and dockerfile for installation.

On Ubuntu, you may run `make install` or

```sh
sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm
```

to install dependencies.

### **3. Activate BPF LSM Availability**

First, please confirm that your kernel version is higher than 5.7. Next, you can use the following command to check if BPF LSM support is enabled:
```sh
$ cat /boot/config-$(uname -r) | grep BPF_LSM
CONFIG_BPF_LSM=y
```

If the output contains CONFIG_BPF_LSM=y, BPF LSM is supported. Provided that the above conditions are met, you can use the following command to check if the output includes the bpf option:
```sh
$ cat /sys/kernel/security/lsm
ndlock,lockdown,yama,integrity,apparmor
```

If the output does not include the bpf option (as in the example above), you can modify /etc/default/grub:
```sh
GRUB_CMDLINE_LINUX="lsm=ndlock,lockdown,yama,integrity,apparmor,bpf"
```

Then, update the grub configuration using the `update-grub2` command (the corresponding command may vary depending on the system), and restart the system.

### **4. Build the project**

To build the project, run the following command:

```sh
make build
```

### **5. Run the Project**

You can run the binary with:

```console
sudo src/youmuu
```

### **Additional**
You can print the kernel space log created by `bpf_printk` following command.
```sh
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## **License**

This project is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.

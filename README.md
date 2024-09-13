# **Youmuu's Ghostblade**

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

Welcome to the **`Youmuu's Ghostblade`**! This project is an eBF based container runtime engine.

## **How to use**

### **2. Clone your new repository**

Clone your newly created repository to your local machine:

```sh
git clone https://github.com/bob-yamong/youmuu.git --recursive
```

Or after clone the repo, you can update the git submodule with following commands:

```sh
git submodule update --init --recursive
```

### **3. Install dependencies**

For dependencies, it varies from distribution to distribution. You can refer to shell.nix and dockerfile for installation.

On Ubuntu, you may run `make install` or

```sh
sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm
```

to install dependencies.

### **4. Build the project**

To build the project, run the following command:

```sh
make build
```

### ***Run the Project***

You can run the binary with:

```console
sudo src/youmuu
```

## **License**

This project is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.

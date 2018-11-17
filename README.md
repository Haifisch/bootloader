## Building

### 1) Grab the sources
The root repository is [bootloader](https://github.com/Haifisch/bootloader), which has scripts for building the bootloader tree along with configuring and building qemu.

#### Primary Repository 
```bash
	git clone https://github.com/Haifisch/bootloader.git
	git submodule update --init --recursive
```

### 2) Building
If all is well with git, simply run the following to build all sources. 
```bash
make all
```

#### 2.a.) QEMU
```bash
make qemu
```

#### 2.b.) bootloader
```bash
make bootloader
```
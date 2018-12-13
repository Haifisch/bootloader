## Signing 
Much TODO but...

```bash
python easy_sign.py --generate // generate signing keys
python easy_sign.py --sign Enclave-Bootloader/STM32F1/build/enclave_stage1.bin // sign firmware image, outputs os.ticket file
python easy_sign.py --stitch Enclave-Bootloader/STM32F1/build/enclave_stage1.bin --ticket os.ticket // stitch the ticket to the firmware
```

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
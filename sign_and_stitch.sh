#!/bin/bash

echo "Signing..."
dfuimagemaker/imagemaker -f Enclave-Bootloader/EnclaveOS/main.bin -t EDOS -o "signed_image.dfu"
echo "Stitching..."
python generate_dfu_firmware.py Enclave-Bootloader/STM32F1/build/enclave_stage1.bin signed_image.dfu qemu_image.bin
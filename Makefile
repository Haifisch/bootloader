QEMU_CONFIGURATION_FLAGS ?= --extra-cflags=-DDEBUG_STM32_UART --extra-cflags=-DSTM32_UART_NO_BAUD_DELAY --extra-cflags=-DSTM32_UART_ENABLE_OVERRUN

# cleaning
clean-qemu:
	@echo "cleaning qemu"
	@cd qemu; make clean

clean-bootloader:
	@echo "cleaning bootloader"

# building
qemu: clean-qemu
	@echo "configuring qemu..."
	@cd qemu; ./configure --enable-debug --target-list="arm-softmmu" $(QEMU_CONFIGURATION_FLAGS)
	@echo "building qemu..."
	@cd qemu; make 
	@echo "qemu built!"

bootloader: clean-bootloader
	@echo "building bootloader..."
	@cd Enclave-Bootloader; make build-all-bl QEMU_BUILD=1
	@echo "bootloader built!"

bl-run:
	@echo "running bootloader in qemu..."
	@cd Enclave-Bootloader; make run-bl

bootloader-all: bootloader bl-run
qemu-all: qemu
all: qemu-all bootloader-all 
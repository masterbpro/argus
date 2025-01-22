UNAME_R := $(shell uname -r)
LINUX_HEADERS := /usr/src/linux-headers-$(UNAME_R)
LINUX_HWE_HEADERS := /usr/src/linux-hwe-5.15-headers-5.15.0-130
INCLUDE_DIR := /usr/include

.PHONY: all install_packages install_headers clean

all: install_packages install_headers

install_packages:
	@echo "Installing required packages..."
	apt-get update
	apt-get install -y \
	    clang \
	    llvm \
	    libbpf-dev \
	    linux-headers-$(UNAME_R) \
	    linux-tools-$(UNAME_R) \
	    linux-libc-dev \
	    libc6-dev:i386 \
	    gcc-multilib

install_headers:
	@echo "Setting up header and library links..."
	mkdir -p $(INCLUDE_DIR)/uapi/asm-generic
	mkdir -p $(INCLUDE_DIR)/asm

	# Create symlinks for required headers
	ln -sf $(LINUX_HEADERS)/include/uapi/asm/types.h $(INCLUDE_DIR)/asm/types.h
	ln -sf $(LINUX_HEADERS)/include/asm-generic/bitsperlong.h $(INCLUDE_DIR)/asm/bitsperlong.h
	ln -sf $(LINUX_HWE_HEADERS)/include/uapi/asm-generic/bitsperlong.h $(INCLUDE_DIR)/uapi/asm-generic/bitsperlong.h
	ln -sf $(LINUX_HWE_HEADERS)/arch/x86/include/uapi/asm/posix_types.h $(INCLUDE_DIR)/asm/posix_types.h
	ln -sf $(LINUX_HWE_HEADERS)/arch/x86/include/uapi/asm/posix_types_64.h $(INCLUDE_DIR)/asm/posix_types_64.h
	ln -sf $(LINUX_HEADERS)/include/uapi/asm/byteorder.h $(INCLUDE_DIR)/asm/byteorder.h
	ln -sf $(LINUX_HWE_HEADERS)/arch/x86/include/uapi/asm/byteorder.h $(INCLUDE_DIR)/asm/byteorder.h
	ln -sf $(LINUX_HWE_HEADERS)/arch/x86/include/uapi/asm/swab.h $(INCLUDE_DIR)/asm/swab.h
	ln -sf $(LINUX_HEADERS)/include/linux/compiler.h $(INCLUDE_DIR)/linux/compiler.h
	ln -sf $(LINUX_HEADERS)/include/linux/compiler_types.h $(INCLUDE_DIR)/linux/compiler_types.h
	ln -sf $(LINUX_HEADERS)/arch/x86/include/generated/asm/rwonce.h $(INCLUDE_DIR)/asm/rwonce.h
	ln -sf $(LINUX_HWE_HEADERS)/include/linux/kasan-checks.h $(INCLUDE_DIR)/linux/kasan-checks.h
	ln -sf $(LINUX_HWE_HEADERS)/include/linux/compiler_attributes.h $(INCLUDE_DIR)/linux/compiler_attributes.h

clean:
	@echo "Cleaning up..."
	rm -rf $(INCLUDE_DIR)/uapi/asm-generic
	rm -rf $(INCLUDE_DIR)/asm
	rm -f $(INCLUDE_DIR)/asm/types.h
	rm -f $(INCLUDE_DIR)/asm/bitsperlong.h
	rm -f $(INCLUDE_DIR)/uapi/asm-generic/bitsperlong.h
	rm -f $(INCLUDE_DIR)/asm/posix_types.h
	rm -f $(INCLUDE_DIR)/asm/posix_types_64.h
	rm -f $(INCLUDE_DIR)/asm/byteorder.h
	rm -f $(INCLUDE_DIR)/asm/swab.h
	rm -f $(INCLUDE_DIR)/linux/compiler.h
	rm -f $(INCLUDE_DIR)/linux/compiler_types.h
	rm -f $(INCLUDE_DIR)/asm/rwonce.h
	rm -f $(INCLUDE_DIR)/linux/kasan-checks.h
	rm -f $(INCLUDE_DIR)/linux/compiler_attributes.h


build:
	# bug
	ln -sf /usr/src/linux-headers-5.15.0-130-generic/arch/x86/include/generated/uapi/asm/types.h /usr/include/asm/types.h

	mkdir -p argus/bin/$(shell uname -m)/$(shell uname -r)
	clang -O2 -g -target bpf -c argus/src/ddos.bpf.c -o argus/target/$(shell uname -m)/$(shell uname -r)/ddos.bpf.o
	gcc argus/main.c -o argus/main -lbpf

upload:
	argus/main argus/target/$(shell uname -m)/$(shell uname -r)/ddos.bpf.o enp0s8

list:
	bpftool prog show
	bpftool map show

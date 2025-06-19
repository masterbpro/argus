UNAME_R        := $(shell uname -r)
UNAME_M        := $(shell uname -m)
KERNEL_BUILD   := /lib/modules/$(UNAME_R)/build
INCLUDE_DIR    := /usr/include
IFACE          ?= $(shell ip route get 8.8.8.8 | awk '{print $$5; exit}')

.PHONY: all install_packages build upload list

all: install_packages

install_packages:
	@echo "Installing required packages..."
	dpkg --add-architecture i386 || true
	apt-get update
	apt-get install -y \
	    clang \
	    llvm \
	    libbpf-dev \
	    linux-libc-dev \
	    libc6-dev:i386 \
	    gcc-multilib \
	    bpftool

build:
	@echo "Building eBPF program..."
	mkdir -p argus/bin
	clang -O2 -g -target bpf -c argus/src/ddos.bpf.c -o argus/bin/ddos.bpf.o
	gcc argus/main.c -o argus/main -lbpf

upload:
	@echo "Uploading eBPF program to interface '$(IFACE)'..."
	argus/main argus/bin/ddos.bpf.o $(IFACE) xdp

list:
	@echo "Listing BPF objects/maps..."
	bpftool prog show
	bpftool map show

uninstall:
	@echo "Detaching XDP program from '$(IFACE)'..."
	@LINK_ID=$$(bpftool link show | grep '/sys/fs/bpf/ddos_link' | cut -d: -f1); \
	if [ -n "$$LINK_ID" ]; then \
		bpftool link detach id $$LINK_ID; \
	else \
		echo "No active XDP link found."; \
	fi
	@echo "Removing pinned link..."
	@rm -f /sys/fs/bpf/ddos_link

GCC = gcc
CC = $(GCC)
CXX = clang++
CLANG = clang

BIN = bin
SRC = src
INC = include
MODULE = $(SRC)/module
EBPF = $(SRC)/ebpf

VMLINUX_H = $(INC)/vmlinux.h

MODULE_NAME := rnet
KDIR := /lib/modules/$(shell uname -r)/build
obj-m := $(MODULE_NAME).o
# Include headers for kernel_module compilation
ccflags-y := -I$(PWD)/$(INC)

all: $(VMLINUX_H) kernel_ebpf user kernel_module

kernel_module: $(BIN)
	cp Makefile ./$(MODULE)
	$(MAKE) -C $(KDIR) M=$(PWD)/$(MODULE) modules
	# Copy .ko file
	mv $(PWD)/$(MODULE)/$(MODULE_NAME).ko $(PWD)/$(BIN)
	# Clean after compilation
	make -C $(KDIR) M=$(PWD)/$(MODULE) clean
	rm ./$(MODULE)/Makefile

kernel_ebpf: $(BIN)
	$(CLANG) -I$(INC) -O2 -g -target bpf -c $(EBPF)/rootkit.c -o $(BIN)/rootkit.bpf.o
	sudo bpftool gen skeleton $(BIN)/rootkit.bpf.o > $(INC)/rootkit.skel.h

user: $(BIN)
	$(CXX) -I$(INC) -lbpf $(SRC)/main.cpp -o $(BIN)/main

$(VMLINUX_H):
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -rf $(BIN)/*

$(BIN):
	mkdir -p $@

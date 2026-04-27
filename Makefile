GCC = gcc
CC = $(GCC)
CXX = clang++
CLANG = clang
# STD_FLAGS = -Wall -Wextra
CXX_FLAGS = -std=c++20 $(STD_FLAGS)

BIN = bin
SRC = src
INC = include
MODULE = $(SRC)/module
EBPF = $(SRC)/ebpf

# User space code consts
USER_NAMESPACE = rootkit
MAIN_BIN = $(BIN)/main

# Sources
MAIN_SRC = $(SRC)/main.cpp
USER_NAMESPACE_SRCS = $(wildcard $(SRC)/$(USER_NAMESPACE)/*.cpp)
# Object files (only main and namespace sources)
OBJS := $(patsubst $(SRC)/%.cpp,$(BIN)/%.o,$(MAIN_SRC) $(USER_NAMESPACE_SRCS))
# Ensure build subdirs exist
$(shell mkdir -p $(BIN) $(BIN)/$(USER_NAMESPACE) 2>/dev/null || true)

# Ebpf and kernel module consts
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

# user: $(BIN)
	# $(CXX) -I$(INC) -lbpf $(SRC)/main.cpp -o $(BIN)/main
user: $(BIN) $(MAIN_BIN)

# Link
$(MAIN_BIN): $(OBJS)
	@echo "Linking"
	$(CXX) -I$(INC) $(CXX_FLAGS) -lbpf -o $@ $^

# Compile rule for objects under build/ (preserve namespace path)
$(BIN)/%.o: $(SRC)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) -I$(INC) $(CXX_FLAGS) -c $< -o $@

$(VMLINUX_H):
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -rf $(BIN)/*

$(BIN):
	mkdir -p $@

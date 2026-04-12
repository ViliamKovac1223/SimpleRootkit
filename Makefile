CC = clang
CXX = clang++
BIN_FOLDER = bin
SRC_FOLDER = src

VMLINUX_H = $(SRC_FOLDER)/vmlinux.h

all: $(VMLINUX_H) kernel user

kernel: $(BIN_FOLDER)
	$(CC) -O2 -g -target bpf -c $(SRC_FOLDER)/rootkit.c -o $(BIN_FOLDER)/rootkit.bpf.o
	sudo bpftool gen skeleton $(BIN_FOLDER)/rootkit.bpf.o > $(SRC_FOLDER)/rootkit.skel.h

user: $(BIN_FOLDER)
	$(CXX) -lbpf $(SRC_FOLDER)/main.cpp -o $(BIN_FOLDER)/main

$(VMLINUX_H):
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -rf $(BIN_FOLDER)/*

$(BIN_FOLDER):
	mkdir -p $@

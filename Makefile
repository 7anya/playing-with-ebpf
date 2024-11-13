# Compile prog.bpf.c into eBPF bytecode
BPF_CLANG=clang
BPF_LLVM_OBJCOPY=llvm-objcopy
BPF_CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86

# Output files
BPF_PROG=prog.bpf.o
USER_PROG=loader

all: $(BPF_PROG) $(USER_PROG)

# Build the eBPF object file
$(BPF_PROG): prog.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_LLVM_OBJCOPY) $@

# Build the user-space loader
$(USER_PROG): loader.c
	gcc loader.c -o $@ -lbpf -lelf

clean:
	rm -f $(BPF_PROG) $(USER_PROG)

.PHONY: all generate build run clean

# bpf2go compiles tracker.bpf.c into a .o file and generates a Go wrapper
# package under ./gen/. The wrapper embeds the .o as a []byte literal, so
# the final binary carries the BPF bytecode — no separate .o at runtime.
generate:
	cd bpf && go generate

# After generate, build the agent normally. CGO is required for go-sqlite3.
build: generate
	CGO_ENABLED=1 go build -o filewatch ./...

# Running requires root (or CAP_BPF + CAP_PERFMON + CAP_SYS_RESOURCE).
run: build
	sudo ./filewatch

clean:
	rm -f filewatch gen/*.go gen/*.o

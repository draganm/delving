# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Delving is a Go library for runtime stack introspection using DWARF debug information. It reads local variables from the current stack frame and all parent call frames by parsing the binary's own debug symbols at runtime.

## Build Commands

```bash
# Build with debug symbols (required for introspection to work)
go build -gcflags='all=-N -l' -o delving .

# Run
./delving

# Standard build (will fail at runtime due to missing DWARF info)
go build
```

The `-gcflags='all=-N -l'` flags disable optimizations and inlining, which is necessary for DWARF variable location information to be accurate.

## Architecture

### Core Components

- **main.go**: Demo application with nested function calls (`level1` → `level2` → `level3`) to demonstrate stack introspection
- **introspect/introspect.go**: Core library that:
  - Loads DWARF data from the running binary (supports macOS/Mach-O and Linux/ELF)
  - Calculates ASLR offset by comparing runtime addresses to DWARF addresses
  - Walks stack frames using `runtime.Callers` and manual frame pointer traversal
  - Evaluates DWARF location expressions (DW_OP_fbreg, DW_OP_call_frame_cfa, etc.)
  - Reads and formats values from memory based on type information

### Platform Support

Assembly files provide `getBasePointer()` for different architectures:
- `introspect/asm_amd64.s`: Returns RBP register
- `introspect/asm_arm64.s`: Returns X29 (FP) register

### Key Functions

- `PrintStackVariables()` / `FprintStackVariables(io.Writer)`: Main entry points for introspection
- `HasDWARFInfo()`: Checks if binary contains debug symbols
- `findFunctionAndVariables()`: Locates function in DWARF and extracts variable metadata
- `evaluateLocation()`: Interprets DWARF location expressions
- `readValueAtAddress()`: Type-aware memory reading

## Development Environment

Uses Nix flakes with direnv. The flake provides Go and disables hardening for unsafe pointer operations.

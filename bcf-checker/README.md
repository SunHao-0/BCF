# BCF Proof Checker

eBPF Certificae Framework (BCF) is a framework that applies proof-guided abstraction refinement to the eBPF verifier, designed to enhance the verifier's precision with on-demand user space reasoning.

This project provides a user-space port of the kernel BCF proof checker, which is standalone, easy-to-use for checking proofs in BCF format. Core features:
- **Code Reuse**: The core `bcf_checker.c` is identical to the kernel version
- **Kernel Compatibility**: All kernel APIs are stubbed with user-space equivalents
- **Standalone**: Check BCF proofs without requiring kernel integration
- **Development**: Easier development, testing, and debugging of proof tools
- **Integration**: Use the checker in other projects that need formal proof validation

## Project Structure

The project separates the kernel-compatible code and checker code:

```
├── bcf_checker.c    # Proof checker (same as the kernel version)
├── main.c           # User-space entry point
├── include/         # Header files (kernel headers + user-space stubs)
│   ├── linux/
│   └── uapi/
└── lib/             # Kernel library ported to user space
    ├── bitmap.c     # Bitmap operations
    ├── string.c
    ├── sort.c
    └── ...
```

To sync the checker code with the kernel version, simply:
```
> cp path/to/kernel/bcf_checker.c ./bcf_checker.c
> # also sync linux/bcf.h, uapi/linux/bcf.h if needed
```

## BCF Proof Format

BCF represents logical proofs using:
- **Boolean expressions**: Logical formulas with AND, OR, NOT, IMPLIES, XOR operations
- **Bit-vector operations**: Arithmetic and logical operations on fixed-width bit vectors
- **Proof steps**: A sequence of logical inference rules that prove a goal statement

The checker supports multiple rule categories (mostly compatible with cvc5):

- **Built-in Rules**: Basic operations like assumptions and rewrites
- **Boolean Rules**: Logical inference rules (resolution, factoring, etc.)
- **Equality Rules**: Reflexivity, symmetry, transitivity, congruence, etc.
- **Bit-Vector Rules**: Bit-blasting and other bit-vector operations

The proof file in BCF binary format must contain:
- **Header**: Magic number, expression count, and step count
- **Expressions**: Boolean and bit-vector expressions (referred by the steps)
- **Proof Steps**: Sequence of logical inference rules

The format is designed to be compact and uses efficient u32-based binary representation, and each proof step can be mechanically checked:
```
BCF Proof File:
├── Header (12 bytes)
│   ├── Magic number (0x0BCF)
│   ├── Expression count
│   └── Step count
├── Expressions (variable size)
│   ├── Expression 0
│   ├── Expression 1
│   └── ...
└── Proof Steps (variable size)
    ├── Step 0
    ├── Step 1
    └── ...
```

## Building and Usage

#### Prerequisites

- Clang or GCC, make, standard C library (can also be built with nolibc with slight modifications)

#### Build

Options:
- `RELEASE=1`: Enable optimizations and strip symbols
- `V=1`: Verbose build output
- `CC=<compiler>`: Specify custom compiler (default: clang)

```bash
> make
# Release build (optimized, stripped) with: `make RELEASE=1`, see `make help`
```

#### Usage

```bash
# Use cvc5 to produce a BCF proof file
# Check a BCF proof file:
> ./bcf-checker <proof_file>
```

## License

This project is licensed under the GPL-2.0 license.

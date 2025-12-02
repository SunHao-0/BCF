<p align="center">
  <img src="./scripts/BCF.png" alt="BCF Logo" width="240"><br>
</p>
<h2 align="center" style="margin-top: -20px;">eBPF Certificate Framework</h2>

**BCF** is a framework designed to enhance the precision of the eBPF verifier through proof-guided abstraction refinement. By combining user-space reasoning with formal proof checking, BCF enables the verifier to achieve high precision while maintaining soundness and low complexity. The framework addresses precision limitations by:

- **Refinement**: Making the verifier's knowledge about program state more precise
- **Delegation**: Delegating refinement reasoning to user space (low kernel complexity)
- **Proof**: Requiring formal proofs that are validated by an in-kernel proof checker

### Upstream Status

- Initial RFC patch [set](./patches-kernel/set1:verifier_and_initial_checker_support): https://lore.kernel.org/bpf/20251106125255.1969938-1-hao.sun@inf.ethz.ch/

<p align="center">
<video src="scripts/demo.mov" controls width="1100"></video>
</p>


## Project Structure

```
├── patches-kernel/     # Kernel patches for BCF integration
├── patches-solver/     # SMT solver (cvc5) patches for proof generation
├── bcf-checker/        # Standalone proof checker (user-space port)
├── bpf-progs/          # eBPF programs for evaluation
├── examples/           # example programs for playing with BCF
├── scripts/            # Build and evaluation scripts
├── build/              # Build artifacts (generated)
└── output/             # Results and binaries (generated)
```

## Key Components

### BCF Operation Flow

1. **Verification Halt**: The eBPF verifier encounters a verification error
2. **State Capture**: BCF backtracks and captures program state and path constraints
3. **Refinement Generation**: The verifier's abstraction is refined with a soundness condition
4. **User-Space Delegation**: The condition is passed to user space for reasoning
5. **Proof Generation**: User space produces a formal proof using the SMT solver
6. **Proof Validation**: The kernel BCF proof checker validates the proof
7. **Continuation**: If valid, verification continues with refined abstraction

### 1. Kernel Integration (`patches-kernel/`)

See [the patch cover letter](patches-kernel/set1:verifier_and_initial_checker_support/0000-cover-letter.patch) for more details.

- Adds BCF expression and formula definitions to the kernel
- Implements state tracking and path constraint collection
- Integrates the BCF proof checker for soundness validation
- Enables on-demand abstraction refinement

### 2. User-Space Loader (`patches-kernel/set5:bpftool_libbpf_support/`)

- Modifies bpftool to detect refinement conditions
- Converts conditions to SMT-LIB format
- Bridges kernel verifier and user-space solver
- Drives the refinement-solving loop

### 3. SMT Solver (`patches-solver/`)
- Patches cvc5 to emit proofs in BCF binary format
- Handles QF_BV formulas for refinement conditions
- Produces refutation proofs for UNSAT cases

### 4. Proof Checker (`bcf-checker/`)

Please refer to [bcf-checker/README.md](bcf-checker/README.md) for more details about the design and the BCF proof format.

- Standalone user-space port of the kernel proof checker
- Validates BCF format proofs
- Supports development and testing of proof tools

## Prerequisites

- Linux environment (tested on Debian Bookworm)
- QEMU with KVM support
- virtiofsd for file sharing
- Standard build tools (make, gcc/clang, git)
- Python3 with standard libraries

The following script will install most of the dependencies for the project automatically. The script should be run as non-root, but with sudo privileges to install packages.

```bash
./scripts/install-deps.sh
```

Try out with example programs, play with the system following the instruction [here](/examples/README.md).

## License

This project is licensed under GPL-2.0.

## Citation

If you use this artifact in your research, please cite the corresponding SOSP paper.

```
@inproceedings {haosun-sosp25,
author = {Hao Sun and Zhendong Su},
title = {Prove It to the Kernel: Precise Extension Analysis via Proof-Guided Abstraction Refinement},
booktitle = {In Proceedings of SOSP, Seoul, Korea, October 13-16, 2025},
year = {2025},
publisher = {Association for Computing Machinery},
address = {Seoul, Korea},
month = oct
}
```

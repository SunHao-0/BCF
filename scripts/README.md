# BCF Scripts

This directory contains scripts for building the BCF project components, running evaluations, and processing results.

Several key components are automatically built:
- **Kernel**: A modified Linux kernel with BCF patches
- **Solver**: CVC5 SMT solver with custom patches
- **BPF Programs**: Test programs for evaluation
- **VM Environment**: QEMU-based virtual machine for testing
- **Analysis Tools**: Scripts for processing and analyzing results

## Directory Structure

```
scripts/
├── install-deps.sh          # Dependency installation
├── vars.sh                  # Script variables
├── build.sh                 # Build components
├── boot_vm.sh               # Boot the VM
├── run_exp.sh               # Run experiments
├── load_prog.py             # Load BPF programs
├── build_bpf_projects.py    # Build BPF projects
├── clang-wrapper.py         # Compiler wrapper
├── process_bcf_result.py    # Result analysis
├── run_PREVAIL.sh           # Run PREVAIL
└── kernel-config            # Kernel config
```

## Workflow

Ensure the following resources are available:
- **Memory**: 256GB RAM minimum
- **Storage**: 100GB+ free space (for the VM image and results)

### Usage Sequence

1. **Setup**:
   ```bash
   ./install-deps.sh
   ./build.sh all
   ```

2. **Run Experiments**:
   ```bash
   ./run_exp.sh --run-load
   ./run_exp.sh --run-bench
   ```

3. **Analyze Results**:
   ```bash
   ./run_exp.sh --analyze
   ```

4. **Run PREVAIL**:
   ```bash
   ./run_PREVAIL.sh
   ```

## Scripts Details

#### `install-deps.sh`
Installs all system dependencies required for the BCF project, it automatically detects the OS and package manager, installs kernel build dependencies, CVC5 solver dependencies, VM tools, and Python packages, and checks the version of critical tools.

```bash
./install-deps.sh                    # Install all dependencies
./install-deps.sh --check-only       # Only check what's missing
./install-deps.sh --help             # Show help
```

#### `vars.sh`
Defines environment variables and utility functions used by other scripts, it includes colored logging functions and SSH command wrapper for VM communication.

#### `build.sh`
Builds the core BCF components (kernel and solver), it downloads source tarballs if missing, applies custom patches from `patches-*/` directories, configures and compiles components.

**Usage**:
```bash
./build.sh solver    # Build only the solver
./build.sh kernel    # Build only the kernel
./build.sh all       # Build both
```

#### `boot_vm.sh`
Boots a QEMU virtual machine for running BCF evaluations, it uses custom kernel image with BCF patches, shared directory mounting via virtiofs, SSH access on port 10023, memory and CPU allocation based on system resources.

**Requirements**:
- QEMU system emulator
- virtiofsd (installed via `install-deps.sh`)
- VM disk image (`imgs/bookworm.img`)
- SSH key pair (`imgs/bookworm.id_rsa`)

```bash
./boot_vm.sh    # Boot the VM and wait for SSH availability
```

#### `run_exp.sh`
Orchestrates the complete BCF evaluation workflow, it checks system resources, validates required files, boots VM if not running, executes `load_prog.py` in VM, monitors progress and provides status updates.

```bash
./run_exp.sh --run-load     # Run load experiments on all programs
./run_exp.sh --run-bench    # Run benchmarks, e.g., load time
./run_exp.sh --analyze      # Process and analyze results
```

**Note**: (1) Both the load and bench experiments can take a long time to complete (e.g., 10 hours), ensure you have enough resources and time to run; (2) The analysis script needs to extract the verifier logs and process them, it can take a long time to complete (e.g., 10 minutes); and (3) The load time bench results can vary on different machines, slight differences are expected.

#### `load_prog.py`
Loads and tests BPF programs in the VM environment, it supports all BPF program types (socket, kprobe, xdp, etc.), automatic program type detection, resource usage monitoring, benchmarking capabilities, and concurrent processing with configurable parallelism.

```bash
python3 load_prog.py --directory /path/to/programs --output /path/to/results --bpftool /path/to/bpftool
python3 load_prog.py --bench --directory /path/to/programs --output /path/to/results
```

#### `build_bpf_projects.py`
Builds BPF programs from various projects with different compiler versions, it supports multi-compiler support (different clang versions), automatic eBPF object detection, version-prefixed output files. It reads compiler configuration, switches system clang symlinks, builds projects with specified compiler, copies eBPF objects with version prefixes, and restores original symlinks.

```bash
python3 build_bpf_projects.py    # Build with configured compiler versions
```

#### `clang-wrapper.py`
Wrapper script for controlling compiler versions and optimization levels, it supports configurable compiler selection via JSON config, automatic optimization level management, and transparent compiler invocation.

```json
{
    "compiler": "clang-11",
    "optimization": "-O3"
}
```

#### `process_bcf_result.py`
Analysis and visualization of BCF evaluation results, it extracts verifier logs, parses verification results, deduplicates similar programs, benchmarks performance, and visualizes results with histograms and box plots.

```bash
python3 process_bcf_result.py --output_dir /path/to/results -p /path/to/programs
```

#### `run_PREVAIL.sh`
Runs the PREVAIL verifier, it builds PREVAIL from source, lists programs in each BPF object, attempts verification for each program, records results (pass/fail, runtime, memory usage), and handles timeouts.

```bash
./run_PREVAIL.sh    # Run PREVAIL verification on all programs
```

#### `kernel-config`
Linux kernel configuration file for BCF-enabled kernel build, it enables BPF syscall and JIT compilation, configures debugging and tracing options, and optimized for eBPF program testing.

### Common Issues

1. **VM Boot Failures**:
   - Check QEMU and virtiofsd installation
   - Verify VM image and SSH keys exist

2. **Build Failures**:
   - Run `./install-deps.sh` to ensure all dependencies
   - Check compiler versions meet requirements

3. **Memory Issues**:
   - Ensure 256GB RAM available
   - Check VM memory allocation in `boot_vm.sh`

4. **Permission Issues**:
   - Ensure write access to `/sys/fs/bpf` in the VM
   - Check sudo privileges for dependency installation

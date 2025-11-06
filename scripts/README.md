# BCF Scripts

```
scripts/
├── install-deps.sh          # Dependency installation
├── vars.sh                  # Script variables
├── build.sh                 # Build components
├── boot_vm.sh               # Boot the VM
├── load_prog.py             # Load BPF programs
└── kernel-config            # Kernel config
```

## Scripts Details

#### `install-deps.sh`
Installs all system dependencies required for the BCF project, it automatically detects the OS and package manager, installs kernel build dependencies, CVC5 solver dependencies, VM tools, and Python packages, and checks the version of critical tools.

```bash
./install-deps.sh                    # Install all dependencies
```

#### `vars.sh`
Defines environment variables and utility functions used by other scripts, it includes colored logging functions and SSH command wrapper for VM communication.

#### `build.sh`
Builds the core BCF components (kernel and solver).

- Kernel: clones `bpf-next`, applies the five patch sets under `patches-kernel/set{1..5}:*/`, configures, builds the kernel image and `bpftool`.
- Solver: downloads cvc5 at commit `f7db8faac6639980ed61a1920042ded79cd15e21`, applies patches in `patches-solver/`, builds and installs to `output/cvc5-libs`.

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
#### `load_prog.py`
Loads and tests BPF programs in the VM environment, it supports all BPF program types (socket, kprobe, xdp, etc.), automatic program type detection, resource usage monitoring, benchmarking capabilities, and concurrent processing with configurable parallelism.

```bash
python3 load_prog.py --directory /path/to/programs --output /path/to/results --bpftool /path/to/bpftool
python3 load_prog.py --bench --directory /path/to/programs --output /path/to/results
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

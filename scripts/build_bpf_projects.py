#!/usr/bin/env python3
import json
import os
import subprocess
import shutil
from collections import defaultdict

COMPILER_CONFIG_FILE = "/path/to/compiler_config.json"


def find_bpf_objects(search_dir):
    """
    Executes a shell command under search_dir to locate all .o files whose file
    description mentions "eBPF". Returns a list of relative file paths.
    """
    # This command searches for .o files, uses the 'file' command to inspect them,
    # filters for those mentioning "eBPF", and extracts the file name.
    cmd = r'find . -type f \( -name "*.o" -o -name "*.elf" -o -name "*.bpf" \) -exec file {} \; | grep "eBPF" | cut -d: -f1'
    try:
        output = subprocess.check_output(
            cmd, shell=True, cwd=search_dir, text=True)
        files = [line.strip() for line in output.splitlines() if line.strip()]
        # Clean up relative paths by removing a leading "./" if present.
        files = [f[2:] if f.startswith("./") else f for f in files]
        return files
    except subprocess.CalledProcessError:
        return []


def copy_bpf_objects_with_version(project_path, output_project_dir, compiler_prefix, obj_path):
    """
    Copies all discovered eBPF object files from project_path to output_project_dir.
    Each destination filename is prefixed with the given compiler_prefix.
    Files with name conflicts are renamed by flattening their relative path.
    """
    if obj_path:
        files = [obj_path]
    else:
        files = find_bpf_objects(project_path)
    if not files:
        print(
            f"Warning: No eBPF object files found in {project_path} for {compiler_prefix}.")
        return

    os.makedirs(output_project_dir, exist_ok=True)
    # Group files by their basename.
    basename_dict = defaultdict(list)
    for rel_path in files:
        base = os.path.basename(rel_path)
        basename_dict[base].append(rel_path)

    for base, rel_paths in basename_dict.items():
        if len(rel_paths) == 1:
            src = os.path.join(project_path, rel_paths[0])
            dest_name = f"{compiler_prefix}_{base}"
            dest = os.path.join(output_project_dir, dest_name)
            shutil.copy(src, dest)
        else:
            for rel_path in rel_paths:
                src = os.path.join(project_path, rel_path)
                # Flatten the relative path by replacing os.sep with underscores.
                flattened = rel_path.replace(os.sep, "_")
                dest_name = f"{compiler_prefix}_{flattened}"
                dest = os.path.join(output_project_dir, dest_name)
                shutil.copy(src, dest)
    print(
        f"Copied {len(files)} eBPF object file(s) for {compiler_prefix} to {output_project_dir}")


def get_original_symlinks():
    """
    Reads and returns the current symlink targets for /usr/bin/clang.
    """
    try:
        clang_target = os.readlink("/usr/bin/clang")
    except Exception as e:
        print(f"Warning: Unable to read /usr/bin/clang symlink: {e}")
        clang_target = None
    return clang_target


def set_clang_version(ver):
    """
    Replaces the /usr/bin/clang symlinks to point to clang-{ver} and clang++-{ver}.
    Searches for the target binaries in both /usr/bin and /usr/local/bin.
    Returns True on success, False if the target version does not exist or on error.
    """
    candidate_dirs = ["/usr/bin", "/usr/local/bin"]
    target_clang = None
    for candidate in candidate_dirs:
        candidate_clang = os.path.join(candidate, f"clang-{ver}")
        if os.path.exists(candidate_clang):
            target_clang = candidate_clang
            break
    if not target_clang:
        print(
            f"Error: clang version {ver} not found in /usr/bin or /usr/local/bin. Skipping.")
        return False

    try:
        subprocess.run(["sudo", "ln", "-sf", target_clang,
                       "/usr/bin/clang"], check=True)
        version_info = subprocess.check_output(
            ["clang", "--version"], text=True).splitlines()[0]
        print(f"Set clang version to {ver}: {version_info}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error setting clang version to {ver}: {e}")
        return False


def restore_symlinks(original_clang):
    """
    Restores the original clang and clang++ symlinks.
    """
    try:
        if original_clang:
            subprocess.run(["sudo", "ln", "-sf", original_clang,
                           "/usr/bin/clang"], check=True)
        print("Restored original clang symlinks.")
    except subprocess.CalledProcessError as e:
        print(f"Error restoring clang symlinks: {e}")


def main():
    OUTPUT_DIR = "../bpf-progs"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ROOT_DIR = "/local/home/sunhao/tools"

    projects = {
        "agent-libs": {
            "build_command": "make -Cdriver/bpf clean && make -Cdriver/bpf -j32",
        },
        "alaz": {
            # Note, requires both a newer libbpf
            "build_command": "rm -rf ./ebpf/c/*.o && make generate",
            "build": True,
        },
        "bad-bpf": {
            "build_command": "cd src && make clean && make -j8",
        },
        "bcc": {
            "build_command": "cd libbpf-tools && make clean && make -j8",
        },
        "beyla": {
            "build_command": "make generate",
        },
        "blixt": {
            "build_command": "rm -rf dataplane/target && cargo xtask build-ebpf --release",
            "default_clang": "14",
            "obj_path": "dataplane/target/bpfel-unknown-none/release/loader",
        },
        "bpf-examples": {
            "build_command": "make clean && make all -j8",
        },
        "bpfman": {
            "build_command": "cargo clean && cargo xtask build-ebpf --libbpf-dir ../bad-bpf/libbpf",
        },
        "bpftune": {
            "build_command": "make clean && make -j8",
        },
        "bumblebee": {
            "build_command": "ls",  # no real build
            "clang-version": "14",  # just copy array.o
        },
        # bpftop: a very small trace program
        # bpftrace DSL programs loader, does not contain programs directly
        "calico": {
            # Note, requires both a newer libbpf and Linux headers
            "build_command": ("make -Cfelix/bpf-apache clean && make -Cfelix/bpf-gpl clean &&"
                              "make -Cfelix build-bpf -j32"),
            "build": True,
        },
        "caretta": {
            "build_command": "make generate_ebpf",
            "clang-version": "14",
        },
        "cilium": {
            "build_command": "cd bpf && make clean && make -j8",
        },
        "coroot-node-agent": {
            "build_command":
            ("clang -g -O2 -I/usr/include -I/usr/include/x86_64-linux-gnu -target bpf -D__KERNEL_FROM=416 -D__TARGET_ARCH_x86 -c ebpftracer/ebpf/ebpf.c -o ebpf416x86.o && llvm-strip --strip-debug ebpf416x86.o &&"
             "clang -g -O2 -I/usr/include -I/usr/include/x86_64-linux-gnu -target bpf -D__KERNEL_FROM=420 -D__TARGET_ARCH_x86 -c ebpftracer/ebpf/ebpf.c -o ebpf420x86.o && llvm-strip --strip-debug ebpf420x86.o &&"
             "clang -g -O2 -I/usr/include -I/usr/include/x86_64-linux-gnu -target bpf -D__KERNEL_FROM=506 -D__TARGET_ARCH_x86 -c ebpftracer/ebpf/ebpf.c -o ebpf506x86.o && llvm-strip --strip-debug ebpf506x86.o &&"
             "clang -g -O2 -I/usr/include -I/usr/include/x86_64-linux-gnu -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_x86 -c ebpftracer/ebpf/ebpf.c -o ebpf512x86.o && llvm-strip --strip-debug ebpf512x86.o &&"
             "clang -g -O2 -I/usr/include -I/usr/include/x86_64-linux-gnu -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_x86 -D__CTX_EXTRA_PADDING -c ebpftracer/ebpf/ebpf.c -o ebpf512x86cep.o && llvm-strip --strip-debug ebpf512x86cep.o"),
        },
        "dae": {
            "build_command": "make clean-ebpf && make ebpf",
        },
        "deepflow": {
            "build_command": "make -Cagent/src/ebpf/kernel clean && make -Cagent/src/ebpf/kernel -j8",
        },
        "eBPF-Package-Repository": {
            "build_command": "./buildscript.sh",
        },
        # ebpf (the golang lib): is a loader project
        "ebpfmanager": {
            "build_command": "go clean && go build && ./examples/test.sh",
        },
        "ecapture": {
            "build_command": "make clean && make -j32",
            "build": True,
        },
        "elastic_ebpf": {
            "build_command": "make clean && make build -j32",
            "skip": True,
        },
        "eunomia-bpf": {
            "build_command": "make clean && make all -j32",
            "skip": True,
        },
        "libs": {  # bpf programs repo for falco
            "build_command": ("rm -rf build && mkdir -p build && cd build && "
                              "cmake -DBUILD_BPF=ON -DUSE_BUNDLED_DEPS=ON "
                              "-DBUILD_LIBSCAP_MODERN_BPF=ON ../ && make bpf && make scap -j32")
        },
        # hubble: uses cilium, does not contain bpf programs directly
        "ingress-node-firewall": {
            "build_command": "make ebpf-generate",
        },
        "inspektor-gadget": {
            "build_command": "make ebpf-objects-outside-docker",
            "build": True,
        },
        "katran": {
            "build_command": "./build_katran.sh",
        },
        "kepler": {
            "build_command": "make generate",
            "default_clang": "14",
        },
        # both kernel-collector and eBPF-pkg rely on 5.15
        "kernel-collector": {
            "build_command": "make clean && make -Ckernel -j32",
        },
        "kflowd": {
            "build_command": "make -Csrc clean && make -Csrc -j32",
        },
        # kindling: bpf programs are in agent-libs, which is compiled above
        "KubeArmor": {
            "build_command": "cd KubeArmor/BPF && make clean && make"
        },
        # kubectl-trace: schedule bpftrace programs, does not contain programs
        "kubeskoop": {
            "build_command": "make generate-bpf",
            "default_clang": "14",
        },
        "kunai": {
            "build_command": "cargo xtask build",
            "obj_path": "target/bpfel-unknown-none/debug/kunai-ebpf",
            "default_clang": "14",
        },
        "kyanos": {
            "build_command": "make clean && make build-bpf -j32",
            "default_clang": "14",
        },
        # l3afd: control plane, no bpf programs
        "loxilb": {
            "build_command": "make -Cloxilb-ebpf clean && make -Cloxilb-ebpf all",
            "build": True,
        },
        "merbridge": {
            "build_command": "rm -rf bpf/*.o && make compile",
        },
        # all eBPF programs in netobserv-ebpf-agent are rejected, and loading is very slow
        #"netobserv-ebpf-agent": {
        #    "build_command": "rm -rf ./pkg/ebpf/*.o && make gen-bpf",
        #},
        # odigos: bpf programs are private, at least I didn't find, is this legal?
        "opentelemetry-ebpf-profiler": {
            "build_command": "make -Csupport/ebpf clean && make -Csupport/ebpf",
            "obj_path": "support/ebpf/tracer.ebpf.release.amd64",
        },
        # parca: dynamically loads tracers from other sources, including opentelemetry
        # pixie: build failure, which uses the ugly bazel
        # ply: like bpftrace, loader tool, not contain bpf programs directly
        "pwru": {
            "build_command": "rm -rf *.o && make pwru",
        },
        "ptcpdump": {
            "build_command": "rm -rf bpf/*.o && make generate",
        },
        "pulsar": {
            "build_command": "cargo clean && cargo build --release",
        },
        "pyroscope": {
            "build_command": "make -Cebpf bpf/gen",
        },
        # scx is only supported in newer kernels
        # "scx": {
        #     "build_command": "rm -rf target build && meson setup build && meson compile -C build",
        # },
        "retina": {
            "build_command": "make generate",
        },
        "skywalking-rover": {
            "build_command": "make generate",
        },
        "suricata": {
            "build_command": "make clean && ./configure --enable-ebpf-build --enable-ebpf && make -j32",
        },
        # SysmonForLinux requires .net runtime
        "tracee": {
            "build_command": "make tracee-ebpf",
        },
        "tracer": {
            "build_command": "make bpf",
        },
        "tetragon": {
            "build_command": "make clean && make tetragon-bpf-local",
            "build": True,
        }
        # vc5: no bpf programs found
        # wachy: use bpftrace
    }

    clang_versions = ["5.0", "6.0", "7", "8", "9", "10", "11", "12",
                      "13", "14", "15", "16", "17", "18", "19", "20", "21"]
    clangs = [f"clang-{ver}" for ver in clang_versions]

    gcc_versions = ["8", "9", "10", "11", "12", "13", "14"]
    gccs = [f"gcc-{ver}" for ver in gcc_versions]

    compilers = gccs + clangs
    compiler_config = [(compiler, opt)
                       for compiler in compilers for opt in ["-O1", "-O2", "-O3", "-Os"]]

    # original_clang = get_original_symlinks()
    # if not original_clang:
    #     print("Warning: Could not detect original clang symlinks.")

    print("compiling {} projects with {} clangs, {} gccs, {} configurations".format(
        len(projects), len(clangs), len(gccs), len(compiler_config)))

    failed = []
    for project, config in projects.items():
        project_path = os.path.join(ROOT_DIR, project)
        temp_dir = os.path.join("/tmp", f"{project}_build")
        os.makedirs(temp_dir, exist_ok=True)

        default_clang = None
        if "default_clang" in config:
            default_clang = "clang-" + config["default_clang"]

        if config.get("skip"):
            print(f"Skipping {project}")
            continue

        if config.get("build") is None or not config["build"]:
            continue

        print(f"\nProcessing project '{project}'")
        for (compiler, opt) in compiler_config:
            if default_clang is not None and compiler != default_clang:
                continue

            # if last_failed_compiler is not None and compiler == last_failed_compiler:
            #     print("Skipping compiler {} due to previous failure.".format(
            #         compiler))
            #     continue

            if config.get("skip_gcc") and compiler.startswith("gcc"):
                continue

            # last_failed_compiler = None

            print(f"Building {project} with {compiler} {opt}...")

            # Write compiler configuration json file in the current directory
            with open(COMPILER_CONFIG_FILE, "w") as f:
                json.dump({"compiler": compiler, "optimization": opt}, f)

            # Use a log file specific to this clang version.
            log_file = os.path.join(temp_dir, f"build_{compiler}.log")
            with open(log_file, "w") as lf:
                result = subprocess.run(config["build_command"],
                                        cwd=project_path,
                                        shell=True,
                                        stdout=lf,
                                        stderr=subprocess.STDOUT)

            if result.returncode != 0:
                print(
                    f"Error: Build for {project} with `{compiler} {opt}` failed. See log at {log_file}.")
                failed.append((project, config, compiler, opt))
                # last_failed_compiler = compiler
            else:
                output_project_dir = os.path.join(OUTPUT_DIR, project)
                copy_bpf_objects_with_version(
                    project_path, output_project_dir, f"{compiler}_{opt}", config.get("obj_path"))

            if default_clang:
                break

    # Restore the original clang symlinks.
    # restore_symlinks(original_clang)

    if len(failed) == 0:
        print(
            f"\nAll builds complete. BPF object files are organized in {OUTPUT_DIR}.")
    else:
        print(f"\nFailed: {failed}")


if __name__ == "__main__":
    main()

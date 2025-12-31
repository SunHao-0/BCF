#!/usr/bin/env python3

import os
import re
import csv
import json
import time
import shutil
import argparse
import subprocess
import concurrent.futures
import sys


PROGRAM_TYPES = [
    "socket", "kprobe", "kretprobe", "classifier", "action", "tracepoint", "raw_tracepoint", "xdp", "perf_event",
    "cgroup/skb", "cgroup/sock", "cgroup/dev", "lwt_in", "lwt_out", "lwt_xmit", "lwt_seg6local", "sockops", "sk_skb",
    "sk_msg", "lirc_mode2", "sk_reuseport", "flow_dissector", "cgroup/sysctl", "cgroup/bind4", "cgroup/bind6",
    "cgroup/post_bind4", "cgroup/post_bind6", "cgroup/connect4", "cgroup/connect6", "cgroup/getpeername4",
    "cgroup/getpeername6", "cgroup/getsockname4", "cgroup/getsockname6", "cgroup/sendmsg4", "cgroup/sendmsg6",
    "cgroup/recvmsg4", "cgroup/recvmsg6", "cgroup/getsockopt", "cgroup/setsockopt", "cgroup/sock_release",
    "struct_ops", "fentry", "fexit", "freplace", "sk_lookup"
]

OBJ_RESULT_FILE = "object_results.csv"
GROUP_RESULT_FILE = "group_results.log"

STATUS_LOADED, STATUS_COMPAT, STATUS_REJECT = 0, 1, 2
STATUS_DICT = {
    STATUS_LOADED: "loaded",
    STATUS_COMPAT: "compat_issue",
    STATUS_REJECT: "rejected"
}

GROUP_LOADED, GROUP_PARTIAL, GROUP_FAILED = 0, 1, 2
GROUP_RESULT_DICT = {
    GROUP_LOADED: "loaded",
    GROUP_PARTIAL: "partially_loaded",
    GROUP_FAILED: "failed"
}

BPFTOOL = "/usr/local/sbin/bpftool"


def check_env(bpftool_path=None):
    """
    Checks for required environment and tools.
    Exits the program if a critical requirement is missing.
    """
    import shutil

    errors = []

    bpftool = bpftool_path or BPFTOOL
    if not os.path.exists(bpftool) or not os.access(bpftool, os.X_OK):
        errors.append(f"bpftool not found or not executable at {bpftool}")

    for tool in ["taskset", "nice", "chrt", "file"]:
        if not shutil.which(tool):
            errors.append(f"'{tool}' utility not found in PATH (required for benchmarking)")

    # Check for /sys/fs/bpf
    if not os.path.exists("/sys/fs/bpf"):
        errors.append("/sys/fs/bpf does not exist (required for pinning BPF objects)")

    if os.path.exists("/sys/fs/bpf") and not os.access("/sys/fs/bpf", os.W_OK):
        errors.append("No write permission to /sys/fs/bpf (required for pinning BPF objects)")

    if errors:
        print("Environment check failed with the following errors:")
        for err in errors:
            print("  -", err)
        sys.exit(1)
    else:
        print("Environment check passed.")


def sys_pin_dir():
    return "/sys/fs/bpf"


def is_ebpf_object(filepath):
    try:
        result = subprocess.run(["file", filepath], capture_output=True, text=True, check=True)
        return "BPF" in result.stdout
    except Exception as e:
        print(f"Error running 'file' on {filepath}: {e}")
        return False


def cleanup_pin_dir(pin_dir, remove_dir=True):
    if not os.path.exists(pin_dir):
        return
    for entry in os.listdir(pin_dir):
        full_path = os.path.join(pin_dir, entry)
        try:
            if os.path.isfile(full_path) or os.path.islink(full_path):
                os.remove(full_path)
            elif os.path.isdir(full_path) and remove_dir:
                shutil.rmtree(full_path)
        except Exception as e:
            print(f"Failed to remove {full_path}: {e}")


def succ(status):
    return status == STATUS_LOADED


def status_str(status):
    return STATUS_DICT.get(status, "unknown")


def load_object(object_file, pin_path, program_type=None, dry_run=False):
    cmd = [BPFTOOL, "-d", "prog", "loadall", object_file, pin_path]
    if program_type:
        cmd += ["type", program_type]
    if dry_run:
        return [BPFTOOL] + cmd[2:]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        return STATUS_COMPAT, f"Exception during load: {e}"
    log = (result.stdout or "").strip() + (result.stderr or "").strip()
    if result.returncode == 0:
        return STATUS_LOADED, log
    load_failure = "END PROG LOAD LOG" in log
    return (STATUS_REJECT if load_failure else STATUS_COMPAT), log


def handle_object(obj_file, pin_dir, prog_type=None, force_type=False):
    status, vlog = load_object(obj_file, pin_dir, prog_type)
    if succ(status) or force_type:
        return status, prog_type, vlog

    err_dict = {}
    no_compat_issue = False
    reject_prog_type = None

    for try_type in PROGRAM_TYPES:
        status, vlog = load_object(obj_file, pin_dir, try_type)
        if succ(status):
            return status, try_type, vlog
        err_dict[try_type] = vlog
        if any(x in vlog for x in ("legacy map definitions", "is static and not supported")):
            return STATUS_COMPAT, None, err_dict
        if status == STATUS_REJECT:
            no_compat_issue = True
            reject_prog_type = try_type

    return (STATUS_REJECT if no_compat_issue else STATUS_COMPAT), reject_prog_type, err_dict


def handle_object_group(
    output_dir, prog_dir, project, group, obj_files,
    result_csv=None, obj_prog_types=None
):
    obj_prog_types = obj_prog_types or {}
    load_dict = {}
    all_loaded = True
    all_failed = True
    prog_type = None
    is_rejected = False

    group_name = group.replace("/", "_").replace(".", "_")
    pin_path = os.path.join(sys_pin_dir(), f"{project}_{group_name}")
    os.makedirs(pin_path, exist_ok=True)
    project_dir = os.path.join(prog_dir, project)

    for obj_file in obj_files:
        obj_path = os.path.join(project_dir, obj_file)
        if obj_file in obj_prog_types:
            prog_type = obj_prog_types[obj_file]
            force_type = True
        elif project == "collected":
            # For collected objects, they are known to load/reject w/o prog type
            prog_type = None
            force_type = True
        else:
            force_type = False

        load_status, loaded_type, vlog = handle_object(obj_path, pin_path, prog_type, force_type)
        loaded = succ(load_status)
        failed = load_status == STATUS_REJECT
        status = status_str(load_status)

        print(f"[{status.upper()}]: {obj_file}")

        if result_csv:
            result_csv.writerow([project, group, obj_file, loaded_type if loaded_type else "null", status])

        try:
            log_path = os.path.join(output_dir, f"{obj_file}.log")
            with open(log_path, "w") as log_file:
                if isinstance(vlog, dict):
                    json.dump(vlog, log_file, indent=4)
                else:
                    log_file.write(str(vlog))
        except Exception as e:
            print(f"Failed to write log for {obj_file}: {e}")

        load_dict[obj_file] = status
        all_loaded &= loaded
        all_failed &= failed
        if failed:
            is_rejected = True
        if loaded:
            prog_type = loaded_type
            force_type = True
            cleanup_pin_dir(pin_path)

    if all_loaded:
        group_status = GROUP_LOADED
    elif all_failed or not is_rejected:
        group_status = GROUP_FAILED
    else:
        group_status = GROUP_PARTIAL

    group_status_str = GROUP_RESULT_DICT[group_status]
    print(f"Project: {project}, Group: {group}, Status: {group_status_str}")

    if os.path.exists(pin_path):
        try:
            shutil.rmtree(pin_path)
        except Exception as e:
            print(f"Failed to remove pin path {pin_path}: {e}")

    return group_status, load_dict


def handle_project(
    prog_dir, output_dir, project_name, obj_groups,
    executor=None, obj_prog_types=None
):
    obj_prog_types = obj_prog_types or {}
    print(f"Handling: {project_name}")

    project_dir = os.path.join(output_dir, project_name)
    os.makedirs(project_dir, exist_ok=True)

    group_result_path = os.path.join(project_dir, GROUP_RESULT_FILE)
    if os.path.exists(group_result_path):
        os.remove(group_result_path)

    obj_result_path = os.path.join(project_dir, OBJ_RESULT_FILE)

    with open(obj_result_path, "w", newline="") as obj_result_file:
        obj_result_csv = csv.writer(obj_result_file)

        if executor and project_name != "cilium":
            futures = {
                group: executor.submit(
                    handle_object_group,
                    project_dir, prog_dir, project_name, group, obj_files, None, obj_prog_types
                )
                for group, obj_files in obj_groups.items()
            }
            for group, future in futures.items():
                group_result, load_dict = future.result()
                group_status = GROUP_RESULT_DICT[group_result]
                for obj_file, status in load_dict.items():
                    prog_type_val = obj_prog_types.get(obj_file)
                    obj_result_csv.writerow([
                        project_name, group, obj_file,
                        prog_type_val if prog_type_val else "null", status
                    ])
                with open(group_result_path, "a") as group_result_file:
                    group_result_file.write(
                        f"Project: {project_name}, Group: {group}, Status: {group_status}\n"
                    )
                with open(
                    os.path.join(project_dir, f"{group}_{group_status}_results.json"), "w"
                ) as outfile:
                    json.dump(load_dict, outfile, indent=4)
        else:
            for group, obj_files in obj_groups.items():
                print(f"\tHandling {project_name}/{group}")
                group_result, load_dict = handle_object_group(
                    project_dir, prog_dir, project_name, group, obj_files, obj_result_csv, obj_prog_types
                )
                group_status = GROUP_RESULT_DICT[group_result]
                print(f"Project: {project_name}, Group: {group}, Status: {group_status}")
                with open(group_result_path, "a") as group_result_file:
                    group_result_file.write(
                        f"Project: {project_name}, Group: {group}, Status: {group_status}\n"
                    )
                with open(
                    os.path.join(project_dir, f"{group}_{group_status}_results.json"), "w"
                ) as outfile:
                    json.dump(load_dict, outfile, indent=4)

    print(f"[Done]: {project_name}")
    cleanup_pin_dir(sys_pin_dir())


def merge_results(output_dir, index):
    obj_result_path = os.path.join(output_dir, OBJ_RESULT_FILE)
    group_result_path = os.path.join(output_dir, GROUP_RESULT_FILE)

    with open(obj_result_path, "w", newline="") as obj_result_file, \
         open(group_result_path, "w") as group_result_log:

        obj_result_csv = csv.writer(obj_result_file)
        obj_result_csv.writerow(["project", "group", "object", "prog_type", "status"])

        for project_name in os.listdir(output_dir):
            if project_name == "merged" or project_name not in index:
                continue
            project_dir = os.path.join(output_dir, project_name)
            if not os.path.isdir(project_dir):
                continue

            with open(os.path.join(project_dir, OBJ_RESULT_FILE), "r") as result_csv_file:
                for row in csv.reader(result_csv_file):
                    if row and row[0] == "project":
                        continue
                    obj_result_csv.writerow(row)

            with open(os.path.join(project_dir, GROUP_RESULT_FILE), "r") as result_log_file:
                group_result_log.write(result_log_file.read())


def load_index(
    prog_dir,
    prog_index_file="prog_index.json",
    obj_prog_type_file="obj_prog_type.json"
):
    with open(os.path.join(prog_dir, prog_index_file), "r") as file:
        index = json.load(file)

    obj_prog_type_path = os.path.join(prog_dir, obj_prog_type_file)
    if not os.path.exists(obj_prog_type_path):
        return index, {}

    with open(obj_prog_type_path, "r") as file:
        obj_prog_types = json.load(file)

    return index, obj_prog_types


def load_all(prog_dir, output_dir, job):
    skips = {}
    index, obj_prog_types = load_index(prog_dir)
    os.makedirs(output_dir, exist_ok=True)
    max_workers = job or min(32, (os.cpu_count() or 1) * 8)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for project_name, obj_groups in index.items():
            if project_name in skips:
                continue
            handle_project(
                prog_dir, output_dir, project_name, obj_groups, executor, obj_prog_types
            )

    cleanup_pin_dir(sys_pin_dir())
    merge_results(output_dir, index)


def get_resource_usage():
    import resource
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return int(usage.ru_utime * 1e6), int(usage.ru_stime * 1e6)


def benchmark_command(command, runs=5, cpu_core=0, use_high_priority=True, cleanup=None):
    results = []
    base_cmd = f"taskset -c {cpu_core} "
    if use_high_priority:
        base_cmd += "nice -n -20 chrt -f 99 "

    try:
        print(f"\tWarming up: {command}")
        subprocess.run(
            f"{base_cmd} {command}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if cleanup:
            cleanup()
    except Exception as e:
        print(f"Warm-up failed: {e}")

    print(f"\tBenching: {base_cmd} {command}")

    for _ in range(runs):
        user_time_start_us, sys_time_start_us = get_resource_usage()
        start_ns = time.monotonic_ns()

        process = subprocess.Popen(
            f"{base_cmd} {command}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True
        )
        if process.wait() != 0:
            print(f"Warning: command failed: {command}")

        end_ns = time.monotonic_ns()
        real_time_us = int((end_ns - start_ns) / 1e3)
        user_time_us, sys_time_us = get_resource_usage()
        user_time_us -= user_time_start_us
        sys_time_us -= sys_time_start_us

        results.append({
            "real_time_us": real_time_us,
            "user_time_us": user_time_us,
            "sys_time_us": sys_time_us
        })

        if cleanup:
            cleanup()

    print(f"\tResults: {results}")
    return results


def bench_load_accepted_prog(prog_dir, output_dir):
    accepted_prog_index, obj_prog_types = load_index(
        output_dir, prog_index_file="accepted_prog_index.json"
    )
    os.makedirs(output_dir, exist_ok=True)
    exec_time_csv_path = os.path.join(output_dir, "prog_load_time.json")
    exec_results = {}

    for project_name, obj_groups in accepted_prog_index.items():
        print(f"Benching: {project_name}")
        for group, obj_files in obj_groups.items():
            for obj_file in obj_files:
                print(f"\tBenching {project_name}/{group}: {obj_file}")
                obj_path = os.path.join(prog_dir, project_name, obj_file)
                prog_type = obj_prog_types.get(obj_file)
                command = " ".join(load_object(obj_path, sys_pin_dir(), prog_type, dry_run=True))
                results = benchmark_command(
                    command,
                    cleanup=lambda: cleanup_pin_dir(sys_pin_dir())
                )
                exec_results[obj_file] = results

    with open(exec_time_csv_path, "w") as outfile:
        json.dump(exec_results, outfile, indent=4)


def build_index(prog_dir):
    """
    Builds an index of eBPF object files.
    The expected file naming format is:
        clang<version>_-O<optimization_level>_<object_name>.o
    Returns a dictionary: {project_name: {object_name: [variants...]}}
    """
    index = {}
    for entry in os.scandir(prog_dir):
        if not entry.is_dir():
            continue
        project_name, project_path = entry.name, entry.path
        index[project_name] = {}
        for obj in os.scandir(project_path):
            if not is_ebpf_object(obj.path):
                continue
            filename = obj.name
            m = re.match(r'^[^_]+(?:_-[^_]+)?_(.+)', filename)
            if m:
                obj_name = m.group(1)
                index[project_name].setdefault(obj_name, []).append(filename)
            else:
                print(
                    f"Warning: file '{filename}' in project '{project_name}' does not match expected pattern"
                )
    return index


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark the eBPF verifier by loading the eBPF objects in the dataset."
    )
    parser.add_argument(
        "-d", "--directory", required=True,
        help="Root directory containing project directories with eBPF object files"
    )
    parser.add_argument(
        "--build-index", action="store_true",
        help="Set this flag to build the index. If not provided, the index is assumed to exist."
    )
    parser.add_argument(
        "-o", "--output", default="output",
        help="Output directory for the results"
    )
    parser.add_argument(
        "-j", "--job", type=int, default=None,
        help="Number of concurrent jobs to run. Default is 8x the number of CPUs."
    )
    parser.add_argument(
        "--bpftool", default="/usr/local/sbin/bpftool",
        help="Path to the bpftool binary"
    )
    parser.add_argument(
        "--bench", action="store_true",
        help="Benchmark the accepted programs"
    )

    args = parser.parse_args()
    global BPFTOOL
    BPFTOOL = args.bpftool

    check_env(BPFTOOL)

    if not os.path.exists(BPFTOOL):
        print(f"bpftool not found at {BPFTOOL}, please install it first")
        return

    if args.bench:
        bench_load_accepted_prog(args.directory, args.output)
        return

    if args.build_index:
        index = build_index(args.directory)
        with open("prog_index.json", "w") as outfile:
            json.dump(index, outfile, indent=4)
        print(f"Index saved to prog_index.json")
        return

    load_all(args.directory, args.output, args.job)


if __name__ == "__main__":
    main()

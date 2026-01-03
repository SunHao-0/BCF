#!/usr/bin/env python3
import os
import sys
import argparse
import subprocess
import concurrent.futures
import time
from pathlib import Path

def get_output_filename(input_path, input_root_dir, output_dir):
    """
    Constructs the output filename based on the input file path relative to the input root directory.
    Replaces directory separators with underscores.
    """
    try:
        rel_path = os.path.relpath(input_path, input_root_dir)
    except ValueError:
        # Fallback if paths are on different drives or something weird
        rel_path = os.path.basename(input_path)

    # Remove extension
    base_name = os.path.splitext(rel_path)[0]

    # Replace separators with underscores
    flat_name = base_name.replace(os.sep, '_')

    return os.path.join(output_dir, f"{flat_name}.bcf")

def process_file(args):
    solver_path, input_file, output_file, tlimit, mode, cvc5_root = args

    if mode == "bcf":
        cmd = [
            solver_path,
            f"--tlimit={tlimit}",
            "--proof-format=bcf",
            "--proof-granularity=dsl-rewrite",
            f"--bcf-proof-out={output_file}",
            "--dump-proof",
            input_file
        ]
    elif mode == "cpc":
        cmd = [
            solver_path,
            f"--tlimit={tlimit}",
            "--proof-format-mode=cpc",
            "--dump-proofs",
            input_file
        ]
    else:
        return {"status": "error", "input": input_file, "error": f"Unknown mode: {mode}"}

    try:
        # Run solver
        start_time = time.time()
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        duration = time.time() - start_time

        if mode == "cpc":
            # Post-process for Ethos
            # Logic adapted from cpc_gen.sh and cpc_gen_and_check.sh

            content = result.stdout
            lines = content.splitlines()

            # Should have at least unsat, (, )
            # tail -n +3 removes first 2 lines
            # head -n -1 removes last line

            if len(lines) > 3 and lines[0].strip() == "unsat":
                body_lines = lines[2:-1] # Skip 'unsat', '(', and last ')'

                sig_dir = os.path.join(cvc5_root, "proofs/eo/cpc")
                header_1 = f'(include "{sig_dir}/Cpc.eo")'
                header_2 = f'(include "{sig_dir}/expert/CpcExpert.eo")'

                final_content = f"{header_1}\n{header_2}\n" + "\n".join(body_lines) + "\n"

                if result.returncode == 0:
                     with open(output_file, "w") as f:
                        f.write(final_content)
            else:
                 # Fallback/Empty check
                 pass

        # Check if output file exists and has size > 0

        # Check if output file exists and has size > 0
        if os.path.exists(output_file):
            size = os.path.getsize(output_file)
            if size > 0:
                return {
                    "status": "success",
                    "input": input_file,
                    "output": output_file,
                    "duration": duration,
                    "size": size
                }
            else:
                # Empty file produced
                os.remove(output_file)
                return {
                    "status": "empty",
                    "input": input_file,
                    "error": "Empty proof file produced"
                }
        else:
            return {
                "status": "failed",
                "input": input_file,
                "error": f"No proof file produced. Stderr: {result.stderr[:200]}..."
            }

    except Exception as e:
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except:
                pass
        return {
            "status": "error",
            "input": input_file,
            "error": str(e)
        }

import hashlib

def calculate_checksum(file_path, chunk_size=8192):
    """Calculates SHA256 checksum of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    except IOError:
        return None

def deduplicate_proofs(output_dir):
    """Removes duplicate proof files based on SHA256 checksum."""
    print("\nStarting deduplication...")
    checksums = {}
    duplicates = 0
    total_files = 0

    files = sorted([f for f in os.listdir(output_dir) if f.endswith(".bcf")])
    total_files = len(files)

    print(f"Checking {total_files} files for duplicates...")

    for filename in files:
        file_path = os.path.join(output_dir, filename)
        checksum = calculate_checksum(file_path)

        if checksum:
            if checksum in checksums:
                # Duplicate found
                duplicates += 1
                try:
                    os.remove(file_path)
                    # print(f"Removed duplicate: {filename} (same as {checksums[checksum]})")
                except OSError as e:
                    print(f"Error removing {filename}: {e}")
            else:
                checksums[checksum] = filename

    print(f"Deduplication complete. Removed {duplicates} duplicates. {len(checksums)} unique files remain.")

def main():
    parser = argparse.ArgumentParser(description="Generate BCF proofs from SMT2 files using cvc5.")
    parser.add_argument("--input-dir", default="QF_BV", help="Directory containing SMT2 files")
    parser.add_argument("--output-dir", default="bcf_proofs", help="Directory to save BCF proofs")
    parser.add_argument("--solver", default="./output/cvc5-libs/bin/cvc5", help="Path to cvc5 executable")
    parser.add_argument("--jobs", "-j", type=int, default=os.cpu_count(), help="Number of parallel jobs")
    parser.add_argument("--tlimit", type=int, default=20000, help="Time limit in milliseconds per formula")
    parser.add_argument("--deduplicate", action="store_true", help="Deduplicate proofs")
    parser.add_argument("--produce-cpc", action="store_true", help="Produce CPC proofs instead of BCF")
    parser.add_argument("--cpc-dir", default="cpc_proofs", help="Directory to save CPC proofs")
    parser.add_argument("--bcf-dir", default="bcf_proofs", help="Directory containing BCF proofs (used for filtering in CPC mode)")
    parser.add_argument("--cvc5-root", default="/local/home/sunhao/smt/cvc5-bcf", help="Root directory of cvc5 repo (required for CPC headers)")

    args = parser.parse_args()

    input_dir = os.path.abspath(args.input_dir)
    solver_path = os.path.abspath(args.solver)
    cvc5_root = os.path.abspath(args.cvc5_root)

    if args.produce_cpc:
        output_dir = os.path.abspath(args.cpc_dir)
        bcf_dir = os.path.abspath(args.bcf_dir)
        if not os.path.exists(bcf_dir):
            print(f"Error: BCF directory '{bcf_dir}' does not exist.")
            sys.exit(1)
        mode = "cpc"
    else:
        output_dir = os.path.abspath(args.output_dir)
        mode = "bcf"

    if args.deduplicate:
        if not os.path.exists(output_dir):
            print(f"Error: Output directory '{output_dir}' does not exist.")
            sys.exit(1)
        deduplicate_proofs(output_dir)
        sys.exit(0)

    if not os.path.exists(input_dir):
        print(f"Error: Input directory '{input_dir}' does not exist.")
        sys.exit(1)

    if not os.path.exists(solver_path):
        print(f"Error: Solver executable '{solver_path}' does not exist.")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    # Collect all .smt2 files
    tasks = []
    skip_dirs = []
    # set(["Sage2"])
    print(f"Scanning '{input_dir}' for .smt2 files...")

    for root, dirs, files in os.walk(input_dir):
        rel_root = os.path.relpath(root, input_dir)

        if rel_root == ".":
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for d in skip_dirs:
                if os.path.exists(os.path.join(input_dir, d)):
                     print(f"Skipping directory: {d}")

        for file in files:
            if file.endswith(".smt2"):
                input_path = os.path.join(root, file)

                if mode == "cpc":
                    # Check if BCF exists
                    bcf_filename = get_output_filename(input_path, input_dir, bcf_dir)
                    if not os.path.exists(bcf_filename):
                        continue
                    output_path = get_output_filename(input_path, input_dir, output_dir)
                    # Change extension to .cpc
                    output_path = os.path.splitext(output_path)[0] + ".cpc"
                else:
                    output_path = get_output_filename(input_path, input_dir, output_dir)

                tasks.append((solver_path, input_path, output_path, args.tlimit, mode, cvc5_root))

    print(f"Found {len(tasks)} files. processing with {args.jobs} threads...")

    success_count = 0
    empty_count = 0
    fail_count = 0
    error_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        # Submit all tasks
        future_to_file = {executor.submit(process_file, task): task[1] for task in tasks}

        total = len(tasks)
        completed = 0

        for future in concurrent.futures.as_completed(future_to_file):
            completed += 1
            result = future.result()

            input_file = result["input"]
            status = result["status"]

            progress = f"[{completed}/{total}]"

            if status == "success":
                success_count += 1
                print(f"{progress} OK: {os.path.basename(input_file)} -> {os.path.basename(result['output'])} ({result['duration']:.2f}s, {result['size']} bytes)")
            elif status == "empty":
                empty_count += 1
                # print(f"{progress} EMPTY: {os.path.basename(input_file)}")
            elif status == "failed":
                fail_count += 1
                # print(f"{progress} FAIL: {os.path.basename(input_file)}")
            else:
                error_count += 1
                print(f"{progress} ERROR: {os.path.basename(input_file)} - {result['error']}")

    print("\nSummary:")
    print(f"Total processed: {total}")
    print(f"Success: {success_count}")
    print(f"Empty (discarded): {empty_count}")
    print(f"Failed (no output): {fail_count}")
    print(f"Errors: {error_count}")

    # Deduplicate proofs
    if success_count > 0:
        deduplicate_proofs(output_dir)

if __name__ == "__main__":
    main()

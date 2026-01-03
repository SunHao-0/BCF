#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import csv
import argparse
import math
import statistics
import time
import tempfile
import shutil

def download_and_build_ethos(build_root="build"):
    if not os.path.exists(build_root):
        os.makedirs(build_root, exist_ok=True)

    ethos_dir = os.path.join(build_root, "ethos")
    ethos_dir = os.path.abspath(ethos_dir)
    if not os.path.exists(ethos_dir):
        print("Cloning ethos...")
        try:
            subprocess.check_call(["git", "clone", "https://github.com/cvc5/ethos.git", ethos_dir])
        except subprocess.CalledProcessError as e:
            print(f"Error cloning ethos: {e}")
            return None

    # Ethos executable path (default release build)
    ethos_bin = os.path.join(ethos_dir, "build", "src", "ethos")

    # Check if we have the correct commit
    try:
        current_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ethos_dir, text=True).strip()
    except:
        current_commit = "unknown"

    target_commit = "59e9ea6a077e1fd73dfc3107966b9f5603896c86"

    if os.path.exists(ethos_bin) and current_commit.startswith(target_commit[:7]):
        print("Ethos already built and on correct commit.")
        return ethos_bin

    print("Building ethos...")
    cwd = os.getcwd()
    try:
        os.chdir(ethos_dir)
        # Checkout specific commit
        subprocess.check_call(["git", "checkout", target_commit])

        subprocess.check_call(["./configure.sh", "release"])

        build_dir = os.path.join(ethos_dir, "build")
        if not os.path.exists(build_dir):
            os.makedirs(build_dir, exist_ok=True)

        os.chdir(build_dir)
        subprocess.check_call(["make", "-j8"])
    except Exception as e:
        print(f"Error building ethos: {e}")
        return None
    finally:
        os.chdir(cwd)

    return ethos_bin

def _run_benchmark_common(base_cmd, proof_path, runs=10, warmup=2, timeout=30):
    try:
        file_size = os.path.getsize(proof_path)

        # Warmup
        for _ in range(warmup):
            subprocess.run(base_cmd, capture_output=True, timeout=timeout)

        times = []
        mems = []
        status = 0

        has_time_cmd = shutil.which("time") is not None

        for _ in range(runs):
            start_t = time.perf_counter_ns()

            if has_time_cmd:
                 with tempfile.NamedTemporaryFile(mode='w+') as tmp:
                    # -f %M gives max RSS in KB
                    cmd = ["/usr/bin/time", "-f", "%M", "-o", tmp.name] + base_cmd
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                    end_t = time.perf_counter_ns()

                    # Read memory
                    tmp.seek(0)
                    mem_str = tmp.read().strip()
                    try:
                        mem_kb = int(mem_str)
                        mems.append(mem_kb * 1024) # Convert to bytes
                    except ValueError:
                        mems.append(0)
            else:
                cmd = base_cmd
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                end_t = time.perf_counter_ns()
                mems.append(0)

            duration_us = (end_t - start_t) / 1000.0
            times.append(duration_us)

            # Check internal status if available (or return code)
            if result.returncode != 0:
                status = result.returncode

        if not times:
            return None

        return {
            'filename': os.path.basename(proof_path),
            'file_size': file_size,
            'status': status,
            'all_times': times,
            'all_mems': mems,
            'time_us_avg': statistics.mean(times),
            'time_us_stdev': statistics.stdev(times) if len(times) > 1 else 0,
            'time_us_min': min(times),
            'time_us_max': max(times),
            'memory_bytes': max(mems)
        }
    except subprocess.TimeoutExpired:
        print(f"Timeout running benchmark on {proof_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Exception running benchmark on {proof_path}: {e}", file=sys.stderr)
        return None

def run_ethos_benchmark(checker_path, proof_path, runs=10, warmup=2):
    return _run_benchmark_common([checker_path, proof_path], proof_path, runs, warmup)

def run_benchmark_external(checker_path, proof_path, runs=10, warmup=2):
    """
    Benchmarks checker using external tools (time command and Python timer).
    Used for fair comparison with Ethos (which is also benchmarked externally).
    """
    return _run_benchmark_common([checker_path, "-b", proof_path], proof_path, runs, warmup)

def run_benchmark(checker_path, proof_path, runs=10, warmup=2):
    try:
        file_size = os.path.getsize(proof_path)

        for _ in range(warmup):
            cmd = [checker_path, "-b", proof_path]
            subprocess.run(cmd, capture_output=True)

        times = []
        mems = []
        status = 0

        for _ in range(runs):
            cmd = [checker_path, "-b", proof_path]
            result = subprocess.run(cmd, capture_output=True, text=True)

            output_lines = result.stdout.strip().split('\n')
            json_line = None
            for line in reversed(output_lines):
                if line.strip().startswith('{') and 'time_us' in line:
                    json_line = line.strip()
                    break

            if json_line:
                data = json.loads(json_line)
                times.append(data['time_us'])
                mems.append(data['memory_bytes'])
                if data['status'] != 0:
                    status = data['status']
            else:
                if result.stderr:
                    print(f"Error output for {proof_path}:\n{result.stderr}", file=sys.stderr)
                return None

        if not times:
            return None

        return {
            'filename': os.path.basename(proof_path),
            'file_size': file_size,
            'status': status,
            'all_times': times,
            'all_mems': mems,
            'time_us_avg': statistics.mean(times),
            'time_us_stdev': statistics.stdev(times) if len(times) > 1 else 0,
            'time_us_min': min(times),
            'time_us_max': max(times),
            'memory_bytes': max(mems) # Memory usage should be deterministic, max is safe
        }

    except Exception as e:
        print(f"Exception running benchmark on {proof_path}: {e}", file=sys.stderr)
        return None

def calculate_correlation(x, y):
    n = len(x)
    if n != len(y) or n == 0:
        return 0

    mean_x = sum(x) / n
    mean_y = sum(y) / n

    numerator = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))

    sum_sq_diff_x = sum((xi - mean_x) ** 2 for xi in x)
    sum_sq_diff_y = sum((yi - mean_y) ** 2 for yi in y)

    denominator = math.sqrt(sum_sq_diff_x * sum_sq_diff_y)

    if denominator == 0:
        return 0

    return numerator / denominator

def plot_figures(results):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n[!] matplotlib not installed. Skipping figure generation.")
        return

    plot_results = results
    all_sizes_kb = []
    all_times_ms = []
    all_mems_kb = []

    for r in plot_results:
        sz = r['file_size'] / 1024.0
        times = r.get('_all_times', [r['time_us_avg']])
        mems = r.get('_all_mems', [r['memory_bytes']])

        for t in times:
            all_sizes_kb.append(sz)
            all_times_ms.append(t / 1000.0)

        for m in mems:
            all_mems_kb.append(m / 1024.0)

    import shutil
    if shutil.which('latex'):
        plt.rcParams.update({
            "text.usetex": True,
            "font.family": "serif",
            "font.serif": ["Computer Modern Roman"],
        })
    else:
        plt.rcParams.update({
            "font.family": "serif",
            "mathtext.fontset": "cm",
        })

    plt.rcParams.update({
        'font.size': 12,
        'axes.labelsize': 14,
        'axes.titlesize': 14,
        'xtick.labelsize': 12,
        'ytick.labelsize': 12,
        'legend.fontsize': 12,
        'figure.figsize': (6, 4),
        'axes.grid': True,
        'grid.alpha': 0.3,
        'grid.linestyle': ':',
    })

    def plot_scatter(x, y, xlabel, ylabel, filename, color, log_scale=False):
        plt.figure()

        if log_scale:
            plt.xscale('log')
            plt.yscale('log')
            x_clean, y_clean = [], []
            for xi, yi in zip(x, y):
                if xi > 0 and yi > 0:
                    x_clean.append(xi)
                    y_clean.append(yi)

            plt.scatter(x_clean, y_clean, alpha=0.5, c=color, edgecolors='none', s=15)

            if len(x_clean) > 1:
                lx = [math.log(xi) for xi in x_clean]
                ly = [math.log(yi) for yi in y_clean]

                n = len(lx)
                m_x = sum(lx) / n
                m_y = sum(ly) / n
                ss_xy = sum(xi*yi for xi, yi in zip(lx, ly)) - n * m_x * m_y
                ss_xx = sum(xi*xi for xi in lx) - n * m_x * m_x

                if ss_xx != 0:
                    k = ss_xy / ss_xx
                    b = m_y - k * m_x

                    # Plot fit line
                    min_x, max_x = min(x_clean), max(x_clean)
                    x_fit = [min_x, max_x]
                    y_fit = [math.exp(b) * (xi**k) for xi in x_fit]

                    eq_str = f"y = {math.exp(b):.2f}x^{{{k:.2f}}}"
                    if plt.rcParams.get("text.usetex"):
                        eq_str = f"$y = {math.exp(b):.2f}x^{{{k:.2f}}}$"

                    plt.plot(x_fit, y_fit, 'k--', alpha=0.8, linewidth=1.5, label=f'Fit: {eq_str}')
                    plt.legend(frameon=True, fancybox=False, edgecolor='k')

        else:
            plt.scatter(x, y, alpha=0.5, c=color, edgecolors='none', s=15)
            # Add trend line using all data points
            if len(x) > 1:
                # Simple linear regression
                n = len(x)
                m_x = sum(x) / n
                m_y = sum(y) / n
                ss_xy = sum(xi*yi for xi, yi in zip(x, y)) - n * m_x * m_y
                ss_xx = sum(xi*xi for xi in x) - n * m_x * m_x
                if ss_xx != 0:
                    b1 = ss_xy / ss_xx
                    b0 = m_y - b1 * m_x

                    # Plot line
                    min_x, max_x = min(x), max(x)
                    # extend line a bit
                    x_line = [min_x, max_x]
                    y_line = [b0 + b1 * xi for xi in x_line]

                    # Equation string
                    eq_str = f"y = {b1:.2f}x + {b0:.2f}"
                    if plt.rcParams.get("text.usetex"):
                        eq_str = f"$y = {b1:.2f}x + {b0:.2f}$"

                    plt.plot(x_line, y_line, 'k--', alpha=0.8, linewidth=1.5, label=f'Fit: {eq_str}')
                    plt.legend(frameon=True, fancybox=False, edgecolor='k')

            # Set x-axis ticks at standard size intervals (0, 1024, 2048, ...) for proof size plots
            if "Proof Size" in xlabel:
                min_x, max_x = min(x), max(x)
                # Round to nearest 1024 boundary
                tick_start = int(min_x // 1024) * 1024
                tick_end = int((max_x // 1024) + 1) * 1024
                # Generate ticks at 1024 intervals
                x_ticks = list(range(tick_start, tick_end + 1, 1024))
                if x_ticks:
                    plt.xticks(x_ticks)

        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Saved figure to {filename}")

    def plot_box(x, y, xlabel, ylabel, filename, color):
        plt.figure()

        # Group x into bins
        if not x: return

        # Determine bins - let's use 10 bins based on x range
        min_x, max_x = min(x), max(x)
        if min_x == max_x:
            # Single value case
            bins = [min_x]
            binned_data = [y]
            labels = [f"{min_x:.1f}"]
        else:
            num_bins = 10
            bin_width = (max_x - min_x) / num_bins

            # Create bins
            bins = []
            binned_data = []
            labels = []

            for i in range(num_bins):
                bin_start = min_x + i * bin_width
                bin_end = min_x + (i + 1) * bin_width

                # Collect y values for x in [bin_start, bin_end]
                # Include bin_end for the last bin to catch max_x
                if i == num_bins - 1:
                    y_in_bin = [yi for xi, yi in zip(x, y) if bin_start <= xi <= bin_end + 1e-9]
                else:
                    y_in_bin = [yi for xi, yi in zip(x, y) if bin_start <= xi < bin_end]

                if y_in_bin:
                    bins.append((bin_start + bin_end) / 2)
                    binned_data.append(y_in_bin)
                    # Label range
                    if bin_end < 10:
                        labels.append(f"{bin_start:.1f}-{bin_end:.1f}")
                    else:
                        labels.append(f"{int(bin_start)}-{int(bin_end)}")

        if binned_data:
            # Create boxplot
            bp = plt.boxplot(binned_data,
                            patch_artist=True,
                            # showfliers=False, # Hide outliers to focus on the main distribution
                            medianprops=dict(color="black", linewidth=1.5),
                            flierprops=dict(marker='o', markerfacecolor=color, markersize=4, linestyle='none', alpha=0.5))

            # Color boxes
            for patch in bp['boxes']:
                patch.set_facecolor(color)
                patch.set_alpha(0.6)

            plt.xticks(range(1, len(labels) + 1), labels, rotation=45)
            plt.xlabel(xlabel)
            plt.ylabel(ylabel)
            plt.grid(True, linestyle=':', alpha=0.3)
            plt.tight_layout()
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
            print(f"Saved figure to {filename}")

    print("\nGenerating figures...")
    plot_scatter(all_sizes_kb, all_times_ms, "Proof Size (KiB)", "Check Time (ms)", "bench_size_time.pdf", "#1f77b4")
    plot_scatter(all_sizes_kb, all_times_ms, "Proof Size (KiB) [Log]", "Check Time (ms) [Log]", "bench_size_time_log.pdf", "#1f77b4", log_scale=True)
    plot_box(all_sizes_kb, all_times_ms, "Proof Size (KiB)", "Check Time (ms)", "bench_size_time_box.pdf", "#1f77b4")

    size_for_mem = []
    mem_vals_kb = []
    for r in plot_results:
        sz = r['file_size'] / 1024.0
        mems = r.get('all_mems', [r['memory_bytes']])
        for m in mems:
            size_for_mem.append(sz)
            mem_vals_kb.append(m / 1024.0)

    plot_scatter(size_for_mem, mem_vals_kb, "Proof Size (KiB)", "Memory Usage (KiB)", "bench_size_mem.pdf", "#ff7f0e")
    plot_scatter(size_for_mem, mem_vals_kb, "Proof Size (KiB) [Log]", "Memory Usage (KiB) [Log]", "bench_size_mem_log.pdf", "#ff7f0e", log_scale=True)
    plot_box(size_for_mem, mem_vals_kb, "Proof Size (KiB)", "Memory Usage (KiB)", "bench_size_mem_box.pdf", "#ff7f0e")

    # Time vs Mem (Time[i] vs Mem[i] for each run)
    time_for_mem = []
    mem_for_time = []
    for r in plot_results:
        times = r.get('all_times', [r['time_us_avg']])
        mems = r.get('all_mems', [r['memory_bytes']])
        for t, m in zip(times, mems):
            time_for_mem.append(t / 1000.0)
            mem_for_time.append(m / 1024.0)

    plot_scatter(time_for_mem, mem_for_time, "Check Time (ms)", "Memory Usage (KiB)", "bench_time_mem.pdf", "#2ca02c")

def compare_results(bcf_csv, ethos_csv):
    print(f"\nComparing {bcf_csv} vs {ethos_csv}...")
    try:
        bcf_data = {}
        with open(bcf_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Key by base name (remove extension)
                base = os.path.splitext(row['filename'])[0]
                # filter out rows with status != 0
                if int(row['status']) != 0:
                    continue
                bcf_data[base] = row

        ethos_data = {}
        with open(ethos_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                base = os.path.splitext(row['filename'])[0]
                # filter out rows with status != 0
                if int(row['status']) != 0:
                    continue
                ethos_data[base] = row

        # Intersection
        common = sorted(list(set(bcf_data.keys()) & set(ethos_data.keys())))
        print(f"Found {len(common)} common proofs.")

        # Analyze common set distribution
        bcf_common_sizes = []
        for base in common:
            try:
                bcf_common_sizes.append(float(bcf_data[base]['file_size']) / 1024.0)
            except: pass

        print("\nCommon Proof Set Distribution (BCF Size):")
        if bcf_common_sizes:
            print(f"  Count:  {len(bcf_common_sizes)}")
            print(f"  Min:    {min(bcf_common_sizes):.2f} KB")
            print(f"  Max:    {max(bcf_common_sizes):.2f} KB")
            print(f"  Avg:    {statistics.mean(bcf_common_sizes):.2f} KB")
            print(f"  Median: {statistics.median(bcf_common_sizes):.2f} KB")
            # Quantiles
            quartiles = statistics.quantiles(bcf_common_sizes, n=4)
            print(f"  25th %: {quartiles[0]:.2f} KB")
            print(f"  75th %: {quartiles[2]:.2f} KB")

            # Print percentiles
            deciles = statistics.quantiles(bcf_common_sizes, n=10)
            print("  Deciles: " + ", ".join([f"{d:.1f}" for d in deciles]))

        if not common:
            return

        bcf_times = [] # us
        ethos_times = [] # us
        bcf_mems = [] # KB
        ethos_mems = [] # KB
        bcf_sizes = [] # KB
        ethos_sizes = [] # KB

        speedups = []
        mem_factors = []
        size_factors = []
        size_reductions = []

        for base in common:
            # Parse values
            b_t = float(bcf_data[base]['time_us_avg'])
            e_t = float(ethos_data[base]['time_us_avg'])
            b_m = float(bcf_data[base]['memory_bytes']) / 1024.0
            e_m = float(ethos_data[base]['memory_bytes']) / 1024.0
            b_s = float(bcf_data[base]['file_size']) / 1024.0
            e_s = float(ethos_data[base]['file_size']) / 1024.0

            # Ensure time is in us for both
            # BCF time is in us
            # Ethos time from run_ethos_benchmark is also in us (time.perf_counter * 1_000_000)

            bcf_times.append(b_t)
            ethos_times.append(e_t)
            bcf_mems.append(b_m)
            ethos_mems.append(e_m)
            bcf_sizes.append(b_s)
            ethos_sizes.append(e_s)

            # Factors (Improvements)
            if b_t > 0: speedups.append(e_t / b_t)
            if b_m > 0: mem_factors.append(e_m / b_m)
            if e_s > 0:
                size_factors.append(b_s / e_s)
                size_reductions.append((b_s - e_s) / b_s * 100)

        def print_stat_block(name, data, unit=""):
            if not data: return
            print(f"\n{name} Statistics:")
            print(f"  Min:    {min(data):.2f} {unit}")
            print(f"  Max:    {max(data):.2f} {unit}")
            print(f"  Avg:    {statistics.mean(data):.2f} {unit}")
            print(f"  Median: {statistics.median(data):.2f} {unit}")
            if len(data) > 1:
                print(f"  Stdev:  {statistics.stdev(data):.2f} {unit}")

        print_stat_block("Checking Time (BCF)", bcf_times, "us")
        print_stat_block("Checking Time (Ethos)", ethos_times, "us")
        print_stat_block("Speedup (Ethos Time / BCF Time)", speedups, "x")

        print_stat_block("Memory Usage (BCF)", bcf_mems, "KB")
        print_stat_block("Memory Usage (Ethos)", ethos_mems, "KB")
        print_stat_block("Memory Factor (Ethos Mem / BCF Mem)", mem_factors, "x")

        print_stat_block("Proof Size (BCF)", bcf_sizes, "KB")
        print_stat_block("Proof Size (CPC)", ethos_sizes, "KB")
        print_stat_block("Size Factor (BCF Size / CPC Size)", size_factors, "x")
        if size_factors:
            inverse_factors = [1/s for s in size_factors if s > 0]
            print_stat_block("Inverse Size Factor (CPC Size / BCF Size)", inverse_factors, "x")

        # Plotting
        try:
            import matplotlib.pyplot as plt
            import matplotlib.colors as mcolors

            # Helper for density plots
            def plot_density(x, y, xlabel, ylabel, title, filename, log=True):
                 plt.figure(figsize=(8, 6))

                 if log:
                     x_clean, y_clean = [], []
                     for xi, yi in zip(x, y):
                         if xi > 0 and yi > 0:
                             x_clean.append(xi)
                             y_clean.append(yi)
                     x, y = x_clean, y_clean
                     # We don't set plt.xscale/yscale here if using hexbin with xscale param,
                     # but we need it for scatter. We'll set it conditionally below.

                 if not x:
                     print(f"Warning: No valid data for {filename}")
                     plt.close()
                     return

                 if len(x) > 1000:
                     # Use hexbin for large datasets
                     # Note: xscale='log' for hexbin requires matplotlib 3.4+
                     hb_args = {'gridsize': 50, 'cmap': 'viridis', 'bins': 'log', 'mincnt': 1}
                     if log:
                         hb_args['xscale'] = 'log'
                         hb_args['yscale'] = 'log'
                         # Ensure axes are log scaled too (hexbin might do it, but explicit is safe)
                         plt.xscale('log')
                         plt.yscale('log')

                     hb = plt.hexbin(x, y, **hb_args)
                     cb = plt.colorbar(hb, label='Count (log)')
                 else:
                     if log:
                         plt.xscale('log')
                         plt.yscale('log')
                     plt.scatter(x, y, alpha=0.5, s=15, edgecolors='none')

                 # Diagonal line
                 if x and y:
                     low = min(min(x), min(y))
                     high = max(max(x), max(y))
                     plt.plot([low, high], [low, high], 'r--', alpha=0.7, label='y=x')
                     plt.legend()

                 plt.xlabel(xlabel)
                 plt.ylabel(ylabel)
                 plt.title(title)
                 plt.grid(True, which="both", ls=":", alpha=0.3)
                 plt.tight_layout()
                 plt.savefig(filename)
                 plt.close()
                 print(f"Saved {filename}")

            plot_density(bcf_times, ethos_times, "BCF Time (us)", "Ethos Time (us)", "Checking Time Comparison", "compare_time_log.pdf", log=True)
            plot_density(bcf_mems, ethos_mems, "BCF Memory (KB)", "Ethos Memory (KB)", "Memory Usage Comparison", "compare_mem_log.pdf", log=True)
            plot_density(bcf_sizes, ethos_sizes, "BCF Size (KB)", "CPC Size (KB)", "Proof Size Comparison", "compare_size_log.pdf", log=True)

            # Histogram for Speedups
            plt.figure(figsize=(8, 6))
            plt.hist(speedups, bins=50, color='skyblue', edgecolor='black', log=True)
            plt.xlabel("Speedup Factor (Ethos Time / BCF Time)")
            plt.ylabel("Count (Log)")
            plt.title("Distribution of Speedups (BCF vs Ethos)")
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig("speedup_hist.pdf")
            plt.close()
            print("Saved speedup_hist.pdf")

            # Histogram for Memory Factors
            plt.figure(figsize=(8, 6))
            plt.hist(mem_factors, bins=50, color='lightgreen', edgecolor='black', log=True)
            plt.xlabel("Memory Factor (Ethos Mem / BCF Mem)")
            plt.ylabel("Count (Log)")
            plt.title("Distribution of Memory Reduction (BCF vs Ethos)")
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig("mem_factor_hist.pdf")
            plt.close()
            print("Saved mem_factor_hist.pdf")

        except ImportError:
            print("matplotlib not found, skipping comparison plots.")

    except Exception as e:
        print(f"Error comparing results: {e}")

def analyze(results):
    if not results:
        return

    valid_results = [r for r in results if r['status'] == 0]
    if not valid_results:
        print("\nNo successful verifications to analyze.")
        return

    print(f"\nAnalysis on {len(valid_results)} successful proofs:")

    sizes = [r['file_size'] for r in valid_results]
    times_us = [r['time_us_avg'] for r in valid_results]
    mems = [r['memory_bytes'] for r in valid_results]

    def print_stats(label, data, scale, unit):
        scaled = [d * scale for d in data]
        if not scaled: return
        print(f"\n{label} ({unit}):")
        print(f"  Min:    {min(scaled):.2f}")
        print(f"  Max:    {max(scaled):.2f}")
        print(f"  Avg:    {statistics.mean(scaled):.2f}")
        if len(scaled) > 1:
            print(f"  Median: {statistics.median(scaled):.2f}")
            print(f"  StdDev: {statistics.stdev(scaled):.2f}")
        print(f"  Total:  {sum(scaled):.2f}")

    print_stats("Proof Size", sizes, 1.0/1024, "KiB")
    print_stats("Check Time", times_us, 1.0, "us")
    print_stats("Memory Usage", mems, 1.0/1024, "KiB")

    corr_size_time = calculate_correlation(sizes, times_us)
    corr_size_mem = calculate_correlation(sizes, mems)
    corr_time_mem = calculate_correlation(times_us, mems)

    print("\nCorrelations (Pearson coefficient):")
    print(f"File Size vs Check Time: {corr_size_time:.4f}")
    print(f"File Size vs Memory:     {corr_size_mem:.4f}")
    print(f"Check Time vs Memory:    {corr_time_mem:.4f}")

    total_size_mb = sum(sizes) / (1024*1024)
    total_time_s = sum(times_us) / 1e6
    if total_time_s > 0:
        print(f"\nThroughput: {total_size_mb/total_time_s:.2f} MB/s")

    plot_figures(valid_results)

def run_benchmark_suite(files, base_dir, runner_func, csv_path, description):
    print(f"Found {len(files)} files. {description}")
    print(f"{'Filename':<40} {'Size (KB)':<10} {'Time (us)':<15} {'Mem (KB)':<10} {'Status'}")
    print("-" * 85)

    results = []
    for f in files:
        path = os.path.join(base_dir, f)
        data = runner_func(path)

        status_str = "ERR"
        time_str = "-"
        mem_str = "-"
        size_str = "-"

        if data:
            results.append(data)
            status_str = "OK" if data['status'] == 0 else f"FAIL({data['status']})"

            # Format time string, handle missing stdev
            avg = data.get('time_us_avg', 0)
            stdev = data.get('time_us_stdev', 0)
            if stdev > 0:
                time_str = f"{avg:.0f} ({stdev:.1f})"
            else:
                time_str = f"{avg:.0f}"

            mem_str = f"{data.get('memory_bytes', 0)/1024:.0f}"
            size_str = f"{data.get('file_size', 0)/1024:.1f}"

        print(f"{f[:37]+'...' if len(f)>40 else f:<40} {size_str:<10} {time_str:<15} {mem_str:<10} {status_str}")

    if results:
        keys = ['filename', 'file_size', 'time_us_avg', 'time_us_min', 'time_us_max', 'time_us_stdev', 'memory_bytes', 'status']
        try:
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for r in results:
                     # Ensure we only write known keys to avoid errors if extra keys exist or missing keys
                    row = {k: r.get(k) for k in keys}
                    writer.writerow(row)
            print(f"\nResults saved to {csv_path}")
        except IOError as e:
            print(f"Error saving CSV: {e}", file=sys.stderr)

    return results

def main():
    parser = argparse.ArgumentParser(description='Benchmark BCF Checker')
    parser.add_argument('proof_dir', nargs='?', default='./bcf-proofs', help='Directory containing proof files')
    parser.add_argument('--checker', default='./bcf-checker', help='Path to bcf_checker executable')
    parser.add_argument('--ext', default='.bcf', help='Proof file extension (default: .bcf)')
    parser.add_argument('--csv', default='benchmark_results.csv', help='Output CSV file')
    parser.add_argument('--runs', type=int, default=10, help='Number of runs per file')
    parser.add_argument('--warmup', type=int, default=2, help='Number of warmup runs')
    parser.add_argument('--analyze-only', action='store_true', help='Only analyze existing CSV file')
    parser.add_argument('--bench-ethos', action='store_true', help='Benchmark Ethos checker')
    parser.add_argument('--bench-bcf-external', action='store_true', help='Benchmark BCF checker using external tools (fair comparison)')
    parser.add_argument('--ethos-csv', default='ethos_results.csv', help='Ethos output CSV file')
    parser.add_argument('--cpc-dir', default='cpc_proofs', help='Directory containing CPC proofs')
    parser.add_argument('--compare-only', action='store_true', help='Only compare BCF and Ethos CSV files')

    args = parser.parse_args()

    results = []

    checker_path = os.path.abspath(args.checker)

    if args.bench_bcf_external:
        if not os.path.exists(checker_path):
            print(f"Checker not found at {checker_path}. Try running 'make' first.", file=sys.stderr)
            sys.exit(1)

        if not os.path.exists(args.proof_dir):
            print(f"Proof directory {args.proof_dir} does not exist.", file=sys.stderr)
            sys.exit(1)

        files = [f for f in os.listdir(args.proof_dir) if f.endswith(args.ext)]
        files.sort()

        results = run_benchmark_suite(
            files,
            args.proof_dir,
            lambda p: run_benchmark_external(checker_path, p, runs=args.runs, warmup=args.warmup),
            args.csv,
            f"Running BCF External Benchmark (warmup={args.warmup}, runs={args.runs})..."
        )

        if results:
             analyze(results)
        return

    if args.bench_ethos:
        ethos_path = download_and_build_ethos()
        if not ethos_path:
            sys.exit(1)

        cpc_dir = os.path.abspath(args.cpc_dir)
        if not os.path.exists(cpc_dir):
            print(f"Error: CPC directory {cpc_dir} does not exist.")
            sys.exit(1)

        files = [f for f in os.listdir(cpc_dir) if f.endswith(".cpc")]
        files.sort()

        # Filter using BCF results if available
        if os.path.exists(args.csv):
            try:
                valid_bcf_bases = set()
                with open(args.csv, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if int(row['status']) == 0:
                            # Assuming filename is like bench_xxxx.bcf
                            base = os.path.splitext(row['filename'])[0]
                            valid_bcf_bases.add(base)

                print(f"Filtering proofs based on {len(valid_bcf_bases)} successful BCF checks from {args.csv}...")
                original_count = len(files)
                files = [f for f in files if os.path.splitext(f)[0] in valid_bcf_bases]
                print(f"Filtered {original_count} -> {len(files)} proofs.")

            except Exception as e:
                print(f"Warning: Could not filter using BCF results: {e}")

        results = run_benchmark_suite(
            files,
            cpc_dir,
            lambda p: run_ethos_benchmark(ethos_path, p, runs=args.runs, warmup=args.warmup),
            args.ethos_csv,
            "Running Ethos benchmark..."
        )

        if results:
            if os.path.exists(args.csv):
                compare_results(args.csv, args.ethos_csv)
            else:
                print(f"BCF results {args.csv} not found, skipping comparison.")

        return

    if args.compare_only:
        if not os.path.exists(args.csv):
            print(f"Error: BCF results file {args.csv} does not exist.", file=sys.stderr)
            sys.exit(1)
        if not os.path.exists(args.ethos_csv):
            print(f"Error: Ethos results file {args.ethos_csv} does not exist.", file=sys.stderr)
            sys.exit(1)

        compare_results(args.csv, args.ethos_csv)

        return

    if args.analyze_only:
        if not os.path.exists(args.csv):
            print(f"Error: CSV file {args.csv} does not exist.", file=sys.stderr)
            sys.exit(1)

        try:
            with open(args.csv, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    row['file_size'] = int(row['file_size'])
                    row['time_us_avg'] = float(row['time_us_avg'])
                    row['memory_bytes'] = int(row['memory_bytes'])
                    row['status'] = int(row['status'])
                    results.append(row)

            analyze(results)
            return
        except Exception as e:
            print(f"Error analyzing CSV: {e}", file=sys.stderr)
            sys.exit(1)

    # Default: BCF internal benchmark
    checker_path = os.path.abspath(args.checker)
    if not os.path.exists(checker_path):
        print(f"Checker not found at {checker_path}. Try running 'make' first.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.proof_dir):
        print(f"Proof directory {args.proof_dir} does not exist.", file=sys.stderr)
        sys.exit(1)

    files = [f for f in os.listdir(args.proof_dir) if f.endswith(args.ext)]
    files.sort()

    if not files:
        print(f"No files found with extension {args.ext} in {args.proof_dir}", file=sys.stderr)
        sys.exit(1)

    results = run_benchmark_suite(
        files,
        args.proof_dir,
        lambda p: run_benchmark(checker_path, p, runs=args.runs, warmup=args.warmup),
        args.csv,
        f"Running benchmark (warmup={args.warmup}, runs={args.runs})..."
    )

    if results:
        analyze(results)

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import csv
import argparse
import math
import statistics

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

    # Filter outliers to focus on the main trend (remove top 10% by size)
    # This addresses the issue of "rare big proofs" obscuring the trend of frequent small proofs.
    plot_results = results
    # if len(results) > 10:
    #     results_sorted = sorted(results, key=lambda x: x['file_size'])
    #     # Use 90th percentile as cutoff to focus on the dense region
    #     cutoff_index = int(len(results) * 0.90)
    #     cutoff_size = results_sorted[cutoff_index]['file_size']

    #     plot_results = [r for r in results if r['file_size'] <= cutoff_size]
    #     print(f"\n[Visuals] Filtering top 10% outliers (> {cutoff_size/1024:.1f} KB) to visualize main trend.")
    #     print(f"Plotting {len(plot_results)}/{len(results)} proofs.")

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

def main():
    parser = argparse.ArgumentParser(description='Benchmark BCF Checker')
    parser.add_argument('proof_dir', default='./bcf-proofs', help='Directory containing proof files')
    parser.add_argument('--checker', default='./bcf-checker', help='Path to bcf_checker executable')
    parser.add_argument('--ext', default='.bcf', help='Proof file extension (default: .bcf)')
    parser.add_argument('--csv', default='benchmark_results.csv', help='Output CSV file')
    parser.add_argument('--runs', type=int, default=10, help='Number of runs per file')
    parser.add_argument('--warmup', type=int, default=2, help='Number of warmup runs')
    parser.add_argument('--analyze-only', action='store_true', help='Only analyze existing CSV file')
    args = parser.parse_args()

    results = []

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

    print(f"Found {len(files)} files. Running benchmark (warmup={args.warmup}, runs={args.runs})...")
    print(f"{'Filename':<40} {'Size (KB)':<10} {'Time (us)':<15} {'Mem (KB)':<10} {'Status'}")
    print("-" * 85)

    for f in files:
        path = os.path.join(args.proof_dir, f)
        data = run_benchmark(checker_path, path, runs=args.runs, warmup=args.warmup)

        status_str = "ERR"
        time_str = "-"
        mem_str = "-"
        size_str = "-"

        if data:
            results.append(data)
            status_str = "OK" if data['status'] == 0 else f"FAIL({data['status']})"
            time_str = f"{data['time_us_avg']:.0f} ({data['time_us_stdev']:.1f})"
            mem_str = f"{data['memory_bytes']/1024:.0f}"
            size_str = f"{data['file_size']/1024:.1f}"

        print(f"{f[:37]+'...' if len(f)>40 else f:<40} {size_str:<10} {time_str:<15} {mem_str:<10} {status_str}")

    if results:
        keys = ['filename', 'file_size', 'time_us_avg', 'time_us_min', 'time_us_max', 'time_us_stdev', 'memory_bytes', 'status']
        try:
            with open(args.csv, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for r in results:
                    writer.writerow({k: r.get(k) for k in keys})
            print(f"\nResults saved to {args.csv}")
        except IOError as e:
            print(f"Error saving CSV: {e}", file=sys.stderr)

        analyze(results)

if __name__ == '__main__':
    main()

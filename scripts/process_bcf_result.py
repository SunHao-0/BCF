#!/usr/bin/env python3

import argparse
import csv
import json
import os
import sys
import numpy as np
import matplotlib.pyplot as plt


verbose = False

def is_tty():
    return sys.stdout.isatty()

def info(msg):
    if verbose and is_tty():
        print("\033[94m[*]\033[0m", msg)

def ack(msg):
    print("\033[93m[*]\033[0m", msg)


def ok(msg):
    if is_tty():
        print("\033[92m[+]\033[0m", msg)
    else:
        print("[+]", msg)

def warn(msg):
    if is_tty():
        print("\033[91m[!]\033[0m", msg)
    else:
        print("[!]", msg)


def extract_vlogs(log):
    """
    Extracts vlogs (verifier logs) from a given log string.

    This function searches for sections in the log string that are enclosed
    between the markers "-- BEGIN PROG LOAD LOG --" and "-- END PROG LOAD LOG --".
    It extracts these sections and returns them as a list of strings.

    Args:
        log (str): The log string from which to extract vlogs.

    Returns:
        list of str: A list of extracted vlogs.
    """
    vlog_begin = "-- BEGIN PROG LOAD LOG --"
    vlog_end = "-- END PROG LOAD LOG --"
    vlogs = []
    start_idx = log.find(vlog_begin)
    while start_idx != -1:
        start_idx += len(vlog_begin)
        end_idx = log.find(vlog_end, start_idx)
        if end_idx == -1:
            warn("broken vlog")
            break

        vlog = log[start_idx:end_idx]
        vlogs.append(vlog)
        start_idx = log.find(vlog_begin, end_idx)

    if len(vlogs) == 0:
        warn("no vlogs found")

    return vlogs


class VerifierResult:
    def __init__(self, summary, bcf_stats=[], verification_time=0, insn_processed=0):
        self.summary = summary
        self.bcf_stats = bcf_stats
        self.verification_time = verification_time
        self.insn_processed = insn_processed

    def to_dict(self):
        return {
            "summary": self.summary,
            "bcf_stats": [stat.to_dict() for stat in self.bcf_stats],
            "verification_time": self.verification_time,
            "insn_processed": self.insn_processed
        }

    @staticmethod
    def from_dict(d):
        return VerifierResult(d["summary"], [BCFStats.from_dict(stat) for stat in d["bcf_stats"]], d["verification_time"], d["insn_processed"])


class BCFStats:
    def __init__(self, check_nth, check_time, proof_size, refine_type, backtrack_length, track_length, cond_size):
        self.check_nth = check_nth
        self.check_time = check_time
        self.proof_size = proof_size
        self.refine_type = refine_type
        self.backtrack_length = backtrack_length
        self.track_length = track_length
        self.cond_size = cond_size

    def to_dict(self):
        return {
            "check_nth": self.check_nth,
            "check_time": self.check_time,
            "proof_size": self.proof_size,
            "refine_type": self.refine_type,
            "backtrack_length": self.backtrack_length,
            "track_length": self.track_length,
            "cond_size": self.cond_size
        }

    @staticmethod
    def from_dict(d):
        return BCFStats(d["check_nth"], d["check_time"], d["proof_size"], d["refine_type"], d["backtrack_length"], d["track_length"], d["cond_size"])


def summarize_vlog(vlog: str, new_format=True):
    """
    Summarizes the verifire log (vlog) and extracts BCF statistics if available.

    Args:
        vlog (str): The verifier log as a string.

    Returns:
        VerifierResult: The verifier result object containing the summary and BCF statistics.
    """
    lines = vlog.splitlines()
    last_line = lines[-1].strip()

    if "bcf requested" in last_line:
        vsummary = "\n".join(lines[-3:]).strip()
        vresult = VerifierResult(vsummary)
    elif "BPF program is too large" in vlog:
        # verification time 468531 usec
        # stack depth 0+256
        # processed 6595 insns (limit 1000000) max_states_per_insn 10 total_states 385 peak_states 258 mark_read 45

        if not 'verification time' in lines[-3]:
            raise ValueError(
                "The second to last line of the vlog does not contain 'verification time'")
        if not 'stack depth' in lines[-2]:
            raise ValueError(
                "The third to last line of the vlog does not contain 'stack depth'")

        vsummary = "\n".join([lines[-4], lines[-1]]).strip()
        verification_time = int(lines[-3].split()[2])
        insn_processed = int(lines[-1].split()[1])
        vresult = VerifierResult(vsummary, verification_time=verification_time,
                                 insn_processed=insn_processed)
    else:
        if not last_line.startswith("processed"):
            # print("vlog:", lines)
            # raise ValueError(
                # "The last line of the vlog does not start with 'processed': " + last_line)
            return None

        vsummary = last_line
        verification_time = int(lines[-3].split()[2])
        insn_processed = int(last_line.split()[1])
        bcf_stats = []

        if not "bcf proof checked" in vlog:
            return VerifierResult(vsummary, bcf_stats, verification_time, insn_processed)

        # extract bcf stats
        for line in lines:
            if not "bcf proof checked" in line:
                continue
            # extract check-nth, proof size, check time
            # Example line:
            # bcf proof checked 37 nth in 99361 ns, size 1196 bytes, type range backtrack_length 20 track_length 23 cond_size 676
            parts = line.split()
            check_nth = int(parts[3])
            check_time = int(parts[6])
            proof_size = int(parts[9])
            refine_type = parts[12]
            backtrack_length = 0
            track_length = 0
            cond_size = 0
            if new_format:
                backtrack_length = int(parts[14])
                track_length = int(parts[16])
                cond_size = int(parts[18])
            bcf_stats.append(BCFStats(check_nth, check_time, proof_size,
                             refine_type, backtrack_length, track_length, cond_size))

        vresult = VerifierResult(
            vsummary, bcf_stats, verification_time, insn_processed)

    return vresult


def summarize_log(log):
    vlogs = extract_vlogs(log)
    summaries = []
    for vlog in vlogs:
        vresult = summarize_vlog(vlog)
        if vresult is None:
            continue
        summaries.append(vresult)
    return summaries


def summary_dup(s1, s2, no_bcf=False):
    """
    Determine if two objects are duplicates based on their verifier logs.

    Two objects are considered duplicates if:
    - Their lengths are the same.
    - Their verifier logs are identical.
    - Neither of the logs contains "bcf requested".
    - Neither of the logs contains "BPF program is too large."
    - If both logs have non-empty BCF statistics, they are not duplicates.

    Args:
        s1: list of VerifierResult
        s2: list of VerifierResult

    Returns:
        bool: True if the objects are considered duplicates, False otherwise.
    """
    if len(s1) != len(s2):
        return False

    # two objects are duplicate if their verifier logs are the same or bcf not used
    for i in range(len(s1)):
        v1 = s1[i]
        v2 = s2[i]
        if v1.summary == v2.summary:
            continue
        if "bcf requested" in v1.summary or "bcf requested" in v2.summary:
            return False
        if "BPF program is too large." in v1.summary or "BPF program is too large." in v2.summary:
            return False
        if no_bcf:
            return False
        # for accept, we see if bcf is used
        if len(v1.bcf_stats) != 0 or len(v2.bcf_stats) != 0:
            return False
    return True


def dedup_objs(objs, summary_map, accepted_objects, no_bcf=False):
    """
    Deduplicate a list of objects.
    """
    objs = sorted(objs)
    i = 0
    while i < len(objs):
        obj_i_loaded = objs[i] in accepted_objects
        if objs[i] not in summary_map:
            objs.pop(i)
            continue
        j = i + 1
        while j < len(objs):
            obj_j_loaded = objs[j] in accepted_objects
            if obj_i_loaded != obj_j_loaded:
                j += 1
                continue

            if objs[j] not in summary_map:
                objs.pop(j)
                continue
            if summary_dup(summary_map[objs[i]], summary_map[objs[j]], no_bcf):
                objs.pop(j)
            else:
                j += 1
        i += 1
    return objs


def summarize_obj_logs(output_dir, prog_index):
    """
    Summarize the verifier logs of all objects in prog_index.
    """
    summary_map = {}

    # load the sumary map if it exists
    summary_map_file = os.path.join(output_dir, "summary_map.json")
    if os.path.exists(summary_map_file):
        with open(summary_map_file, "r") as f:
            ack(f"Loading summary map from {summary_map_file}")
            summary_dict = json.load(f)
            for obj, summaries in summary_dict.items():
                summary_map[obj] = [
                    VerifierResult.from_dict(s) for s in summaries]
            return summary_map

    ack(f"Extracting verifier log for {len(prog_index)} projects")
    for project, groups in prog_index.items():
        obj_n = len([obj for _, objs in groups.items() for obj in objs])
        ack(f"\t{project} ({obj_n} objects)...")
        for _, objs in groups.items():
            for obj in objs:
                log_file = os.path.join(output_dir, project, obj + ".log")
                # skip if the log file does not exist
                if not os.path.exists(log_file):
                    warn(f"Log file {log_file} not found")
                    continue
                with open(log_file, "r") as f:
                    log = f.read()
                ack(f"Summarizing log for {obj}")
                summaries = summarize_log(log)

                info(f"{obj}: {len(summaries)} vlogs")
                summary_map[obj] = summaries

    with open(summary_map_file, "w") as f:
        summary_dict = {k: [v.to_dict() for v in vs]
                        for k, vs in summary_map.items()}
        json.dump(summary_dict, f, indent=2)
        ack(f"Saved summary map to {summary_map_file}")

    return summary_map


def accepted_objects_set(output_dir):
    """
    Collect the set of accepted objects from the object_results.csv file.
    """
    accepted_objs = set()
    ack(f"Loading accepted objects from {output_dir}")
    with open(os.path.join(output_dir, "object_results.csv"), "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 5:
                print(f"Invalid row: {row}")
            if row[4] == "loaded":
                accepted_objs.add(row[2])
    return accepted_objs


def dedup_prog_index(output_dir, prog_index, summary_map, no_bcf=False):
    """
    Deduplicates the program index and saves the result to a JSON file.

    Special handling for the project "calico":
    - For "calico", objects from all groups are merged and then deduplicated.
    - The merged objects are stored under a single group named "merged".

    This function processes a given program index, removes duplicate objects
    based on the provided summary map, and saves the deduplicated index to a
    JSON file in the specified output directory. If the deduplicated index file
    already exists, it loads and returns the existing file.

    Args:
        output_dir (str): The directory where the deduplicated index file will be saved.
        prog_index (dict): The original program index containing projects and their groups of objects.
        summary_map (dict): A map used to deduplicate objects.

    Returns:
        dict: The deduplicated program index.
    """
    old_len = 0
    new_len = 0
    new_index = {}
    ack(f"dedup: {len(prog_index)} projects")

    deduped_index_file = os.path.join(output_dir, "deduped_prog_index.json")
    if os.path.exists(deduped_index_file):
        with open(deduped_index_file, "r") as f:
            return json.load(f)

    accepted_objects = accepted_objects_set(output_dir)
    for project, groups in prog_index.items():
        new_index[project] = {}

        if project == "collected":
            # we know those objects are unique
            new_index[project] = groups
            # add new len
            for _, objs in groups.items():
                new_len += len(objs)
            continue

        if project == "calico":
            # for calico, we merge objs from all groups and then dedup
            objs = []
            for group, objs_ in groups.items():
                objs.extend(objs_)
            old_len += len(objs)
            objs_unique = dedup_objs(objs, summary_map, accepted_objects, no_bcf)
            new_len += len(objs_unique)
            ack(f"\t{project}: {len(objs)} -> {len(objs_unique)}")
            new_index[project]["merged"] = objs_unique
            continue

        for group, objs in groups.items():
            old_len += len(objs)
            objs_unique = dedup_objs(objs, summary_map, accepted_objects, no_bcf)
            new_len += len(objs_unique)
            ack(f"\t{project}/{group}: {len(objs)} -> {len(objs_unique)}")
            if len(objs_unique) > 0:
                new_index[project][group] = objs_unique

    ack(f"dedup: {old_len} -> {new_len}")

    with open(deduped_index_file, "w") as f:
        json.dump(new_index, f, indent=2)
    return new_index


def process_object_results(output_dir, deduped_prog_index, summary_map, no_bcf=False):
    """
        This function processes the results of object files, preserving only unique objects
        based on the provided deduped_prog_index. It reads from an input CSV file named
        'object_results.csv' located in the output_dir, and writes the unique results to
        'object_results_unique.csv'. Additionally, it generates two other CSV files:
        'bcf_stats.csv' for storing BCF statistics of loaded objects, and 'fail_stats.csv'
        for storing failure reasons of rejected objects.

        Args:
            output_dir (str): The directory where the input and output CSV files are located.
            deduped_prog_index (dict): A dictionary containing the deduplication index for
                                       programs, organized by project and group.
            summary_map (dict): A dictionary mapping objects to their summary information.

        Raises:
            KeyError: If a project or group is not found in the deduped_prog_index.
            FileNotFoundError: If the input CSV file 'object_results.csv' is not found in the output_dir.

        Outputs:
            - 'object_results_unique.csv': Contains the unique object results.
            - 'bcf_stats.csv': Contains BCF statistics for loaded objects.
            - 'fail_stats.csv': Contains failure reasons for rejected objects.
    """
    OBJ_RESULT_FILE = "object_results.csv"
    NEW_OBJ_RESULT_FILE = "object_results_unique.csv"

    # open a bcf stats csv file to record the results of all unique objects
    BCF_STATS_FILE = "bcf_stats.csv"
    if os.path.exists(os.path.join(output_dir, BCF_STATS_FILE)):
        return

    bcf_file = open(os.path.join(output_dir, BCF_STATS_FILE), "w")
    bcf_stat_writer = csv.writer(bcf_file)
    bcf_stat_writer.writerow(["project", "group", "object",
                             "check_nth", "check_time", "proof_size", "refine_type", "backtrack_length", "track_length", "cond_size"])

    FAIL_STATS_FILE = "fail_stats.csv"
    fail_file = open(os.path.join(output_dir, FAIL_STATS_FILE), "w")
    fail_stat_writer = csv.writer(fail_file)
    fail_stat_writer.writerow(["project", "group", "object", "reason"])

    accepted_prog_indx = {}

    with open(os.path.join(output_dir, OBJ_RESULT_FILE), mode="r") as result_csv_file:
        result_csv_reader = csv.reader(result_csv_file)
        with open(os.path.join(output_dir, NEW_OBJ_RESULT_FILE), mode="w") as new_result_csv_file:
            result_csv_writer = csv.writer(new_result_csv_file)
            result_csv_writer.writerow(
                ["project", "group", "object", "prog_type", "status"])
            skip_first = True
            for row in result_csv_reader:
                if skip_first:
                    skip_first = False
                    continue

                project = row[0]
                group = row[1]
                obj = row[2]
                index = deduped_prog_index[project]
                if project == "calico":
                    if obj not in index["merged"]:
                        continue
                elif group not in index or obj not in index[group]:
                    continue

                result_csv_writer.writerow(row)
                if no_bcf:
                    continue

                # for every loaded unique obj, dump bcf stats in a csv file with the following format:
                # project, group, object, check_nth, check_time, proof_size
                summaries = summary_map[obj]
                if row[4] == "loaded":
                    for summary in summaries:
                        for bcf_stat in summary.bcf_stats:
                            bcf_stat_writer.writerow(
                                [project, group, obj, bcf_stat.check_nth, bcf_stat.check_time, bcf_stat.proof_size, bcf_stat.refine_type, bcf_stat.backtrack_length, bcf_stat.track_length, bcf_stat.cond_size])

                    if project not in accepted_prog_indx:
                        accepted_prog_indx[project] = {}
                    if group not in accepted_prog_indx[project]:
                        accepted_prog_indx[project][group] = []
                    accepted_prog_indx[project][group].append(obj)
                else:
                    # for rejected unique objs, we categorize them into two types:
                    # 1. bcf requested, but failed to load due to sat
                    # 2. program too large
                    dumped = False
                    for summary in summaries:
                        if "BPF program is too large." in summary.summary:
                            fail_stat_writer.writerow(
                                [project, group, obj, "path_exceed"])
                            dumped = True
                            break
                        if "bcf requested" in summary.summary:
                            fail_stat_writer.writerow(
                                [project, group, obj, "sat"])
                            dumped = True
                            break

                    if not dumped:
                        fail_stat_writer.writerow(
                            [project, group, obj, "bcf_not_requested"])

    bcf_file.close()
    fail_file.close()
    print(f"Unique object results are saved in {NEW_OBJ_RESULT_FILE}")
    print(f"BCF stats are saved in {BCF_STATS_FILE}")
    print(f"Fail stats are saved in {FAIL_STATS_FILE}")

    # dump the accepted_prog_indx
    with open(os.path.join(output_dir, "accepted_prog_index.json"), "w") as f:
        json.dump(accepted_prog_indx, f, indent=2)


def process_bcf_result(prog_dir, output_dir, no_bcf=False):
    """
    Process the load results.

    Args:
        prog_dir (str): The directory containing all the eBPF programs.
        output_dir (str): The directory containing all project results.
    """
    prog_index_file = os.path.join(prog_dir, "prog_index.json")
    with open(prog_index_file, "r") as f:
        prog_index = json.load(f)
    ack(f"Loaded {len(prog_index)} projects from {prog_index_file}")

    summary_map = summarize_obj_logs(output_dir, prog_index)
    ack(f"Summarized logs for {len(summary_map)} objects")

    # deduped_prog_index = dedup_prog_index(output_dir, prog_index, summary_map, no_bcf)
    # info(f"Deduplicated {len(deduped_prog_index)} projects")
    # load deduped_prog_index.json from prog_dir/deduped_prog_index.json
    deduped_prog_index_file = os.path.join(prog_dir, "deduped_prog_index.json")
    with open(deduped_prog_index_file, "r") as f:
        deduped_prog_index = json.load(f)
    ack(f"Loaded {len(deduped_prog_index)} projects from {deduped_prog_index_file}")

    process_object_results(output_dir, deduped_prog_index, summary_map, no_bcf)



def collect_object_sizes(output_dir, prog_dir, prog_index):
    """
    Collect the sizes of all objects in the program index.

    Args:
        output_dir (str): The directory containing all project results.
        prog_dir (str): The directory containing all the eBPF programs.
        prog_index (dict): The program index containing projects and their groups of objects.

    Returns:
        dict: A dictionary mapping objects to their sizes.
    """
    obj_sizes = {}

    # strip the object file and output the stripped binary to output/stripped
    stripped_dir = os.path.join(output_dir, "stripped")
    if not os.path.exists(stripped_dir):
        os.makedirs(stripped_dir)

    for project, groups in prog_index.items():
        for _, objs in groups.items():
            for obj in objs:
                obj_file = os.path.join(prog_dir, project, obj)
                stripped_file = os.path.join(stripped_dir, obj)
                if not os.path.exists(obj_file):
                    warn(f"object file {obj_file} not found")
                    continue
                if not os.path.exists(stripped_file):
                    # use llvm-strip to strip the object file
                    info(f"stripping {obj_file} to {stripped_file}")
                    os.system(f"llvm-strip -o {stripped_file} {obj_file}")

                # collect size in kb
                obj_size = os.path.getsize(stripped_file) / 1024
                obj_sizes[obj] = obj_size

    return obj_sizes


def unique_objects_size(output_dir, progs_dir):
    """
    Collect the sizes of all unique objects in the program index.
    """
    # load unique object index from deduped_prog_index.json
    info(f"Collecting unique objects sizes from {output_dir}")
    deduped_index_file = os.path.join(output_dir, "deduped_prog_index.json")
    with open(deduped_index_file, "r") as f:
        deduped_prog_index = json.load(f)
    obj_sizes = collect_object_sizes(output_dir, progs_dir, deduped_prog_index)

    # collect min/avg/max sizes
    sizes = list(obj_sizes.values())
    min_size = min(sizes)
    avg_size = np.mean(sizes)
    max_size = max(sizes)
    ok(f"Unique object sizes min/avg/max (Kb): {min_size}/{avg_size:.2f}/{max_size}")

    # draw histogram
    draw_hist(sizes, "Object Size Distribution", "Size (Kb)", "Count", "unique_obj_sizes.pdf", draw_sep_line=False,
              bins=[0, 32, 64, 128, 256, 512])


def analyze_prog_load_time(output_dir):
    """Analyze 'prog_load_time.json' to generate statistics and plots.

    The data file contains load time following this format:
        {objs: [{'real_time_us': xx, 'user_time_us': xx, 'sys_time_us': xx}, ...], ...}

    We analyze the distribution of each metric and calculate the proportion of time spent in user/sys
    comparing to real_time.
    Each object is loaded five times, so we calculate the average time for each object.
    """
    prog_load_time_file = os.path.join(output_dir, "prog_load_time.json")
    with open(prog_load_time_file, "r") as f:
        prog_load_time = json.load(f)

    real_times = []
    user_times = []
    sys_times = []
    user_proportion = []
    sys_proportion = []
    min_real_time = float('inf')
    max_real_time = 0
    min_user_time = float('inf')
    max_user_time = 0
    min_sys_time = float('inf')
    max_sys_time = 0
    for _, times in prog_load_time.items():
        obj_real_times = [t['real_time_us'] for t in times]
        obj_user_times = [t['user_time_us'] for t in times]
        obj_sys_times = [t['sys_time_us'] for t in times]

        obj_real_time = np.mean(obj_real_times)
        obj_user_time = np.mean(obj_user_times)
        obj_sys_time = np.mean(obj_sys_times)

        # compute proportion using geometric mean
        real_time = np.array(obj_user_times) + np.array(obj_sys_times)
        user_proportion.append(np.exp(np.mean(np.log(np.array(obj_user_times) / real_time))))
        sys_proportion.append(np.exp(np.mean(np.log(np.array(obj_sys_times) / real_time))))

        real_times.append(obj_real_time)
        user_times.append(obj_user_time)
        sys_times.append(obj_sys_time)
        min_real_time = min(min_real_time, obj_real_time)
        max_real_time = max(max_real_time, obj_real_time)
        min_user_time = min(min_user_time, obj_user_time)
        max_user_time = max(max_user_time, obj_user_time)
        min_sys_time = min(min_sys_time, obj_sys_time)
        max_sys_time = max(max_sys_time, obj_sys_time)

    # convert time from us to s
    real_time_avg = np.mean(real_times) / 1e6
    user_time_avg = np.mean(user_times) / 1e6
    sys_time_avg = np.mean(sys_times) / 1e6
    ok(f"Real time min/avg/max (s): {min_real_time/1e6:.2f}/{real_time_avg:.2f}/{max_real_time/1e6:.2f}")
    ok(f"User time min/avg/max (s): {min_user_time/1e6:.2f}/{user_time_avg:.2f}/{max_user_time/1e6:.2f}")
    ok(f"Sys time min/avg/max (s): {min_sys_time/1e6:.2f}/{sys_time_avg:.2f}/{max_sys_time/1e6:.2f}")
    ok(f"User proportion min/avg/max (%): {min(user_proportion)*100:.2f}/{np.mean(user_proportion)*100:.2f}/{max(user_proportion)*100:.2f}")
    ok(f"Sys proportion min/avg/max (%): {min(sys_proportion)*100:.2f}/{np.mean(sys_proportion)*100:.2f}/{max(sys_proportion)*100:.2f}")

    # draw histograms real time
    # convert real time from us to s
    real_times = [t / 1e3 for t in real_times]
    draw_hist(real_times, "Real Time Distribution", "Time (ms)", "Count", "real_time.pdf")



def validate_failed_reasons(output_dir, project, group, obj, expected):
    """
    Validate the failed reasons of rejected objects.

    For the rejected obj, read its log and check if the failed reason is
    either sat or program too big.
    """

    log_file = os.path.join(output_dir, project, obj + ".log")
    with open(log_file, "r") as f:
        log = f.read()

    # extract the last vlog, which should be the log for the rejected program
    vlogs = extract_vlogs(log)
    if len(vlogs) == 0:
        warn(f"no vlogs found for {obj}")
        return False

    # extract the last five lines and validate the failed reason
    vlog = vlogs[-1]
    lines = vlog.splitlines()
    if len(lines) < 5:
        warn(f"not enough lines in vlog for {obj}")
        return False

    last_five = lines[-5:]
    # if the reason is sat, then the last line should be bcf log
    if "bcf requested" in last_five[-1]:
        reason = "sat"
    # if the reason is program too big, then the last five line should contain "BPF program is too large"
    elif any("BPF program is too large" in line for line in last_five):
        reason = "path_exceed"
    else:
        warn(
            f"failed reason not 'sat' or 'program too large; for {obj}")
        warn(f"last five lines: {last_five}")
        reason = "unknown"

    if reason != expected:
        warn(
            f"failed reason mismatch for {obj}: expected {expected}, got {reason}")
        return False

    return True


def draw_hist(data, title, xlabel, ylabel, filename, bins=None, last_bin_start=-1, convertor=None, draw_sep_line=True, round_up=True):

    if bins is None:
        bin_edges = np.percentile(data, [0, 10, 30, 60, 80, 95, 100])
        bins = []
        for edge in bin_edges:
            # round up to the nearest multiple of 10
            if edge > 10 and round_up:
                edge = int(np.ceil(edge / 10.0)) * 10
            bins.append(edge)
        if last_bin_start != -1:
            bins[len(bins) - 2] = last_bin_start
        bins[0] = min(data)
    bins[len(bins)-1] = max(data)
    bin_edges = bins

    counts, edges = np.histogram(data, bins=bin_edges)
    total = np.sum(counts)
    assert total == len(data)

    # Generate labels for each bin with half-open intervals (except the last bin is closed)
    bin_labels = []
    for i in range(len(edges) - 1):
        lower = int(edges[i])
        upper = int(edges[i+1])
        if convertor:
            lower = convertor(lower)
            upper = convertor(upper)
        if i == len(edges) - 2:
            label = f"{lower}+"
        else:
            label = f"[{lower}, {upper})"
        bin_labels.append(label)

    x_pos = np.arange(len(bin_labels))
    plt.figure(figsize=(8, 5))
    # increase font size a bit
    plt.rcParams.update({'font.size': 12})
    # Use the scientific notation for y-axis
    plt.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    plt.gca().yaxis.get_offset_text().set_fontsize(14)
    bars = plt.bar(x_pos, counts, width=0.8, color='skyblue',
                   edgecolor='black', alpha=0.7)

    # draw a line in the space between the last two bins to show the percentage of all previous bins
    if draw_sep_line:
        plt.axvline(x=x_pos[-2] + 0.5, color='red', linestyle='--')
        percent = (np.sum(counts[:-1]) / total) * 100
        sep = f"{bins[-2]}"
        if convertor:
            sep = convertor(bins[-2])
            sep = f"{sep:.1f}"
        plt.text(
            # place the text to the right of the line plus a bit of padding
            x_pos[-2] + 0.5 + 0.1,
            max(counts) * 0.8,  # a bit above the bar
            f"< {sep}\n({percent:.1f}%)",
            # to the right of the line
            ha='left', va='bottom', fontsize=10
        )

    # Annotate each bar
    for i, bar in enumerate(bars):
        height = bar.get_height()
        percent = (height / total) * 100
        # add a comma to the height if it is greater than 1000
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height + 1,  # a bit above the bar
            f"{int(height):,}\n({percent:.1f}%)",
            ha='center', va='bottom', fontsize=10
        )

    plt.xticks(x_pos, bin_labels, rotation=45)
    if xlabel:
        plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    # 1) Increase the top y-limit to avoid text clipping
    plt.ylim(top=max(counts) * 1.2)
    # 2) Add a bit of padding around the figure
    plt.tight_layout()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(filename)


def power_law(x, a, b):
    return a * np.power(x, b)


def plot_fitted_curve(x_data, y_data, x_label, y_label, title, bin_size=64, save_path='fitted_curve.png'):
    from scipy.optimize import curve_fit

    # convert list input to numpy array
    x_data = np.array(x_data)
    y_data = np.array(y_data)
    # Bin data into fewer points
    binned_x = x_data[:len(x_data)//bin_size *
                      bin_size].reshape(-1, bin_size).mean(axis=1)
    binned_y = y_data[:len(y_data)//bin_size *
                      bin_size].reshape(-1, bin_size).mean(axis=1)

    # Fit power law
    params, _ = curve_fit(power_law, x_data, y_data)

    # Generate reduced x values for plotting trend
    x_smooth = np.linspace(min(x_data), max(x_data), 100)
    y_smooth = power_law(x_smooth, *params)

    # Identify outliers (points significantly deviating from the fit)
    y_pred = power_law(x_data, *params)
    residuals = np.abs(y_data - y_pred)
    threshold = np.percentile(residuals, 90)  # Top 10% as outliers
    outliers = residuals > threshold

    # Plot setup
    plt.figure(figsize=(8, 6))
    plt.scatter(binned_x, binned_y, color='blue',
                label='Binned Data', marker='o', edgecolor='black')
    plt.plot(x_smooth, y_smooth, color='red', linestyle='--',
             label=f'Fit: $y = {params[0]:.2f}x^{{{params[1]:.2f}}}$')

    # Highlight outlier regions
    plt.fill_between(x_data[outliers], y_data[outliers] - threshold, y_data[outliers] +
                     threshold, color='orange', alpha=0.3, label='Outlier Region')

    # Labels and styling
    plt.xlabel(x_label, fontsize=14)
    plt.ylabel(y_label, fontsize=14)
    plt.title(title, fontsize=16)
    plt.legend(fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tick_params(axis='both', which='major', labelsize=12)
    plt.tight_layout()

    plt.savefig(save_path)


def plot_boxplot(x_data, y_data, x_label, y_label, title, bin_count=10, save_path='boxplot.png'):
    import seaborn as sns

    # Define bins as exact powers of two, include 128, 256, 512, 1024, 2048, 4096
    # bins = [0]
    bins = [2**i for i in range(5, 13)]
    assert bins[0] <= min(x_data)
    if bins[-1] < max(x_data):
        bins.append(max(x_data) + 1)
    bins = np.array(bins)
    bin_indices = np.digitize(x_data, bins) - 1

    # Prepare data for boxplot
    # bins.pop()  # Remove the last bin edge
    binned_data = [[] for _ in range(len(bins))]
    added = 0
    for i, y in zip(bin_indices, y_data):
        if 0 <= i < len(bins):
            binned_data[i].append(y)
            added += 1
    assert added == len(x_data) # ensure we considered all data points

    # generate bin labels similar to the histogram
    bin_labels = []
    for i in range(len(bins) - 1):
        # Remove empty bins
        if not binned_data[i]:
            continue
        lower = int(bins[i])
        upper = int(bins[i+1])
        if i == len(bins) - 2:
            label = f"{lower}+"
        else:
            label = f"[{lower}, {upper})"
        bin_labels.append(label)

    binned_data = [data for data in binned_data if data]

    # Filter extreme outliers based on interquartile range (IQR): https://en.wikipedia.org/wiki/Interquartile_range
    def filter_outliers(data):
        if len(data) < 2:
            return data  # No filtering if too few data points
        q1, q3 = np.percentile(data, [25, 75])
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        return [y for y in data if lower_bound <= y <= upper_bound]

    binned_data = [filter_outliers(data) for data in binned_data]

    # Plot boxplot with improved style
    plt.figure(figsize=(10, 6))
    sns.boxplot(data=binned_data, notch=True,
                boxprops={'facecolor': 'lightblue'})

    # Labels and styling
    plt.xticks(range(len(bin_labels)), bin_labels, rotation=45)
    plt.xlabel(x_label, fontsize=14)
    plt.ylabel(y_label, fontsize=14)
    plt.title(title, fontsize=16)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tick_params(axis='both', which='major', labelsize=12)
    plt.tight_layout()

    # Save and show
    plt.savefig(save_path)


def analyze_bcf_stats(output_dir, progs_dir, validate_fails=False, summary_map=None):
    """
    Analyze the BCF statistics of loaded objects.

    For each loaded object, we analyze the following:
        (1) The number of bcf proof checks performed.
        (2) The total time taken for all bcf proof checks.
        (3) The total size of all proofs generated.

    For all loaded objects, we analyze the following:
        (1) The distribution of the number of bcf proof checks.
        (2) The distribution of the time taken for bcf proof checks.
        (3) The distribution of the size of proofs generated.
    Where the min, avgerage, and max values are also calculated for each distribution.

    For proof generated, we also correlate the size of the proof with the time taken for the check.
    """

    # First, dump object size distribution
    unique_objects_size(output_dir, progs_dir)


    # Then, let's read object_results_unique.csv to calculate the number of objects loaded/rejected
    ack("Loading results...")
    OBJ_RESULT_FILE = "object_results_unique.csv"
    all_objs = set()
    loaded_objs = set()
    rejected_objs = set()
    with open(os.path.join(output_dir, OBJ_RESULT_FILE), "r") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            all_objs.add(row[2])
            if row[4] == "loaded":
                loaded_objs.add(row[2])
            else:
                rejected_objs.add(row[2])

    if is_tty():
        # colored output
        ok("load results: \033[92m{}/{}/{}\033[0m loaded/rejected/total".format(
            len(loaded_objs), len(rejected_objs), len(all_objs)))
        ok("load results: \033[92m{:.2%}\033[0m loaded".format(
            len(loaded_objs) / len(all_objs)))
        ok("load results: \033[91m{:.2%}\033[0m rejected".format(
            len(rejected_objs) / len(all_objs)))
    else:
        ok("load results: {}/{}/{} loaded/rejected/total".format(
            len(loaded_objs), len(rejected_objs), len(all_objs)))
        ok("load results: {:.2%} loaded".format(
            len(loaded_objs) / len(all_objs)))
        ok("load results: {:.2%} rejected".format(
            len(rejected_objs) / len(all_objs)))

    # analyze_prog_load_time(output_dir)

    # Next, let's read bcf_stats.csv to analyze the BCF statistics of loaded objects
    ack("Analyzing BCF statistics of loaded objects...")
    BCF_STATS_FILE = "bcf_stats.csv"
    bcf_stats = []
    with open(os.path.join(output_dir, BCF_STATS_FILE), "r") as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            # analyze only deduplicated objects
            if row[2] not in all_objs:
                continue
            # project, group, object, check_nth, check_time, proof_size, refine_type, backtrack_length, track_length, cond_size
            bcf_stats.append((row[0], row[1], row[2], int(
                row[3]), int(row[4]), int(row[5]), row[6], int(row[7]), int(row[8]), int(row[9])))

    # Analyze the BCF statistics of loaded objects
    # Here we ignore the check nth, but simply count the number of records for each object
    # and calculate the total time taken and total size of proofs generated.
    obj_stats = {}
    min_check_obj = None
    min_check_size = 0xffffffff
    for stat in bcf_stats:
        obj = stat[2]
        if obj not in obj_stats:
            obj_stats[obj] = {"count": 0, "time": [],
                              "size": [], "time_total": 0, "size_total": 0, "cond_size": []}
        obj_stats[obj]["count"] += 1
        obj_stats[obj]["time"].append(stat[4])
        obj_stats[obj]["size"].append(stat[5])
        if stat[5] < min_check_size:
            min_check_size = stat[5]
            min_check_obj = obj
        obj_stats[obj]["time_total"] += stat[4]
        obj_stats[obj]["size_total"] += stat[5]
        obj_stats[obj]["cond_size"].append(stat[9])

    info("Min check size: {} bytes for object {}".format(
        min_check_size, min_check_obj))

    # Analyze the distribution of the number of bcf proof checks
    check_counts = [stats["count"] for stats in obj_stats.values()]
    check_count_min = min(check_counts)
    check_count_avg = sum(check_counts) / len(check_counts)
    check_count_max = max(check_counts)
    check_count_total = sum(check_counts)
    # log the min, avg, max with different color
    ok(f"check count min/avg/max/total: {check_count_min}/{check_count_avg:.2f}/{check_count_max}/{check_count_total}")
    # draw_hist(check_counts, "Distribution of Proof Request Times",
    #           "Proof Request Times", "Frequency", "check_counts_hist.pdf", last_bin_start=900)
    # ack("check_counts_hist.pdf saved")

    # count and output objs without bcf proof checks, those are the objs in the accepted set but not in the obj_stats
    no_bcf_objs = loaded_objs - set(obj_stats.keys())
    ok(f"objs without bcf proof checks: {len(no_bcf_objs)}")

    # Analyze the distribution of the time taken for bcf proof checks
    check_times = [time for stats in obj_stats.values()
                   for time in stats["time"]]
    check_time_min = min(check_times) / 1000  # convert to us
    check_time_avg = sum(check_times) / len(check_times) / 1000
    check_time_max = max(check_times) / 1000
    ok(f"check time (us) min/avg/max: {check_time_min}/{check_time_avg:.2f}/{check_time_max}")
    # draw_hist(check_times, "Distribution of Time Taken for Proof Checks",
    #           "Proof Check Times (us)", "Frequency", "check_times_hist.pdf", convertor=lambda x: x / 1000)
    # ack("check_times_hist.pdf saved")

    # Analyze the distribution of the size of proofs generated
    proof_sizes = [size for stats in obj_stats.values()
                   for size in stats["size"]]
    proof_size_min = min(proof_sizes)
    proof_size_avg = sum(proof_sizes) / len(proof_sizes)
    proof_size_max = max(proof_sizes)
    ok(f"proof size (bytes) min/avg/max: {proof_size_min}/{proof_size_avg:.2f}/{proof_size_max}")
    # draw_hist(proof_sizes, "Distribution of Proof Sizes (Bytes)",
    #           None, "Frequency", "proof_sizes_hist.pdf",
              # bins=[128, 256, 512, 1024, 4096, 0])
    # ack("proof_sizes_hist.pdf saved")

    # ack("Analyzing the correlation between the size of proofs and time taken...")
    # Correlate the size of the proof with the time taken for the check
    # proof_sizes = []
    # proof_times = []
    # for stats in obj_stats.values():
    #     for size, time in zip(stats["size"], stats["time"]):
    #         proof_sizes.append(size)
    #         proof_times.append(time/1000)
    # plot_boxplot(proof_sizes, proof_times, 'Proof Size (bytes)', 'Proof Check Time (us)',
    #              'Proof Size vs. Check Time', save_path='proof_size_vs_check_time_boxplot.pdf')
    # ack("proof_size_vs_check_time_boxplot.pdf saved")


    # proof time / verification time
    track_lengths = []
    track_length_prop = []
    cond_sizes = []
    proof_time_vtime = []
    proof_n_insn_n = []
    for obj in loaded_objs:
        summary = summary_map[obj]
        assert len(summary) != 0
        for s in summary:
            if len(s.bcf_stats) == 0:
                continue
            if s.verification_time == 0:
                warn(f"verification time is 0 for {obj}")
                continue

            proof_check_time = 0
            proof_n = len(s.bcf_stats)
            track_length = 0
            for bcf_stat in s.bcf_stats:
                proof_check_time += bcf_stat.check_time
                track_length += bcf_stat.track_length
                track_lengths.append(bcf_stat.track_length)
                cond_sizes.append(bcf_stat.cond_size)

            track_length_prop.append((track_length, s.insn_processed + track_length))
            proof_time_vtime.append(
                (proof_check_time, s.verification_time * 1000)) # convert to ns
            proof_n_insn_n.append((proof_n, s.insn_processed))

    # track length min/avg/max
    track_length_min = min(track_lengths)
    track_length_avg = np.mean(track_lengths)
    track_length_max = max(track_lengths)
    ok(f"track length min/avg/max: {track_length_min}/{track_length_avg:.2f}/{track_length_max}")

    # cond size min/avg/max
    cond_size_min = min(cond_sizes)
    cond_size_avg = np.mean(cond_sizes)
    cond_size_max = max(cond_sizes)
    ok(f"cond size min/avg/max: {cond_size_min}/{cond_size_avg:.2f}/{cond_size_max}")

    # track length vs. insn processed
    track_length_prop_min = min([t[0]/t[1] for t in track_length_prop])
    track_length_prop_max = max([t[0]/t[1] for t in track_length_prop])
    # geometric mean
    track_length_prop_avg = np.exp(
        np.mean([np.log(t[0]/t[1]) for t in track_length_prop]))
    ok(f"track length / insn processed min/avg/max: {track_length_prop_min:.6f}/{track_length_prop_avg:.6f}/{track_length_prop_max:.6f}")

    # compute the geometric mean of the proof time / verification time
    proof_percetage_min = min([p[0]/p[1] for p in proof_time_vtime])
    proof_percetage_max = max([p[0]/p[1] for p in proof_time_vtime])
    # geometric mean
    proof_percetage_avg = np.exp(
        np.mean([np.log(p[0]/p[1]) for p in proof_time_vtime]))
    # ok(f"proof time / verification time min/avg/max: {proof_percetage_min:.6f}/{proof_percetage_avg:.6f}/{proof_percetage_max:.6f}")
    # draw_hist([p[0]/p[1] for p in proof_time_vtime], "Distribution of Proof Time / Verification Time",
    #           "Proof Time / Verification Time", "Frequency", "proof_time_vtime_hist.pdf", convertor=lambda x: x)

    # proof request time vs. insn processed
    proof_n_min = min([p[0]/p[1] for p in proof_n_insn_n])
    proof_n_max = max([p[0]/p[1] for p in proof_n_insn_n])
    # geometric mean
    proof_n_avg = np.exp(np.mean([np.log(p[0]/p[1]) for p in proof_n_insn_n]))
    # ok(f"insn with proof / total insn processed min/avg/max: {proof_n_min:.6f}/{proof_n_avg:.6f}/{proof_n_max:.6f}")
    # draw_hist([p[1]/p[0] for p in proof_n_insn_n], "Distribution of Proof N / Insn Processed",
    #           "Proof N / Insn Processed", "Frequency", "proof_n_insn_hist.pdf", convertor=lambda x: x)

    from prettytable import PrettyTable  # type: ignore
    table = PrettyTable()
    table.field_names = ["Metric", "Min", "Avg", "Max"]
    table.align["Metric"] = "l"
    table.align["Min"] = "l"
    table.align["Avg"] = "l"
    table.align["Max"] = "l"
    # table.align["Count"] = "l"
    # print flow with .2f precision
    table.add_row(["Refinement Frequency", check_count_min,
                  f'{check_count_avg:.1f}', check_count_max])
    table.add_row(["Symbolic Track Length", f'{track_length_min:.1f}',
                  f'{track_length_avg:.1f}', f'{track_length_max:.1f}'])
    table.add_row(["Condition Size (bytes)", cond_size_min,
                  f'{cond_size_avg:.1f}', cond_size_max])
    table.add_row(["Proof Check Time (us)", f'{check_time_min:.1f}',
                  f'{check_time_avg:.1f}', f'{check_time_max:.1f}'])
    table.add_row(["Proof Size (bytes)", proof_size_min,
                  f'{proof_size_avg:.1f}', proof_size_max])
    table.add_row(["Proof Time / Verification Time",
                  f'{proof_percetage_min:.6f}', f'{proof_percetage_avg:.6f}', f'{proof_percetage_max:.6f}'])
    table.add_row(["Insn with Proof / Total Insn Processed",
                  f'{proof_n_min:.6f}', f'{proof_n_avg:.6f}', f'{proof_n_max:.6f}'])
    print(table)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process the load results.")
    parser.add_argument(
        "-o", "--output_dir", help="The directory containing all project results.")
    parser.add_argument(
        "-p", "--progs_dir", help="The directory containing all the eBPF programs.")
    parser.add_argument(
        "-v", "--validate_fails", help="Validate the failed reasons of rejected objects.", action="store_true")
    parser.add_argument(
        "-vv", "--verbose", help="Verbose mode.", action="store_true"
    )
    args = parser.parse_args()

    if args.verbose:
        verbose = True

    process_bcf_result(args.progs_dir, args.output_dir)

    prog_index_file = os.path.join(args.progs_dir, "prog_index.json")
    with open(prog_index_file, "r") as f:
        prog_index = json.load(f)
    ack(f"Loaded {len(prog_index)} projects from {prog_index_file}")
    summary_map = summarize_obj_logs(args.output_dir, prog_index)
    analyze_bcf_stats(args.output_dir, args.progs_dir, args.validate_fails, summary_map)

## BCF Program Set

We use a compiler-driven approach to automatically reveal the verifier's precision issues, as described bellow.

We consider a set of popular user space projects that extensively use eBPF.
For each project (corresponds to a directory), we compile their bpf programs with different compiler versions and optimization levels (as shown under each diectory, each variant is prefixed with compiler_version-optimization_level-obj_name).
Since the compiler configuration is different, the produced bytecode varies a lot. This pose different analysis challenges to the verifier, e.g., different register usage, instruction types, and control flow can trigger different abstract operators; hence different analysis results and procedures.

Importanly, different variants from the same source bpf program are semantically equivalent. Hence, the verifier should produce the same analysis results for them; any differences incicate a problem. The diverse code patterns and equivance of those variants, collectlively, allow us to evaluate the verifier's precision, automatically. Conversely, it allows us to show the BCF's improvement over the vanilla verifier.

This directory contains the resulting bpf programs from the above process.
The `prog_index.json` presents a stuctured index of the programs.
The `obj_prog_type.json` provides program type information.

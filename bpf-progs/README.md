## BCF Program Set

We use a compiler-driven approach to automatically reveal the verifier's precision issues, as described bellow.

We consider a set of popular user space projects that extensively use eBPF.
For each project (corresponds to a directory), we compile their bpf programs with different compiler versions and optimization levels (as shown under each diectory, each variant is prefixed with compiler_version-optimization_level-obj_name).
Since the compiler configuration is different, the produced bytecode varies a lot. This pose different analysis challenges to the verifier, e.g., different register usage, instruction types, and control flow can trigger different abstract operators; hence different analysis results and procedures.

Importanly, different variants from the same source bpf program are semantically equivalent. Hence, the verifier should produce the same analysis results for them; any differences incicate a problem. The diverse code patterns and equivance of those variants, collectlively, allow us to evaluate the verifier's precision, automatically. Conversely, it allows us to show the BCF's improvement over the vanilla verifier.

This directory contains the resulting bpf programs from the above process.
The `prog_index.json` presents a stuctured index of the programs.
The `obj_prog_type.json` provides program type information.

To automatically load all progs and test BCF, boot the VM and inside it, run the followling:

```
> ./scripts/load_prog.py -d bpf-progs
```

It automatically loads all the progs listed in the index. Since our modified bpftool detects the supported cvc5, the load command used by the script is same as the normally used one. To use script for testing load without BCF support, please replace the bpftool pre-installed in the provided disked image, which are under:

```
/usr/bin/bpftool /use/local/sbin/bpftool
```

Because loading with modified `bpftool` on normal kernel can lead to `-E2BIG` due to our modification to uapi `union bpf_attr`.

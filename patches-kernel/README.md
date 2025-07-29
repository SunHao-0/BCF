## BCF Kernel Patch Set

This patch set introduces abstraction refinement to the eBPF verifier and integrates the BCF proof checker into the kernel.

See the cover letter and the commit message of each patch for more details.

To apply the patch set, run:

```bash
cd path/to/linux-6.13.4
for patch in patches-kernel/*.patch; do
    git am $patch
done
```

Notes: The patch set is tested on Linux 6.13.4, x86_64, using a bookworm disk image.

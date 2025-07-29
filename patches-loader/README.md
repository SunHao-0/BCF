## BCF Loader Patch Set

The user-space loader (bpftool) is modified to:
- Detect refinement conditions in the bcf_buf
- Convert conditions to the SMT-LIB format
- Interact with the SMT solver
- Bridge the kernel verifier and user-space solver
- Drive the refinement-solving loop

See the cover letter and the commit message of each patch for more details.

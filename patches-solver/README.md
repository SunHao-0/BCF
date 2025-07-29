## BCF Solver Patch Set

The solver reasons about the refinement condition (a QF_BV formula):
- If SAT: refinement is unsound, no valid proof exists
- If UNSAT: produces a refutation proof
- Modified to emit proofs in BCF (binary) format
- Loader receives the proof and transmits it to the kernel

Note: This part is less organized than the kernel patch set, and we improved it in the latest implementation.

The patch set is test on cvc5 8514715cbc48f898f620955f8c718495f926777d.
